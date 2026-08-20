//! Server-side P2P orchestration: bind the video listener, create a P2P
//! [`ListenerSession`] that relays to it, and drive capability issuance and the
//! relay bind leg from the GUI via a command channel.
//!
//! The manual exchange the operator performs (spec §13 / plan §3.5):
//! 1. the initiator reveals its `endpoint_id`;
//! 2. [`ServerInfo::listener_id`] + an issued capability go to the initiator;
//! 3. the initiator connects and reveals its `connection_id`;
//! 4. [`ServerCommand::Bind`] attaches the relay for it.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;

use bytes::Bytes;
use isekai_p2p::agent::{ObservedAddressWatch, RelayOptions};
use isekai_p2p::{
    issue_endpoint_token, proxy_client, AcceptPolicy, ListenerSession, P2pConfig, SignalingEvent,
};
// The loop that drives the session, and what asks it to do things. Both moved
// to the layer in phase 1c-iii-c -- nothing in either was a camera -- and the
// command type keeps the name this crate's GUI already spells.
pub use isekai_p2p::listener::ListenerCommand as ServerCommand;
use msquic_async::Registration;
use tokio::sync::{broadcast, mpsc};
use tokio_util::sync::CancellationToken;

use crate::video::{bind_video_listener, serve_frames_with, RelayLegs, ServeOptions};

/// What the operator conveys to the initiator once the server is up.
#[derive(Clone, Debug)]
pub struct ServerInfo {
    /// The private Peer Listener's id.
    pub listener_id: String,
    /// This Endpoint's id.
    pub endpoint_id: String,
    /// The local video listener address the relay forwards to (for diagnostics).
    pub video_addr: SocketAddr,
}

/// A running P2P server: static [`ServerInfo`] plus the command channel.
///
/// Cancel the `shutdown` token passed to [`spawn_p2p_server`] to stop it (that
/// ends both the video service and the relay session).
pub struct ServerHandle {
    pub info: ServerInfo,
    pub commands: mpsc::Sender<ServerCommand>,
    /// What the automatic binding did, for the UI to show.
    ///
    /// A broadcast rather than a queue: the handle is passed around behind a
    /// lock, so a single `Receiver` could only be read from wherever it was
    /// moved to. Subscribers that fall behind lose the oldest events, which is
    /// the right trade — a stalled notification must never hold up the loop
    /// that binds connections.
    pub signaling: broadcast::Sender<SignalingEvent>,
    /// How the proxy sees this Endpoint's relay bind leg — `None` until a leg
    /// is bound and reports. This is the address advertised to each video
    /// client as a direct path; surfacing it makes a stuck migration
    /// diagnosable from the UI.
    pub observed: ObservedAddressWatch,
    /// Resolves once the session has shut down and its listener has been
    /// withdrawn from the proxy.
    ///
    /// **An application that exits without awaiting this races its own
    /// cleanup.** Cancelling the token only makes the loop start closing; the
    /// withdrawal that follows is an HTTP request over the same msquic
    /// registration the process is about to drain, so a drain that finishes
    /// first takes the request with it and the listener is left to lapse —
    /// visible to every paired peer, for the rest of its lease, as something
    /// that looks connectable and is not.
    pub finished: tokio::task::JoinHandle<()>,
    /// The video listener's msquic registration. A `msquic_async::Listener`
    /// borrows its registration rather than keeping it alive, so this must
    /// outlive the listener (which runs in the spawned `serve_frames` task);
    /// holding it here ties its lifetime to the handle.
    _video_reg: Arc<Registration>,
}

/// Bind the video listener, create the P2P listener session forwarding to it,
/// and start serving frames from `frame_rx`. Returns once the listener and
/// session exist; capability issuance and binding then happen via
/// [`ServerHandle::commands`].
///
/// `video_key_path` is where this device's video TLS key lives. Named by the
/// caller rather than derived here, because what it holds is the thing this
/// whole arrangement exists to keep: a key that is generated on first use,
/// reused for every issuance after, and sent nowhere.
pub async fn spawn_p2p_server(
    reg: Option<Arc<Registration>>,
    cfg: P2pConfig,
    video_key_path: &Path,
    frame_rx: mpsc::Receiver<Bytes>,
    policy: AcceptPolicy,
    shutdown: CancellationToken,
) -> anyhow::Result<ServerHandle> {
    // Issue the Endpoint Token once, then reuse it for both the certificate
    // download and the listener session.
    let endpoint_token = issue_endpoint_token(&cfg).await?.endpoint_token;

    // Get this Endpoint's relay certificate for a key generated here, so the
    // video listener can present it and the initiator can validate it.
    //
    // **The key is this device's and is not sent anywhere.** The relay carries
    // the ciphertext this key opens; while the proxy generated it, the
    // encryption on that leg protected the peers from everyone except the proxy
    // in the middle of it (spec §8.6.2). What goes out is a certificate request.
    //
    // `None` when the proxy issues nothing — the listener then presents a dev
    // certificate and the initiator skips validation, as before.
    let video_key = crate::tls::load_or_generate_video_key(video_key_path)?;
    let proxy = proxy_client(&cfg, &endpoint_token)?;
    let cert = crate::tls::issue_video_cert(&proxy, &cfg.key, &video_key).await?;
    if cert.is_none() {
        tracing::warn!("proxy issues no relay certificate; using a development one");
    }

    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
    let (video_reg, listener, video_addr) = bind_video_listener(reg, bind_addr, cert.as_ref())?;

    // The relay delivers the initiator's traffic to the video listener address.
    //
    // The bind leg goes on a shared, unconnected socket so a direct path can
    // later be opened from its binding, and on the *same* registration as the
    // video listener — msquic looks bindings up per registration, so a leg on
    // another one could never be shared with the accepted connections
    // (docs/p2p_mode_migration_plan.md §2.2.3, §2.4).
    let session = ListenerSession::create_with_token_and_options(
        &cfg,
        &endpoint_token,
        video_addr,
        None,
        RelayOptions {
            unconnected: true,
            registration: Some(video_reg.clone()),
        },
    )
    .await?;
    let info = ServerInfo {
        listener_id: session.listener_id.clone(),
        endpoint_id: session.endpoint_id.clone(),
        video_addr,
    };

    // The session-wide watch, for the operator's benefit: it carries whichever
    // leg reported last, which is fine to show and wrong to advertise. What is
    // advertised to each connection is its own leg (`RelayLegs::PerConnection`).
    //
    // Taken before any leg is bound — which is the normal order, since binding
    // waits on a connection id conveyed by hand. It survives that gap and any
    // later rebind.
    let observed_for_handle = session.observed_address();
    tokio::spawn(serve_frames_with(
        listener,
        frame_rx,
        shutdown.clone(),
        ServeOptions {
            legs: Some(RelayLegs::PerConnection(session.legs())),
        },
    ));

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (signaling, _) = broadcast::channel(32);
    let finished = tokio::spawn(isekai_p2p::listener::run(
        session,
        cmd_rx,
        policy,
        signaling.clone(),
        shutdown,
    ));

    Ok(ServerHandle {
        info,
        commands: cmd_tx,
        signaling,
        observed: observed_for_handle,
        finished,
        _video_reg: video_reg,
    })
}
