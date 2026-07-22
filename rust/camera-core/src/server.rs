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
use std::sync::Arc;

use bytes::Bytes;
use isekai_p2p::{ListenerSession, P2pConfig};
use msquic_async::Registration;
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::video::{bind_video_listener, serve_frames};

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

/// Commands the GUI drives the running server with. Each carries a reply channel.
pub enum ServerCommand {
    /// Mint a capability for the initiator's Endpoint ID; replies with the token.
    IssueCapability {
        allowed_endpoint: String,
        ttl: Option<u64>,
        reply: oneshot::Sender<anyhow::Result<String>>,
    },
    /// Attach the relay bind leg for the initiator's connection id.
    Bind {
        connection_id: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
}

/// A running P2P server: static [`ServerInfo`] plus the command channel.
///
/// Cancel the `shutdown` token passed to [`spawn_p2p_server`] to stop it (that
/// ends both the video service and the relay session).
pub struct ServerHandle {
    pub info: ServerInfo,
    pub commands: mpsc::Sender<ServerCommand>,
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
pub async fn spawn_p2p_server(
    reg: Option<Arc<Registration>>,
    cfg: P2pConfig,
    frame_rx: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
) -> anyhow::Result<ServerHandle> {
    let bind_addr: SocketAddr = "127.0.0.1:0".parse().expect("valid loopback addr");
    let (video_reg, listener, video_addr) = bind_video_listener(reg, bind_addr)?;

    // The relay delivers the initiator's traffic to the video listener address.
    let session = ListenerSession::create(&cfg, video_addr, None).await?;
    let info = ServerInfo {
        listener_id: session.listener_id.clone(),
        endpoint_id: session.endpoint_id.clone(),
        video_addr,
    };

    tokio::spawn(serve_frames(listener, frame_rx, shutdown.clone()));

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    tokio::spawn(command_loop(session, cmd_rx, shutdown));

    Ok(ServerHandle {
        info,
        commands: cmd_tx,
        _video_reg: video_reg,
    })
}

async fn command_loop(
    mut session: ListenerSession,
    mut cmd_rx: mpsc::Receiver<ServerCommand>,
    shutdown: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            cmd = cmd_rx.recv() => match cmd {
                Some(ServerCommand::IssueCapability { allowed_endpoint, ttl, reply }) => {
                    let result = session
                        .issue_capability(&allowed_endpoint, ttl)
                        .await
                        .map(|cap| cap.capability);
                    let _ = reply.send(result);
                }
                Some(ServerCommand::Bind { connection_id, reply }) => {
                    let result = session.bind(&connection_id).await;
                    let _ = reply.send(result);
                }
                None => break,
            },
        }
    }
    session.close().await;
}
