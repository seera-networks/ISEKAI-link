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
use std::time::Duration;

use bytes::Bytes;
use isekai_p2p::agent::ListenerEvent;
use isekai_p2p::agent::{Grant, ObservedAddressWatch, PairingCode, RelayOptions};
use isekai_p2p::{
    fetch_relay_certificate, issue_endpoint_token, AcceptPolicy, ListenerSession, P2pConfig,
    SignalingEvent, SignalingState,
};
use msquic_async::Registration;
use tokio::sync::{broadcast, mpsc, oneshot};
use tokio_util::sync::CancellationToken;

use crate::video::{bind_video_listener, serve_frames_with, ServeOptions};

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
    ///
    /// Only needed under [`AcceptPolicy::Manual`]; otherwise the session binds
    /// what the proxy says is waiting, without anyone carrying an id across.
    Bind {
        connection_id: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Mint a pairing code to display. Replaces whatever code this listener had.
    ShowPairingCode {
        ttl: Option<u64>,
        reply: oneshot::Sender<anyhow::Result<PairingCode>>,
    },
    /// Who is currently allowed to connect.
    ListGrants {
        reply: oneshot::Sender<anyhow::Result<Vec<Grant>>>,
    },
    /// Withdraw one. Takes effect on that peer's next connect.
    RevokeGrant {
        grant_id: String,
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
pub async fn spawn_p2p_server(
    reg: Option<Arc<Registration>>,
    cfg: P2pConfig,
    frame_rx: mpsc::Receiver<Bytes>,
    policy: AcceptPolicy,
    shutdown: CancellationToken,
) -> anyhow::Result<ServerHandle> {
    // Issue the Endpoint Token once, then reuse it for both the certificate
    // download and the listener session.
    let endpoint_token = issue_endpoint_token(&cfg).await?.endpoint_token;

    // Download this Endpoint's per-endpoint relay certificate so the video
    // listener can present it and the initiator can validate it. `None` when the
    // proxy has relay certificates disabled — the listener then uses a dev cert.
    let cert = fetch_relay_certificate(&cfg, &endpoint_token).await?;
    if let Some(bundle) = &cert {
        tracing::info!(
            "using per-endpoint relay certificate for {}",
            bundle.hostname
        );
    } else {
        tracing::warn!("proxy has relay certificates disabled; using a dev certificate");
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

    // Taken before any leg is bound — which is the normal order, since binding
    // waits on a connection id conveyed by hand. The session's watch survives
    // that gap and any later rebind.
    let observed = session.observed_address();
    let observed_for_handle = observed.clone();
    tokio::spawn(serve_frames_with(
        listener,
        frame_rx,
        shutdown.clone(),
        ServeOptions {
            observed: Some(observed),
        },
    ));

    let (cmd_tx, cmd_rx) = mpsc::channel(8);
    let (signaling, _) = broadcast::channel(32);
    let finished = tokio::spawn(command_loop(
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

/// How often the listener asks the proxy whether anyone is waiting.
///
/// The wait it replaces was a person reading a connection id off one screen and
/// typing it into another, so seconds is already an enormous improvement and
/// there is nothing to gain from going lower. It also bounds how much traffic a
/// camera generates while nobody is connecting, which is most of the time.
const SIGNALING_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How often the listener tells the proxy that the peers it is serving are
/// still being served (spec §8.5.4).
///
/// Well inside the proxy's connect TTL, whose default is five minutes, because
/// this side does not know that number and losing every viewer at once is what
/// happens if the guess is wrong. A request per peer per minute is nothing next
/// to the video going the other way.
///
/// It is also the window each leg is judged over: only legs that have carried
/// something since the last tick are renewed. Anything comfortably longer than
/// the path keepalive works — a peer that is there is heard from every ten
/// seconds — and a pass that skips a leg costs nothing, since several fit
/// inside one TTL.
const CONNECTION_RENEW_INTERVAL: Duration = Duration::from_secs(60);

/// How often the listener reads its connections while an event stream is up.
///
/// The stream says when to look, so this is not how a peer is noticed any more
/// — it is the backstop for the case where the stream is healthy and wrong,
/// which is the case its own design cannot rule out (spec §8.11: nothing is
/// replayed). Far apart, because being wrong for a minute is the cost and
/// asking every three seconds was the thing worth removing.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How long to wait before opening the stream again after it ends.
///
/// Ending is ordinary — the proxy restarting, a connection dropping, a
/// subscriber cut off for falling behind — and the listener keeps working from
/// the poll while it is away, so this only has to be short enough not to
/// matter.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(3);

/// The longest gap between attempts once they keep failing.
///
/// A proxy that does not serve this route refuses every time, and retrying it
/// every few seconds would double this camera's request rate forever and burn a
/// nonce on the proxy for each attempt — the store those go in is capped. So
/// the gap grows until it reaches this, and drops back the moment one succeeds.
const RESUBSCRIBE_MAX_DELAY: Duration = Duration::from_secs(300);

async fn command_loop(
    mut session: ListenerSession,
    mut cmd_rx: mpsc::Receiver<ServerCommand>,
    policy: AcceptPolicy,
    events: broadcast::Sender<SignalingEvent>,
    shutdown: CancellationToken,
) {
    let mut signaling = SignalingState::default();
    // Two rates for the same read. While a stream is up it is a backstop and
    // runs a minute apart; without one it is how a waiting peer is noticed at
    // all, and runs every few seconds. Which one applies is decided by whether
    // `stream` holds anything.
    let mut poll = tokio::time::interval(SIGNALING_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut renew = tokio::time::interval(CONNECTION_RENEW_INTERVAL);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Opened below rather than here, so a proxy that cannot stream costs a
    // refused request rather than a failed startup.
    let mut stream: Option<mpsc::Receiver<ListenerEvent>> = None;
    let mut resubscribe_delay = RESUBSCRIBE_DELAY;
    let mut resubscribe_at = tokio::time::Instant::now();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            // Open, or re-open, the event stream. Nothing else waits on this:
            // the poll keeps the listener working while there is no stream, so
            // failing here is a slower camera and not a stopped one.
            _ = tokio::time::sleep_until(resubscribe_at),
                    if stream.is_none() && policy != AcceptPolicy::Manual => {
                match session.subscribe().await {
                    Ok(events) => {
                        tracing::info!("signaling: event stream open");
                        stream = Some(events);
                        resubscribe_delay = RESUBSCRIBE_DELAY;
                        // Rebuilding the interval is what makes the next line
                        // matter: `interval` completes its first tick at once,
                        // so a reconcile runs now and picks up anything that
                        // happened before the stream was listening. Anyone
                        // changing this to `interval_at(now + period, ..)`
                        // opens a gap of one whole period right here.
                        poll = tokio::time::interval(RECONCILE_INTERVAL);
                        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "no event stream, polling instead (retrying in {resubscribe_delay:?}): {e:#}"
                        );
                        resubscribe_delay = (resubscribe_delay * 2).min(RESUBSCRIBE_MAX_DELAY);
                        resubscribe_at = tokio::time::Instant::now() + resubscribe_delay;
                    }
                }
            }
            // An event says something changed; the listing says what. Keeping
            // the decision in one place is what makes it safe for the stream to
            // be best effort — a missed event costs latency until the next
            // reconcile and never a wrong decision (spec §8.11).
            event = async { stream.as_mut().expect("guarded").recv().await },
                    if stream.is_some() => {
                match event {
                    Some(ListenerEvent::Keepalive) => {}
                    Some(_) => poll.reset_immediately(),
                    None => {
                        tracing::info!("signaling: event stream ended; polling until it returns");
                        stream = None;
                        // A stream that worked and then ended is worth trying
                        // again straight away — the usual reason is the proxy
                        // restarting. Only repeated failures back off.
                        resubscribe_at = tokio::time::Instant::now();
                        // And, as above, the first tick of a fresh interval is
                        // immediate: the listener goes back to reading rather
                        // than waiting out a period it has no reason to.
                        poll = tokio::time::interval(SIGNALING_POLL_INTERVAL);
                        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    }
                }
            }
            // Renewing is not conditioned on the policy: a connection bound by
            // hand under `Manual` is being served just as much as one bound
            // automatically, and would otherwise lapse under the operator.
            _ = renew.tick() => {
                for event in session.renew_connections(&signaling).await {
                    tracing::warn!("signaling: {event:?}");
                    let _ = events.send(event);
                }
            }
            // Nothing to poll for under `Manual`: the operator binds, as before.
            _ = poll.tick(), if policy != AcceptPolicy::Manual => {
                match session.poll_signaling(&mut signaling, policy).await {
                    Ok(found) => {
                        for event in found {
                            tracing::info!("signaling: {event:?}");
                            // No subscribers is not a failure — the camera
                            // binds whether or not a UI is watching.
                            let _ = events.send(event);
                        }
                    }
                    // The proxy being briefly unreachable is not a reason to
                    // stop serving; the next tick tries again.
                    Err(e) => tracing::warn!("signaling poll failed: {e:#}"),
                }
            }
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
                Some(ServerCommand::ShowPairingCode { ttl, reply }) => {
                    let _ = reply.send(session.show_pairing_code(ttl).await);
                }
                Some(ServerCommand::ListGrants { reply }) => {
                    let _ = reply.send(session.list_grants().await);
                }
                Some(ServerCommand::RevokeGrant { grant_id, reply }) => {
                    let _ = reply.send(session.revoke_grant(&grant_id).await);
                }
                None => break,
            },
        }
    }
    session.close().await;
}
