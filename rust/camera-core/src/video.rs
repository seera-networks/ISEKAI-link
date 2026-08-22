//! The camera video transport over QUIC (`sample` ALPN): MJPEG frames, one per
//! unidirectional stream. This is the same wire protocol the camera apps
//! already use; here it is factored out so it works over any address — a public
//! one (legacy) or the P2P relay's loopback address.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{Connection, ConnectionEvent, Listener, Registration, StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

use isekai_p2p::agent::{ObservedAddress, ObservedAddressWatch};
// The path arithmetic and the two ways of moving onto a path went to the
// layer with the rest of the direct-path machinery in phase 4; what stays
// here is when this app asks for a move, which is a camera question.
use isekai_p2p::direct_path::prefer_path;
use isekai_p2p::peer::log_connection_stats;
// Re-exported under the names the viewers and the FFI already import.
pub use isekai_p2p::peer::{AttestedPeer, Unpinnable};

use crate::tls::{dev_cert, VideoCert};

/// ALPN for the camera video protocol.
pub const VIDEO_ALPN: &str = "sample";
/// How often to sample the connection's RTT for [`VideoRecvOptions::rtt`].
const RTT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// How often the heartbeat ticks. See [`spawn_heartbeat`].
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// How long to wait for the relay leg's observed address before dialing without
/// it. The report normally lands within a round trip of the leg coming up; if it
/// does not, streaming over the relay matters more than a direct path.
const OBSERVED_ADDRESS_WAIT: Duration = Duration::from_secs(3);
/// How long a video connection may go without traffic before it is dropped.
///
/// [`isekai_p2p::peer::IDLE_TIMEOUT`] states it and says why; this is the name
/// the FFI exports, because an iOS viewer coming back from the background knows
/// only how long it was away and longer than this means the connection is gone
/// whatever the app still holds.
pub const VIDEO_IDLE_TIMEOUT: Duration = isekai_p2p::peer::IDLE_TIMEOUT;

/// How long a migrated path may carry nothing before falling back to the relay.
///
/// Generous next to a frame interval, so a stutter never triggers it, and short
/// enough to be well inside the 30 s idle timeout that would otherwise take the
/// whole connection down.
const MIGRATED_PATH_GRACE: Duration = Duration::from_secs(5);

/// Bind a video QUIC listener on `addr`.
///
/// With `cert` (the per-endpoint bundle downloaded from the proxy) the listener
/// presents that certificate, so the initiator — dialing the matching loopback
/// FQDN — can validate it. Without one it falls back to a generated dev
/// certificate (dev only; the initiator then skips validation).
///
/// Returns the registration (created when `reg` is `None`), the listener, and
/// its bound local address — for P2P, pass that address to the relay bind leg.
pub fn bind_video_listener(
    reg: Option<Arc<Registration>>,
    addr: SocketAddr,
    cert: Option<&VideoCert>,
) -> anyhow::Result<(Arc<Registration>, Listener, SocketAddr)> {
    let (cert_pem, key_pem, pkcs12) = match cert {
        Some(bundle) => (
            bundle.cert_pem.clone(),
            bundle.key_pem.clone(),
            bundle.pkcs12.clone(),
        ),
        None => {
            // On Windows the bundle is what makes the dev certificate usable at
            // all; elsewhere it is `None` and the PEM path is taken. See
            // `crate::tls`.
            let dev = dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
            (dev.cert_pem, dev.key_pem, dev.pkcs12)
        }
    };
    let (reg, listener) = isekai_link_utils::make_msquic_async_listener_with(
        reg,
        VIDEO_ALPN,
        Some(addr),
        &cert_pem,
        &key_pem,
        pkcs12.as_deref(),
        isekai_link_utils::ListenerOptions {
            // Offered unconditionally. A viewer that has not been updated does
            // not offer it back, so the connection is exactly the one it always
            // got — the spike asks that as question 6 — which is what lets the
            // camera ship before the viewers.
            multipath: true,
        },
    )?;
    let local = listener
        .local_addr()
        .context("read listener local address")?;
    Ok((reg, listener, local))
}

/// How [`serve_frames_with`] serves. Default is the plain relay-only behaviour.
#[derive(Default)]
pub struct ServeOptions {
    /// The relay legs peers reach this listener through, and how to tell which
    /// belongs to whom (see [`RelayLegs`]).
    ///
    /// When set, each accepted connection is told the binding of its own leg,
    /// so the initiator can validate a direct path to it and migrate off the
    /// relay. Without it the connection stays relay-only, which is the
    /// pre-migration behaviour.
    pub legs: Option<RelayLegs>,
}

/// Accept video connections and fan frames from `frame_rx` out to each
/// connected client as a unidirectional stream. Runs until `shutdown` fires or
/// the frame source closes.
///
/// **Latest wins.** A client that cannot keep up does not accumulate a backlog:
/// frames it missed are dropped and it gets the newest one as soon as it is
/// ready. For a live camera that is the only sensible policy — a queued frame
/// is just latency, and one slow client must not hold up the others or the
/// accept loop.
pub async fn serve_frames(
    listener: Listener,
    frame_rx: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
) {
    serve_frames_with(listener, frame_rx, shutdown, ServeOptions::default()).await
}

/// [`serve_frames`] with the direct-path advertisement wired in.
pub async fn serve_frames_with(
    listener: Listener,
    mut frame_rx: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
    opts: ServeOptions,
) {
    // One slot, not a queue: publishing replaces whatever the slowest client had
    // not picked up yet. Each client subscribes and always reads the newest
    // frame, so a client that falls behind skips ahead instead of working
    // through stale ones — and publishing never blocks, so a slow client cannot
    // stall this loop and with it `accept` and shutdown.
    let (frames, _) = watch::channel::<Option<Bytes>>(None);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => {
                    if let Some(legs) = &opts.legs {
                        isekai_p2p::direct_path::advertise(
                            conn.clone(),
                            legs.clone(),
                            shutdown.clone(),
                        );
                    }
                    tokio::spawn(push_frames(conn, frames.subscribe()));
                }
                Err(e) => {
                    tracing::error!("video accept failed: {e}");
                    break;
                }
            },
            frame = frame_rx.recv() => match frame {
                Some(frame) => {
                    frames.send_replace(Some(frame));
                }
                None => break,
            },
        }
    }
}

/// How an accepted connection is told which binding to punch to.
///
/// The name the camera apps and the FFI already import; it and everything it
/// drives are [`isekai_p2p::direct_path`] as of phase 4, because getting a peer
/// connection off the relay has nothing to do with video and portal needs every
/// line of it.
pub use isekai_p2p::direct_path::RelayLegs;

/// Push the newest frame to one client, for as long as it keeps up with itself.
///
/// Whatever arrives while `push_one` is in flight replaces the pending frame
/// rather than queueing behind it, so this always sends what the camera has
/// *now*.
async fn push_frames(conn: Connection, mut frames: watch::Receiver<Option<Bytes>>) {
    // Sample on a timer rather than per frame. Counting frames looks equivalent
    // and is not: when the peer stops acknowledging, `push_one` blocks on flow
    // control and the frame counter stops advancing — so the logging goes quiet
    // exactly when something has gone wrong and the numbers matter most. A
    // stalled server then leaves no record of which path it was using.
    let stats = tokio::spawn(log_stats_until_closed(conn.clone()));
    while let Some(frame) = next_frame(&mut frames).await {
        if let Err(e) = push_one(&conn, &frame).await {
            tracing::debug!("video push ended: {e}");
            break;
        }
    }
    stats.abort();
}

/// The next frame to send, skipping any superseded while the last one was in
/// flight. `None` once the server stops publishing.
///
/// This is where "latest wins" actually happens: several frames may have been
/// published while `push_one` was awaiting, and only the last of them is worth
/// sending.
async fn next_frame(frames: &mut watch::Receiver<Option<Bytes>>) -> Option<Bytes> {
    loop {
        frames.changed().await.ok()?;
        // A published `None` cannot happen today, but skipping rather than
        // stopping keeps this honest if an empty slot is ever published.
        if let Some(frame) = frames.borrow_and_update().clone() {
            return Some(frame);
        }
    }
}

/// Abort a task when the value is dropped, so a watchdog cannot outlive what it
/// is watching.
struct CancelOnDrop(tokio::task::JoinHandle<()>);

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// How long a connection may go on receiving without producing a frame before
/// that is worth saying out loud.
///
/// Generous compared with the frame period: a camera that has stopped capturing
/// is not this, and neither is a slow link. What this is looking for is bytes
/// arriving with nothing coming out, which is not something a working stream
/// does for seconds at a time.
const STALLED_READ_WARN: Duration = Duration::from_secs(5);

/// Report the connection's counters, and say so when it is receiving bytes but
/// producing no frames.
///
/// That combination has one meaning: data has arrived and been acknowledged at
/// the connection level, and a stream's share of it is not being handed to the
/// application — so the read this loop is parked on will never finish. Left
/// unlabelled it looks like a dead camera, a dead network, or a stalled
/// migration, and telling those apart from the outside took three rounds of
/// logs the first time it happened.
async fn watch_for_a_stalled_read(conn: Connection, delivered: Arc<AtomicU64>) {
    let mut interval = tokio::time::interval(RTT_SAMPLE_INTERVAL);
    let mut last_frames = delivered.load(Ordering::Relaxed);
    let mut last_bytes = 0u64;
    let mut silent_since: Option<Instant> = None;
    loop {
        interval.tick().await;
        let Ok(stats) = conn.get_stats() else { break };
        log_connection_stats(&conn, &stats, "receiving");

        let frames = delivered.load(Ordering::Relaxed);
        let bytes = stats.Recv.TotalBytes;
        let receiving = bytes > last_bytes;
        let producing = frames > last_frames;
        (last_frames, last_bytes) = (frames, bytes);

        match (receiving, producing) {
            (true, false) => {
                let since = *silent_since.get_or_insert_with(Instant::now);
                if since.elapsed() >= STALLED_READ_WARN {
                    tracing::warn!(
                        stalled_for_s = since.elapsed().as_secs(),
                        recv_bytes = bytes,
                        "the connection is still receiving but no frame has been \
                         delivered: a stream's buffered data is not reaching the \
                         application, and the read waiting on it cannot finish",
                    );
                    silent_since = Some(Instant::now());
                }
            }
            _ => silent_since = None,
        }
    }
}

/// Log a connection's counters once a second for as long as it lives.
async fn log_stats_until_closed(conn: Connection) {
    let mut interval = tokio::time::interval(RTT_SAMPLE_INTERVAL);
    loop {
        interval.tick().await;
        match conn.get_stats() {
            Ok(stats) => log_connection_stats(&conn, &stats, "serving"),
            Err(e) => {
                tracing::debug!("stopped sampling the video connection: {e}");
                break;
            }
        }
    }
}

async fn push_one(conn: &Connection, frame: &[u8]) -> anyhow::Result<()> {
    let mut stream = conn
        .open_outbound_stream(StreamType::Unidirectional, false)
        .await?;
    stream.write_all(frame).await?;
    poll_fn(|cx| stream.poll_finish_write(cx)).await?;
    Ok(())
}

/// What happened to the video connection's path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PathEvent {
    /// The path the connection established on — over the relay.
    Relay {
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// A path other than the relay one has been validated: the peers punched a
    /// direct route and [`migrate`](VideoRecvOptions::migrate) can switch to it.
    DirectValidated {
        local: SocketAddr,
        remote: SocketAddr,
    },
    /// `activate_path` succeeded and this is now the active path.
    Activated {
        local: SocketAddr,
        remote: SocketAddr,
    },
}

/// How [`receive_frames_with`] connects and what it reports back. Default is
/// the plain relay-only behaviour [`receive_frames`] has always had.
#[derive(Default)]
pub struct VideoRecvOptions {
    /// Reuse an existing msquic registration instead of opening one.
    ///
    /// Must be the same registration as the relay leg's when migration is
    /// wanted: msquic looks bindings up per registration.
    pub registration: Option<Arc<Registration>>,
    /// Validate the peer's certificate against the dialed name. Off is dev-only
    /// (the self-signed [`dev_cert`]).
    pub verify: bool,
    /// Require the handshake to present the key the peer signed for.
    ///
    /// **This is the check the proxy cannot satisfy.** It can obtain a second
    /// certificate for the same name — it owns the name — but it cannot sign as
    /// the peer's Endpoint, so a certificate that is not the attested one is
    /// somebody else's (spec §8.6.5).
    ///
    /// `None` means the peer published no statement, which is the ordinary case
    /// while this is being adopted: the connection then proceeds on name
    /// validation alone, exactly as it did before.
    pub pin: Option<AttestedPeer>,
    /// How the proxy sees this session's relay connect leg
    /// ([`InitiatorSession::observed_address`](isekai_p2p::InitiatorSession::observed_address)).
    ///
    /// When set, that pair is offered as a direct-path candidate before the
    /// handshake, and the connection is put on a shared, unconnected socket so
    /// the path can be opened from the leg's binding. Without it the connection
    /// is relay-only.
    pub observed: Option<ObservedAddressWatch>,
    /// Where to report path changes.
    pub path_events: Option<mpsc::Sender<PathEvent>>,
    /// Requests to switch to a `(local, remote)` path — the pair from a
    /// [`PathEvent`].
    pub migrate: Option<mpsc::Receiver<(SocketAddr, SocketAddr)>>,
    /// Where to report RTT samples, in milliseconds, once a second.
    pub rtt: Option<mpsc::Sender<f64>>,
}

/// Dial a video QUIC connection at `host:port` and deliver inbound frames —
/// tagged with the stream id as a monotonically increasing sequence — to
/// `frame_tx`. Runs until `shutdown` fires or the connection ends.
///
/// `host` is used both to resolve the address (a P2P loopback FQDN resolves to
/// `127.0.0.1`) and as the TLS server name. With `verify` the peer's
/// certificate is validated against `host`; without it, validation is skipped
/// (dev only, for the self-signed [`dev_cert`]).
pub async fn receive_frames(
    reg: Option<Arc<Registration>>,
    host: &str,
    port: u16,
    verify: bool,
    frame_tx: mpsc::Sender<(u64, Bytes)>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    receive_frames_with(
        host,
        port,
        frame_tx,
        shutdown,
        VideoRecvOptions {
            registration: reg,
            verify,
            ..Default::default()
        },
    )
    .await
}

/// [`receive_frames`] with path migration wired in.
///
/// With [`VideoRecvOptions::observed`] set, the connection is put on a shared,
/// unconnected socket pinned to *loopback* and the relay leg's address is
/// offered as a candidate before the handshake. The connection therefore keeps
/// talking to the loopback relay bridge as it always did, while the peers punch
/// a direct path between their two relay legs' real addresses — which is what
/// makes this work on Windows, where a socket bound to a real interface address
/// cannot reach `127.0.0.1` at all (`docs/p2p_mode_migration_plan.md` §2.2.3).
pub async fn receive_frames_with(
    host: &str,
    port: u16,
    frame_tx: mpsc::Sender<(u64, Bytes)>,
    shutdown: CancellationToken,
    opts: VideoRecvOptions,
) -> anyhow::Result<()> {
    let VideoRecvOptions {
        registration,
        verify,
        pin,
        observed,
        path_events,
        mut migrate,
        rtt,
    } = opts;

    // Runs for as long as this receive does, and ends with it: the guard cancels
    // the child token on every exit path, including the `?`s below.
    let heartbeat = shutdown.child_token();
    let _heartbeat = heartbeat.clone().drop_guard();
    spawn_heartbeat(heartbeat);

    // Resolve the candidate before dialing: `add_candidate_addr` has to be in
    // place before `start`, and a handshake here can take a minute (it rides
    // across the peer's relay-bind gap), so there is no useful "add it later".
    let candidate = match observed {
        Some(watch) => wait_for_observed(watch, &shutdown).await,
        None => None,
    };

    // Held for the whole receive: it owns the configuration this connection may
    // not outlive, and dropping it on any exit path below releases the three
    // handles in the order msquic wants them released.
    let session = isekai_p2p::peer::dial(
        registration,
        isekai_p2p::peer::DialOptions {
            alpn: VIDEO_ALPN,
            host,
            port,
            verify,
            pin,
            candidate,
            // The video carries frames on unidirectional streams and never a
            // datagram; advertising otherwise would only invite them.
            datagrams: false,
        },
        &shutdown,
    )
    .await?;
    let conn = session.connection().clone();

    let relay_path = (conn.get_local_addr()?, conn.get_remote_addr()?);
    report_path(
        &path_events,
        PathEvent::Relay {
            local: relay_path.0,
            remote: relay_path.1,
        },
    )
    .await;

    // Sampled from its own task, not from the loop below. The loop reads one
    // stream to completion at a time, so a read that never finishes takes the
    // loop's own sampling down with it — which is exactly when the numbers are
    // worth having. The server side already works this way (see `push_frames`).
    let delivered = Arc::new(AtomicU64::new(0));
    let watchdog = tokio::spawn(watch_for_a_stalled_read(conn.clone(), delivered.clone()));
    let _watchdog = CancelOnDrop(watchdog);

    let mut rtt_interval = tokio::time::interval(RTT_SAMPLE_INTERVAL);
    // Watchdog state for a migration that silently carries nothing. `None` while
    // on the relay path; `Some(when)` records when we left it, and is pushed
    // forward by every frame that arrives afterwards.
    let mut migrated_since: Option<Instant> = None;
    // Path ids, learned from `PathAdded` and keyed by the address pair the
    // caller asks to move onto. Empty means the peer has no multipath, and the
    // old switch is all there is.
    let mut direct_paths: BTreeMap<(SocketAddr, SocketAddr), u32> = BTreeMap::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            // The RTT sampler doubles as the watchdog tick, so it runs whether
            // or not anyone asked for RTT.
            _ = rtt_interval.tick() => {
                match conn.get_stats() {
                    // Rtt is reported in microseconds.
                    Ok(stats) => {
                        if let Some(rtt) = &rtt {
                            let _ = rtt.try_send(stats.Rtt as f64 / 1000.0);
                        }
                        log_connection_stats(&conn, &stats, "tick");
                    }
                    Err(e) => tracing::debug!("could not read connection stats: {e}"),
                }
                // A direct path that is preferred and then carries nothing takes
                // the whole connection down with it: the peer never sees our
                // packets, and both ends sit there until the idle timeout fires.
                // Go back to the path that was working rather than let that
                // happen. Under multipath that is a smaller move than it used to
                // be — the relay path was never left, only declared backup, so
                // this is withdrawing a preference rather than switching back.
                if let Some(since) = migrated_since {
                    if since.elapsed() >= MIGRATED_PATH_GRACE {
                        tracing::warn!(
                            local = %relay_path.0,
                            remote = %relay_path.1,
                            "no frames for {MIGRATED_PATH_GRACE:?} since preferring the \
                             direct path; going back to the relay path",
                        );
                        migrated_since = None;
                        if prefer_path(&conn, relay_path, relay_path, &direct_paths) {
                            report_path(&path_events, PathEvent::Activated {
                                local: relay_path.0,
                                remote: relay_path.1,
                            }).await;
                        }
                    }
                }
            }
            event = poll_fn(|cx| conn.poll_event(cx)) => match event {
                Ok(ConnectionEvent::PathValidated { local_address, remote_address }) => {
                    // Anything but the path we started on is the direct one.
                    // Still raised with multipath negotiated — `PathAdded`
                    // follows it for the same path — so this stays the report
                    // the UI hangs "a direct path exists" off, whichever kind of
                    // camera is on the other end.
                    if (local_address, remote_address) != relay_path {
                        report_path(&path_events, PathEvent::DirectValidated {
                            local: local_address,
                            remote: remote_address,
                        }).await;
                    }
                }
                // Multipath. The path id is what every later operation needs and
                // this event is the only thing that carries it, so remember it
                // against the pair the caller will ask for.
                Ok(ConnectionEvent::PathAdded { path_id, local_address, peer_address }) => {
                    if (local_address, peer_address) != relay_path {
                        // Held as backup until somebody asks for it. msquic makes
                        // a path active the moment it is added, and
                        // `QuicConnChoosePath` picks at random among the active
                        // ones — so without this the direct path starts carrying
                        // traffic as soon as it validates, while the caller still
                        // believes it is on the relay and has not chosen anything.
                        if let Err(e) = conn.set_path_status(path_id, false) {
                            tracing::warn!(
                                path_id,
                                "could not hold the new path as backup; it will carry \
                                 traffic before it is asked to: {e}",
                            );
                        }
                        tracing::info!(
                            path_id, local = %local_address, remote = %peer_address,
                            "the peer has multipath; the direct path is kept alive as a \
                             backup rather than waiting to be migrated onto",
                        );
                        direct_paths.insert((local_address, peer_address), path_id);
                    }
                }
                Ok(ConnectionEvent::PathRemoved { path_id, local_address, peer_address }) => {
                    tracing::warn!(
                        path_id, local = %local_address, remote = %peer_address,
                        "a path was removed",
                    );
                    direct_paths.remove(&(local_address, peer_address));
                    // Preferring a path that no longer exists is not something to
                    // keep waiting on.
                    if (local_address, peer_address) != relay_path {
                        migrated_since = None;
                    }
                }
                // The peer's own view of a path, which is the only way to read
                // it back: `QUIC_PARAM_CONN_PATH_STATUS` is set-only.
                Ok(ConnectionEvent::PathStatusChanged { path_id, is_active, .. }) => {
                    tracing::info!(path_id, is_active, "the peer declared a path status");
                }
                Ok(other) => tracing::debug!("video connection event: {other:?}"),
                Err(e) => {
                    tracing::debug!("video connection event stream ended: {e}");
                    break;
                }
            },
            request = async { migrate.as_mut().unwrap().recv().await }, if migrate.is_some() => {
                match request {
                    Some((local, remote)) => {
                        if prefer_path(&conn, (local, remote), relay_path, &direct_paths) {
                            // Watch a move *away* from the relay; a move back to
                            // it is the recovery, not something to time out.
                            migrated_since = ((local, remote) != relay_path).then(Instant::now);
                            // A snapshot on each side is what tells a stalled
                            // move apart from a broken one: whether packets
                            // still leave, whether any arrive, and what MTU the
                            // path settled on.
                            if let Ok(stats) = conn.get_stats() {
                                log_connection_stats(&conn, &stats, "after preferring a path");
                            }
                            report_path(&path_events, PathEvent::Activated { local, remote }).await;
                        }
                    }
                    // The requester is gone; stop polling but keep streaming.
                    None => migrate = None,
                }
            }
            stream = conn.accept_inbound_uni_stream() => {
                let mut stream = stream?;
                // Traffic is arriving on whatever path is current, so restart
                // the watchdog rather than count from the migration itself.
                migrated_since = migrated_since.map(|_| Instant::now());
                let seq = stream.id().unwrap_or(0);
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await?;
                delivered.fetch_add(1, Ordering::Relaxed);
                // Full/closed receiver: drop the frame (UDP-like semantics).
                let _ = frame_tx.try_send((seq, Bytes::from(buf)));
            }
        }
    }
    Ok(())
}

/// Tick once a second, touching nothing but the clock.
///
/// Every other sampler here calls `get_stats`, which msquic serves by queueing
/// an operation to the connection's worker and blocking until the worker runs
/// it. So when those samplers go quiet, a wedged msquic worker and a stalled
/// runtime look exactly the same from the log, and they are not the same bug.
/// This task has no such dependency, and `tokio::time::interval` bursts its
/// missed ticks on the way out, so the gap it leaves also measures itself:
///
/// - ticks continue while the samplers stop → the runtime is fine, the block is
///   inside msquic
/// - ticks stop too, then burst → the runtime itself was not scheduling this
///   task, so the block is upstream of msquic
fn spawn_heartbeat(shutdown: CancellationToken) {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(HEARTBEAT_INTERVAL);
        let mut ticks = 0u64;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    ticks += 1;
                    tracing::debug!(ticks, "heartbeat");
                }
            }
        }
    });
}

async fn report_path(events: &Option<mpsc::Sender<PathEvent>>, event: PathEvent) {
    tracing::info!("video path: {event:?}");
    if let Some(events) = events {
        let _ = events.send(event).await;
    }
}

/// Wait briefly for the relay leg's observed address.
///
/// `None` means carry on relay-only: a missing report costs a direct path, not
/// the stream, and blocking on it would be the wrong trade.
async fn wait_for_observed(
    mut watch: ObservedAddressWatch,
    shutdown: &CancellationToken,
) -> Option<ObservedAddress> {
    if let Some(address) = *watch.borrow_and_update() {
        return Some(address);
    }
    let waited = tokio::time::timeout(OBSERVED_ADDRESS_WAIT, async {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return None,
                changed = watch.changed() => {
                    changed.ok()?;
                    if let Some(address) = *watch.borrow_and_update() {
                        return Some(address);
                    }
                }
            }
        }
    })
    .await;
    match waited {
        Ok(address) => address,
        Err(_) => {
            tracing::warn!(
                "no observed address from the relay leg within {OBSERVED_ADDRESS_WAIT:?}; \
                 streaming over the relay without a direct-path candidate",
            );
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frames published while a send is in flight are superseded, not queued:
    /// the next send takes the newest and skips the rest. Without this a slow
    /// client works through a backlog, and every frame in it is latency.
    #[tokio::test]
    async fn only_the_newest_frame_survives_a_slow_send() {
        let (tx, mut rx) = watch::channel::<Option<Bytes>>(None);
        for i in 1..=3u8 {
            tx.send_replace(Some(Bytes::from(vec![i])));
        }
        assert_eq!(next_frame(&mut rx).await, Some(Bytes::from(vec![3u8])));
    }

    /// And it waits rather than spinning when nothing new has been published.
    #[tokio::test]
    async fn waits_for_a_frame_that_has_not_arrived_yet() {
        let (tx, mut rx) = watch::channel::<Option<Bytes>>(None);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), next_frame(&mut rx))
                .await
                .is_err(),
            "there is nothing to send yet",
        );
        tx.send_replace(Some(Bytes::from_static(b"frame")));
        assert_eq!(
            next_frame(&mut rx).await,
            Some(Bytes::from_static(b"frame"))
        );
    }

    /// The server going away ends the push loop instead of leaving it parked.
    #[tokio::test]
    async fn stops_when_the_server_stops_publishing() {
        let (tx, mut rx) = watch::channel::<Option<Bytes>>(None);
        drop(tx);
        assert_eq!(next_frame(&mut rx).await, None);
    }
}
