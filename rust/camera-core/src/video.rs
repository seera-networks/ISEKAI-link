//! The camera video transport over QUIC (`sample` ALPN): MJPEG frames, one per
//! unidirectional stream. This is the same wire protocol the camera apps
//! already use; here it is factored out so it works over any address — a public
//! one (legacy) or the P2P relay's loopback address.

use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{msquic, Connection, ConnectionEvent, Listener, Registration, StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

use isekai_p2p::agent::{CertBundle, ObservedAddress, ObservedAddressWatch};

use crate::tls::dev_cert;

/// ALPN for the camera video protocol.
pub const VIDEO_ALPN: &str = "sample";

/// How long to keep retrying the video handshake before giving up. This spans
/// the gap between the initiator opening its relay leg and the peer binding
/// *its* leg (e.g. a human pressing "bind relay" on the camera server).
const VIDEO_CONNECT_DEADLINE: Duration = Duration::from_secs(120);
/// Delay between video handshake attempts.
const VIDEO_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(500);
/// How often to sample the connection's RTT for [`VideoRecvOptions::rtt`].
const RTT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
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
    cert: Option<&CertBundle>,
) -> anyhow::Result<(Arc<Registration>, Listener, SocketAddr)> {
    let (cert_pem, key_pem, pkcs12) = match cert {
        // `pkcs12` is empty when the proxy doesn't ship one; fall back to the
        // PEM path then instead of importing an empty PKCS#12 blob.
        Some(bundle) => (
            bundle.cert_pem.clone(),
            bundle.key_pem.clone(),
            (!bundle.pkcs12.is_empty()).then(|| bundle.pkcs12.clone()),
        ),
        None => {
            // On Windows the bundle is what makes the dev certificate usable at
            // all; elsewhere it is `None` and the PEM path is taken. See
            // `crate::tls`.
            let dev = dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
            (dev.cert_pem, dev.key_pem, dev.pkcs12)
        }
    };
    let (reg, listener) = isekai_link_utils::make_msquic_async_listener(
        reg,
        VIDEO_ALPN,
        Some(addr),
        &cert_pem,
        &key_pem,
        pkcs12.as_deref(),
    )?;
    let local = listener
        .local_addr()
        .context("read listener local address")?;
    Ok((reg, listener, local))
}

/// How [`serve_frames_with`] serves. Default is the plain relay-only behaviour.
#[derive(Default)]
pub struct ServeOptions {
    /// How the proxy sees this Endpoint's relay bind leg
    /// ([`ListenerSession::observed_address`](isekai_p2p::ListenerSession::observed_address)).
    ///
    /// When set, every accepted connection is told about that address so the
    /// initiator can validate a direct path to it and migrate off the relay.
    /// Without it the connection stays relay-only, which is the pre-migration
    /// behaviour.
    pub observed: Option<ObservedAddressWatch>,
}

/// Accept video connections and fan every frame from `frame_rx` out to each
/// connected client as a unidirectional stream. Runs until `shutdown` fires or
/// the frame source closes.
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
    let mut senders: Vec<mpsc::Sender<Bytes>> = Vec::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => {
                    if let Some(observed) = &opts.observed {
                        advertise_direct_path(conn.clone(), observed.clone(), shutdown.clone());
                    }
                    let (tx, rx) = mpsc::channel::<Bytes>(100);
                    senders.push(tx);
                    tokio::spawn(push_frames(conn, rx));
                }
                Err(e) => {
                    tracing::error!("video accept failed: {e}");
                    break;
                }
            },
            frame = frame_rx.recv() => match frame {
                Some(frame) => {
                    // Drop connections whose push task has ended.
                    senders.retain(|s| !s.is_closed());
                    for s in &senders {
                        let _ = s.send(frame.clone()).await;
                    }
                }
                None => break,
            },
        }
    }
}

/// Tell `conn` about the relay leg's binding, so the peer can punch a direct
/// path to it and migrate off the relay.
///
/// The address may not be known yet. In P2P mode the bind leg only comes up
/// once an operator pastes the connection id, which can happen *after* the
/// video connection has been accepted — so when the watch is still empty this
/// keeps a task alive to apply the address when it arrives. It also re-applies
/// on a genuine change, which is what a rebind onto a new leg produces.
///
/// Failures are logged, not fatal: an Endpoint that cannot advertise a direct
/// path simply keeps streaming over the relay.
fn advertise_direct_path(
    conn: Connection,
    mut observed: ObservedAddressWatch,
    shutdown: CancellationToken,
) {
    let mut applied: Option<ObservedAddress> = None;
    if let Some(address) = address_to_apply(applied, *observed.borrow_and_update()) {
        apply_direct_path(&conn, address);
        applied = Some(address);
    }
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                changed = observed.changed() => {
                    if changed.is_err() {
                        break;
                    }
                    if let Some(address) = address_to_apply(applied, *observed.borrow_and_update()) {
                        apply_direct_path(&conn, address);
                        applied = Some(address);
                    }
                }
            }
        }
    });
}

/// Which address, if any, to hand to the connection given what is already on it.
///
/// Applying the *same* address twice fails with `QUIC_STATUS_ADDRESS_IN_USE` —
/// the binding is already attached — so an unchanged report is a no-op rather
/// than a logged failure. A watch that goes back to `None` is also a no-op: the
/// address already on the connection stays valid, and there is nothing better
/// to replace it with.
fn address_to_apply(
    applied: Option<ObservedAddress>,
    latest: Option<ObservedAddress>,
) -> Option<ObservedAddress> {
    match latest {
        Some(address) if applied != Some(address) => Some(address),
        _ => None,
    }
}

fn apply_direct_path(conn: &Connection, address: ObservedAddress) {
    if let Err(e) = conn.add_bound_addr(address.local) {
        tracing::warn!(
            local = %address.local,
            "could not add the relay leg's binding to the video connection; \
             staying relay-only: {e}",
        );
        return;
    }
    if let Err(e) = conn.add_observed_addr(address.local, address.observed) {
        tracing::warn!(
            local = %address.local,
            observed = %address.observed,
            "could not advertise the observed address; staying relay-only: {e}",
        );
        return;
    }
    // Advertise the host address too — see the note in `prepare_for_migration`:
    // a peer on the same LAN can only reach us there, because a NAT that does
    // not hairpin drops packets sent from inside to its own public address.
    if address.local != address.observed {
        if let Err(e) = conn.add_observed_addr(address.local, address.local) {
            tracing::debug!("could not advertise the host address: {e}");
        }
    }
    tracing::info!(
        local = %address.local,
        observed = %address.observed,
        "advertised a direct path to the video client",
    );
}

async fn push_frames(conn: Connection, mut rx: mpsc::Receiver<Bytes>) {
    // Sample on a timer rather than per frame. Counting frames looks equivalent
    // and is not: when the peer stops acknowledging, `push_one` blocks on flow
    // control and the frame counter stops advancing — so the logging goes quiet
    // exactly when something has gone wrong and the numbers matter most. A
    // stalled server then leaves no record of which path it was using.
    let stats = tokio::spawn(log_stats_until_closed(conn.clone()));
    while let Some(frame) = rx.recv().await {
        if let Err(e) = push_one(&conn, &frame).await {
            tracing::debug!("video push ended: {e}");
            break;
        }
    }
    stats.abort();
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
    Relay { local: SocketAddr, remote: SocketAddr },
    /// A path other than the relay one has been validated: the peers punched a
    /// direct route and [`migrate`](VideoRecvOptions::migrate) can switch to it.
    DirectValidated { local: SocketAddr, remote: SocketAddr },
    /// `activate_path` succeeded and this is now the active path.
    Activated { local: SocketAddr, remote: SocketAddr },
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
    /// An address to offer as a direct-path candidate, with the NAT mapping the
    /// proxy observed for it.
    ///
    /// This must be an address **nothing currently holds** — see
    /// [`probe_direct_path_address`](isekai_p2p::probe_direct_path_address). A
    /// path opened on a binding a live MASQUE leg is using validates and then
    /// carries no data (`docs/p2p_mode_migration_plan.md` §2.2.5), so passing
    /// the leg's own address here is exactly what not to do.
    ///
    /// Without it the connection is relay-only.
    pub candidate: Option<ObservedAddress>,
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
        candidate,
        path_events,
        mut migrate,
        rtt,
    } = opts;

    // ISEKAI_MIGRATION_NO_CANDIDATE drops the candidate entirely, leaving any
    // direct path to whatever msquic finds from the peer's advertisement alone.
    // Kept as an escape hatch: it is what first showed that a path on a binding
    // msquic opens for itself works where one on the relay leg's does not.
    let candidate = match candidate {
        Some(_) if std::env::var_os("ISEKAI_MIGRATION_NO_CANDIDATE").is_some() => {
            tracing::warn!(
                "ISEKAI_MIGRATION_NO_CANDIDATE set: not offering a direct-path candidate",
            );
            None
        }
        other => other,
    };

    let (reg, config) = video_client_config(registration, verify, candidate.is_some())?;
    let conn = dial_video(&reg, &config, host, port, candidate, &shutdown).await?;

    let relay_path = (conn.get_local_addr()?, conn.get_remote_addr()?);
    report_path(
        &path_events,
        PathEvent::Relay {
            local: relay_path.0,
            remote: relay_path.1,
        },
    )
    .await;

    let mut rtt_interval = tokio::time::interval(RTT_SAMPLE_INTERVAL);
    // Watchdog state for a migration that silently carries nothing. `None` while
    // on the relay path; `Some(when)` records when we left it, and is pushed
    // forward by every frame that arrives afterwards.
    let mut migrated_since: Option<Instant> = None;
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
                // A direct path that validates and then carries nothing takes
                // the whole connection down with it: the peer never sees our
                // packets, so it never follows the migration, and both ends sit
                // there until the idle timeout fires. Go back to the path that
                // was working rather than let that happen.
                if let Some(since) = migrated_since {
                    if since.elapsed() >= MIGRATED_PATH_GRACE {
                        tracing::warn!(
                            local = %relay_path.0,
                            remote = %relay_path.1,
                            "no frames for {MIGRATED_PATH_GRACE:?} since migrating; \
                             falling back to the relay path",
                        );
                        match conn.activate_path(relay_path.0, relay_path.1) {
                            Ok(()) => {
                                migrated_since = None;
                                report_path(&path_events, PathEvent::Activated {
                                    local: relay_path.0,
                                    remote: relay_path.1,
                                }).await;
                            }
                            Err(e) => {
                                // Nothing else to try; let the idle timeout end
                                // it rather than spin on a failing call.
                                tracing::error!("could not fall back to the relay path: {e}");
                                migrated_since = None;
                            }
                        }
                    }
                }
            }
            event = poll_fn(|cx| conn.poll_event(cx)) => match event {
                Ok(ConnectionEvent::PathValidated { local_address, remote_address }) => {
                    // Anything but the path we started on is the direct one.
                    if (local_address, remote_address) != relay_path {
                        report_path(&path_events, PathEvent::DirectValidated {
                            local: local_address,
                            remote: remote_address,
                        }).await;
                    }
                }
                Ok(other) => tracing::debug!("video connection event: {other:?}"),
                Err(e) => {
                    tracing::debug!("video connection event stream ended: {e}");
                    break;
                }
            },
            request = async { migrate.as_mut().unwrap().recv().await }, if migrate.is_some() => {
                match request {
                    Some((local, remote)) => match conn.activate_path(local, remote) {
                        Ok(()) => {
                            tracing::info!(%local, %remote, "activated path");
                            // Watch a move *away* from the relay; a move back to
                            // it is the recovery, not something to time out.
                            migrated_since = ((local, remote) != relay_path).then(Instant::now);
                            // A snapshot on each side of the switch is what
                            // tells a stalled migration apart from a broken
                            // one: whether packets still leave, whether any
                            // arrive, and what MTU the new path settled on.
                            if let Ok(stats) = conn.get_stats() {
                                log_connection_stats(&conn, &stats, "after activate_path");
                            }
                            report_path(&path_events, PathEvent::Activated { local, remote }).await;
                        }
                        Err(e) => tracing::warn!(%local, %remote, "could not activate path: {e}"),
                    },
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
                // Full/closed receiver: drop the frame (UDP-like semantics).
                let _ = frame_tx.try_send((seq, Bytes::from(buf)));
            }
        }
    }
    Ok(())
}

/// Log what the connection is actually doing, which is the difference between
/// "the migration stalled" and "the migration broke the connection".
///
/// `Send.PathMtu` is worth watching in particular: a newly opened path has to
/// size itself, and this connection is configured with a `MaximumMtu` below
/// msquic's default `MinimumMtu`.
fn log_connection_stats(conn: &Connection, stats: &msquic::ffi::QUIC_STATISTICS, when: &str) {
    tracing::debug!(
        when,
        local = ?conn.get_local_addr().ok(),
        remote = ?conn.get_remote_addr().ok(),
        rtt_us = stats.Rtt,
        send_path_mtu = stats.Send.PathMtu,
        send_packets = stats.Send.TotalPackets,
        send_lost = stats.Send.SuspectedLostPackets,
        recv_packets = stats.Recv.TotalPackets,
        recv_dropped = stats.Recv.DroppedPackets,
        "video connection stats",
    );
}

async fn report_path(events: &Option<mpsc::Sender<PathEvent>>, event: PathEvent) {
    tracing::info!("video path: {event:?}");
    if let Some(events) = events {
        let _ = events.send(event).await;
    }
}

/// Dial the video QUIC, letting a single handshake ride across the peer's
/// relay-bind gap; retry only as a fallback, until the deadline or `shutdown`.
///
/// Over the P2P relay the initiator opens its own leg first and only then does
/// the peer bind *its* leg — it needs the connection id out of band (e.g. a
/// human pasting it into the camera server). Until both legs are bridged, the
/// handshake's packets reach a half-open relay edge and go unanswered. A
/// completed handshake is itself the readiness signal (both legs are up), and
/// there is nothing on the control plane to poll — the loopback relay
/// rendezvous injects no reachable candidate.
///
/// The key is to keep **one** connection retransmitting its Initial for the
/// whole gap (a long `HandshakeIdleTimeoutMs`) rather than firing many
/// short-lived attempts. Local relay testing showed rapid short attempts
/// (a few seconds each) leave the relay path wedged so it never recovers even
/// after the bind lands, whereas a single persistent handshake completes as
/// soon as the far leg comes up. The retry loop below is therefore a
/// last-resort fallback for a genuinely failed handshake, not the mechanism
/// that bridges the gap.
async fn dial_video(
    reg: &Registration,
    config: &msquic::Configuration,
    host: &str,
    port: u16,
    candidate: Option<ObservedAddress>,
    shutdown: &CancellationToken,
) -> anyhow::Result<Connection> {
    let deadline = Instant::now() + VIDEO_CONNECT_DEADLINE;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let conn = Connection::new(reg)?;
        // Every attempt builds a fresh connection, so the migration setup has
        // to be redone on each one.
        if let Some(candidate) = candidate {
            prepare_for_migration(&conn, candidate)?;
        }
        let result = tokio::select! {
            _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing video"),
            r = conn.start(config, host, port) => r,
        };
        match result {
            Ok(()) => return Ok(conn),
            Err(e) => {
                drop(conn);
                if Instant::now() >= deadline {
                    return Err(anyhow::Error::new(e).context(format!(
                        "video QUIC handshake to {host}:{port} did not complete within \
                         {VIDEO_CONNECT_DEADLINE:?} ({attempt} attempts); the peer may not have \
                         bound its relay leg"
                    )));
                }
                tracing::debug!(
                    "video handshake attempt {attempt} failed ({e}); retrying — the peer relay \
                     leg may not be up yet"
                );
                tokio::select! {
                    _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing video"),
                    _ = sleep(VIDEO_CONNECT_RETRY_DELAY) => {}
                }
            }
        }
    }
}

/// Put a video connection on a shared, unconnected socket and offer the relay
/// leg's address as a direct-path candidate. Must run before `start`.
///
/// The order is fixed: `set_unconnected_socket` requires a shared binding, and
/// an unconnected socket requires a specific — non-wildcard — local address.
/// That address is deliberately **loopback**: this connection's own traffic
/// goes to the relay bridge on `127.0.0.1`, and pinning it to a real interface
/// address instead cannot work on Windows at all. The direct path does not need
/// it, because `add_candidate_addr` accepts an address that is not bound here
/// yet — msquic opens the path from the relay leg's binding once the peer's
/// ADD_ADDRESS arrives (`docs/p2p_mode_migration_plan.md` §2.2.3).
fn prepare_for_migration(conn: &Connection, candidate: ObservedAddress) -> anyhow::Result<()> {
    conn.set_share_binding(true)
        .map_err(|e| anyhow::anyhow!("could not share the UDP binding: {e}"))?;
    conn.set_unconnected_socket(true)
        .map_err(|e| anyhow::anyhow!("could not use an unconnected socket: {e}"))?;
    conn.set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| anyhow::anyhow!("could not pin the local address: {e}"))?;
    conn.add_candidate_addr(candidate.local, candidate.observed)
        .map_err(|e| anyhow::anyhow!("could not offer a direct-path candidate: {e}"))?;
    // Also offer the host address itself. A peer on the same LAN can reach it
    // directly, while the observed one is only reachable from outside the NAT —
    // and a NAT that does not hairpin (most of them) drops a packet sent from
    // inside to its own public address, so without this two peers behind the
    // same NAT can never find each other. Across the internet this candidate
    // simply fails to validate and the observed one wins.
    if candidate.local != candidate.observed {
        if let Err(e) = conn.add_candidate_addr(candidate.local, candidate.local) {
            tracing::debug!("could not offer the host candidate: {e}");
        }
    }
    tracing::info!(
        local = %candidate.local,
        observed = %candidate.observed,
        "offered direct-path candidates to the video server",
    );
    Ok(())
}

/// Video client config: ALPN `sample`. With `verify` the peer's certificate is
/// validated against the dialed server name (the per-endpoint relay cert);
/// without it validation is **disabled** — dev only, for the self-signed
/// [`dev_cert`].
fn video_client_config(
    reg: Option<Arc<Registration>>,
    verify: bool,
    enable_migration: bool,
) -> anyhow::Result<(Arc<Registration>, msquic::Configuration)> {
    let reg = match reg {
        Some(reg) => reg,
        None => Arc::new(Registration::new(&msquic::RegistrationConfig::default())?),
    };
    let alpn = [msquic::BufferRef::from(VIDEO_ALPN)];
    let settings = msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                // Keep a single unanswered handshake alive long enough to span
                // the peer's relay-bind gap: msquic keeps retransmitting the
                // Initial on ONE connection until the far leg comes up, rather
                // than many short-lived attempts (which poison the relay path).
                .set_HandshakeIdleTimeoutMs(60_000)
                // Cap the MTU so a video QUIC packet (a QUIC Initial is padded
                // to 1200) plus CONNECT-UDP encapsulation fits inside the relay
                // tunnel's HTTP datagram. Matches the listener (see
                // `make_msquic_async_listener`). Without it the default 1500-MTU
                // packets overflow the tunnel and are dropped as `TooLarge`.
                .set_MaximumMtu(1200)
                .set_PeerUnidiStreamCount(100)
                .set_StreamMultiReceiveEnabled();
    // NAT-traversal mode is what makes the peer probe our candidate address and
    // report a `PathValidated` for the direct path; the observed-address reports
    // are the other half of the exchange.
    let settings = if enable_migration {
        settings
            .set_ReceiveObservedAddressReports()
            .set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
    } else {
        settings
    };
    let config = reg.open_configuration(&alpn, Some(&settings))?;
    let mut cred = msquic::CredentialConfig::new_client();
    if !verify {
        cred = cred.set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    }
    config.load_credential(&cred)?;
    Ok((reg, config))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn observed(port: u16) -> ObservedAddress {
        ObservedAddress {
            local: SocketAddr::from(([192, 168, 1, 59], port)),
            observed: SocketAddr::from(([203, 0, 113, 5], port)),
        }
    }

    /// The bind leg usually comes up after the connection was accepted, so the
    /// first address seen has to be applied whenever it arrives.
    #[test]
    fn a_first_address_is_applied() {
        assert_eq!(address_to_apply(None, Some(observed(1000))), Some(observed(1000)));
    }

    /// Re-applying the same address fails with ADDRESS_IN_USE, so an unchanged
    /// report must be a no-op rather than a logged failure.
    #[test]
    fn an_unchanged_address_is_not_reapplied() {
        assert_eq!(address_to_apply(Some(observed(1000)), Some(observed(1000))), None);
    }

    /// A rebind onto a new leg is a genuine change and has to be advertised.
    #[test]
    fn a_changed_address_is_applied() {
        assert_eq!(
            address_to_apply(Some(observed(1000)), Some(observed(2000))),
            Some(observed(2000))
        );
    }

    /// A watch that empties leaves the connection as it is: what it already has
    /// still works, and there is nothing better to offer.
    #[test]
    fn an_empty_report_leaves_the_connection_alone() {
        assert_eq!(address_to_apply(Some(observed(1000)), None), None);
        assert_eq!(address_to_apply(None, None), None);
    }
}
