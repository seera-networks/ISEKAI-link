//! The camera video transport over QUIC (`sample` ALPN): MJPEG frames, one per
//! unidirectional stream. This is the same wire protocol the camera apps
//! already use; here it is factored out so it works over any address — a public
//! one (legacy) or the P2P relay's loopback address.

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{msquic, Connection, ConnectionEvent, Listener, Registration, StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, watch};
use tokio::time::{sleep, Instant};
use tokio_util::sync::CancellationToken;

use isekai_p2p::agent::{
    certificate_matches, verify as verify_attestation, Attestation, ObservedAddress,
    ObservedAddressWatch, PeerConnection,
};
use isekai_p2p::LegDirectory;
use time::OffsetDateTime;

use crate::tls::{dev_cert, VideoCert};

/// ALPN for the camera video protocol.
pub const VIDEO_ALPN: &str = "sample";

/// How long to keep retrying the video handshake before giving up.
///
/// This spans an entirely manual gap: the initiator opens its relay leg, and the
/// peer can only bind *its* leg once a human has carried the connection id
/// across — reading it off a phone, typing it into the camera server, starting
/// the camera, pressing bind. Two minutes looked generous and was not: every
/// field failure we chased for a day ended at exactly this deadline, with the
/// relay leg still healthy and the operator still typing.
///
/// So it is set to a span no operator will lose a race against. Waiting costs
/// nothing here — the connection retransmits an Initial every few seconds — and
/// the caller can stop it at any time by cancelling `shutdown`, which is what
/// the disconnect button does.
const VIDEO_CONNECT_DEADLINE: Duration = Duration::from_secs(900);
/// Delay between video handshake attempts.
const VIDEO_CONNECT_RETRY_DELAY: Duration = Duration::from_millis(500);
/// How often to sample the connection's RTT for [`VideoRecvOptions::rtt`].
const RTT_SAMPLE_INTERVAL: Duration = Duration::from_secs(1);
/// How often to report what the handshake is doing while it is still unanswered.
const HANDSHAKE_PROBE_INTERVAL: Duration = Duration::from_secs(1);
/// How often the heartbeat ticks. See [`spawn_heartbeat`].
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(1);
/// How long to wait for the relay leg's observed address before dialing without
/// it. The report normally lands within a round trip of the leg coming up; if it
/// does not, streaming over the relay matters more than a direct path.
const OBSERVED_ADDRESS_WAIT: Duration = Duration::from_secs(3);
/// How long a video connection may carry nothing before it is closed.
///
/// Also the answer to "was this connection still alive?" for anything that
/// could not watch it — an iOS viewer coming back from the background knows
/// only how long it was away, and longer than this means the connection is
/// gone whatever the app still holds. Exported for that.
pub const VIDEO_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// How long the whole connection may go without sending before it gets a PING.
///
/// Distinct from [`DIRECT_PATH_KEEPALIVE`], which is per path; this one is
/// reset by any activity and so only fires on a connection carrying nothing.
/// Well inside the 30 s idle timeout, with two attempts to spare.
const CONNECTION_KEEPALIVE: Duration = Duration::from_secs(10);

/// How long a path may go without sending before it gets a PING.
///
/// `PathKeepAliveIntervalMs`, and **not** `KeepAliveIntervalMs`. The two look
/// interchangeable and are not: the connection keepalive is re-armed by
/// `QuicConnResetIdleTimeout` on every ack-eliciting packet received and on the
/// first packet put in flight, so it fires only once the *whole connection* has
/// gone quiet. A video connection is never quiet — that is what it is for — so
/// it never fired, and the direct path decayed exactly as it did before, with
/// the setting apparently in place. This one is counted per path, from what that
/// path itself carried, and nothing resets it.
///
/// Both ends still have to set it: the timer runs off each connection's own
/// settings, and the default is 0, meaning no PING is ever sent.
///
/// Ten seconds is well inside the 30 s idle timeout and cheap — a path that is
/// carrying traffic on its own never gets a redundant PING.
const DIRECT_PATH_KEEPALIVE: Duration = Duration::from_secs(10);

/// How long a migrated path may carry nothing before falling back to the relay.
///
/// Generous next to a frame interval, so a stutter never triggers it, and short
/// enough to be well inside the 30 s idle timeout that would otherwise take the
/// whole connection down.
const MIGRATED_PATH_GRACE: Duration = Duration::from_secs(5);

/// Why a connection has nothing to pin.
///
/// Only the first is ordinary. The other two are a connect response that does
/// not hold together, and saying so is the difference between a peer that has
/// not adopted this yet and a proxy behaving oddly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unpinnable {
    /// The peer has published no statement. The transitional default.
    NoStatement,
    /// A statement arrived, but the response does not name the peer it should
    /// have come from — so there is nothing to check it against.
    NoPeerEndpoint,
    /// A statement arrived, but the response names no host to dial.
    NoHost,
}

impl std::fmt::Display for Unpinnable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoStatement => f.write_str(
                "the peer published no statement about its key; trusting the proxy about \
                 which certificate is right",
            ),
            Self::NoPeerEndpoint => f.write_str(
                "the peer signed for its key, but the proxy named no endpoint to check the \
                 statement against; not pinning",
            ),
            Self::NoHost => f.write_str(
                "the peer signed for its key, but the proxy named no host to dial; not pinning",
            ),
        }
    }
}

/// What the peer said about its own key, and who it had to be.
///
/// Carried together because checking one without the others proves nothing: a
/// signature is only meaningful once it is known to be *this peer's*, about
/// *this name*.
#[derive(Debug, Clone)]
pub struct AttestedPeer {
    /// The statement, from the `peer_connect` response.
    pub attestation: Attestation,
    /// Who the proxy says is on the other end. The statement has to be signed
    /// by this Endpoint or it is about somebody else.
    pub peer_endpoint: String,
    /// The name being dialed, which is inside the signed text.
    pub video_host: String,
}

impl AttestedPeer {
    /// What a `peer_connect` response says about the peer's key, if anything.
    ///
    /// `None` where there is nothing to pin — a peer that has published no
    /// statement, or a proxy with no certificates configured. That is the
    /// ordinary case while this is being adopted, and it leaves the connection
    /// exactly as it was: validated by name and no more.
    ///
    /// Called by the initiator, so the peer is the target. `peer_endpoint` is
    /// what the connect response names it; `target_endpoint` is the same thing
    /// under the name the listing uses, and is taken when the first is absent.
    ///
    /// **The three ways this comes back empty are not the same**, and this is
    /// the fail-open path of a security control, so it says which. A peer that
    /// published nothing is ordinary. A response carrying a statement but no
    /// name to check it against is the proxy answering strangely, and reporting
    /// that as "the camera published nothing" blames the wrong party.
    pub fn from_connection(connection: &PeerConnection) -> Result<Self, Unpinnable> {
        let Some(attestation) = connection.video_attestation.clone() else {
            return Err(Unpinnable::NoStatement);
        };
        let peer_endpoint = connection
            .peer_endpoint
            .clone()
            .or_else(|| connection.target_endpoint.clone())
            .ok_or(Unpinnable::NoPeerEndpoint)?;
        let video_host = connection.video_host.clone().ok_or(Unpinnable::NoHost)?;
        Ok(Self {
            attestation,
            peer_endpoint,
            video_host,
        })
    }

    /// Whether `der` is the certificate this peer signed for.
    ///
    /// The statement does not carry the key's digest — it does not need to.
    /// The verifier already has a candidate in front of it, so the digest of
    /// the presented certificate goes into the signed text and the signature
    /// either verifies or does not. **Verification and pinning are the same
    /// operation.**
    fn accepts(&self, der: &[u8]) -> Result<(), String> {
        let spki = crate::tls::spki_sha256_of_certificate(der)
            .ok_or_else(|| "the peer's certificate could not be read".to_owned())?;
        verify_attestation(
            &self.attestation,
            &self.peer_endpoint,
            &self.video_host,
            &spki,
            OffsetDateTime::now_utc(),
        )
        .map_err(|e| format!("{e}"))
    }
}

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
                        advertise_direct_path(conn.clone(), legs.clone(), shutdown.clone());
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
/// Two situations, and which one applies is not a detail: a listener with one
/// leg can hand its address to anybody, and a listener with several cannot.
#[derive(Clone)]
pub enum RelayLegs {
    /// One leg serves everybody, so every connection gets its address.
    ///
    /// What a single-viewer harness has. Wrong for a listener serving several
    /// peers: each has a leg of its own, with a binding of its own.
    Single(ObservedAddressWatch),
    /// Legs told apart by the address a connection arrives from
    /// ([`LegDirectory`]).
    PerConnection(LegDirectory),
}

/// How long to wait for the leg a connection arrived on to identify itself.
///
/// The leg records its forwarding socket when it creates one, which is when the
/// peer's first packet arrives — before the video handshake this connection has
/// just finished. So it is normally already there and this is for the race, not
/// for the usual case.
const LEG_LOOKUP_WAIT: Duration = Duration::from_secs(3);
const LEG_LOOKUP_POLL: Duration = Duration::from_millis(50);

/// Tell `conn` about the binding of the leg **it** arrived on, so the peer can
/// punch a direct path to it and migrate off the relay.
///
/// **Which leg matters, and used not to be answerable.** Every leg delivers
/// here, and each has its own binding, so handing a connection the wrong leg's
/// address advertises a path the peer cannot reach — it stays on the relay, and
/// nothing says why. Worse, before this the newest address replaced whatever a
/// connection had, so a second viewer arriving re-pointed the first viewer's
/// connection at the new leg and stopped its relay traffic.
///
/// The answer is the address the connection came *from*: a leg forwards what it
/// receives from a socket of its own, so that socket's address names the leg
/// (see [`LegDirectory`]). What replaced the bug in between — take the first
/// address offered and never change it — was right only while legs came up in
/// the order their peers connected, which `Manual`, two near-simultaneous
/// viewers, and a leg that reconnects all break.
///
/// Failures are logged, not fatal: an Endpoint that cannot advertise a direct
/// path simply keeps streaming over the relay.
fn advertise_direct_path(conn: Connection, legs: RelayLegs, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let Some(mut observed) = leg_of(&conn, &legs, &shutdown).await else {
            return;
        };
        // Applied once, and the `break` is what says so. Not because a later
        // address might be somebody else's — this now knows whose leg it is
        // watching — but because the binding is by then attached to the
        // connection, and a second `add_bound_addr` fails with
        // `QUIC_STATUS_ADDRESS_IN_USE`. So a leg that reconnects onto a new
        // binding is not re-advertised; the peer keeps the path it validated.
        loop {
            if let Some(address) = *observed.borrow_and_update() {
                apply_direct_path(&conn, address);
                break;
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                changed = observed.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// The watch belonging to the leg `conn` came in on.
///
/// `None` means there is no direct path to advertise to this connection, and
/// says which of the two reasons it is: a connection that did not come through
/// a leg at all, or a leg that never identified itself in time.
async fn leg_of(
    conn: &Connection,
    legs: &RelayLegs,
    shutdown: &CancellationToken,
) -> Option<ObservedAddressWatch> {
    let directory = match legs {
        RelayLegs::Single(observed) => return Some(observed.clone()),
        RelayLegs::PerConnection(directory) => directory,
    };
    let peer = match conn.get_remote_addr() {
        Ok(peer) => peer,
        Err(e) => {
            tracing::warn!("could not read a connection's peer address; staying relay-only: {e}");
            return None;
        }
    };
    let deadline = tokio::time::Instant::now() + LEG_LOOKUP_WAIT;
    loop {
        if let Some(observed) = directory.leg_for(peer) {
            return Some(observed);
        }
        if tokio::time::Instant::now() >= deadline {
            // Two different things, and only one of them is fine.
            //
            // With no leg claiming any address, this is a connection that did
            // not come through a relay — something dialled the video listener
            // directly — and relay-only is the right answer.
            //
            // With legs claiming addresses and none of them this one, the way a
            // leg is identified has stopped working (see `LegDirectory`), and
            // *every* connection is about to quietly lose its direct path. Said
            // loudly, because the symptom on its own is only that migration
            // never happens.
            match directory.claimed() {
                0 => tracing::debug!(%peer, "no relay leg has reported; staying relay-only"),
                claimed => tracing::warn!(
                    %peer,
                    claimed,
                    "no relay leg claims this connection, though others are claimed; \
                     staying relay-only",
                ),
            }
            return None;
        }
        tokio::select! {
            _ = shutdown.cancelled() => return None,
            _ = tokio::time::sleep(LEG_LOOKUP_POLL) => {}
        }
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

/// The connection's first path — the relay one — as msquic numbers it.
///
/// There is no event that names it: `PathAdded` reports paths that were opened
/// after a probe validated, and the path the handshake ran on was never probed.
/// It is `Paths[0]`, whose path id is 0.
const RELAY_PATH_ID: u32 = 0;

/// What a request to move onto a path turns into.
///
/// The two arms are the two worlds this has to work in at once, and which one
/// applies is decided by the peer rather than by us: multipath is negotiated, so
/// a viewer that has been updated still talks to cameras that have not.
#[derive(Debug, Clone, PartialEq, Eq)]
enum PathPreference {
    /// Multipath: say which path carries traffic, and keep the rest warm.
    ///
    /// This is the operation that replaces switching, and it does two things at
    /// once. To the peer it sends PATH_AVAILABLE / PATH_BACKUP; locally it flips
    /// `Path->IsActive`, and `QuicConnChoosePath` picks at random among the
    /// active paths — so a path left available is a path this side really does
    /// send on. Declaring exactly one available is what makes "which path are we
    /// using" answerable.
    ///
    /// A path declared backup is still bound, still validated and still pinged
    /// by the path keepalive, so it does not decay while it waits — which is the
    /// whole of risk #24. That is the difference from switching: nothing is torn
    /// down, so coming back costs nothing.
    Declare { available: u32, backup: Vec<u32> },
    /// The peer never sent a `PathAdded`, so it has no multipath and the only
    /// operation available is the old switch.
    Switch,
}

/// Turn a request to move onto `wanted` into the operation to perform.
///
/// `direct_paths` is what `PathAdded` has named so far. Empty means the peer has
/// no multipath — and it stays empty for a path that only ever validated, which
/// is exactly the pre-multipath camera.
///
/// Everything known and not preferred is declared backup, not just the path
/// being left. Two candidates are offered whenever the observed address differs
/// from the host one, and both can validate on the same LAN, so "the other path"
/// is not always one path.
fn preference_for(
    wanted: (SocketAddr, SocketAddr),
    relay_path: (SocketAddr, SocketAddr),
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> PathPreference {
    if direct_paths.is_empty() {
        return PathPreference::Switch;
    }
    let available = if wanted == relay_path {
        RELAY_PATH_ID
    } else {
        match direct_paths.get(&wanted) {
            Some(id) => *id,
            // Validated but never added: the peer has multipath for some other
            // path and not for this one, which should not happen — switching is
            // still better than doing nothing.
            None => return PathPreference::Switch,
        }
    };
    let backup = std::iter::once(RELAY_PATH_ID)
        .chain(direct_paths.values().copied())
        .filter(|id| *id != available)
        .collect();
    PathPreference::Declare { available, backup }
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

    let (reg, config) =
        video_client_config(registration, verify, candidate.is_some(), pin.is_some())?;
    let conn = dial_video(
        &reg,
        &config,
        host,
        port,
        candidate,
        verify,
        pin.as_ref(),
        &shutdown,
    )
    .await?;

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
                        if prefer_path(&conn, relay_path, relay_path, &direct_paths).is_ok() {
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
                        if prefer_path(&conn, (local, remote), relay_path, &direct_paths).is_ok() {
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

/// Log what the connection is actually doing, which is the difference between
/// "the migration stalled" and "the migration broke the connection".
///
/// `Send.PathMtu` is worth watching when a path has just been opened, since it
/// has to size itself.
///
/// For loss, `send_lost` alone says very little: it counts packets the loss
/// detector *declared* lost, and `send_spurious_lost` is how many of those
/// turned out to have arrived after all. A high first number with a high second
/// is an over-eager loss detector, not a lossy path, and the two want opposite
/// fixes. `send_congestion` and the byte counters give the other half — whether
/// the congestion controller is actually backing off, and what throughput that
/// leaves.
fn log_connection_stats(conn: &Connection, stats: &msquic::ffi::QUIC_STATISTICS, when: &str) {
    tracing::debug!(
        when,
        local = ?conn.get_local_addr().ok(),
        remote = ?conn.get_remote_addr().ok(),
        rtt_us = stats.Rtt,
        send_path_mtu = stats.Send.PathMtu,
        send_packets = stats.Send.TotalPackets,
        send_lost = stats.Send.SuspectedLostPackets,
        send_spurious_lost = stats.Send.SpuriousLostPackets,
        send_congestion = stats.Send.CongestionCount,
        send_persistent_congestion = stats.Send.PersistentCongestionCount,
        send_bytes = stats.Send.TotalBytes,
        recv_packets = stats.Recv.TotalPackets,
        recv_dropped = stats.Recv.DroppedPackets,
        recv_bytes = stats.Recv.TotalBytes,
        "video connection stats",
    );
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

/// Move the connection onto `wanted`, by whichever operation the peer supports.
///
/// Errors are logged rather than returned upward: a connection that cannot be
/// moved keeps streaming on the path it is already on, which is worse than the
/// caller asked for and much better than dropping the video. `Err(())` says only
/// that nothing changed, so the caller does not report a move that did not
/// happen.
fn prefer_path(
    conn: &Connection,
    wanted: (SocketAddr, SocketAddr),
    relay_path: (SocketAddr, SocketAddr),
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> Result<(), ()> {
    let (local, remote) = wanted;
    match preference_for(wanted, relay_path, direct_paths) {
        PathPreference::Declare { available, backup } => {
            // Demote first. Promoting first would leave a window with two
            // active paths, and msquic picks among them at random — so traffic
            // would split across both, which is the state this whole call
            // exists to avoid. The other order leaves a window with none, and
            // `QuicConnChoosePath` falls back to `Paths[0]`, the relay: still a
            // working path, which is the safe side to be wrong on.
            for id in &backup {
                if let Err(e) = conn.set_path_status(*id, false) {
                    tracing::warn!(path_id = id, "could not declare a path backup: {e}");
                }
            }
            match conn.set_path_status(available, true) {
                Ok(()) => {
                    tracing::info!(
                        %local, %remote, path_id = available, ?backup,
                        "declared a path available; every path stays active",
                    );
                    Ok(())
                }
                Err(e) => {
                    tracing::warn!(%local, %remote, "could not declare a path available: {e}");
                    Err(())
                }
            }
        }
        PathPreference::Switch => match conn.activate_path(local, remote) {
            Ok(()) => {
                tracing::info!(%local, %remote, "activated path (the peer has no multipath)");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(%local, %remote, "could not activate path: {e}");
                Err(())
            }
        },
    }
}

async fn report_path(events: &Option<mpsc::Sender<PathEvent>>, event: PathEvent) {
    tracing::info!("video path: {event:?}");
    if let Some(events) = events {
        let _ = events.send(event).await;
    }
}

/// Refuse the handshake unless the certificate names `host` and, where the peer
/// published one, is the key `pin` vouches for.
///
/// Either check can be absent: `host` is `None` when validation is off, and
/// `pin` is `None` for a peer that has published nothing. At least one is
/// always present, or this is not installed at all.
///
/// The handler runs on msquic's thread during the handshake and its return
/// status is the verdict, so everything it needs is copied in beforehand and it
/// does no I/O.
///
/// A rejection is logged at `warn` and not swallowed: a certificate for the
/// wrong name, or one on a connection that expected an attested key, is either
/// a misconfiguration or the thing this exists to catch, and both want saying.
fn install_certificate_check(
    conn: &Connection,
    // The host to hold the certificate against, or `None` when validation is
    // off and only the pin is left to check.
    host: Option<String>,
    pin: Option<AttestedPeer>,
    refused: Arc<Mutex<Option<String>>>,
) {
    conn.set_peer_certificate_received_callback(move |certificate, _flags, _status, _chain| {
        // `USE_PORTABLE_CERTIFICATES` makes this a `QUIC_BUFFER` of DER. It is
        // msquic's memory and lives only for this call, so nothing is kept.
        let der = unsafe {
            (certificate as *const msquic::ffi::QUIC_BUFFER)
                .as_ref()
                .map(|buffer| msquic::BufferRef::from_ffi_ref(buffer).as_bytes())
        };
        let verdict = match der {
            // The name first: a certificate for somebody else is somebody
            // else's whatever it carries, and saying so names the right
            // problem.
            Some(der) => host
                .as_deref()
                .map_or(Ok(()), |host| certificate_matches(der, host))
                .and_then(|()| match &pin {
                    Some(pin) => pin.accepts(der),
                    None => Ok(()),
                }),
            None => Err("the peer presented no certificate".to_owned()),
        };
        match verdict {
            Ok(()) if pin.is_none() => {
                tracing::debug!(
                    host = host.as_deref().unwrap_or_default(),
                    "the video certificate is for the host dialled",
                );
                Ok(())
            }
            Ok(()) => {
                // Said at `info`, and once per handshake. "We are going to
                // check" and "it held" are different facts, and only the second
                // one is the protection — an operator who sees the first and
                // then silence cannot tell which of them happened.
                tracing::info!(
                    peer = pin
                        .as_ref()
                        .map(|p| p.peer_endpoint.as_str())
                        .unwrap_or_default(),
                    "the peer presented the key it signed for; the connection is pinned to it",
                );
                Ok(())
            }
            Err(reason) => {
                tracing::warn!(
                    peer = pin
                        .as_ref()
                        .map(|p| p.peer_endpoint.as_str())
                        .unwrap_or_default(),
                    host = host.as_deref().unwrap_or_default(),
                    "refusing the video connection: {reason}",
                );
                // Left where the dial can find it. The handshake is about to
                // fail, and every other reason it fails is worth retrying — so
                // without this the one answer that means *stop* is retried for
                // fifteen minutes and then reported as something else entirely.
                *refused.lock().expect("pin verdict lock poisoned") = Some(reason);
                Err(msquic::Status::from(
                    msquic::ffi::QUIC_STATUS_BAD_CERTIFICATE,
                ))
            }
        }
    });
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
///
/// `host` is a *name*, never an address to look up. Every caller dials the relay
/// bridge on loopback, and the name is the per-endpoint FQDN the listener's relay
/// certificate is issued for — it exists so the certificate can be validated, and
/// its only DNS record points back at `127.0.0.1`. Pinning the remote address
/// below says that outright, and keeps msquic from resolving the name: msquic
/// resolves with a blocking `getaddrinfo` on the connection's worker thread, and
/// that worker also drives the relay leg, so a slow resolver takes the leg down
/// with it. A loopback-only name is exactly what mobile resolvers are slowest
/// about — DNS64 will not synthesise an AAAA for `127.0.0.0/8`, and resolvers
/// with rebinding protection refuse to return it at all — which is why this
/// showed up on iOS long before it would have anywhere else.
// Each of these is a distinct thing the dial needs and none of them group into
// anything that would read better as a struct.
#[allow(clippy::too_many_arguments)]
async fn dial_video(
    reg: &Registration,
    config: &msquic::Configuration,
    host: &str,
    port: u16,
    candidate: Option<ObservedAddress>,
    // Whether this connection validates at all. Off is dev-only, and then
    // there is nothing to check the certificate against.
    verify: bool,
    pin: Option<&AttestedPeer>,
    shutdown: &CancellationToken,
) -> anyhow::Result<Connection> {
    let deadline = Instant::now() + VIDEO_CONNECT_DEADLINE;
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        let conn = Connection::new(reg)?;
        // Every attempt builds a fresh connection, so the setup below has to be
        // redone on each one.
        conn.set_remote_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))
            .map_err(|e| anyhow::anyhow!("could not pin the relay bridge address: {e}"))?;
        if let Some(candidate) = candidate {
            prepare_for_migration(&conn, candidate)?;
        }
        // One slot per attempt: a verdict from a connection that has been
        // dropped says nothing about this one.
        let refused: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
        // The name is checked when this connection validates; the pin is
        // checked whenever the peer published one, insecure switch included.
        let check_name = verify && std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_none();
        if check_name || pin.is_some() {
            install_certificate_check(
                &conn,
                check_name.then(|| host.to_owned()),
                pin.cloned(),
                Arc::clone(&refused),
            );
        }
        // The handshake can stay unanswered for a long time by design, and until
        // it is answered there is nothing else to go on. Report what it is doing
        // while it waits: whether our packets are still leaving tells a peer
        // that has not bound its leg apart from a path that has stopped
        // carrying anything, and those want opposite fixes.
        let start = conn.start(config, host, port);
        tokio::pin!(start);
        let mut probe = tokio::time::interval(HANDSHAKE_PROBE_INTERVAL);
        probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Carried out of the loop because the failure below has to describe a
        // connection it has already had to drop.
        let mut last: Option<(u64, u64)> = None;
        let result = loop {
            tokio::select! {
                _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing video"),
                r = &mut start => break r,
                _ = probe.tick() => match conn.get_stats() {
                    Ok(stats) => {
                        last = Some((stats.Send.TotalPackets, stats.Recv.TotalPackets));
                        log_connection_stats(&conn, &stats, "handshake");
                    }
                    Err(e) => tracing::debug!("could not read handshake stats: {e}"),
                },
            }
        };
        // Checked before the retry decision, because it is the one failure that
        // retrying cannot help: the peer signed for a key, and this certificate
        // is not it. Trying again produces the same answer, ~1,700 times, and
        // the error finally reported would be the relay-leg timeout — which is
        // what "the operator has not pasted the connection id yet" looks like.
        // The two want opposite responses.
        if let Some(reason) = refused.lock().expect("pin verdict lock poisoned").take() {
            // Deliberately not naming the attestation: the same slot carries a
            // name mismatch, and pointing an operator at a statement the peer
            // never published sends them to the wrong problem.
            anyhow::bail!("the peer's certificate was refused, so this is not the peer it claims to be: {reason}");
        }
        match result {
            Ok(()) => return Ok(conn),
            Err(e) => {
                let observed = conn
                    .get_stats()
                    .ok()
                    .map(|s| (s.Send.TotalPackets, s.Recv.TotalPackets))
                    .or(last);
                drop(conn);
                if Instant::now() >= deadline {
                    // Say what was seen, not what it might mean. The old wording
                    // asserted the peer had not bound its leg, and a day went
                    // into chasing that assertion while it was wrong; the packet
                    // counts distinguish the cases without guessing. Nothing
                    // received at all is the peer never answering — a leg not
                    // bridged yet, or an operator who has not finished carrying
                    // the connection id across.
                    let seen = match observed {
                        Some((sent, received)) => {
                            format!("{sent} packets sent, {received} received")
                        }
                        None => "no packet counts available".to_owned(),
                    };
                    return Err(anyhow::Error::new(e).context(format!(
                        "video QUIC handshake to {host}:{port} did not complete within \
                         {VIDEO_CONNECT_DEADLINE:?} ({attempt} attempts, {seen})"
                    )));
                }
                // Debug, not Display: the transport status is what names the
                // cause — an untrusted certificate and an unanswered handshake
                // both read as "connection lost" otherwise.
                tracing::debug!("video handshake attempt {attempt} failed: {e:?}");
                tokio::select! {
                    _ = shutdown.cancelled() => anyhow::bail!("shut down while dialing video"),
                    _ = sleep(VIDEO_CONNECT_RETRY_DELAY) => {}
                }
            }
        }
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
    // All three are required for a direct path to be validated at all — without
    // them msquic never raises `PathValidated`, whatever candidate is offered.
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
    pinning: bool,
) -> anyhow::Result<(Arc<Registration>, msquic::Configuration)> {
    let reg = match reg {
        Some(reg) => reg,
        None => Arc::new(Registration::new(&msquic::RegistrationConfig::default())?),
    };
    let alpn = [msquic::BufferRef::from(VIDEO_ALPN)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(VIDEO_IDLE_TIMEOUT.as_millis() as u64)
        // Keep a single unanswered handshake alive long enough to span
        // the peer's relay-bind gap: msquic keeps retransmitting the
        // Initial on ONE connection until the far leg comes up, rather
        // than many short-lived attempts (which poison the relay path).
        .set_HandshakeIdleTimeoutMs(60_000)
        // Keep the connection from going idle into the timeout above.
        //
        // The other keepalive, and both are wanted. `DIRECT_PATH_KEEPALIVE`
        // below explains why this one does not keep a *path* warm: it is
        // re-armed by activity anywhere on the connection, so on a connection
        // carrying video it never fires at all. What it covers is the case
        // where there is no video — the camera stopped streaming, or has not
        // started — and the connection would otherwise be dropped at thirty
        // seconds with the viewer still sitting there. The listener side has
        // had this all along (`isekai_link_utils`); this side had not.
        .set_KeepAliveIntervalMs(CONNECTION_KEEPALIVE.as_millis() as u32)
        // msquic clamps `MaximumMtu` up to QUIC_DPLPMTUD_MIN_MTU
        // (1248), so asking for less is silently ignored — 1248 is what
        // this connection actually uses, and stating it keeps the code
        // honest about the cap it is applying.
        //
        // The cap exists so a video QUIC packet plus CONNECT-UDP
        // encapsulation fits inside the relay tunnel's HTTP datagram.
        // Without it the default 1500 overflows the tunnel and packets
        // are dropped as `TooLarge`. The outer connection's
        // `MinimumMtu` (see `isekai_p2p_core::transport`, which does the
        // arithmetic) is what is sized to carry 1248 plus that
        // encapsulation. Deliberately not repeated here: this said 1400
        // for a while after that floor became 1350, and a number in two
        // places is a number that disagrees with itself.
        .set_MaximumMtu(1248)
        .set_PeerUnidiStreamCount(100)
        .set_StreamMultiReceiveEnabled();
    // NAT-traversal mode is what makes the peer probe our candidate address and
    // report a `PathValidated` for the direct path; the observed-address reports
    // are the other half of the exchange.
    //
    // Multipath goes on top of that rather than instead of it. NAT traversal is
    // what opens a path between two peers behind NATs — an application adding
    // paths by hand cannot hole-punch — so the probing stays exactly as it was;
    // what multipath changes is what a validated path *becomes*: another active
    // path instead of somewhere to migrate to.
    //
    // And the path keepalive is what stops the second path decaying while
    // nothing is sent on it, which is the whole of risk #24. It is not optional,
    // it is not the connection keepalive — see `DIRECT_PATH_KEEPALIVE` for why
    // that distinction cost a field test — and it is not symmetric with the
    // listener's: the timer runs off each connection's own settings, so this
    // side pinging says nothing about the other side. The listener sets its own
    // (`isekai_link_utils::PATH_KEEP_ALIVE_INTERVAL_MS`), which is why both ends
    // ping rather than one.
    //
    // **These PINGs are also what tells the camera this viewer is still here.**
    // Once the video is on the direct path they are the only thing this side
    // still sends across the relay leg, and the camera renews the connection's
    // lease only while something arrives on it
    // (`ListenerSession::renew_connections`). Reading this as "the direct path's
    // keepalive, so the relay path does not need it" would cut this viewer off
    // one connect TTL into watching.
    let settings = if enable_migration {
        settings
            .set_ReceiveObservedAddressReports()
            .set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
            .set_MultipathEnabled()
            .set_PathKeepAliveIntervalMs(DIRECT_PATH_KEEPALIVE.as_millis() as u32)
    } else {
        settings
    };
    let config = reg.open_configuration(&alpn, Some(&settings))?;
    // The video connection has its own `CredentialConfig`, separate from the
    // control/relay one in `isekai_p2p_core::transport`, so it needs the same
    // treatment rather than inheriting it.
    //
    // **`USE_TLS_BUILTIN_CERTIFICATE_VALIDATION` is deliberately not set here.**
    // It was, briefly, and it is wrong on three of the four platforms:
    //
    // * Windows builds msquic with schannel (`CMakeLists.txt`), and
    //   `tls_schannel.c` answers `QUIC_STATUS_INVALID_PARAMETER` to any
    //   credential carrying this flag -- so `load_credential` fails and *every*
    //   client connection stops being possible, insecure escape hatch included.
    // * Linux and Android are `CX_PLATFORM_LINUX`, where `tls_quictls.c` ORs
    //   the flag in itself. Setting it changes nothing.
    // * Darwin is the one platform where it does something, and what it does is
    //   a regression: it replaces msquic's `CxPlatCertVerifyRawCertificate`
    //   (SecTrust, with the dialed name) with a bare `X509_verify_cert` against
    //   `SSL_CTX_set_default_verify_paths()` -- an empty store on iOS.
    //
    // What Android actually needed is below: a CA file, because it has no
    // system PEM for the default paths to find.
    let mut cred = msquic::CredentialConfig::new_client();
    // Android ships no system PEM file, so the default verify paths find
    // nothing; the app copies a bundle out of its assets and points
    // `SSL_CERT_FILE` at it. Setting `CaCertificateFile` drives
    // `SSL_CTX_load_verify_locations()` directly rather than depending on the
    // environment variable being honoured by this quictls build.
    //
    // An unset variable leaves the platform's own defaults alone, which is what
    // every other platform wants. An empty one is ignored rather than passed
    // on: `load_verify_locations` failing is fatal to the whole credential.
    if let Some(ca_file) = std::env::var("SSL_CERT_FILE")
        .ok()
        .filter(|p| !p.is_empty())
    {
        cred = cred.set_ca_certificate_file(ca_file);
    }
    // The same dev-only opt-in the proxy and Identity connections honour
    // (`isekai_p2p_core::transport`), which this one ignored — so the one switch
    // an operator has did not cover the one connection that carries the video.
    // It is only an escape hatch; never set in production.
    let skip_verify = std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_some();
    if verify && skip_verify {
        tracing::warn!(
            "ISEKAI_INSECURE_SKIP_VERIFY set: skipping video TLS certificate validation"
        );
    }
    if !verify || skip_verify {
        cred = cred.set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    }
    if (verify && !skip_verify) || pinning {
        // **Added to whatever validation is already happening, not instead of
        // it.** The flags are OR'd, so nothing msquic does is switched off;
        // this asks to be shown the certificate as well, in a form that parses
        // on every platform.
        //
        // Asked for whenever the name has to be checked (#134) **or** there is
        // a key to pin — including with the insecure switch on. That switch
        // means "do not validate the certificate"; it has never meant "ignore
        // what the peer signed for", and msquic raises the indication even with
        // `NO_CERTIFICATE_VALIDATION`, so the pin can go on holding. A
        // certificate that is never handed over cannot be checked at all.
        cred = cred
            .set_credential_flags(msquic::CredentialFlags::INDICATE_CERTIFICATE_RECEIVED)
            .set_credential_flags(msquic::CredentialFlags::USE_PORTABLE_CERTIFICATES);
    }
    config.load_credential(&cred)?;
    Ok((reg, config))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The three ways there is nothing to pin are told apart, because only one
    /// of them is ordinary and the other two are the proxy answering strangely.
    /// Reporting all of them as "the peer published nothing" blames the camera
    /// for the proxy's behaviour.
    #[test]
    fn not_pinning_says_which_of_the_three_it_is() {
        let plain: PeerConnection = serde_json::from_str(
            r#"{"connection_id":"c","state":"relay","listener_id":"pl_1",
                "peer_endpoint":"ep:b","protocol":"mjpeg","relay_session_id":"s",
                "candidates":[],"peer_candidates":[]}"#,
        )
        .expect("a connect response");
        assert_eq!(
            AttestedPeer::from_connection(&plain).unwrap_err(),
            Unpinnable::NoStatement,
            "no statement is the ordinary case",
        );

        let attested: PeerConnection = serde_json::from_str(
            r#"{"connection_id":"c","state":"relay","listener_id":"pl_1",
                "peer_endpoint":"ep:b","protocol":"mjpeg","relay_session_id":"s",
                "candidates":[],"peer_candidates":[],
                "video_attestation":{"jwk":{},"expires_at":"2099-01-01T00:00:00Z",
                                     "signature":"x"}}"#,
        )
        .expect("a connect response with a statement");
        assert_eq!(
            AttestedPeer::from_connection(&attested).unwrap_err(),
            Unpinnable::NoHost,
            "a statement with nowhere to dial is not the camera's doing",
        );
    }
    use std::net::SocketAddr;

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

    fn pair(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([192, 168, 1, 59], port)),
            SocketAddr::from(([203, 0, 113, 5], port)),
        )
    }

    /// The relay pair, standing in for the loopback bridge the video connection
    /// actually runs over.
    fn relay() -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], 5000)),
            SocketAddr::from(([127, 0, 0, 1], 5001)),
        )
    }

    /// A camera without multipath never sends `PathAdded`, so there are no path
    /// ids and the only thing that can be done is what was always done.
    ///
    /// This is the mixed pair, and it is not hypothetical: cameras and viewers
    /// are updated separately, so an updated viewer meets old cameras for as
    /// long as the rollout takes.
    #[test]
    fn a_peer_without_multipath_still_gets_the_old_switch() {
        assert_eq!(
            preference_for(pair(1000), relay(), &BTreeMap::new()),
            PathPreference::Switch,
        );
    }

    /// With multipath, moving onto the direct path declares it available and the
    /// relay backup — and the relay is *kept*, which is the whole difference.
    #[test]
    fn moving_onto_the_direct_path_declares_the_relay_backup() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(pair(1000), relay(), &direct),
            PathPreference::Declare {
                available: 1,
                backup: vec![RELAY_PATH_ID],
            },
        );
    }

    /// And going back is the same operation with the preference reversed, not a
    /// different one — there is nothing to switch back to, because nothing was
    /// left.
    #[test]
    fn going_back_to_the_relay_is_the_same_operation_reversed() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(relay(), relay(), &direct),
            PathPreference::Declare {
                available: RELAY_PATH_ID,
                backup: vec![1],
            },
        );
    }

    /// Both candidates can validate at once — the host address and the observed
    /// one, which is what happens on the LAN behind the peer's own NAT — so
    /// "the other path" is not always a single path. Everything not preferred
    /// is declared backup, or the peer is left with two available paths and a
    /// preference that says nothing.
    #[test]
    fn every_path_that_is_not_preferred_is_declared_backup() {
        let direct = BTreeMap::from([(pair(1000), 1), (pair(2000), 2)]);
        assert_eq!(
            preference_for(pair(2000), relay(), &direct),
            PathPreference::Declare {
                available: 2,
                backup: vec![RELAY_PATH_ID, 1],
            },
        );
    }

    /// A pair that validated but was never added has no id to declare anything
    /// about. Switching is worse than declaring and much better than ignoring
    /// the request.
    #[test]
    fn a_path_with_no_id_falls_back_to_switching() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(pair(9999), relay(), &direct),
            PathPreference::Switch,
        );
    }
}
