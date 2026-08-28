//! UDP forwarding: the sockets, the session table, and the pump both ways.
//!
//! **Phase 3b of `docs/portal_plan.md` §4.1.** [`crate::datagram`] settled the
//! wire and the two bounds with nothing plugged into them; this is what plugs
//! in.
//!
//! ```text
//!   application          portal-client              portal-server        target
//!   :51314  ──────▶  the bound local port  ──open──▶  catalogue lookup
//!                       one session per            one UDP socket per  ──▶ :53
//!                    (source address, service)         session
//!           ◀──────       send_to(source)   ◀──datagrams──   recv       ◀──
//! ```
//!
//! # Both ends live here, and that is the point
//!
//! `server` and `client` are the two ends of a TCP forward and they share
//! nothing but the frame. The two ends of a UDP forward share the session table
//! and the pump that feeds it, because there is exactly one datagram stream per
//! QUIC connection and everything on it has to be demultiplexed in one place.
//! Splitting that across two modules would mean two copies of the one piece of
//! code where a mistake loses traffic silently.
//!
//! # One receiver per connection
//!
//! msquic-async delivers datagrams from a single per-connection queue, so a
//! second task polling it would take datagrams belonging to the first. There is
//! therefore exactly one [`Sessions`] per peer connection, it owns the pump, and
//! everything that forwards UDP over that connection goes through it. On the
//! client that means one `Sessions` shared by every `--map`, not one per map.
//!
//! # What a session is, and when it ends
//!
//! A session is one (source address, service) pair on the client and one UDP
//! socket on the server, tied together by the id in every datagram's header. It
//! ends when any of these happens, and all of them end it on both sides because
//! the stream that opened it carries the news:
//!
//! - the application or the target stops for [`IDLE`];
//! - either end finishes the stream;
//! - the socket fails;
//! - the connection goes away.
//!
//! **The idle sweep is the select's own timer**, re-armed by every iteration, so
//! "no traffic in either direction for a minute" needs no timestamps and cannot
//! drift out of step with the traffic it is watching.

use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{Connection, DgramSendError, StreamType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::datagram::{decode, encode, Drops, Push, Queue, MAX_PAYLOAD};
use crate::frame::{read_status, write_open, write_status, Open, Status};

/// How long a session may go without traffic in either direction before it is
/// swept.
///
/// The plan's number. UDP has no close, so something has to decide when a
/// conversation is over, and the cost of deciding too early is one extra open
/// on the next packet — while deciding too late is a socket and a table entry
/// held for a client that has gone. Not on the CLI yet, which is phase 5;
/// [`Sessions::start_with_idle`] is where it is chosen.
pub const IDLE: Duration = Duration::from_secs(60);

/// The most sessions one connection may have at a time.
///
/// **This is a file-descriptor bound before it is anything else.** Each session
/// on the server is a UDP socket, and a peer that opens sessions without bound
/// exhausts the process's descriptors — reaching further than the forwarding,
/// since everything else this process does needs one too. A Grant says two
/// Endpoints may talk; it does not say how much of this machine the other one
/// may have.
///
/// A thousand is far above what a forward with a resolver behind it uses — a
/// stub resolver has a handful of source ports in flight — and far below any
/// default descriptor limit.
pub const MAX_SESSIONS: usize = 1024;

/// Enough for the largest UDP payload there is (65507 bytes).
///
/// **Deliberately larger than [`MAX_PAYLOAD`]**: `recv` on a UDP socket
/// truncates to the buffer and says nothing about it, so a buffer sized to what
/// can be forwarded would turn "too large, dropped and counted" into "silently
/// cut short" — the exact failure [`crate::datagram`] exists to prevent.
const RECV_BUFFER: usize = 65_536;

/// Every UDP session on one peer connection, and the pump that feeds them.
///
/// One per connection — see the module header.
pub struct Sessions {
    conn: Connection,
    table: Mutex<HashMap<u32, Arc<Queue>>>,
    /// Where the next client-allocated id comes from. Only the initiator
    /// allocates, so there is one allocator per connection and no collisions to
    /// resolve between the two ends.
    next: AtomicU32,
    /// How long a session here may go quiet — [`IDLE`] unless
    /// [`start_with_idle`](Self::start_with_idle) said otherwise.
    idle: Duration,
    /// What was lost, and why. Read by anything that wants to report it; the
    /// pump logs a summary when the connection ends.
    pub drops: Drops,
    /// Sessions that could not be opened — refused, unreachable, or a stream
    /// that failed.
    ///
    /// **Separate from [`Drops`], which counts datagrams.** This counts
    /// conversations that never started, and it exists because the first one is
    /// logged and the rest are not: a `--map udp:5353:dsn` with the name
    /// misspelt is refused on every datagram the application sends, and a
    /// `warn!` each would bury everything else the forward has to say. What is
    /// lost with them is counted where losses are — the queued payloads go
    /// through [`Sessions::end`] and `abandon` like any other.
    pub open_failures: AtomicU64,
}

/// What [`Sessions::accept`] made of an id the peer chose.
enum Accept {
    Ready(Arc<Queue>),
    /// The peer used an id it already has open.
    InUse,
    /// [`MAX_SESSIONS`] reached.
    Full,
}

impl Sessions {
    /// Start receiving datagrams on `conn`.
    ///
    /// The pump runs until `shutdown` or until the connection ends. **Both
    /// matter**: the connection ending is the ordinary case, and `shutdown` is
    /// what lets a caller release its handles — a pump still holding a
    /// `Connection` clone is a handle `RegistrationClose` will block on, which
    /// is why `session::Connected::close` cancels before it drains.
    pub fn start(conn: Connection, shutdown: CancellationToken) -> Arc<Self> {
        Self::start_with_idle(conn, shutdown, IDLE)
    }

    /// [`start`](Self::start) with a sweep other than [`IDLE`].
    ///
    /// **Here so that the sweep is testable at all.** It is the one behaviour in
    /// this module that only shows itself after a minute of quiet, and an
    /// untested sweep fails in the direction nobody notices: sessions and their
    /// sockets accumulate on a server that is working. A suite cannot wait a
    /// minute, so the minute is a parameter.
    ///
    /// It is also where the plan's "configurable" ends up when phase 5 gives the
    /// CLI a knob for it.
    pub fn start_with_idle(
        conn: Connection,
        shutdown: CancellationToken,
        idle: Duration,
    ) -> Arc<Self> {
        let sessions = Arc::new(Self {
            conn,
            table: Mutex::new(HashMap::new()),
            // 1, so that a session id of zero in a log is always a bug rather
            // than the first session anyone opened.
            next: AtomicU32::new(1),
            idle,
            drops: Drops::default(),
            open_failures: AtomicU64::new(0),
        });
        tokio::spawn({
            let sessions = Arc::clone(&sessions);
            async move { sessions.pump(shutdown).await }
        });
        sessions
    }

    fn connection(&self) -> &Connection {
        &self.conn
    }

    /// Receive datagrams and hand each to its session, until there are no more.
    async fn pump(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let received = tokio::select! {
                _ = shutdown.cancelled() => break,
                received = std::future::poll_fn(|cx| self.conn.poll_receive_datagram(cx)) => received,
            };
            match received {
                Ok(datagram) => self.deliver(datagram),
                // The connection ending is how this is meant to finish.
                Err(e) => {
                    tracing::debug!("no longer receiving portal datagrams: {e}");
                    break;
                }
            }
        }
        // **Reported once, here, rather than never.** Nothing else reads these
        // counters yet, and a drop that is counted into a number nobody prints
        // is a drop that was not counted.
        let failed_opens = self.open_failures.load(Ordering::Relaxed);
        if self.drops.any() || failed_opens != 0 {
            tracing::info!(
                oversize = self.drops.oversize.load(Ordering::Relaxed),
                refused_too_big = self.drops.refused_too_big.load(Ordering::Relaxed),
                overflow = self.drops.overflow.load(Ordering::Relaxed),
                unknown_session = self.drops.unknown_session.load(Ordering::Relaxed),
                malformed = self.drops.malformed.load(Ordering::Relaxed),
                unsent = self.drops.unsent.load(Ordering::Relaxed),
                sessions_full = self.drops.sessions_full.load(Ordering::Relaxed),
                failed_opens,
                "UDP forwarding lost traffic on this connection",
            );
        }
        // Every session's reader learns the connection has gone rather than
        // waiting out its idle timer for something that can no longer arrive.
        for (_, queue) in self.table.lock().expect("session table poisoned").drain() {
            queue.close();
        }
    }

    fn deliver(&self, datagram: Bytes) {
        let Some((id, payload)) = decode(&datagram) else {
            self.drops.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        let queue = self
            .table
            .lock()
            .expect("session table poisoned")
            .get(&id)
            .cloned();
        match queue.map(|queue| queue.push(payload)) {
            Some(Push::Queued) => {}
            Some(Push::Evicted) => {
                self.drops.overflow.fetch_add(1, Ordering::Relaxed);
            }
            // Ordinary when a session is swept while the peer is still sending,
            // which is why neither of these is louder than a counter.
            Some(Push::Closed) | None => {
                self.drops.unknown_session.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Frame `payload` for `session` and send it to the peer.
    ///
    /// `false` means it was dropped, and by then it has been counted. Not
    /// `async`: msquic takes a datagram without waiting, because there is
    /// nothing for a datagram to wait for.
    fn send(&self, session: u32, payload: &[u8]) -> bool {
        let Some(framed) = encode(session, payload) else {
            self.oversize(session, payload.len());
            return false;
        };
        match self.conn.send_datagram(&framed) {
            Ok(()) => true,
            // **Not `oversize`, and that distinction is the point.** Reaching
            // here means the payload was inside `MAX_PAYLOAD` and the
            // connection still would not take it — so the path underneath is
            // narrower than the floor that constant is derived from, which is
            // the connection's business rather than the caller's.
            Err(DgramSendError::TooBig) => {
                self.refused_too_big(session, payload.len());
                false
            }
            // **Counted, not merely logged.** `Denied` here is not one lost
            // datagram: it says the peer never advertised that it would
            // receive any, so every reply on every session of this connection
            // goes the same way — on sessions that answered `Ready`. A forward
            // that looks perfect and delivers nothing was exactly what phase
            // 3a's review caught, and a drop with no counter is how it stayed
            // invisible.
            Err(e) => {
                if self.drops.unsent.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!(
                        session,
                        "the connection would not take a datagram: {e}; \
                         further ones on this connection are counted, not logged",
                    );
                } else {
                    tracing::debug!(session, "a datagram was not sent: {e}");
                }
                false
            }
        }
    }

    /// **Said once per connection and counted every time.** An application that
    /// sends one oversize datagram usually sends a great many, and a line each
    /// would bury everything else the forward has to say — but an operator who
    /// never sees the first one has no way to know why a service that "works"
    /// loses exactly its large messages.
    fn oversize(&self, session: u32, len: usize) {
        if self.drops.oversize.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!(
                session,
                len,
                limit = MAX_PAYLOAD,
                "a UDP payload is too large to forward and was dropped; \
                 further ones on this connection are counted, not logged",
            );
        } else {
            tracing::debug!(session, len, "another oversize UDP payload dropped");
        }
    }

    /// The other half of [`oversize`](Self::oversize), said once for the same
    /// reason and worth its own line because the fix is somewhere else.
    ///
    /// An operator seeing this has a connection that cannot carry what
    /// `MAX_PAYLOAD` promises. That is not something the application can size
    /// its way out of, and it should not be reported as though it were.
    fn refused_too_big(&self, session: u32, len: usize) {
        if self.drops.refused_too_big.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!(
                session,
                len,
                limit = MAX_PAYLOAD,
                "the connection refused a UDP payload that is within portal's limit, so \
                 this path carries less than the guaranteed datagram; \
                 further ones on this connection are counted, not logged",
            );
        } else {
            tracing::debug!(
                session,
                len,
                "another UDP payload refused by the connection"
            );
        }
    }

    /// Allocate a session id, which only the initiator does.
    ///
    /// `None` at [`MAX_SESSIONS`].
    fn open(&self) -> Option<(u32, Arc<Queue>)> {
        let mut table = self.table.lock().expect("session table poisoned");
        if table.len() >= MAX_SESSIONS {
            return None;
        }
        // At most `MAX_SESSIONS` ids are taken, so this many candidates is
        // enough to find a free one — the loop exists for the wrap, not for
        // contention.
        for _ in 0..=MAX_SESSIONS {
            let id = self.next.fetch_add(1, Ordering::Relaxed);
            if id == 0 {
                continue;
            }
            if let Entry::Vacant(slot) = table.entry(id) {
                let queue = Queue::new();
                slot.insert(Arc::clone(&queue));
                return Some((id, queue));
            }
        }
        None
    }

    /// Take an id the peer chose.
    fn accept(&self, id: u32) -> Accept {
        let mut table = self.table.lock().expect("session table poisoned");
        if table.len() >= MAX_SESSIONS {
            return Accept::Full;
        }
        match table.entry(id) {
            Entry::Vacant(slot) => {
                let queue = Queue::new();
                slot.insert(Arc::clone(&queue));
                Accept::Ready(queue)
            }
            Entry::Occupied(_) => Accept::InUse,
        }
    }

    /// Forget `id`, and count whatever the peer sent in the moment before that.
    ///
    /// Called once the session's own loop has finished, so there is no reader
    /// left to drain the queue — which is why this abandons rather than closes.
    fn end(&self, id: u32) {
        let removed = self
            .table
            .lock()
            .expect("session table poisoned")
            .remove(&id);
        if let Some(queue) = removed {
            let lost = queue.abandon();
            if lost != 0 {
                self.drops
                    .unknown_session
                    .fetch_add(lost as u64, Ordering::Relaxed);
            }
        }
    }

    /// How many sessions are open. For tests and diagnostics.
    pub fn len(&self) -> usize {
        self.table.lock().expect("session table poisoned").len()
    }

    /// Whether any session is open.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// A socket that can only hear from `target`.
///
/// **Connected rather than merely bound**, and that is a filter and not a
/// convenience: an unconnected socket accepts a datagram from anybody who
/// guesses the ephemeral port, and whatever arrives on this one is forwarded
/// straight to the peer as though the service had said it. The kernel dropping
/// everything from another address is the cheapest possible version of that
/// check and the only one that cannot be forgotten.
async fn bind_toward(target: SocketAddr) -> anyhow::Result<UdpSocket> {
    let any: SocketAddr = if target.is_ipv4() {
        (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
    } else {
        (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
    };
    let socket = UdpSocket::bind(any)
        .await
        .context("failed to open a UDP socket for the forward")?;
    socket
        .connect(target)
        .await
        .with_context(|| format!("failed to point a UDP socket at {target}"))?;
    Ok(socket)
}

/// Serve one UDP session: the server's end.
///
/// Called once the catalogue has offered `target` under `service`. Answers the
/// open request itself, because **the order matters**: the session has to be in
/// the table before `Ready` leaves, or the client's first datagram — which
/// follows immediately — arrives for a session that does not exist yet and is
/// counted as a drop on the very first packet of every forward.
pub async fn serve(
    sessions: Arc<Sessions>,
    id: u32,
    service: &str,
    target: SocketAddr,
    mut stream: msquic_async::Stream,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let socket = match bind_toward(target).await {
        Ok(socket) => socket,
        Err(e) => {
            tracing::warn!(service, %target, "no socket toward the target: {e:#}");
            return crate::server::refuse(stream, Status::Unreachable).await;
        }
    };
    let queue = match sessions.accept(id) {
        Accept::Ready(queue) => queue,
        Accept::InUse => {
            tracing::warn!(service, id, "the peer reused a UDP session id");
            return crate::server::refuse(stream, Status::Refused).await;
        }
        Accept::Full => {
            sessions.drops.sessions_full.fetch_add(1, Ordering::Relaxed);
            tracing::warn!(
                service,
                limit = MAX_SESSIONS,
                "refusing a UDP session: the peer has as many open as it may",
            );
            return crate::server::refuse(stream, Status::Refused).await;
        }
    };
    if let Err(e) = write_status(&mut stream, Status::Ready).await {
        // **The entry went in before the status and has to come back out on
        // this path.** `accept` above inserted it deliberately early, so that
        // the client's first datagram — which follows `Ready` immediately — has
        // somewhere to land. A status that never leaves, because the peer reset
        // the stream or the connection went, would otherwise leave that entry
        // for the life of the connection: a thousand of them and `accept`
        // answers `Full` to every new session, which the client reports as the
        // service not being offered.
        sessions.end(id);
        return Err(e);
    }
    tracing::debug!(service, id, %target, "a UDP session opened");

    let mut buf = vec![0_u8; RECV_BUFFER];
    let mut unexpected = [0_u8; 1];
    let ended = loop {
        tokio::select! {
            // **Not only the pump's table drain.** That runs once, when the
            // pump stops; a stream accepted just before the cancel whose
            // `accept` lands after it would otherwise sit here for the whole
            // idle timeout holding a `Stream` and a `Connection` clone — which
            // is precisely the `RegistrationClose` wedge `server::serve` says
            // cancelling prevents.
            _ = shutdown.cancelled() => break "the server is leaving".to_owned(),
            // From the peer, out to the target.
            payload = queue.pop() => match payload {
                Some(payload) => if let Err(e) = socket.send(&payload).await {
                    break format!("the target stopped accepting: {e}");
                },
                None => break "the connection ended".to_owned(),
            },
            // From the target, back to the peer.
            read = socket.recv(&mut buf) => match read {
                Ok(n) => { sessions.send(id, &buf[..n]); }
                // **Ends the session rather than continuing.** On Linux a
                // connected UDP socket reports the target's ICMP port
                // unreachable here, and a target that is not listening is one
                // worth reopening against rather than reading from in a loop.
                // The client's next packet opens a fresh session, so its own
                // retry pacing is what bounds the attempts.
                Err(e) => break format!("the target's socket failed: {e}"),
            },
            // The client finishing the stream is how it says the session is
            // over. Bytes on it are not part of this protocol, and a peer
            // sending them has got something wrong that ending is the honest
            // answer to.
            read = stream.read(&mut unexpected) => break match read {
                Ok(0) => "the client closed it".to_owned(),
                Ok(_) => "the client sent bytes on a UDP session's stream".to_owned(),
                Err(e) => format!("the session's stream failed: {e}"),
            },
            _ = tokio::time::sleep(sessions.idle) => break format!("nothing for {:?}", sessions.idle),
        }
    };

    sessions.end(id);
    tracing::debug!(service, id, %target, "a UDP session closed: {ended}");
    // Finished rather than dropped, so the client sees the session end instead
    // of a reset it has to guess at — `server::refuse` documents the difference.
    let _ = stream.shutdown().await;
    Ok(())
}

/// Listen on `local` and forward every datagram to `service` over the peer
/// connection: the client's end.
///
/// Returns the address actually bound, and forwards until `shutdown`.
///
/// **One local socket, many sessions.** Replies have to leave from the port the
/// application sent to or its connected socket will not accept them, so this
/// end cannot give each session a socket of its own the way the server does —
/// the source address is what separates them, and it is also what the session
/// id stands for.
///
/// **The mapping is this side's business** (plan §4.3): which local port stands
/// for which service is a fact about this machine, and nothing about it is
/// sent. The far side is only ever told the name.
pub async fn forward(
    sessions: Arc<Sessions>,
    local: SocketAddr,
    service: String,
    shutdown: CancellationToken,
) -> anyhow::Result<SocketAddr> {
    let socket = Arc::new(
        UdpSocket::bind(local)
            .await
            .with_context(|| format!("failed to bind the forwarded UDP port {local}"))?,
    );
    let bound = socket
        .local_addr()
        .context("read the forwarded port's address")?;
    tracing::info!(%bound, service = %service, "forwarding a local UDP port");

    tokio::spawn(async move {
        let sources: Sources = Arc::new(Mutex::new(HashMap::new()));
        let mut buf = vec![0_u8; RECV_BUFFER];
        loop {
            let read = tokio::select! {
                _ = shutdown.cancelled() => break,
                read = socket.recv_from(&mut buf) => read,
            };
            let (n, from) = match read {
                Ok(pair) => pair,
                Err(e) => {
                    tracing::warn!(%bound, "stopped receiving on the forwarded port: {e}");
                    break;
                }
            };
            let payload = Bytes::copy_from_slice(&buf[..n]);

            // An established session takes it without this loop awaiting
            // anything — which is why the outbound side is a queue rather than
            // a send: opening a session takes a round trip, and a receive loop
            // that waits for one stops serving every other source while it does.
            let established = sources
                .lock()
                .expect("source table poisoned")
                .get(&from)
                .cloned();
            if let Some(outbound) = established {
                match outbound.push(payload.clone()) {
                    Push::Queued => continue,
                    Push::Evicted => {
                        sessions.drops.overflow.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    // Swept between the lookup and the push. Falls through and
                    // opens a new session for it rather than losing it, which
                    // is what an application resending after a quiet minute
                    // does and it should not cost a packet.
                    Push::Closed => {}
                }
            }

            let Some((id, inbound)) = sessions.open() else {
                // Its own counter, not `unknown_session`: that one is the
                // ordinary race with the sweep, and this one means the forward
                // has stopped taking new sources altogether.
                if sessions.drops.sessions_full.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!(
                        %from,
                        service = %service,
                        limit = MAX_SESSIONS,
                        "not opening another UDP session; further datagrams \
                         turned away on this connection are counted, not logged",
                    );
                }
                continue;
            };
            let outbound = Queue::new();
            outbound.push(payload);
            sources
                .lock()
                .expect("source table poisoned")
                .insert(from, Arc::clone(&outbound));
            tokio::spawn(session(
                Arc::clone(&sessions),
                id,
                service.clone(),
                from,
                Arc::clone(&socket),
                inbound,
                outbound,
                Arc::clone(&sources),
                shutdown.clone(),
            ));
        }
        // Whatever is still open goes with the port it was reached through.
        // `close` and not `abandon`: each session's task is still running and
        // will forward what is left before its `pop` returns `None`.
        for (_, outbound) in sources.lock().expect("source table poisoned").drain() {
            outbound.close();
        }
    });
    Ok(bound)
}

/// Which local source address has which session's outbound queue.
type Sources = Arc<Mutex<HashMap<SocketAddr, Arc<Queue>>>>;

/// One client-side session, from the open request to the sweep.
#[allow(clippy::too_many_arguments)]
async fn session(
    sessions: Arc<Sessions>,
    id: u32,
    service: String,
    from: SocketAddr,
    socket: Arc<UdpSocket>,
    inbound: Arc<Queue>,
    outbound: Arc<Queue>,
    sources: Sources,
    shutdown: CancellationToken,
) {
    if let Err(e) = run_session(
        &sessions, id, &service, from, &socket, &inbound, &outbound, &shutdown,
    )
    .await
    {
        // **Said once per connection and counted every time**, for the same
        // reason an oversize payload is. A `--map udp:5353:dsn` with the name
        // misspelt is refused on *every* datagram the application sends —
        // there is no negative caching here, deliberately, because a refusal
        // is also what a momentarily full server answers and holding a source
        // off after one would turn a transient into an outage. So the cost of
        // a wrong map is one stream open per datagram, bounded by
        // `MAX_SESSIONS`, and one log line rather than a flood.
        if sessions.open_failures.fetch_add(1, Ordering::Relaxed) == 0 {
            tracing::warn!(
                %from,
                service = %service,
                "the UDP forward failed: {e:#}; further failures on this \
                 connection are counted, not logged",
            );
        } else {
            tracing::debug!(%from, service = %service, "the UDP forward failed: {e:#}");
        }
    }

    sessions.end(id);
    // Abandoned rather than closed for the reason `end` above gives: this
    // loop's reader is this task, and it has finished. What the application
    // sent in the instant before that is lost, and is counted rather than
    // quietly freed.
    let unsent = outbound.abandon();
    if unsent != 0 {
        sessions
            .drops
            .unknown_session
            .fetch_add(unsent as u64, Ordering::Relaxed);
    }
    // **Only this session's entry.** A datagram that arrived after the close
    // above got `Push::Closed`, and the receive loop answers that by opening a
    // successor and overwriting the entry — so removing by key alone would
    // throw away a session that is already carrying traffic.
    let mut table = sources.lock().expect("source table poisoned");
    if table
        .get(&from)
        .is_some_and(|queue| Arc::ptr_eq(queue, &outbound))
    {
        table.remove(&from);
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    sessions: &Arc<Sessions>,
    id: u32,
    service: &str,
    from: SocketAddr,
    socket: &UdpSocket,
    inbound: &Queue,
    outbound: &Queue,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    let mut stream = sessions
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .context("failed to open the session's stream")?;
    write_open(
        &mut stream,
        &Open::Udp {
            service: service.to_owned(),
            session: id,
        },
    )
    .await?;
    // Waited for before any payload moves, as the TCP forward does: a session
    // whose datagrams left before the status arrived would be sending into a
    // connection whose far side has no socket for them.
    let status = tokio::time::timeout(crate::client::STATUS_DEADLINE, read_status(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("`{service}` did not answer the open request in time"))??;
    match status {
        Status::Ready => {}
        Status::Refused => anyhow::bail!("the peer does not offer `{service}` over UDP"),
        Status::Unreachable => anyhow::bail!("the peer could not reach `{service}`"),
    }
    tracing::debug!(%from, service, id, "a UDP session opened");

    let mut unexpected = [0_u8; 1];
    let ended = loop {
        tokio::select! {
            _ = shutdown.cancelled() => break "the client is leaving".to_owned(),
            // From the application, out to the peer.
            payload = outbound.pop() => match payload {
                Some(payload) => { sessions.send(id, &payload); }
                None => break "the forwarded port closed".to_owned(),
            },
            // From the peer, back to the application. `send_to` and not `send`:
            // the socket is shared with every other source.
            payload = inbound.pop() => match payload {
                Some(payload) => if let Err(e) = socket.send_to(&payload, from).await {
                    break format!("the local application stopped accepting: {e}");
                },
                None => break "the connection ended".to_owned(),
            },
            read = stream.read(&mut unexpected) => break match read {
                Ok(0) => "the peer closed it".to_owned(),
                Ok(_) => "the peer sent bytes on a UDP session's stream".to_owned(),
                Err(e) => format!("the session's stream failed: {e}"),
            },
            _ = tokio::time::sleep(sessions.idle) => break format!("nothing for {:?}", sessions.idle),
        }
    };

    tracing::debug!(%from, service, id, "a UDP session closed: {ended}");
    let _ = stream.shutdown().await;
    Ok(())
}
