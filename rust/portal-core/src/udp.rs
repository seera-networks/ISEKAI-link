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
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{Connection, DgramSendError, StreamType};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

use crate::datagram::{decode, encode, Drops, Push, Queue, MAX_PAYLOAD, MAX_STREAM_PAYLOAD};
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

/// How many oversize datagrams may be waiting for a stream of their own.
///
/// **Small on purpose.** Each one already has a whole payload in memory, the
/// transport allows a hundred streams at once, and anything that queues here is
/// something the connection is already behind on. A deeper queue would hold
/// megabytes to deliver datagrams later than the application would have liked
/// anyway; `datagram::QUEUE_BYTES` is where waiting belongs.
const BIG_SENDS_WAITING: usize = 16;

/// One oversize datagram on its way to a stream of its own.
struct BigSend {
    session: u32,
    payload: Bytes,
    /// From the forward's `--map`: abort the stream on the first detected loss
    /// rather than retransmitting.
    no_retrans: bool,
}

/// The largest payload that can leave, given what is known about the peer.
///
/// A free function so the decision has somewhere to be tested: the states it
/// turns on live on a [`Sessions`], which needs a connection to build.
fn sendable_payload(peer_takes_oversize: Option<bool>) -> usize {
    if peer_takes_oversize == Some(false) {
        MAX_PAYLOAD
    } else {
        MAX_STREAM_PAYLOAD
    }
}

/// What a peer said about receiving oversize datagrams on streams.
///
/// **Three states and not two**: "not asked yet" has to be distinct from "no",
/// because the first is worth one round trip to resolve and the second must not
/// be paid for again on every session of the connection.
///
/// Its own type so that the rules worth stating have somewhere to be tested
/// without a connection.
///
/// **Four states, because a refusal is inferred rather than told.** A `yes` is
/// a peer that answered an open it understood. A `no` is inferred from a stream
/// that died without a status — and a stream can die for reasons that have
/// nothing to do with the kind it carried. Latching on the first of those would
/// let one transient cost the feature for the life of the connection, and never
/// latching would pay a failed session open on every session against a peer
/// that simply does not have it. So **one failure is remembered and the second
/// decides.**
#[derive(Debug, Default)]
struct PeerOversize(AtomicU8);

impl PeerOversize {
    const UNKNOWN: u8 = 0;
    /// Asked once and got nothing back. Still worth asking again.
    const REFUSED_ONCE: u8 = 1;
    const YES: u8 = 2;
    const NO: u8 = 3;

    fn get(&self) -> Option<bool> {
        match self.0.load(Ordering::Relaxed) {
            Self::YES => Some(true),
            Self::NO => Some(false),
            _ => None,
        }
    }

    /// Whether a session opening now should ask.
    ///
    /// Separate from [`get`](Self::get) because "do not know" and "do not ask"
    /// are different: after one unanswered probe the answer is still unknown
    /// and asking again is right.
    fn should_probe(&self) -> bool {
        self.0.load(Ordering::Relaxed) != Self::NO
    }

    /// The peer answered an open it understood. **Sticky**: nothing downgrades
    /// a peer that has proven itself.
    fn learn_takes(&self) {
        self.0.store(Self::YES, Ordering::Relaxed);
    }

    /// What an arriving open's kind said outright. Definitive both ways.
    fn learn_told(&self, takes: bool) {
        self.0.store(
            if takes { Self::YES } else { Self::NO },
            Ordering::Relaxed,
        );
    }

    /// A probe went unanswered. Counts once, then latches.
    ///
    /// Relaxed ordering. Two sessions probing at once may both report a failure
    /// and latch a state apart from where a stricter ordering would have left
    /// it; the outcomes either way are "ask again" or "stop asking", and both
    /// are safe.
    fn learn_unanswered(&self) {
        // **One step per call, and the first version of this took two.** Two
        // `compare_exchange`es in sequence both succeed on the same call --
        // `UNKNOWN` becomes `REFUSED_ONCE` and then immediately `NO` -- which
        // latched on the first failure and threw away the whole point of the
        // extra state. The test for "remembered but not believed" is what
        // caught it.
        let step = match self.0.load(Ordering::Relaxed) {
            Self::UNKNOWN => (Self::UNKNOWN, Self::REFUSED_ONCE),
            Self::REFUSED_ONCE => (Self::REFUSED_ONCE, Self::NO),
            // `YES` is sticky and `NO` is already settled.
            _ => return,
        };
        let _ = self
            .0
            .compare_exchange(step.0, step.1, Ordering::Relaxed, Ordering::Relaxed);
    }
}

/// Enough for the largest UDP payload there is (65507 bytes).
///
/// **Deliberately larger than [`MAX_PAYLOAD`]**: `recv` on a UDP socket
/// truncates to the buffer and says nothing about it, so a buffer sized to what
/// can be forwarded would turn "too large, dropped and counted" into "silently
/// cut short" — the exact failure [`crate::datagram`] exists to prevent.
pub(crate) const RECV_BUFFER: usize = 65_536;

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
    /// Whether the peer receives oversize datagrams on unidirectional streams.
    ///
    /// **Per connection, not per session**, which is what keeps §5.2's fallback
    /// to one round trip: the capability is a property of the peer's build, so
    /// the first session that finds out pays and the rest read it.
    peer_oversize: PeerOversize,
    /// Oversize datagrams waiting for a stream.
    ///
    /// **A channel because [`send`](Self::send) cannot wait.** Opening a stream
    /// is `async` and `send` is called from the loop reading a local socket: a
    /// send that waited would stop that loop, the kernel's buffer would
    /// overflow, and **the small datagrams would be lost by the machinery for
    /// carrying large ones**. So the handoff is a `try_send` and a full channel
    /// is a counted drop.
    big_sends: tokio::sync::mpsc::Sender<BigSend>,
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
        let (big_sends, big_waiting) = tokio::sync::mpsc::channel(BIG_SENDS_WAITING);
        let sessions = Arc::new(Self {
            conn,
            table: Mutex::new(HashMap::new()),
            // 1, so that a session id of zero in a log is always a bug rather
            // than the first session anyone opened.
            next: AtomicU32::new(1),
            idle,
            drops: Drops::default(),
            peer_oversize: PeerOversize::default(),
            big_sends,
            open_failures: AtomicU64::new(0),
        });
        tokio::spawn({
            // **`Arc::downgrade`, and the first version of this leaked for
            // want of it.** The channel's only `Sender` is the `big_sends`
            // field *inside* `Sessions`, so a pump holding a strong handle
            // keeps alive the thing that keeps the channel open: `recv` could
            // never return `None` and the task outlived every connection it
            // was spawned for, each one holding a `Connection` clone. `serve`
            // is handed the server-wide token, so cancellation does not come
            // when one client leaves.
            let sessions = Arc::downgrade(&sessions);
            let shutdown = shutdown.clone();
            async move { Sessions::pump_big_sends(sessions, big_waiting, shutdown).await }
        });
        tokio::spawn({
            let sessions = Arc::clone(&sessions);
            let shutdown = shutdown.clone();
            async move { sessions.pump_streams(shutdown).await }
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

    /// The largest payload that can leave on *this* connection.
    ///
    /// **Asked before anything is queued**, because the byte bound made
    /// queueing the unsendable expensive: a payload over this is dropped
    /// whatever happens, and under `datagram::QUEUE_BYTES` a 64 KB one takes
    /// half a session's budget on the way to being dropped, evicting the small
    /// datagrams waiting behind it.
    ///
    /// `None` from [`peer_takes_oversize`](Self::peer_takes_oversize) is
    /// treated as yes. The first session open settles it, and being generous
    /// while the answer is unknown costs at most one dropped datagram, where
    /// being strict would refuse what the connection turns out to carry.
    pub fn sendable_payload(&self) -> usize {
        sendable_payload(self.peer_takes_oversize())
    }

    /// Whether the peer takes oversize datagrams on unidirectional streams, or
    /// `None` if no session has found out yet.
    pub fn peer_takes_oversize(&self) -> Option<bool> {
        self.peer_oversize.get()
    }

    /// What the **kind an open arrived with** says about the opener, which is
    /// told rather than inferred — so either answer is definitive, unlike the
    /// opener's side where only a `yes` is.
    ///
    /// A correct peer asks the same way on every session of a connection, so
    /// the two answers never arrive on one [`Sessions`]; and the two roles do
    /// not share one either — a server only answers and a client only opens.
    pub(crate) fn learn_peer_told_oversize(&self, takes: bool) {
        self.peer_oversize.learn_told(takes);
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
                stream_malformed = self.drops.stream_malformed.load(Ordering::Relaxed),
                stream_too_big = self.drops.stream_too_big.load(Ordering::Relaxed),
                stream_lost = self.drops.stream_lost.load(Ordering::Relaxed),
                stream_blocked = self.drops.stream_blocked.load(Ordering::Relaxed),
                stream_cancelled = self.drops.stream_cancelled.load(Ordering::Relaxed),
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

    /// Accept unidirectional streams and read one oversize datagram from each.
    ///
    /// **A second loop rather than an arm of [`pump`](Self::pump)**: reading a
    /// stream takes many polls and a whole datagram has to be assembled before
    /// any of it can be delivered, so doing it inline would let one 64 KB
    /// arrival hold up every datagram on the connection — which is the
    /// head-of-line objection `crate::datagram`'s header raises against
    /// streams, reintroduced in the one place it would really bite.
    ///
    /// **Everything accepted is read.** Declining to accept does not save
    /// memory: MsQuic has already created the stream and granted its receive
    /// window, and an unaccepted one sits in an unbounded queue inside
    /// `msquic-async`. So the bound is the transport's `PeerUnidiStreamCount`
    /// (100, `isekai-p2p::peer`), which with [`MAX_STREAM_PAYLOAD`] is 6.4 MB
    /// in flight for one connection. Lowering that is a transport setting, not
    /// something this loop can do.
    async fn pump_streams(self: Arc<Self>, shutdown: CancellationToken) {
        loop {
            let accepted = tokio::select! {
                _ = shutdown.cancelled() => break,
                accepted = std::future::poll_fn(|cx| {
                    self.conn.poll_accept_inbound_uni_stream(cx)
                }) => accepted,
            };
            match accepted {
                Ok(stream) => {
                    let sessions = Arc::clone(&self);
                    let shutdown = shutdown.clone();
                    tokio::spawn(async move {
                        sessions.read_big_datagram(stream, shutdown).await;
                    });
                }
                // The connection ending is how this is meant to finish.
                Err(e) => {
                    tracing::debug!("no longer accepting portal streams: {e}");
                    break;
                }
            }
        }
    }

    /// Give each waiting oversize datagram a stream of its own.
    ///
    /// **One task per datagram**, so a slow stream does not hold up the ones
    /// behind it. That is the price of "one datagram per stream", paid here;
    /// what it buys is the thing the whole design rests on — streams are
    /// unordered with respect to each other, so a retransmit of one datagram
    /// never waits on another.
    async fn pump_big_sends(
        sessions: std::sync::Weak<Self>,
        mut waiting: tokio::sync::mpsc::Receiver<BigSend>,
        shutdown: CancellationToken,
    ) {
        loop {
            let next = tokio::select! {
                _ = shutdown.cancelled() => break,
                next = waiting.recv() => next,
            };
            // `None` once every `Sessions` handle has gone, which drops the
            // `Sender` this task deliberately does not hold — see the
            // `downgrade` in `start_with_idle`. This is the ordinary end for a
            // connection whose client left without the server shutting down.
            let Some(send) = next else { break };
            // Taken for this datagram only. Gone already means the connection
            // went between the queueing and here, and there is nothing to send
            // it on.
            let Some(sessions) = sessions.upgrade() else { break };
            let shutdown = shutdown.clone();
            tokio::spawn(async move { sessions.write_big_datagram(send, shutdown).await });
        }
    }

    /// Put one oversize datagram on a unidirectional stream.
    async fn write_big_datagram(&self, send: BigSend, shutdown: CancellationToken) {
        let BigSend {
            session,
            payload,
            no_retrans,
        } = send;
        // **`fail_on_blocked`, so this never waits for a stream.** The
        // transport allows a hundred at once; past that, dropping and counting
        // is the same answer the queue gives when it is full, and waiting here
        // would hold a payload indefinitely for a datagram the application has
        // long since given up on.
        let opening = self
            .conn
            .open_outbound_stream(msquic_async::StreamType::Unidirectional, true);
        let mut stream = match tokio::select! {
            _ = shutdown.cancelled() => return,
            opened = opening => opened,
        } {
            Ok(stream) => stream,
            Err(e) => {
                if self.drops.stream_blocked.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!(
                        session,
                        "no stream was available for an oversize datagram: {e}; \
                         further ones on this connection are counted, not logged",
                    );
                } else {
                    tracing::debug!(session, "another oversize datagram found no stream: {e}");
                }
                return;
            }
        };

        // Two chunks and one call: the head and the payload go out together,
        // with the FIN, and nothing is copied to join them.
        let chunks = [
            Bytes::copy_from_slice(&crate::frame::big_datagram_head(session)),
            payload,
        ];
        let written = if no_retrans {
            stream.write_chunks_no_retrans(&chunks, true).await
        } else {
            stream.write_chunks(&chunks, true).await
        };
        if let Err(e) = written {
            self.drops.unsent.fetch_add(1, Ordering::Relaxed);
            tracing::debug!(session, "an oversize datagram was not written: {e}");
            return;
        }

        // **The write returning is not the datagram leaving.** MsQuic resolves
        // it when it accepts the request, and dropping a stream short of
        // `ShutdownComplete` aborts it -- so ending here would reset almost
        // every oversize datagram. `camera_core::video::push_one` and
        // `server::refuse` both say the same thing about their own writes.
        let finished = tokio::select! {
            // Cancellation is a teardown, not a loss: the connection is going
            // and the counters are about to be reported.
            _ = shutdown.cancelled() => return,
            finished = std::future::poll_fn(|cx| stream.poll_finish_write(cx)) => finished,
        };
        match finished {
            Ok(()) => {}
            // **What `no-retrans` asked for.** The stream met loss and was
            // abandoned rather than retransmitted, which is only reachable for
            // a forward that chose it.
            Err(msquic_async::WriteError::CancelledOnLoss) => {
                self.drops.stream_cancelled.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    session,
                    "an oversize datagram was given up on rather than retransmitted",
                );
            }
            Err(e) => {
                self.drops.unsent.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(session, "an oversize datagram did not finish: {e}");
            }
        }
    }

    /// Read one oversize datagram from `stream` and hand it to its session.
    ///
    /// Assembled whole before it is delivered, because a datagram is
    /// indivisible — there is nothing partial to pass on.
    ///
    /// **Both bounds are load-bearing, and neither was here at first.** A read
    /// parks until the peer finishes, resets, or the connection dies, and none
    /// of those is `shutdown`:
    ///
    /// - **`shutdown`**, because this task holds an `Arc<Sessions>` and so a
    ///   `Connection` clone, which is a handle `RegistrationClose` blocks on —
    ///   the hazard `start_with_idle` and `session::Connected::close` both
    ///   describe. A peer that writes the head and then stops left `close`
    ///   cancelling, dropping its handles, and timing out its five-second
    ///   drain.
    /// - **A deadline**, because a peer can hold a stream without the
    ///   connection being in any trouble, and the transport allows a hundred of
    ///   them: without one, a peer that stalls them all stops every oversize
    ///   datagram on the connection and nothing ever says why. [`Sessions`]'s
    ///   own `idle` is the bound used, which is generous for any real link
    ///   (65507 bytes needs under a second on anything that is working) and is
    ///   already a parameter so a test need not wait a minute for it.
    async fn read_big_datagram(
        &self,
        mut stream: msquic_async::ReadStream,
        shutdown: CancellationToken,
    ) {
        let read = tokio::select! {
            _ = shutdown.cancelled() => return,
            _ = tokio::time::sleep(self.idle) => {
                self.drops.stream_lost.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    after = ?self.idle,
                    "an oversize datagram's stream did not finish in time; dropped",
                );
                return;
            }
            read = self.assemble_big_datagram(&mut stream) => read,
        };
        let Some((session, payload)) = read else {
            return;
        };
        self.deliver_payload(session, payload);
    }

    /// The read itself, so [`read_big_datagram`](Self::read_big_datagram) can
    /// wrap it in a `select!` and keep the bounds in one place.
    ///
    /// `None` when nothing is deliverable; by then it has been counted.
    async fn assemble_big_datagram(
        &self,
        stream: &mut msquic_async::ReadStream,
    ) -> Option<(u32, Bytes)> {
        let session = match crate::frame::read_big_datagram_head(stream).await {
            Ok(session) => session,
            Err(e) => {
                if self.drops.stream_malformed.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!(
                        "a stream did not carry an oversize datagram: {e:#}; \
                         further ones on this connection are counted, not logged",
                    );
                } else {
                    tracing::debug!("another stream did not carry one: {e:#}");
                }
                return None;
            }
        };
        // **One byte past the cap, deliberately.** Reading exactly the cap
        // cannot tell a payload at the limit from one over it, and the
        // difference decides whether this is delivered or counted.
        let mut payload = Vec::new();
        let read = tokio::io::AsyncReadExt::read_to_end(
            &mut tokio::io::AsyncReadExt::take(stream, MAX_STREAM_PAYLOAD as u64 + 1),
            &mut payload,
        )
        .await;
        match read {
            Ok(_) if payload.len() > MAX_STREAM_PAYLOAD => {
                self.drops.stream_too_big.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    session,
                    limit = MAX_STREAM_PAYLOAD,
                    "an oversize datagram was larger than UDP allows; dropped",
                );
                None
            }
            Ok(_) => Some((session, Bytes::from(payload))),
            // **Ordinary as well as a fault.** A sender that asked not to have
            // its data retransmitted has its stream aborted on the first
            // detected loss, and this is what that looks like from here.
            Err(e) => {
                self.drops.stream_lost.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(
                    session,
                    "an oversize datagram's stream ended before its end: {e}",
                );
                None
            }
        }
    }

    fn deliver(&self, datagram: Bytes) {
        let Some((id, payload)) = decode(&datagram) else {
            self.drops.malformed.fetch_add(1, Ordering::Relaxed);
            return;
        };
        self.deliver_payload(id, payload);
    }

    /// Hand one assembled payload to its session.
    ///
    /// **The two carriers meet here and nowhere else.** A datagram arrives with
    /// its session id in a four-byte header and a stream arrives with the same
    /// id in a six-byte one; past this point there is one queue, one bound and
    /// one set of counters, which is what keeps the second carrier from being a
    /// second pipeline.
    fn deliver_payload(&self, id: u32, payload: Bytes) {
        let queue = self
            .table
            .lock()
            .expect("session table poisoned")
            .get(&id)
            .cloned();
        match queue.map(|queue| queue.push(payload)) {
            Some(Push::Queued) => {}
            // **Counted by how many, not by how often.** One oversize arrival
            // can displace several small ones, and `overflow` is meant to say
            // how much was lost.
            Some(Push::Evicted(dropped)) => {
                self.drops
                    .overflow
                    .fetch_add(dropped as u64, Ordering::Relaxed);
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
    /// nothing for a datagram to wait for — and **the stream carrier keeps that
    /// property** by handing over to a task rather than opening a stream here.
    ///
    /// `no_retrans` comes from the forward's `--map` and only reaches the
    /// stream carrier; a DATAGRAM frame is never retransmitted anyway.
    fn send(&self, session: u32, payload: &[u8], no_retrans: bool) -> bool {
        let Some(framed) = encode(session, payload) else {
            // **Too large for a datagram is no longer the end of it.** Over
            // `MAX_PAYLOAD` goes on a stream of its own if the peer takes them,
            // and is dropped as before if it does not.
            return self.send_on_stream(session, payload, no_retrans);
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

    /// Hand an oversize payload to the stream carrier.
    ///
    /// **A `try_send` and nothing else.** Everything that could wait — opening
    /// the stream, writing it, waiting for the FIN to be acknowledged — happens
    /// in `pump_big_sends`, because the caller is a loop reading a local socket
    /// and a send that waits there loses the small datagrams too.
    fn send_on_stream(&self, session: u32, payload: &[u8], no_retrans: bool) -> bool {
        if self.peer_takes_oversize() == Some(false) {
            self.oversize(Some(session), payload.len());
            return false;
        }
        let send = BigSend {
            session,
            payload: Bytes::copy_from_slice(payload),
            no_retrans,
        };
        match self.big_sends.try_send(send) {
            Ok(()) => true,
            Err(_) => {
                // Full, or the pump has gone with the connection. Either way
                // this one is not going out, and the counter says which kind of
                // behind this end is.
                if self.drops.stream_blocked.fetch_add(1, Ordering::Relaxed) == 0 {
                    tracing::warn!(
                        session,
                        waiting = BIG_SENDS_WAITING,
                        "too many oversize datagrams at once; one was dropped. \
                         Further ones on this connection are counted, not logged",
                    );
                } else {
                    tracing::debug!(session, "another oversize datagram found no room");
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
    /// `session` is `None` when the payload was refused before a session
    /// existed — at the local read, where the size is already known.
    /// **Not zero standing in for it**: a session id of zero in a log is meant
    /// to be a bug, which is what `next` starting at 1 is for.
    fn oversize(&self, session: Option<u32>, len: usize) {
        if self.drops.oversize.fetch_add(1, Ordering::Relaxed) == 0 {
            // **One reason, now that there is only one.** This used to pick
            // between three -- this build not carrying them, the peer not
            // taking them, this build not sending them -- and S3 made two of
            // those untrue. Both callers reach here only when
            // `peer_takes_oversize()` is `Some(false)`: `send_on_stream`
            // checks it, and `forward` compares against `sendable_payload`,
            // which is `MAX_STREAM_PAYLOAD` in every other state and above
            // what a local `recv` can produce.
            //
            // Keeping the dead arms would have left two sentences pointing an
            // operator at the wrong end, beside a `limit` that was wrong for
            // them as well.
            tracing::warn!(
                ?session,
                len,
                limit = MAX_PAYLOAD,
                "a UDP payload is too large to forward and was dropped: the peer does \
                 not receive oversize datagrams on streams; further ones on this \
                 connection are counted, not logged",
            );
        } else {
            tracing::debug!(?session, len, "another oversize UDP payload dropped");
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
    // From the opener's `--map`, carried on the open frame, for every reply on
    // this session.
    no_retrans: bool,
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
                // **The opener's choice, carried on the open frame.** This end
                // has no `--map` -- it has a catalogue -- so the only way for a
                // reply to honour what was asked for is for the request to have
                // said it. Before that it always retransmitted, which did half
                // of what `no-retrans` means.
                Ok(n) => { sessions.send(id, &buf[..n], no_retrans); }
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
    no_retrans: bool,
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
            // **Refused here rather than at the send.** A payload over
            // `sendable_payload` is dropped whatever happens, and queueing one
            // first used to cost a 64th of the depth -- under `QUEUE_BYTES` a
            // 64 KB payload that can never leave takes half the session's
            // budget and evicts the small datagrams waiting behind it. The
            // counter is the same one `Sessions::send` would have reached;
            // what changes is that the budget stays for traffic that can go.
            // **Asked of the connection, not of a constant.** What can leave
            // depends on whether the peer takes oversize datagrams on streams,
            // and refusing here is what keeps a payload that cannot leave from
            // spending a session's byte budget on the way to being dropped.
            if n > sessions.sendable_payload() {
                sessions.oversize(None, n);
                continue;
            }
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
                    Push::Evicted(dropped) => {
                        sessions
                            .drops
                            .overflow
                            .fetch_add(dropped as u64, Ordering::Relaxed);
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
                no_retrans,
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
    no_retrans: bool,
    from: SocketAddr,
    socket: Arc<UdpSocket>,
    inbound: Arc<Queue>,
    outbound: Arc<Queue>,
    sources: Sources,
    shutdown: CancellationToken,
) {
    if let Err(e) = run_session(
        &sessions, id, &service, no_retrans, from, &socket, &inbound, &outbound, &shutdown,
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

/// Open one UDP session and come back with its lifetime stream.
///
/// **Asks for oversize-on-stream when this build can receive it**, and learns
/// from the answer. `docs/portal_oversize_udp_plan.md` §5.2: a peer that does
/// not know [`KIND_UDP_BIG`](crate::frame) refuses that one open, so the cost
/// of asking is a session rather than a forward. A version bump would have cost
/// every open on the connection, TCP included.
///
/// **It does not re-ask in the same session, and that is deliberate.** The open
/// frame carries the id, the answerer takes the id *before* it writes a status
/// (`serve`), and the id belongs to the caller — so a second attempt under the
/// same id would meet `Accept::InUse` and come back as `Status::Refused`,
/// reported as "the peer does not offer this service". A wrong answer stated
/// with authority is worse than a lost session: this returns the real failure,
/// remembers it, and the next datagram opens a fresh session under a fresh id
/// that does not ask. The cost is **one lost session per connection** on first
/// contact with a peer that lacks the feature.
async fn open_session(
    sessions: &Arc<Sessions>,
    id: u32,
    service: &str,
    no_retrans: bool,
) -> anyhow::Result<msquic_async::Stream> {
    let probe = crate::frame::RECEIVES_OVERSIZE_ON_STREAM && sessions.peer_oversize.should_probe();
    let mut stream = sessions
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .context("failed to open the session's stream")?;
    // **Everything above says nothing about the kind.** A connection that is
    // gone, or a stream limit reached, would fail the same way for a plain
    // open, so a failure there must not be read as an answer about
    // `KIND_UDP_BIG` -- hence the probe's inference starts only below.
    write_open(
        &mut stream,
        &Open::Udp {
            service: service.to_owned(),
            session: id,
            // The capability and the choice travel together: the options are
            // meaningless without it, which is why the type nests them.
            oversize: probe.then_some(crate::frame::OversizeOptions { no_retrans }),
        },
    )
    .await?;
    // Waited for before any payload moves, as the TCP forward does: a session
    // whose datagrams left before the status arrived would be sending into a
    // connection whose far side has no socket for them.
    let status = tokio::time::timeout(crate::client::STATUS_DEADLINE, read_status(&mut stream))
        .await
        .map_err(|_| anyhow::anyhow!("`{service}` did not answer the open request in time"));
    let status = match status.and_then(|read| read) {
        Ok(status) => status,
        Err(e) => {
            if probe {
                // Inferred, not told. The peer never said why, and the kind is
                // the likeliest reason but not the only one -- which is why one
                // of these is remembered and the second decides.
                sessions.peer_oversize.learn_unanswered();
                tracing::debug!(
                    service,
                    id,
                    "an oversize-capable open went unanswered ({e:#}); \
                     a later session will not ask",
                );
            }
            return Err(e);
        }
    };
    // **A status of any value proves the peer read the kind.** So a `Refused`
    // is about the service, and treating it as evidence against the kind would
    // turn a configuration mistake into a permanent loss of the feature.
    if probe {
        sessions.peer_oversize.learn_takes();
    }
    match status {
        Status::Ready => Ok(stream),
        Status::Refused => anyhow::bail!("the peer does not offer `{service}` over UDP"),
        Status::Unreachable => anyhow::bail!("the peer could not reach `{service}`"),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_session(
    sessions: &Arc<Sessions>,
    id: u32,
    service: &str,
    no_retrans: bool,
    from: SocketAddr,
    socket: &UdpSocket,
    inbound: &Queue,
    outbound: &Queue,
    shutdown: &CancellationToken,
) -> anyhow::Result<()> {
    let mut stream = open_session(sessions, id, service, no_retrans).await?;
    tracing::debug!(%from, service, id, "a UDP session opened");

    let mut unexpected = [0_u8; 1];
    let ended = loop {
        tokio::select! {
            _ = shutdown.cancelled() => break "the client is leaving".to_owned(),
            // From the application, out to the peer.
            payload = outbound.pop() => match payload {
                Some(payload) => { sessions.send(id, &payload, no_retrans); }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_peer_is_unknown_until_a_session_finds_out() {
        let seen = PeerOversize::default();
        assert_eq!(seen.get(), None);
        assert!(seen.should_probe(), "and worth asking");
    }

    #[test]
    fn an_answered_probe_settles_it() {
        let seen = PeerOversize::default();
        seen.learn_takes();
        assert_eq!(seen.get(), Some(true));
    }

    /// **One unanswered probe is not an answer.** It could be the kind, and it
    /// could be a reset, a stream limit or a stall -- none of which say
    /// anything about what the peer understands. So the state moves but the
    /// conclusion does not, and the next session asks again.
    #[test]
    fn one_unanswered_probe_is_remembered_but_not_believed() {
        let seen = PeerOversize::default();
        seen.learn_unanswered();
        assert_eq!(seen.get(), None, "still unknown");
        assert!(seen.should_probe(), "so ask again");
    }

    /// **The second decides.** Never latching would pay a lost session on every
    /// session against a peer that simply does not have the feature.
    #[test]
    fn two_unanswered_probes_stop_the_asking() {
        let seen = PeerOversize::default();
        seen.learn_unanswered();
        seen.learn_unanswered();
        assert_eq!(seen.get(), Some(false));
        assert!(!seen.should_probe());
    }

    /// A peer that has proven itself is not downgraded by a bad moment
    /// afterwards, because a `no` on this side is only ever inferred.
    #[test]
    fn a_proven_peer_survives_later_trouble() {
        let seen = PeerOversize::default();
        seen.learn_takes();
        seen.learn_unanswered();
        seen.learn_unanswered();
        assert_eq!(seen.get(), Some(true), "still yes");
    }

    /// **The pump has to end without being cancelled.** `serve` is handed the
    /// server-wide token, so a client leaving cancels nothing — the channel
    /// closing is the only signal, and it only arrives because this task holds
    /// a `Weak` rather than the `Arc` it was first written with. With a strong
    /// handle it kept alive the `Sessions` that owns the only `Sender`, so
    /// `recv` could never return `None` and one task plus one `Connection`
    /// clone stayed for the life of the server, per connection.
    #[tokio::test]
    async fn the_send_pump_ends_when_the_sessions_go() {
        let (big_sends, waiting) = tokio::sync::mpsc::channel(1);
        // As dropping `Sessions` does, since the field is the only sender.
        drop(big_sends);
        tokio::time::timeout(
            Duration::from_secs(1),
            Sessions::pump_big_sends(std::sync::Weak::new(), waiting, CancellationToken::new()),
        )
        .await
        .expect("the pump returned rather than parking");
    }

    /// **Generous while the answer is unknown**, and the asymmetry is the
    /// point: the first session open settles it, so being generous costs at
    /// most one dropped datagram, while being strict would refuse what the
    /// connection turns out to carry for as long as nobody has asked.
    #[test]
    fn what_can_leave_depends_on_the_peer() {
        assert_eq!(sendable_payload(Some(true)), MAX_STREAM_PAYLOAD);
        assert_eq!(sendable_payload(None), MAX_STREAM_PAYLOAD, "generous");
        assert_eq!(
            sendable_payload(Some(false)),
            MAX_PAYLOAD,
            "a peer from before this existed takes the datagram carrier only",
        );
    }

    /// The answerer's side is told rather than inferring, so both answers are
    /// definitive there.
    #[test]
    fn what_a_kind_says_outright_is_taken_either_way() {
        let no = PeerOversize::default();
        no.learn_told(false);
        assert_eq!(no.get(), Some(false));

        let yes = PeerOversize::default();
        yes.learn_told(true);
        assert_eq!(yes.get(), Some(true));
    }
}
