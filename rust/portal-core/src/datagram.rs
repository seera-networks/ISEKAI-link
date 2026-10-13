//! UDP over QUIC datagrams: the wire, the size limit, and the queue.
//!
//! **Phase 3a of `docs/portal_plan.md` §4.1.** A UDP forward is datagrams
//! keyed by a session id:
//!
//! ```text
//! [ session u32 ][ payload ]
//! ```
//!
//! Datagrams rather than an unreliable stream because UDP's own semantics are
//! datagram semantics — losing one is allowed, reordering is allowed, and a
//! stream would add head-of-line blocking the application does not expect.
//!
//! What is here is the part with no sockets in it, which is also the part the
//! plan says will bite: the size bound and the queue bound. The sockets, the
//! session table and the idle sweep are [`crate::udp`].
//!
//! # Where a session id comes from
//!
//! **The datagram header is only an id, and that is deliberate**: it says which
//! session a payload belongs to and nothing else, because at this size every
//! byte is one the payload does not get.
//!
//! So the binding from id to service is made on a stream, not here. A UDP
//! forward opens one, sends [`crate::frame::Open::Udp`] with the service name
//! and the id the client allocated, and reads a status — after which the stream
//! is the session's lifetime handle and the datagrams carry the id alone.
//! Closing it ends the session; an id that arrives without one has no service
//! to belong to and is counted [`Drops::unknown_session`].
//!
//! That is also why there is no version byte here when [`crate::frame`] has
//! one: the version was agreed on the stream that opened the session, and
//! paying for it again in every datagram would buy nothing.
//!
//! 3b built that exchange as described, which is what the shape being settled
//! ahead of it was for.
//!
//! # Neither bound may be silent
//!
//! A datagram service that quietly truncates is worse than one that quietly
//! loses, because the application cannot tell. So an oversize payload is
//! **dropped, never split**, and both drops are counted where an operator can
//! see them.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use bytes::{BufMut, Bytes, BytesMut};
use tokio::sync::Notify;

/// Bytes of framing before the payload: the session id.
pub const HEADER: usize = 4;

/// The largest UDP payload this will carry, and why that number.
///
/// **Derived, not chosen.** [`isekai_p2p::peer::GUARANTEED_DATAGRAM`] is what a
/// peer connection promises to take — 1248 less IPv6 and UDP headers, less the
/// QUIC packet and DATAGRAM frame overhead, all of it measured and written down
/// there — and this is that, less the four bytes [`HEADER`] spends on the
/// session id. Nothing here is a round number somebody picked.
///
/// ```text
///   PEER_MTU                     1248
///   - IPv6 + UDP headers          -48    IPv4 has 20 spare; not offered
///   - QUIC packet + DATAGRAM      -33    measured
///   = guaranteed datagram        1167
///   - portal's [u32 session]       -4
///   = MAX_PAYLOAD                1163
/// ```
///
/// **This is a floor and the connection's own limit is usually higher.** msquic
/// reports a per-connection maximum that is 20 bytes larger on an IPv4 path,
/// and today every relay path is IPv4 — the inner connection's relay leg is the
/// local end of the MASQUE tunnel, so it dials 127.0.0.1. Sizing to that would
/// mean a forward that works over the relay and loses its large datagrams the
/// moment it moves onto an IPv6 direct path, which is the failure this number
/// exists to not have.
///
/// **It was 1180 and that was 17 too much.** A payload of 1164..=1180 was
/// accepted here and refused by the connection on any IPv6 path; it never bit
/// because the relay leg is IPv4. `docs/portal_mtu_plan.md` §6.2 has the
/// measurement.
///
/// **The runtime value is watched rather than adopted.**
/// `ConnectionEvent::DatagramStateChanged` carries the real `max_send_length`,
/// and [`crate::path`] compares it against this constant on every connection:
/// below it is a warning, because payloads between the two would be accepted
/// here and refused by the connection.
///
/// It is not *raised* to match. This number is a promise `docs/portal.md` makes
/// to whoever runs a forward, and msquic's limit moves with the path — following
/// it would leave a DNS forward working from one place and silently losing
/// responses from another, which is worse than a bound that is the same
/// everywhere and slightly low. Raising the floor is what the MTU plan's
/// contract B is for, and it raises it by making the connection keep its word
/// rather than by trusting a number that can fall.
///
/// The event's other half, `send_enabled`, is why a peer that will not receive
/// datagrams at all is now said once at connect time rather than as one
/// `Denied` per datagram — which is how phase 3a's bug hid.
///
/// # What this rules out, said plainly
///
/// **A UDP payload over 1163 bytes cannot cross a portal forward today**, and
/// raising this constant does not change that — the true limit is the peer
/// connection's. Splitting is not an option either; `portal_plan.md` §4.1 is
/// explicit that a datagram service which silently splits is worse than one
/// which silently loses.
///
/// The case to know about is DNS: EDNS0 commonly advertises a 1232-byte buffer,
/// so a large response can exceed this and be dropped — with no truncation bit
/// and no ICMP, which leaves a stub resolver waiting for a timeout instead of
/// retrying over TCP. A resolver configured for a smaller buffer, or one that
/// falls back on timeout, is fine.
pub const MAX_PAYLOAD: usize = isekai_p2p::peer::GUARANTEED_DATAGRAM - HEADER;

/// How many datagrams a session may hold before the oldest is dropped.
///
/// **Streams have flow control and datagrams have none**, so something has to
/// bound this or a peer that sends faster than the target reads is a memory
/// leak wearing a queue's name.
///
/// The oldest goes rather than the newest: for the protocols that use UDP, a
/// datagram that has been waiting is usually the one that has already been
/// retried or superseded, and dropping the arrival would make a burst look like
/// a dead path.
pub const QUEUE_DEPTH: usize = 64;

/// How many **bytes** a session may hold before the oldest is dropped.
///
/// **[`QUEUE_DEPTH`] alone stopped bounding memory** the moment a queued
/// datagram could be larger than [`MAX_PAYLOAD`]. Sixty-four entries was
/// chosen when an entry was at most 1163 bytes — 74 KB a session — and
/// 64 × 65507 is 4.19 MB, which at [`crate::udp::MAX_SESSIONS`] puts one
/// connection's table near 4.3 GB. A count is not a memory bound once the
/// items vary by fifty-six times.
///
/// 128 KB, which is a little over the 74 KB the depth already allowed, so
/// nothing that works today starts dropping — and 131 MB rather than 4.3 GB
/// for a full table. At the maximum datagram size the effective depth is
/// **two**, which is the right shape: this queue exists so a burst survives a
/// slow reader, not so a session can bank megabytes.
pub const QUEUE_BYTES: usize = 128 * 1024;

/// The largest UDP payload a unidirectional stream will carry: the largest
/// there is.
///
/// **No portal-specific limit.** Cutting it at 8 or 16 KB would replace
/// "portal carries 1163 bytes" with "portal carries 16384", which is the same
/// conversation a second time. Memory is bounded by [`QUEUE_BYTES`] and by how
/// many streams the transport allows at once, both of which hold whatever the
/// size is.
pub const MAX_STREAM_PAYLOAD: usize = 65_507;

/// The largest payload this build can actually put on the wire.
///
/// **[`MAX_PAYLOAD`] until S3**, which adds the stream carrier and makes this
/// [`MAX_STREAM_PAYLOAD`]. One name for it, because two places need the same
/// answer and they would otherwise drift: the queue refuses what cannot leave,
/// and the send path counts what it was handed anyway.
///
/// It exists because of what the byte bound changed. A payload over this is
/// dropped at [`crate::udp::Sessions::send`] whatever happens, and queueing one
/// first used to cost a 64th of the depth; under [`QUEUE_BYTES`] a 64 KB
/// payload that can never leave takes **half the session's budget** and evicts
/// the small datagrams behind it. So the refusal moved to where the size is
/// first known.
pub const SENDABLE_PAYLOAD: usize = MAX_PAYLOAD;

/// One datagram must always fit after the queue is emptied, or [`Queue::push`]
/// would evict everything and still exceed the bound.
///
/// Checked here rather than guarded at runtime: it is a property of constants,
/// so a build that breaks it should not compile.
///
/// **Both carriers, and the first version of this named only one.** The largest
/// thing [`Queue::push`] can be handed is not [`MAX_STREAM_PAYLOAD`]: a local
/// socket read fills [`crate::udp::RECV_BUFFER`] bytes (65536, twenty-nine more
/// than UDP's own maximum, because a read that truncates says nothing about
/// it). Asserting the smaller of the two held only because both are far under
/// 128 KB — a `QUEUE_BYTES` between them would have compiled with the promise
/// above false.
const _: () = assert!(MAX_STREAM_PAYLOAD <= QUEUE_BYTES);
const _: () = assert!(crate::udp::RECV_BUFFER <= QUEUE_BYTES);

/// Frame `payload` for `session`, or `None` if it will not fit.
///
/// `None` rather than a truncated datagram, and the caller counts it — see the
/// module header.
pub fn encode(session: u32, payload: &[u8]) -> Option<Bytes> {
    if payload.len() > MAX_PAYLOAD {
        return None;
    }
    let mut framed = BytesMut::with_capacity(HEADER + payload.len());
    framed.put_u32(session);
    framed.put_slice(payload);
    Some(framed.freeze())
}

/// Split a datagram into its session id and payload.
///
/// `None` for anything too short to be one. A datagram with a session nobody
/// knows is *not* an error here — that is the table's answer, and it happens
/// legitimately when a session is swept while the peer is still sending.
pub fn decode(datagram: &Bytes) -> Option<(u32, Bytes)> {
    if datagram.len() < HEADER {
        return None;
    }
    let session = u32::from_be_bytes(datagram[..HEADER].try_into().expect("checked"));
    Some((session, datagram.slice(HEADER..)))
}

/// What was dropped and why, for the operator.
///
/// Plain atomics rather than methods: [`crate::udp`] increments the one that
/// applies, and there is nothing here worth hiding behind a setter. Two of them
/// are the plan's; the rest exist because the alternative to counting a drop is
/// a service that loses data silently.
#[derive(Debug, Default)]
pub struct Drops {
    /// Payloads larger than [`MAX_PAYLOAD`], which is the size this promises to
    /// carry — so these are the application's, and no path will fix them.
    pub oversize: AtomicU64,
    /// Payloads within [`MAX_PAYLOAD`] that the connection refused as too big.
    ///
    /// **Separate from `oversize`, and the difference is who has to act.** That
    /// one says the application sent something larger than portal ever offered.
    /// This one says portal offered it and the connection would not take it,
    /// which means the path underneath is narrower than [`MAX_PAYLOAD`]
    /// assumes — a floor derived from `PEER_MTU` and the worst-case IP header,
    /// so a path under it is a surprise worth being able to see.
    ///
    /// Counted together they were indistinguishable, and the two lead
    /// different places: one to the caller's message size, one to the
    /// connection.
    pub refused_too_big: AtomicU64,
    /// Datagrams discarded because a session's queue was full.
    pub overflow: AtomicU64,
    /// Datagrams with nowhere to go: a session that was swept while the peer
    /// was still sending, which is ordinary; one that was never opened, which
    /// is not; and whatever was still queued when a session ended.
    pub unknown_session: AtomicU64,
    /// Datagrams too short to carry a session id.
    ///
    /// Separate from `unknown_session` because they mean different things: that
    /// one is a race with the sweep and this one is a peer sending something
    /// this protocol does not have, which is worth being able to tell apart
    /// when a forward is misbehaving.
    pub malformed: AtomicU64,
    /// Datagrams the connection would not take: `Denied`, a lost connection, or
    /// anything else msquic answers with.
    ///
    /// **`Denied` is the one to have a counter for.** It means the peer never
    /// advertised that it would receive datagrams, so it is not one datagram
    /// lost — it is every datagram in that direction, on a session that
    /// answered `Ready`. Without this the forward looks perfect and delivers
    /// nothing, with `total()` at zero.
    pub unsent: AtomicU64,
    /// Datagrams dropped because the connection already has as many sessions
    /// open as it may.
    ///
    /// Not `unknown_session`: that one is ordinary and this one means the
    /// forward has stopped accepting new sources, which is the difference
    /// between a summary an operator can skip and one they cannot.
    pub sessions_full: AtomicU64,
    /// Oversize datagrams whose stream carried a head this protocol does not
    /// have — a wrong version, a wrong kind, or one that ended inside it.
    ///
    /// Separate from [`malformed`](Self::malformed), which is the same fault on
    /// a datagram: the two arrive by different routes and a forward misbehaving
    /// on one is not misbehaving on the other.
    pub stream_malformed: AtomicU64,
    /// Oversize datagrams whose stream carried more than
    /// [`MAX_STREAM_PAYLOAD`].
    ///
    /// **The peer's doing, not a path's.** Nothing this protocol can send is
    /// that large, so a stream over the cap is a peer sending what UDP itself
    /// cannot carry — refused rather than assembled, because the alternative is
    /// letting a peer choose how much memory to take.
    pub stream_too_big: AtomicU64,
    /// Oversize datagrams whose stream ended before its FIN.
    ///
    /// **The ordinary way a cancelled one looks.** A sender that asked not to
    /// have its data retransmitted gets the stream aborted on the first
    /// detected loss, and this end sees a reset part-way through — so this
    /// counter is the receiving half of that choice as much as it is a fault.
    pub stream_lost: AtomicU64,
}

impl Drops {
    /// Whether anything at all was lost, which is the question an operator asks
    /// first and the only one a zero answers.
    pub fn any(&self) -> bool {
        self.total() != 0
    }

    /// Everything lost, however.
    ///
    /// **Every field is in here, and adding one means adding it here too.** A
    /// counter this misses is a loss that reports as no loss at all, which is
    /// worse than not counting it — `any()` is what a test and an operator both
    /// ask first.
    pub fn total(&self) -> u64 {
        let Self {
            oversize,
            refused_too_big,
            overflow,
            unknown_session,
            malformed,
            unsent,
            sessions_full,
            stream_malformed,
            stream_too_big,
            stream_lost,
        } = self;
        [
            oversize,
            refused_too_big,
            overflow,
            unknown_session,
            malformed,
            unsent,
            sessions_full,
            stream_malformed,
            stream_too_big,
            stream_lost,
        ]
        .into_iter()
        .map(|counter| counter.load(Ordering::Relaxed))
        .sum()
    }
}

/// What [`Queue::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Taken, and the reader will see it.
    Queued,
    /// Taken, and this many of the oldest were dropped to make room — count
    /// them.
    ///
    /// **A number rather than a flag**, because one arrival can now displace
    /// several: a 64 KB datagram makes room by evicting however many small ones
    /// are in front of it, and a caller that counted one loss per push would
    /// under-report by exactly the amount that matters.
    Evicted(usize),
    /// Refused: the session has ended. Count it; the payload is gone either
    /// way, and the difference from `Queued` is the whole point of saying so.
    Closed,
}

/// A bounded queue of datagrams for one session.
///
/// Not an `mpsc`: the bound has to drop the **oldest**, and a channel's sender
/// cannot reach the item that has been waiting longest.
#[derive(Debug)]
pub struct Queue {
    waiting: Mutex<Waiting>,
    arrived: Notify,
    closed: std::sync::atomic::AtomicBool,
}

/// The queue and its size, under one lock.
///
/// Together rather than beside each other: the byte total is only useful if it
/// cannot disagree with what is in the queue, and two locks is how that starts.
#[derive(Debug)]
struct Waiting {
    queue: VecDeque<Bytes>,
    bytes: usize,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            waiting: Mutex::new(Waiting {
                queue: VecDeque::with_capacity(QUEUE_DEPTH),
                bytes: 0,
            }),
            arrived: Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Queue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add `payload`, dropping the oldest until it fits.
    ///
    /// **Full means either bound**: [`QUEUE_DEPTH`] entries or [`QUEUE_BYTES`]
    /// bytes. The second is what keeps a queue of oversize datagrams from being
    /// a memory bound in name only.
    ///
    /// The answer says which of the three things happened, because two of them
    /// are losses and a caller that cannot tell them apart cannot count them —
    /// which is the thing this module exists to prevent.
    pub fn push(&self, payload: Bytes) -> Push {
        let outcome = {
            let mut waiting = self.waiting.lock().expect("datagram queue lock poisoned");
            // Checked under the same lock as the push, so a sweep that closes
            // between the two cannot leave a payload in a queue whose reader
            // has gone. Without this the datagram is neither delivered nor
            // counted: it sits there until the last `Arc` drops.
            if self.closed.load(Ordering::Acquire) {
                Push::Closed
            } else {
                let mut dropped = 0;
                // The `pop_front` is what ends this: the depth bound needs at
                // most one pass and the byte bound at most the whole queue,
                // and one datagram always fits into an empty one -- the
                // `assert!` on `MAX_STREAM_PAYLOAD` above is that promise.
                while waiting.queue.len() >= QUEUE_DEPTH
                    || waiting.bytes + payload.len() > QUEUE_BYTES
                {
                    let Some(oldest) = waiting.queue.pop_front() else {
                        break;
                    };
                    waiting.bytes -= oldest.len();
                    dropped += 1;
                }
                waiting.bytes += payload.len();
                waiting.queue.push_back(payload);
                if dropped == 0 {
                    Push::Queued
                } else {
                    Push::Evicted(dropped)
                }
            }
        };
        if outcome != Push::Closed {
            self.arrived.notify_one();
        }
        outcome
    }

    /// The next datagram, waiting for one if the queue is empty.
    ///
    /// `None` once [`close`](Self::close) has been called and nothing is left,
    /// which is how a reader learns the session has ended rather than that it
    /// is merely quiet — the two are indistinguishable in UDP otherwise.
    pub async fn pop(&self) -> Option<Bytes> {
        loop {
            // Registered before the check, so a push between the two wakes this
            // rather than being missed until the next one.
            let arrived = self.arrived.notified();
            tokio::pin!(arrived);
            arrived.as_mut().enable();
            {
                let mut waiting = self.waiting.lock().expect("datagram queue lock poisoned");
                if let Some(payload) = waiting.queue.pop_front() {
                    waiting.bytes -= payload.len();
                    return Some(payload);
                }
            }
            if self.closed.load(Ordering::Acquire) {
                return None;
            }
            arrived.await;
        }
    }

    /// End the session: [`pop`](Self::pop) drains what is left and then stops.
    ///
    /// For the case where a reader is still there to drain it. When there is
    /// not, [`abandon`](Self::abandon) is the honest one.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.arrived.notify_waiters();
    }

    /// [`close`](Self::close) when nobody is left to read, returning how many
    /// datagrams went with it.
    ///
    /// **The difference is whether the loss is counted.** A session's reader is
    /// gone by the time the session is removed from the table, so anything the
    /// peer pushed in the moment before that removal is waiting for a reader
    /// that has already left: `close` alone would leave it to be freed when the
    /// last `Arc` drops, delivered to nobody and counted by nobody. That is the
    /// same silent hole `push` returning [`Push::Closed`] exists to prevent,
    /// one instant earlier.
    pub fn abandon(&self) -> usize {
        self.closed.store(true, Ordering::Release);
        let discarded = {
            let mut waiting = self.waiting.lock().expect("datagram queue lock poisoned");
            let discarded = waiting.queue.len();
            waiting.queue.clear();
            waiting.bytes = 0;
            discarded
        };
        self.arrived.notify_waiters();
        discarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The number, guarded.** Everything `docs/portal.md` promises rides on
    /// this, and it is derived from two constants in another crate — so a
    /// change to `PEER_MTU` or `DATAGRAM_OVERHEAD` should land here rather than
    /// on somebody's DNS forward.
    ///
    /// The derivation, once more, so this test says why and not only what:
    /// 1248 MTU, less 48 for IPv6 and UDP headers, less 33 measured for the
    /// QUIC packet and DATAGRAM frame, less 4 for the session id.
    #[test]
    fn the_limit_is_what_was_measured() {
        assert_eq!(isekai_p2p::peer::PEER_MTU, 1248);
        assert_eq!(isekai_p2p::peer::DATAGRAM_OVERHEAD, 33);
        assert_eq!(isekai_p2p::peer::GUARANTEED_DATAGRAM, 1167);
        assert_eq!(MAX_PAYLOAD, 1163);
        assert_eq!(
            MAX_PAYLOAD + HEADER,
            isekai_p2p::peer::GUARANTEED_DATAGRAM,
            "a framed datagram at the limit has to fit the guarantee exactly",
        );
    }

    #[test]
    fn a_payload_at_the_limit_is_framed_and_one_over_it_is_not() {
        let at = vec![0xab_u8; MAX_PAYLOAD];
        let framed = encode(7, &at).expect("a payload at the limit fits");
        assert_eq!(framed.len(), HEADER + MAX_PAYLOAD);

        let over = vec![0xab_u8; MAX_PAYLOAD + 1];
        assert!(
            encode(7, &over).is_none(),
            "one byte over the limit must be refused, not truncated: a datagram \
             service that silently splits is worse than one that silently loses",
        );
    }

    #[test]
    fn a_framed_datagram_survives_the_round_trip() {
        let framed = encode(0xdead_beef, b"hello").expect("fits");
        let (session, payload) = decode(&framed).expect("decodes");
        assert_eq!(session, 0xdead_beef);
        assert_eq!(&payload[..], b"hello");
    }

    #[test]
    fn a_datagram_too_short_to_have_a_session_is_not_one() {
        for len in 0..HEADER {
            assert!(
                decode(&Bytes::from(vec![0_u8; len])).is_none(),
                "{len} bytes"
            );
        }
        // Exactly the header is a legitimate empty datagram: UDP has those.
        let (session, payload) = decode(&Bytes::from(vec![0_u8; HEADER])).expect("empty payload");
        assert_eq!((session, payload.len()), (0, 0));
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_oldest_and_says_so() {
        let queue = Queue::new();
        for i in 0..QUEUE_DEPTH {
            assert_eq!(
                queue.push(Bytes::from(vec![i as u8])),
                Push::Queued,
                "still has room at {i}",
            );
        }
        assert_eq!(
            queue.push(Bytes::from_static(b"newest")),
            Push::Evicted(1),
            "the queue is full, so something had to go -- one of it",
        );

        let first = queue.pop().await.expect("a datagram");
        assert_eq!(
            first[0], 1,
            "the datagram that had been waiting longest is the one that went",
        );
    }

    /// **A datagram that arrives after the sweep is a loss like any other**, and
    /// has to be counted like one. Taking it into a queue nobody is reading
    /// would report it delivered and then lose it — a third silent hole in a
    /// module whose whole subject is not having any.
    #[tokio::test]
    async fn a_closed_queue_refuses_rather_than_swallows() {
        let queue = Queue::new();
        queue.close();
        assert_eq!(queue.push(Bytes::from_static(b"too late")), Push::Closed);
        assert!(queue.pop().await.is_none(), "and nothing was kept");
    }

    #[tokio::test]
    async fn a_closed_queue_drains_and_then_ends() {
        let queue = Queue::new();
        queue.push(Bytes::from_static(b"left over"));
        queue.close();
        assert_eq!(
            queue.pop().await.as_deref(),
            Some(&b"left over"[..]),
            "closing must not discard what has already arrived",
        );
        assert!(
            queue.pop().await.is_none(),
            "and then it ends, which is how a reader tells a finished session \
             from a quiet one",
        );
    }

    /// **The other end of the same question `close` answers.** When a reader is
    /// there, closing must not discard what has arrived; when there is not,
    /// keeping it would be a loss nobody counts. The two differ only in whether
    /// anyone is left to drain, so they are two methods and not one guess.
    #[tokio::test]
    async fn abandoning_says_how_much_went_with_it() {
        let queue = Queue::new();
        queue.push(Bytes::from_static(b"one"));
        queue.push(Bytes::from_static(b"two"));
        assert_eq!(queue.abandon(), 2, "and the caller can count them");
        assert!(queue.pop().await.is_none(), "nothing was kept");
        assert_eq!(
            queue.push(Bytes::from_static(b"later")),
            Push::Closed,
            "and it is closed, like `close`",
        );
        assert_eq!(queue.abandon(), 0, "with nothing left to lose twice");
    }

    #[tokio::test]
    async fn a_waiting_reader_is_woken_by_an_arrival() {
        let queue = Queue::new();
        let reader = {
            let queue = Arc::clone(&queue);
            tokio::spawn(async move { queue.pop().await })
        };
        // Enough for the reader to be parked rather than merely spawned.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        queue.push(Bytes::from_static(b"wake up"));
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), reader)
            .await
            .expect("the reader woke within five seconds")
            .expect("the reader did not panic");
        assert_eq!(got.as_deref(), Some(&b"wake up"[..]));
    }

    /// **The byte bound, which the depth alone does not give.** Sixty-four
    /// entries of 65507 bytes is 4.19 MB a session; the point of `QUEUE_BYTES`
    /// is that the count stopped being a memory bound once entries could vary
    /// by fifty-six times.
    #[tokio::test]
    async fn the_queue_is_bounded_in_bytes_as_well_as_entries() {
        let queue = Queue::new();
        let big = Bytes::from(vec![0_u8; MAX_STREAM_PAYLOAD]);
        // Two of these fit (131014 of 131072) and the third cannot.
        assert_eq!(queue.push(big.clone()), Push::Queued);
        assert_eq!(queue.push(big.clone()), Push::Queued);
        assert_eq!(
            queue.push(big.clone()),
            Push::Evicted(1),
            "well under QUEUE_DEPTH, and still full",
        );
    }

    /// **One arrival can displace several, and the count has to say how many.**
    /// A caller that added one to `overflow` per push would under-report by
    /// exactly the amount that matters.
    #[tokio::test]
    async fn one_large_arrival_evicts_as_many_as_it_needs_and_reports_them() {
        let queue = Queue::new();
        // Eight small ones, then something that needs most of the budget.
        for _ in 0..8 {
            assert_eq!(queue.push(Bytes::from(vec![0_u8; 8 * 1024])), Push::Queued);
        }
        let dropped = match queue.push(Bytes::from(vec![0_u8; 100 * 1024])) {
            Push::Evicted(dropped) => dropped,
            other => panic!("expected an eviction, got {other:?}"),
        };
        // 8 x 8 KB = 64 KB waiting, and 100 KB needs all but 28 KB of the
        // budget -- so five of the eight have to go, not one.
        assert_eq!(dropped, 5);
    }

    /// Popping gives the bytes back, or a queue that has been busy would
    /// slowly refuse everything.
    #[tokio::test]
    async fn draining_restores_the_budget() {
        let queue = Queue::new();
        let big = Bytes::from(vec![0_u8; MAX_STREAM_PAYLOAD]);
        assert_eq!(queue.push(big.clone()), Push::Queued);
        assert_eq!(queue.push(big.clone()), Push::Queued);
        queue.pop().await.expect("one back");
        queue.pop().await.expect("the other");
        assert_eq!(queue.push(big), Push::Queued, "and there is room again");
    }
}
