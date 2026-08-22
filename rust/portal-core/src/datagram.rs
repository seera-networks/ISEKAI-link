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

/// The largest UDP payload this can carry, and why that number.
///
/// **The arithmetic, because the failure is silent otherwise.** A portal
/// datagram rides inside the peer QUIC connection, which
/// `isekai_p2p::peer::client_config` caps at `MaximumMtu(1248)` — msquic clamps
/// that up to `QUIC_DPLPMTUD_MIN_MTU` and no lower value can be asked for. A
/// connection's maximum datagram length runs about 42 bytes under its MTU
/// (`isekai_p2p_core::transport` does the same sum for the relay leg), so about
/// 1206 bytes are available; [`HEADER`] takes four of them.
///
/// 1180 is under that with room to spare, and the spare is deliberate: the
/// number above is msquic's arithmetic rather than ours, and a payload that is
/// one byte too large is dropped rather than rejected at the caller. Being
/// wrong in this direction costs a few bytes per datagram; being wrong in the
/// other costs a silent hole in a service that looked like it worked.
///
/// **It is a ceiling, not a promise.** msquic reports its own limit per
/// connection and refuses anything over it with `DgramSendError::TooBig`; the
/// sender checks this constant first so the refusal is counted here rather than
/// arriving as an error from three layers down, and handles `TooBig` anyway
/// because the runtime value is the one that is true.
///
/// # What this rules out, said plainly
///
/// **A UDP payload over about 1200 bytes cannot cross a portal forward**, and
/// raising this constant does not change that — the true limit is the peer
/// connection's, and its 1248-byte MTU is itself a floor msquic will not go
/// under. Splitting is not an option either; §4.1 is explicit that a datagram
/// service which silently splits is worse than one which silently loses.
///
/// The case to know about is DNS: EDNS0 commonly advertises a 1232-byte buffer,
/// so a large response can exceed this and be dropped — with no truncation bit
/// and no ICMP, which leaves a stub resolver waiting for a timeout instead of
/// retrying over TCP. A resolver configured for a smaller buffer, or one that
/// falls back on timeout, is fine. This is a property of forwarding UDP inside
/// a relayed QUIC connection rather than something phase 3 can fix.
pub const MAX_PAYLOAD: usize = 1180;

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
    /// Payloads that would not fit in one datagram.
    pub oversize: AtomicU64,
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
}

impl Drops {
    /// Whether anything at all was lost, which is the question an operator asks
    /// first and the only one a zero answers.
    pub fn any(&self) -> bool {
        self.total() != 0
    }

    /// Everything lost, however.
    pub fn total(&self) -> u64 {
        self.oversize.load(Ordering::Relaxed)
            + self.overflow.load(Ordering::Relaxed)
            + self.unknown_session.load(Ordering::Relaxed)
            + self.malformed.load(Ordering::Relaxed)
    }
}

/// What [`Queue::push`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Push {
    /// Taken, and the reader will see it.
    Queued,
    /// Taken, and the oldest was dropped to make room — count it.
    Evicted,
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
    waiting: Mutex<VecDeque<Bytes>>,
    arrived: Notify,
    closed: std::sync::atomic::AtomicBool,
}

impl Default for Queue {
    fn default() -> Self {
        Self {
            waiting: Mutex::new(VecDeque::with_capacity(QUEUE_DEPTH)),
            arrived: Notify::new(),
            closed: std::sync::atomic::AtomicBool::new(false),
        }
    }
}

impl Queue {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Add `payload`, dropping the oldest if the queue is full.
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
            } else if waiting.len() >= QUEUE_DEPTH {
                waiting.pop_front();
                waiting.push_back(payload);
                Push::Evicted
            } else {
                waiting.push_back(payload);
                Push::Queued
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
            if let Some(payload) = self
                .waiting
                .lock()
                .expect("datagram queue lock poisoned")
                .pop_front()
            {
                return Some(payload);
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
            let discarded = waiting.len();
            waiting.clear();
            discarded
        };
        self.arrived.notify_waiters();
        discarded
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
            Push::Evicted,
            "the queue is full, so something had to go",
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
}
