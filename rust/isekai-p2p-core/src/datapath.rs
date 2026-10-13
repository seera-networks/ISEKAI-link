//! Interposing on the packets of an inner QUIC connection.
//!
//! `docs/isekai_p2p_datapath_hook_plan.md`. Two carriers share one
//! [`DatapathHook`]: a **relay leg**, where `channel-masque`'s bridge consults
//! it (set through [`crate::bind::RelayOptions`]), and a [`Hop`], which is two
//! sockets and nothing else.
//!
//! # Which carrier to reach for
//!
//! | | |
//! | --- | --- |
//! | the relay leg | **a live relay.** The only way to lose a packet on a real session, which is what the relay investigation never had |
//! | a [`Hop`] | **a test.** A seam on both sides, and no tunnel to stand up |
//!
//! The relay leg's seam exists only on the end that *dialled* — a listening
//! leg forwards by another route entirely — so a test that wants to drop what
//! either end sends wants a hop.
//!
//! # Behind the `msquic` feature, and it costs nothing
//!
//! The plan left this open: putting the trait where the bridge can call it puts
//! a hop behind the native stack too. **In practice that is free** — anything
//! wanting a hop wants two QUIC endpoints to put it between, and those need
//! the feature anyway.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

pub use channel_masque::masque::connect_udp::{DatapathHook, Verdict};

/// A UDP hop between two endpoints of one inner QUIC connection.
///
/// The dialling end sends to [`addr`](Self::addr) instead of to the listener,
/// and every packet in both directions passes the hook before it is forwarded.
///
/// # Which direction is which
///
/// [`DatapathHook`]'s two methods are named for the relay leg, where the hook
/// sits *at* one end. A hop sits *between*, so the mapping is stated once here
/// rather than guessed at each hook:
///
/// | hook method | a hop calls it for |
/// | --- | --- |
/// | [`DatapathHook::outbound`] | a packet from the **dialling** end |
/// | [`DatapathHook::inbound`] | a packet from the **listening** end |
///
/// So a hook written for a relay leg keeps its meaning when it is moved to a
/// hop, as long as the dialling end is the same one.
///
/// # It learns where to reply
///
/// One socket, so the listener answers to the hop and the hop answers to
/// whoever last spoke from somewhere other than the listener. **Nothing can go
/// back before something has come out**, which is harmless for the only thing
/// this is for: a QUIC client speaks first, always.
pub struct Hop {
    addr: SocketAddr,
    /// Cancelled when the hop stops, so a caller can tell it did.
    stopped: CancellationToken,
    /// **Dropping the handle stops the hop**, which is what makes holding one
    /// mean something.
    ///
    /// Without it the only stop signal was the caller's token, and a caller
    /// that passed a long-lived one — the natural thing — would leave the task
    /// forwarding whatever reached its port for the life of the process,
    /// holding a bound socket, a 64 KiB buffer and the hook.
    _armed: tokio_util::sync::DropGuard,
}

impl Hop {
    /// Start a hop that forwards to `target`, consulting `hook` both ways.
    ///
    /// Bound on loopback — `127.0.0.1` or `[::1]` to match `target`'s family,
    /// since a hop that cannot reach its target is only a slow way to time out.
    /// Loopback because this is a test instrument and a hop reachable from the
    /// network is a hole with no reason to exist.
    pub async fn start(
        target: SocketAddr,
        hook: Arc<dyn DatapathHook>,
        shutdown: CancellationToken,
    ) -> anyhow::Result<Self> {
        // **The target's family, not always IPv4.** Binding `127.0.0.1` for an
        // IPv6 target left every `send_to` failing with `EAFNOSUPPORT`, logged
        // at `debug!` and carried on from — so the caller saw a handshake time
        // out with nothing above `debug` to say why.
        let local: SocketAddr = if target.is_ipv6() {
            "[::1]:0".parse().expect("a literal")
        } else {
            "127.0.0.1:0".parse().expect("a literal")
        };
        let socket = UdpSocket::bind(local)
            .await
            .context("failed to bind a datapath hop")?;
        let addr = socket
            .local_addr()
            .context("failed to read the hop's address")?;
        // **Either signal stops it**: the caller's token, or this handle going
        // away. A child, so cancelling the caller's still reaches the task.
        let mine = shutdown.child_token();
        let stopped = CancellationToken::new();
        tokio::spawn({
            let ended = stopped.clone();
            let shutdown = mine.clone();
            async move {
                // Dropped on the way out however this ends, so a caller
                // waiting on `stopped` is told by the error path as well as
                // the tidy one.
                let _armed = ended.drop_guard();
                if let Err(e) = run(socket, target, hook, shutdown).await {
                    tracing::debug!(%target, "a datapath hop stopped: {e:#}");
                }
            }
        });
        Ok(Self {
            addr,
            stopped,
            _armed: mine.drop_guard(),
        })
    }

    /// Where the dialling end should send, instead of to the listener.
    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    /// Resolves once the hop has stopped forwarding.
    pub async fn stopped(&self) {
        self.stopped.cancelled().await;
    }
}

async fn run(
    socket: UdpSocket,
    target: SocketAddr,
    hook: Arc<dyn DatapathHook>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    // The largest a UDP payload can be, so nothing is truncated into looking
    // like a corrupt QUIC packet.
    let mut buf = vec![0_u8; 65_535];
    let mut dialler: Option<SocketAddr> = None;
    let mut said_send_failed = false;
    loop {
        let received = tokio::select! {
            _ = shutdown.cancelled() => return Ok(()),
            r = socket.recv_from(&mut buf) => r,
        };
        let (n, from) = match received {
            Ok(pair) => pair,
            // **`ConnectionReset` is not the socket failing.** On Windows an
            // unconnected UDP socket surfaces an ICMP port-unreachable as
            // `WSAECONNRESET` from `recv_from` -- which is exactly what happens
            // when a reply is forwarded to a dialler msquic has just torn down.
            // Treating it as fatal silently ended the hop, and these tests run
            // on `windows-latest`.
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                tracing::debug!("a datapath hop ignored an ICMP error: {e}");
                continue;
            }
            Err(e) => return Err(e).context("a datapath hop stopped receiving"),
        };
        let (verdict, to) = if from == target {
            // From the listener, so it is going back to whoever dialled -- and
            // there is nothing to send to until somebody has.
            let Some(dialler) = dialler else {
                tracing::debug!("a datapath hop dropped a reply: nothing has dialled yet");
                continue;
            };
            (hook.inbound(&buf[..n]), dialler)
        } else if let Some(known) = dialler {
            // **The first dialler keeps the hop, and a stranger does not take
            // it.** Re-learning from any source meant one stray datagram on
            // this ephemeral port redirected the listener's replies and wedged
            // the connection under test, with a `debug!` line as the only
            // trace. A hop carries one connection; anything else is noise.
            if from != known {
                tracing::debug!(%from, "a datapath hop ignored a datagram from a stranger");
                continue;
            }
            (hook.outbound(&buf[..n]), target)
        } else {
            // **Recorded before the hook may drop it**, for the reason the
            // bridge records `last_src` first: a drop stands for a packet lost
            // in flight, and it was still sent from here.
            dialler = Some(from);
            (hook.outbound(&buf[..n]), target)
        };
        if verdict == Verdict::Drop {
            continue;
        }
        if let Err(e) = socket.send_to(&buf[..n], to).await {
            // Dropped and carried on, as the bridge does: one transient
            // failure must not end the hop and take the connection with it.
            //
            // **The first one is said out loud**, though: a hop that cannot
            // reach where it is forwarding fails every packet, and at `debug!`
            // alone that reads as a handshake that simply never completed.
            if said_send_failed {
                tracing::debug!(%to, "a datapath hop could not forward: {e}");
            } else {
                said_send_failed = true;
                tracing::warn!(
                    %to,
                    "a datapath hop could not forward a packet: {e}; \
                     further ones are logged at debug",
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// Counts both directions and can be told to lose the next few of either.
    #[derive(Default)]
    struct Counting {
        out: AtomicUsize,
        in_: AtomicUsize,
        drop_out: AtomicUsize,
        drop_in: AtomicUsize,
    }

    impl Counting {
        /// One decrement, not a load and a store: the trait is `Send + Sync`
        /// and arrives as an `Arc`, so a hook shared by two carriers would
        /// otherwise race and lose a packet's worth of budget.
        fn spend(budget: &AtomicUsize) -> bool {
            budget
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
        }
    }

    impl DatapathHook for Counting {
        fn outbound(&self, _packet: &[u8]) -> Verdict {
            self.out.fetch_add(1, Ordering::Relaxed);
            if Self::spend(&self.drop_out) {
                Verdict::Drop
            } else {
                Verdict::Pass
            }
        }
        fn inbound(&self, _packet: &[u8]) -> Verdict {
            self.in_.fetch_add(1, Ordering::Relaxed);
            if Self::spend(&self.drop_in) {
                Verdict::Drop
            } else {
                Verdict::Pass
            }
        }
    }

    /// Stands in for the listening end: echoes, upper-cased, so a reply is
    /// recognisable as having gone all the way.
    async fn shouting_echo() -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let addr = socket.local_addr().expect("addr");
        let task = tokio::spawn(async move {
            let mut buf = vec![0_u8; 2048];
            while let Ok((n, from)) = socket.recv_from(&mut buf).await {
                let loud = buf[..n].to_ascii_uppercase();
                if socket.send_to(&loud, from).await.is_err() {
                    return;
                }
            }
        });
        (addr, task)
    }

    #[tokio::test]
    async fn a_hop_carries_both_ways_and_the_hook_sees_both() {
        let (target, _echo) = shouting_echo().await;
        let hook = Arc::new(Counting::default());
        let shutdown = CancellationToken::new();
        let hop = Hop::start(target, hook.clone(), shutdown.clone())
            .await
            .expect("start the hop");

        let dialler = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        dialler.send_to(b"ping", hop.addr()).await.expect("send");

        let mut got = [0_u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(1), dialler.recv_from(&mut got))
            .await
            .expect("a reply within a second")
            .expect("recv");
        assert_eq!(&got[..n], b"PING", "it went to the listener and came back");
        assert_eq!(from, hop.addr(), "and it came back from the hop");

        assert_eq!(hook.out.load(Ordering::Relaxed), 1);
        assert_eq!(hook.in_.load(Ordering::Relaxed), 1);

        shutdown.cancel();
        hop.stopped().await;
    }

    /// **The direction mapping, pinned.** A hook written for a relay leg keeps
    /// its meaning on a hop only if `outbound` stays "from the dialling end",
    /// and nothing but a test says which way round it is.
    #[tokio::test]
    async fn outbound_is_the_dialling_ends_packet() {
        let (target, _echo) = shouting_echo().await;
        let hook = Arc::new(Counting::default());
        hook.drop_out.store(1, Ordering::Relaxed);
        let shutdown = CancellationToken::new();
        let hop = Hop::start(target, hook.clone(), shutdown.clone())
            .await
            .expect("start the hop");

        let dialler = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        dialler.send_to(b"lost", hop.addr()).await.expect("send");
        dialler.send_to(b"kept", hop.addr()).await.expect("send");

        let mut got = [0_u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), dialler.recv_from(&mut got))
            .await
            .expect("a reply within a second")
            .expect("recv");
        assert_eq!(&got[..n], b"KEPT", "the first never reached the listener");

        assert_eq!(hook.out.load(Ordering::Relaxed), 2, "both were offered");
        assert_eq!(
            hook.in_.load(Ordering::Relaxed),
            1,
            "and only one reply existed to come back",
        );

        shutdown.cancel();
        hop.stopped().await;
    }

    #[tokio::test]
    async fn a_reply_can_be_dropped_too() {
        let (target, _echo) = shouting_echo().await;
        let hook = Arc::new(Counting::default());
        hook.drop_in.store(1, Ordering::Relaxed);
        let shutdown = CancellationToken::new();
        let hop = Hop::start(target, hook.clone(), shutdown.clone())
            .await
            .expect("start the hop");

        let dialler = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        dialler.send_to(b"one", hop.addr()).await.expect("send");

        // **Waited for, not assumed.** The negative assertion below is safe
        // under load -- nothing arriving stays nothing -- but reading the
        // counter needs the reply to have reached the hop, and a 300 ms
        // round trip is not guaranteed on a loaded runner. So: wait for the
        // offer on the suite's own budget, then assert the drop.
        let offered = tokio::time::timeout(Duration::from_secs(5), async {
            while hook.in_.load(Ordering::Relaxed) == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await;
        assert!(offered.is_ok(), "the reply reached the hop within five seconds");

        let mut got = [0_u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), dialler.recv_from(&mut got))
                .await
                .is_err(),
            "and it was lost on the way back rather than forwarded",
        );

        // The next one gets through, so what was dropped was that reply rather
        // than the hop having stopped.
        dialler.send_to(b"two", hop.addr()).await.expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), dialler.recv_from(&mut got))
            .await
            .expect("a reply within a second")
            .expect("recv");
        assert_eq!(&got[..n], b"TWO");

        shutdown.cancel();
        hop.stopped().await;
    }

    /// **A stranger does not take the connection over.** Re-learning the
    /// dialler from any source meant one stray datagram on the hop's ephemeral
    /// port sent the listener's replies somewhere else for good, wedging
    /// whatever was running through it.
    #[tokio::test]
    async fn a_datagram_from_a_stranger_does_not_redirect_the_replies() {
        let (target, _echo) = shouting_echo().await;
        let hook = Arc::new(Counting::default());
        let shutdown = CancellationToken::new();
        let hop = Hop::start(target, hook.clone(), shutdown.clone())
            .await
            .expect("start the hop");

        let dialler = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        dialler.send_to(b"mine", hop.addr()).await.expect("send");
        let mut got = [0_u8; 64];
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), dialler.recv_from(&mut got))
            .await
            .expect("a reply")
            .expect("recv");
        assert_eq!(&got[..n], b"MINE");

        // Somebody else sends to the hop's port.
        let stranger = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        stranger.send_to(b"theirs", hop.addr()).await.expect("send");
        assert!(
            tokio::time::timeout(Duration::from_millis(300), stranger.recv_from(&mut got))
                .await
                .is_err(),
            "the stranger's datagram went nowhere",
        );

        // And the connection still works, which is what the old behaviour
        // would have broken.
        dialler.send_to(b"still", hop.addr()).await.expect("send");
        let (n, _) = tokio::time::timeout(Duration::from_secs(1), dialler.recv_from(&mut got))
            .await
            .expect("a reply still comes back")
            .expect("recv");
        assert_eq!(&got[..n], b"STILL");

        shutdown.cancel();
        hop.stopped().await;
    }

    /// **Dropping the handle stops it**, which is what makes holding one mean
    /// anything — and the field in `portal-core`'s harness that says so was
    /// wrong until this existed.
    #[tokio::test]
    async fn dropping_the_handle_stops_the_hop() {
        let (target, _echo) = shouting_echo().await;
        let hook = Arc::new(Counting::default());
        // A token nothing will cancel, which is the case that used to leak.
        let hop = Hop::start(target, hook.clone(), CancellationToken::new())
            .await
            .expect("start the hop");
        let addr = hop.addr();
        let stopped = hop.stopped.clone();
        drop(hop);

        tokio::time::timeout(Duration::from_secs(5), stopped.cancelled())
            .await
            .expect("the hop stopped when its handle went");

        // And its port carries nothing, which is the observable half.
        let after = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        after.send_to(b"ping", addr).await.expect("send");
        let mut got = [0_u8; 64];
        assert!(
            tokio::time::timeout(Duration::from_millis(300), after.recv_from(&mut got))
                .await
                .is_err(),
        );
    }

    /// Nothing can go back before something has come out — stated in `Hop`'s
    /// doc, and harmless only because a QUIC client speaks first.
    #[tokio::test]
    async fn a_reply_before_anything_dialled_has_nowhere_to_go() {
        let listener = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
        let target = listener.local_addr().expect("addr");
        let hook = Arc::new(Counting::default());
        let shutdown = CancellationToken::new();
        let hop = Hop::start(target, hook.clone(), shutdown.clone())
            .await
            .expect("start the hop");

        // The listener speaks first, which cannot happen with QUIC and is the
        // case the doc warns about.
        listener.send_to(b"early", hop.addr()).await.expect("send");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_eq!(
            hook.in_.load(Ordering::Relaxed),
            0,
            "dropped before the hook, because there was nowhere to send it",
        );

        shutdown.cancel();
        hop.stopped().await;
    }
}
