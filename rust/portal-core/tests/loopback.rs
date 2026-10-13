//! Bytes reach a TCP service and datagrams reach a UDP one, through the
//! forward — and a service that is not offered gets neither.
//!
//! Phase 0's question is whether the framing and the stream mapping hold up, so
//! this drives a real QUIC connection between the two halves rather than a
//! mock: the `Open`/status exchange, the stream a forwarded connection lives
//! on, and the copy in both directions.
//!
//! **Phase 3b's question needs the same connection and could not be asked
//! anywhere else.** The size limit, the queue and the wire have unit tests in
//! `datagram`; what only a real connection can show is whether a datagram
//! sent by one end is delivered to the right session at the other, whether the
//! reply comes back out of the port the application sent to, and whether a
//! payload at the limit survives a path that has msquic's own datagram
//! arithmetic in the middle of it. Those are the three ways a UDP forward can
//! look like it works and lose traffic.
//!
//! **The registration is shared and drained**, for the reason
//! `camera-core/tests/video_loopback.rs` documents at length: `RegistrationClose`
//! is a synchronous, uninterruptible wait on every handle derived from it, so
//! dropping one while a connection is live hangs the process with no way out.
//!
//! # Why these are current-thread tests
//!
//! They were `multi_thread`, and on `windows-latest` whichever of the two ran
//! second had a dial that never completed — #155. The mechanism is one this
//! repository had already written down somewhere else: `get_stats` is served by
//! queueing an operation to msquic's connection worker and **blocking the
//! calling thread** until it runs (`camera_core::video::spawn_heartbeat` says
//! so), and `peer::dial`'s handshake probe calls it every second *while the
//! handshake is in flight*.
//!
//! `receive_frames` samples the same way but only after its dial has returned,
//! which is why `video_loopback.rs` never met this. Two multi-threaded runtimes
//! on a two-core runner, each making a blocking call into a different
//! registration's worker once a second, is enough to starve the future being
//! reported on.
//!
//! A current-thread runtime is what `video_loopback.rs` uses, and there is
//! nothing here that wants worker threads: every task in the forward is async
//! all the way down.

use std::sync::Arc;
use std::time::Duration;

use msquic_async::StreamType;
use msquic_async::{msquic, Registration};
use portal_core::datagram::{MAX_PAYLOAD, MAX_STREAM_PAYLOAD};
use portal_core::server::{Catalogue, Protocol};
use portal_core::udp::Sessions;
use portal_core::{client, frame, server, transport, udp};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_util::sync::CancellationToken;

/// How long the loopback handshake may take before the test says so itself.
///
/// **The dial's own deadline is fifteen minutes**
/// (`isekai_p2p::peer::CONNECT_DEADLINE`), which is right for a peer whose relay
/// leg an operator is still bringing up and wrong for two halves of one process.
///
/// **It bounds the dial, not the process**, and the first version of this
/// comment claimed otherwise. Timing out panics, panicking unwinds, and
/// unwinding drops the last `Arc<Registration>` while the spawned server task
/// still holds the `Listener`. [`Teardown`] cancels and calls `shutdown()` on
/// the way out, but the unwind has no await in it, so the task is not
/// necessarily polled before that last drop — and then `RegistrationClose`
/// waits on a handle nobody is going to release.
///
/// Measured rather than reasoned about: pointing the dial at a port nothing
/// listens on hangs past three minutes under the default test threads, and
/// aborts under `--test-threads=1`. So this turns "fifteen minutes and then
/// something bad" into "half a minute and then something bad", and the job
/// timeout is still the backstop. Worth having and not worth mistaking for a
/// fix.
///
/// **Thirty seconds rather than ten**, because ten made this a latency
/// assertion and not a backstop: a `windows-latest` runner with both tests in
/// flight took longer than that for a loopback handshake, and the same commit
/// passed on the other run. Nothing here has an opinion about how fast a
/// handshake should be — only that a wait which is never going to end should
/// end.
const DIAL_BUDGET: Duration = Duration::from_secs(30);

/// Uppercases every datagram it is sent, and replies to the address it came
/// from — which is what a UDP service does and what makes the reply path
/// testable at all.
///
/// One socket for every source, as a real one has: if the forward's sessions
/// were crossed, two sources would still both get uppercase back, so the tests
/// check *which* reply reaches which local socket rather than merely that one
/// arrives.
/// A datagram service that hands back **what it received** rather than an
/// answer.
///
/// [`shouting_datagram_service`] proves a round trip, which is the wrong
/// instrument for the oversize receive path: the reply would be larger than
/// `MAX_PAYLOAD` and there is no send side yet, so it would be dropped and the
/// test would fail for a reason it is not about. This reports the arrival
/// instead.
async fn recording_datagram_service(
) -> (std::net::SocketAddr, tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>) {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the datagram service");
    let addr = socket.local_addr().expect("service address");
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 70_000];
        loop {
            let Ok((n, _from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            if tx.send(buf[..n].to_vec()).is_err() {
                return;
            }
        }
    });
    (addr, rx)
}

async fn shouting_datagram_service() -> std::net::SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind the datagram service");
    let addr = socket.local_addr().expect("service address");
    tokio::spawn(async move {
        let mut buf = vec![0_u8; 70_000];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let loud = buf[..n].to_ascii_uppercase();
            if socket.send_to(&loud, from).await.is_err() {
                return;
            }
        }
    });
    addr
}

/// Uppercases whatever it is sent, so a reply proves both directions rather
/// than just one — an echo would pass even if the two copies were crossed.
async fn shouting_service() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the service");
    let addr = listener.local_addr().expect("service address");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0_u8; 1024];
                loop {
                    match socket.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            let loud = buf[..n].to_ascii_uppercase();
                            if socket.write_all(&loud).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// **`Drop` is load-bearing.** A failing assertion unwinds, so nothing written
/// after it in the test body runs: the teardown has to be in `Drop` or it is not
/// teardown, it is a happy path.
///
/// The *ordering* half of the trap is no longer this file's problem —
/// [`isekai_p2p::peer::PeerSession`] holds the connection, its configuration and
/// the registration in the order they have to be released, so there is no field
/// order here to get wrong. What is left is what only this test knows: which
/// tasks are holding handles, and when to stop them.
///
/// This is the trap `camera-core/tests/video_loopback.rs` documents, met from
/// the other side: there the danger is dropping a registration you made, here it
/// is failing before you get to.
struct Halves {
    /// `None` only after [`drain`] has taken it, which is the last thing that
    /// happens to a `Halves`.
    session: Option<isekai_p2p::peer::PeerSession>,
    /// The client's end of UDP forwarding: one per connection, made here even
    /// for the TCP tests because it costs a task that ends with the connection.
    ///
    /// **`Option` for the same reason the field above is.** It holds a
    /// `Connection` clone, so [`drain`] has to let it go before it waits —
    /// exactly what `session::Connected::close` does in the real client.
    sessions: Option<Arc<Sessions>>,
    /// The **server's** side of the connection, for the one test that has to
    /// send something the server never sends.
    ///
    /// Everything else in this file drives the server through the client, which
    /// is the right way round. A unidirectional stream towards the client is
    /// the exception: S3 does not exist, so nothing on the server opens one,
    /// and the client's receive bounds would otherwise have no way to be
    /// observed — its `Sessions` is the only one a test can read counters from.
    peer_side: Option<msquic_async::Connection>,
    teardown: Teardown,
}

/// Cancels the tasks and lets msquic release its handles, whenever it is
/// dropped.
///
/// **Separate from [`Halves`] because it has to exist before the dial does.**
/// Everything that can go wrong between binding the listener and holding a
/// connection — a handshake that never completes, a certificate the listener
/// cannot present — ends in a panic, and a panic that leaves the server task
/// holding the `Listener` turns the registration's own drop into an
/// uninterruptible `RegistrationClose`. Owning the cancel from the first line
/// means that path runs teardown too.
struct Teardown {
    shutdown: CancellationToken,
    /// `None` only inside [`Drop`], which is the only thing that takes it.
    reg: Option<Arc<Registration>>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        // Stops the accept loop, the serve task and the datagram pump, which are
        // what hold the `Listener` and the `Connection` clones; `shutdown()`
        // then tells msquic to let its handles go so the close has nothing to
        // wait on. Neither blocks, which is the whole reason they are what
        // `Drop` does and the waiting is not.
        self.shutdown.cancel();
        let reg = self.reg.take().expect("dropped once");
        reg.shutdown();
        if std::thread::panicking() {
            // **A failing test must fail rather than wedge**, and until here it
            // did neither reliably. Cancelling does not make the tasks run: an
            // unwind has no await in it, so nothing is polled between the cancel
            // above and this drop, and the `Listener` and `Connection` clones
            // those tasks hold are still live handles. Dropping the last
            // `Arc<Registration>` then enters `RegistrationClose`, which is a
            // synchronous, uninterruptible wait for handles that nobody is left
            // to release.
            //
            // Measured, not reasoned about: turning off the client's datagram
            // advertisement makes the three UDP tests panic on their read
            // deadlines, and every one of them then sat in a futex until it was
            // killed — a CI job that would burn its whole timeout and say
            // nothing, in place of three named failures in two minutes.
            //
            // So on the way out of a test that is already failing, the
            // registration is leaked instead. The process is about to die with
            // the panic; what it costs is a registration in a doomed process,
            // and what it buys is the failure being reported at all.
            // `PeerSession::drain` does the same thing for the same reason when
            // its wait times out.
            //
            // The successful path is untouched: [`drain`] drops this *before* it
            // waits, so the wait is `PeerSession::drain`'s, on a registration
            // this no longer holds, with an assertion on the result.
            //
            // The same experiment now ends in three named failures in twelve
            // seconds, and then a `SIGABRT` from msquic on the way out about the
            // handles nobody closed. That is after cargo has printed which tests
            // failed and why, which is the whole of what was missing.
            std::mem::forget(reg);
        }
    }
}

impl Halves {
    fn connection(&self) -> &msquic_async::Connection {
        self.session
            .as_ref()
            .expect("the session is only taken by `drain`")
            .connection()
    }

    fn sessions(&self) -> &Arc<Sessions> {
        self.sessions
            .as_ref()
            .expect("the sessions are only taken by `drain`")
    }
}

/// A portal server offering `catalogue`, and a connection to it.
async fn connected(catalogue: Catalogue) -> Halves {
    connected_with_idle(catalogue, udp::IDLE).await
}

/// [`connected`], with a UDP sweep this side of a minute.
async fn connected_with_idle(catalogue: Catalogue, idle: Duration) -> Halves {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let (_reg, listener, bound) =
        transport::bind(Some(reg.clone()), "127.0.0.1:0".parse().unwrap(), None)
            .expect("bind the portal listener");
    let shutdown = CancellationToken::new();
    // Before the dial, so a failure between here and `Halves` still tears down.
    let teardown = Teardown {
        shutdown: shutdown.clone(),
        reg: Some(reg.clone()),
    };

    let serving = shutdown.clone();
    let (peer_tx, peer_rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        tokio::select! {
            _ = serving.cancelled() => {}
            accepted = listener.accept() => {
                if let Ok(conn) = accepted {
                    // Cloned before `serve` takes it. A clone is a handle, so
                    // `drain` has to see it dropped -- which is why `Halves`
                    // holds it in an `Option` like the two beside it.
                    let _ = peer_tx.send(conn.clone());
                    let _ = server::serve(conn, catalogue, serving.clone()).await;
                }
            }
        }
    });

    // **`127.0.0.1`, not `localhost`** — this is #155. The listener above is
    // bound on `127.0.0.1`, and on Windows `localhost` resolves to `::1` first;
    // a handshake that goes there completes never rather than slowly, which is
    // the shape this failed in. `spike.rs` carried a comment predicting exactly
    // that and was only ever run on Linux, so it was never tested.
    //
    // A literal cannot be resolved, so nothing here depends on whether
    // `set_remote_addr` is enough to stop msquic trying. `video_loopback.rs`
    // dials a literal for the same reason and has never failed on Windows.
    //
    // Validation is off because the listener is presenting the self-signed
    // fallback, so the name is not doing anything else here either.
    // Timed, because #155 turned on a distinction the budget alone cannot make.
    // Three times I called this failure "binary -- milliseconds or never", and
    // that was an inference from three numbers that were all just the budget.
    // What the log says is only "longer than the budget". So: print it.
    let began = std::time::Instant::now();
    let session = tokio::time::timeout(
        DIAL_BUDGET,
        transport::connect(
            Some(reg.clone()),
            "127.0.0.1",
            bound.port(),
            transport::ConnectOptions::default(),
            &shutdown,
        ),
    )
    .await
    .expect("the loopback handshake completed inside its budget")
    .expect("dial the portal");
    eprintln!("#155: the dial took {:?}", began.elapsed());
    let sessions = Sessions::start_with_idle(session.connection().clone(), shutdown.clone(), idle);
    Halves {
        session: Some(session),
        sessions: Some(sessions),
        // Arrives once the handshake the dial above completed is accepted, so
        // it is already there; a timeout rather than a `blocking` wait because
        // a failure here should say what it was.
        peer_side: tokio::time::timeout(DIAL_BUDGET, peer_rx)
            .await
            .expect("the listener accepted inside the dial budget")
            .ok(),
        teardown,
    }
}

#[tokio::test]
async fn bytes_reach_the_service_and_come_back() {
    let target = shouting_service().await;
    let halves = connected(Catalogue::new().with("db", Protocol::Tcp, target)).await;

    let local = client::forward(
        halves.connection().clone(),
        "127.0.0.1:0".parse().unwrap(),
        "db".to_owned(),
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local port");

    let mut client = TcpStream::connect(local)
        .await
        .expect("connect to the forward");
    assert_eq!(&exchange(&mut client, b"hello").await, b"HELLO");

    // The service replying proves the request arrived; the reply arriving
    // proves the copy back. A second exchange proves the stream stays open
    // rather than carrying one message.
    assert_eq!(&exchange(&mut client, b"again").await, b"AGAIN");

    drop(client);
    drain(halves).await;
}

/// **A service offered over the other protocol is refused the same way** as one
/// that does not exist (plan §4.3). The unit test in `config` checks the
/// catalogue's answer; this checks the byte, because the property is about what
/// a caller can learn by asking and only the wire says that.
#[tokio::test]
async fn a_udp_service_is_refused_exactly_as_an_unknown_one_is() {
    let target = shouting_service().await;
    // Offered, but not over TCP -- and TCP is what a stream is.
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let mut stream = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(&mut stream, &tcp_open("dns"))
        .await
        .expect("write the open");
    let offered_as_udp =
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status");
    drop(stream);

    let mut stream = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(&mut stream, &tcp_open("no-such-thing"))
        .await
        .expect("write the open");
    let never_heard_of =
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status");
    drop(stream);

    assert_eq!(offered_as_udp, frame::Status::Refused);
    assert_eq!(
        offered_as_udp, never_heard_of,
        "a caller must not be able to tell a wrong-protocol service from a missing one",
    );

    drain(halves).await;
}

#[tokio::test]
async fn a_service_that_is_not_offered_gets_no_connection() {
    let target = shouting_service().await;
    // The catalogue offers `db`, and the forward below asks for something else.
    let halves = connected(Catalogue::new().with("db", Protocol::Tcp, target)).await;

    let local = client::forward(
        halves.connection().clone(),
        "127.0.0.1:0".parse().unwrap(),
        "not-offered".to_owned(),
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local port");

    // The local accept succeeds — it has to, the refusal has not happened yet —
    // and then the connection closes without carrying anything.
    let mut client = TcpStream::connect(local)
        .await
        .expect("connect to the forward");
    let _ = client.write_all(b"hello").await;
    let mut anything = [0_u8; 1];
    let read = tokio::time::timeout(Duration::from_secs(5), client.read(&mut anything)).await;
    assert!(
        matches!(read, Ok(Ok(0)) | Ok(Err(_))),
        "the forward should have closed, not answered: {read:?}",
    );

    // **And the byte itself arrived**, which the assertion above cannot tell
    // from a stream that was reset — the two look identical to a TCP client,
    // and that is exactly how a status that never left would go unnoticed.
    //
    // In its own scope, because **a `Stream` still in hand is a handle the
    // registration cannot close** — and the wait below would then time out
    // pointing at msquic rather than at the line that is still holding it.
    {
        let mut stream = halves
            .connection()
            .open_outbound_stream(StreamType::Bidirectional, false)
            .await
            .expect("open a stream");
        frame::write_open(&mut stream, &tcp_open("not-offered"))
            .await
            .expect("write the open");
        let status = tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status");
        assert_eq!(status, frame::Status::Refused);
    }

    drain(halves).await;
}

fn tcp_open(service: &str) -> frame::Open {
    frame::Open::Tcp {
        service: service.to_owned(),
    }
}

/// **The phase 3b criterion, minus the resolver.** A datagram reaches the
/// service, the answer comes back out of the port the application sent to, and
/// the session carries a second exchange rather than being one message long.
///
/// The size is the other half of it: a payload at [`MAX_PAYLOAD`] crosses a path
/// with msquic's own datagram arithmetic in the middle, which is the number
/// `datagram`'s constant is deliberately under and the only place it is checked
/// against the real one rather than against itself.
#[tokio::test]
async fn datagrams_reach_the_service_and_come_back() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        false,
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    // Connected, which is what makes the assertion about *where* the reply came
    // from into something the kernel checks: a reply from another address is
    // not delivered here at all, so a forward that answered from a fresh socket
    // would time out rather than quietly pass.
    client.connect(local).await.expect("connect to the forward");

    assert_eq!(&say(&client, b"hello").await, b"HELLO");
    assert_eq!(
        &say(&client, b"again").await,
        b"AGAIN",
        "a session carries more than one datagram",
    );

    let big = vec![b'a'; MAX_PAYLOAD];
    client.send(&big).await.expect("send");
    let mut reply = vec![0_u8; MAX_PAYLOAD + 1];
    let n = tokio::time::timeout(Duration::from_secs(10), client.recv(&mut reply))
        .await
        .expect("the largest allowed payload came back within ten seconds")
        .expect("recv");
    assert_eq!(n, MAX_PAYLOAD, "and it came back whole");
    assert!(reply[..n].iter().all(|b| *b == b'A'));

    assert_eq!(
        halves.sessions().drops.total(),
        0,
        "nothing was dropped along the way",
    );
    drain(halves).await;
}

/// **Two source ports are two sessions**, and their replies must not be
/// swapped. Nothing else in the suite can catch a crossed session table: one
/// source alone gets its own datagrams back however the demultiplexing works.
#[tokio::test]
async fn two_sources_get_their_own_replies() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        false,
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let one = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    one.connect(local).await.expect("connect");
    let two = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    two.connect(local).await.expect("connect");

    // Both in flight before either is read, so a table that keyed on the last
    // sender rather than on the source address has somewhere to go wrong.
    one.send(b"first").await.expect("send");
    two.send(b"secnd").await.expect("send");

    assert_eq!(&read5(&one).await, b"FIRST");
    assert_eq!(&read5(&two).await, b"SECND");
    assert_eq!(halves.sessions().len(), 2, "and they are two sessions");

    drain(halves).await;
}

/// **A payload over the datagram limit now crosses, and comes back.** This test
/// used to assert the opposite — that 1164 bytes reached nobody — and S3 is
/// what changed the answer. It failing is how the round trip was first
/// observed working.
///
/// **Both directions, through the real send path.** The hand-written stream in
/// `an_oversize_datagram_arrives_on_a_stream_of_its_own` pins the wire format
/// independently of our own sender; this one goes through `Sessions::send`,
/// which is the code an application actually reaches — and the reply proves the
/// server's half, where no `--map` reaches and the default is what runs.
#[tokio::test]
async fn an_oversize_datagram_crosses_and_comes_back() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        false,
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.connect(local).await.expect("connect");

    // One byte over the datagram limit, so nothing but the limit itself decides
    // which carrier this takes; and then something a large DNS answer's size,
    // so the test is not only about the boundary.
    for len in [MAX_PAYLOAD + 1, 4096] {
        client.send(&vec![b'a'; len]).await.expect("send");
        let mut reply = vec![0_u8; 70_000];
        let got = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut reply))
            .await
            .unwrap_or_else(|_| panic!("{len} bytes came back within five seconds"))
            .expect("receive");
        assert_eq!(got, len, "the whole datagram, not a prefix");
        assert_eq!(&reply[..got], vec![b'A'; len], "and it went through the service");
    }

    // Small ones still work afterwards, which is the thing to check when a
    // second carrier appears: the first one is what everything else uses.
    assert_eq!(&say(&client, b"after").await, b"AFTER");

    assert_eq!(
        halves.sessions().drops.total(),
        0,
        "and nothing was lost on the way",
    );

    drain(halves).await;
}

/// **The opener's `no-retrans` reaches the answerer.** The flag is on the
/// client's `--map` and the server has only a catalogue, so the open frame is
/// the only way a reply can honour what was asked for — and the large half of a
/// request/response pair is usually the reply.
///
/// Read on the wire rather than through a forward, because what the server does
/// with it is invisible from here: the observable difference needs loss, which
/// is open question 10. What this pins is that the bit travels, and that
/// `None` and `Some(default)` are not confused for each other.
#[tokio::test]
async fn the_openers_no_retrans_choice_crosses() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    for (session, no_retrans) in [(60, false), (61, true)] {
        let mut stream = halves
            .connection()
            .open_outbound_stream(StreamType::Bidirectional, false)
            .await
            .expect("open a stream");
        frame::write_open(
            &mut stream,
            &frame::Open::Udp {
                service: "dns".to_owned(),
                session,
                oversize: Some(frame::OversizeOptions { no_retrans }),
            },
        )
        .await
        .expect("write the open");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
                .await
                .expect("the peer answered within five seconds")
                .expect("read the status"),
            frame::Status::Ready,
            "no_retrans={no_retrans} was accepted",
        );
        drop(stream);
    }

    drain(halves).await;
}

/// **An option the peer does not know is answered, not met with silence.**
///
/// This is open question 12's whole point. Dropping the stream was the obvious
/// refusal and the expensive one: a dead stream is exactly how `open_session`
/// learns that a peer does not know `KIND_UDP_BIG`, so a refused *option*
/// would have been read as a missing *capability* and latched after the second
/// one — costing the connection its oversize datagrams entirely, against a peer
/// that supports them.
///
/// Written by hand because no build can ask for an option it does not have: the
/// bit here is one nothing defines. That is also the limit of this test — it
/// shows the answer arrives, while the inference it protects cannot be driven
/// from one build (open question 8's wall).
#[tokio::test]
async fn an_unknown_oversize_option_is_answered_rather_than_dropped() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let mut stream = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    // The frame by hand: version, the big kind, the name, the session, and a
    // bit no option claims.
    let mut frame = vec![2_u8, 2, 3];
    frame.extend_from_slice(b"dns");
    frame.extend_from_slice(&70_u32.to_be_bytes());
    frame.push(0x80);
    stream.write_all(&frame).await.expect("write the open");

    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status"),
        frame::Status::Unsupported,
        "answered by name rather than by a dead stream",
    );

    // And the connection is untouched: a plain session still opens, which is
    // what would not be true if the refusal had been read as a capability.
    assert_eq!(udp_status(&halves, "dns", 71).await, frame::Status::Ready);

    drop(stream);
    drain(halves).await;
}

/// **`no-retrans` is wired, and costs nothing on a path that is not losing.**
///
/// Whether the stream is actually abandoned on loss is MsQuic's to decide and
/// needs loss to show — `QuicTestMultipathPathValidationRetry` is the shape
/// that would take, with a datapath hook. What can be checked here is the half
/// that would break silently: that asking for it still delivers. A flag that
/// quietly stopped a forward working would otherwise be found by whoever set
/// it.
#[tokio::test]
async fn a_no_retrans_forward_still_delivers() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        true,
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.connect(local).await.expect("connect");

    let len = MAX_PAYLOAD + 1;
    client.send(&vec![b'z'; len]).await.expect("send");
    let mut reply = vec![0_u8; 70_000];
    let got = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut reply))
        .await
        .expect("it came back within five seconds")
        .expect("receive");
    assert_eq!(got, len);
    assert_eq!(&reply[..got], vec![b'Z'; len]);

    // Nothing was given up on, because nothing was lost.
    assert_eq!(
        halves
            .sessions()
            .drops
            .stream_cancelled
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
    );

    drain(halves).await;
}

/// **A session that goes quiet is swept, and the next datagram opens another.**
///
/// The sweep is what keeps a server that has been up for a week from holding a
/// socket and a table entry for every source address that ever spoke to it, and
/// it is the one thing here that shows itself only after a minute of nothing —
/// so the minute is a parameter, and this is what that parameter is for.
///
/// The second exchange is half the test: a sweep that ended the *forward*
/// rather than the session would pass an assertion that only looked at the
/// table.
#[tokio::test]
async fn a_quiet_session_is_swept_and_the_next_datagram_opens_another() {
    let target = shouting_datagram_service().await;
    // **A second, not the 300ms this had first.** The sweep applies to the
    // second exchange below too, which has to open a stream, read a status and
    // reach the service inside it — so a runner that stalls once turns a
    // correct forward into a session swept mid-flight and a ten-second timeout.
    // A second is still nothing next to the wait below and leaves no such race
    // on any machine that can run the rest of this suite.
    let halves = connected_with_idle(
        Catalogue::new().with("dns", Protocol::Udp, target),
        Duration::from_secs(1),
    )
    .await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        false,
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.connect(local).await.expect("connect");
    assert_eq!(&say(&client, b"hello").await, b"HELLO");
    assert_eq!(halves.sessions().len(), 1);

    // Generous next to the sweep, and it asserts on the table rather than on
    // the clock: this waits for the session to go, and fails by timing out
    // rather than by racing.
    let swept = tokio::time::timeout(Duration::from_secs(20), async {
        while !halves.sessions().is_empty() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(swept.is_ok(), "the quiet session was never swept");

    assert_eq!(
        &say(&client, b"again").await,
        b"AGAIN",
        "and the forward still works: a source that comes back gets a new session",
    );
    assert_eq!(halves.sessions().len(), 1);

    drain(halves).await;
}

/// **A session id the peer already has open is refused rather than taken over.**
/// Silently rebinding it would point one id at two sockets, and every datagram
/// after that would reach whichever the table happened to hold — traffic
/// crossing between two conversations, which is the worst thing a forward can
/// do quietly.
#[tokio::test]
async fn a_reused_session_id_is_refused() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    // Held open, so the id is still in the server's table when the second asks
    // for it.
    let mut first = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(
        &mut first,
        &frame::Open::Udp {
            service: "dns".to_owned(),
            session: 77,
            oversize: None,
        },
    )
    .await
    .expect("write the open");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut first))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status"),
        frame::Status::Ready,
    );

    assert_eq!(udp_status(&halves, "dns", 77).await, frame::Status::Refused);
    // And a different id on the same service is still fine, so what was refused
    // was the reuse and not the service.
    assert_eq!(udp_status(&halves, "dns", 78).await, frame::Status::Ready);

    drop(first);
    drain(halves).await;
}

/// Put one oversize datagram on a unidirectional stream of its own.
///
/// Returns the stream, because **the caller has to keep it until the drain**: a
/// finished stream is still a handle the registration waits on, and dropping it
/// early is what made the first version of these tests fail with every
/// assertion passing.
///
/// The head comes from `frame::big_datagram_head` — the real writer — because a
/// test that spells out bytes stops testing the format the moment the format
/// moves.
async fn send_big_datagram(halves: &Halves, session: u32, payload: &[u8]) -> msquic_async::Stream {
    let mut stream = halves
        .connection()
        .open_outbound_stream(StreamType::Unidirectional, false)
        .await
        .expect("open a unidirectional stream");
    stream
        .write_all(&frame::big_datagram_head(session))
        .await
        .expect("write the head");
    stream.write_all(payload).await.expect("write the payload");
    // **Finished, not dropped.** Closing a stream that has not finished aborts
    // it and the datagram never lands -- `camera_core::video::push_one` and
    // `server::refuse` both say so, and S3's send path will do the same.
    std::future::poll_fn(|cx| stream.poll_finish_write(cx))
        .await
        .expect("finish the stream");
    stream
}

/// **The oversize receive path, end to end.** A payload larger than
/// `MAX_PAYLOAD` crosses on a unidirectional stream of its own and reaches the
/// service — which is the whole of S2, and the first time anything larger than
/// 1163 bytes has gone through a forward.
///
/// There is no send side yet, so the stream is written by hand with
/// `frame::big_datagram_head`: the real writer, not bytes spelled out here,
/// because a test that hand-rolls the header stops testing the format the
/// moment the format moves.
#[tokio::test]
async fn an_oversize_datagram_arrives_on_a_stream_of_its_own() {
    let (target, mut arrived) = recording_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    // Opening with the big kind is also the assertion that this build grants
    // it: before S2 `read_open` refused the kind and this would be a dead
    // stream rather than a `Ready`.
    let mut session = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(
        &mut session,
        &frame::Open::Udp {
            service: "dns".to_owned(),
            session: 42,
            oversize: Some(frame::OversizeOptions::default()),
        },
    )
    .await
    .expect("write the open");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut session))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status"),
        frame::Status::Ready,
        "the big kind is granted now that there is an accept loop behind it",
    );

    // Four kilobytes: comfortably past `MAX_PAYLOAD`, and the size a large DNS
    // answer actually is.
    let payload = vec![0xa5_u8; 4096];
    let stream = send_big_datagram(&halves, 42, &payload).await;

    let got = tokio::time::timeout(Duration::from_secs(5), arrived.recv())
        .await
        .expect("the service heard something within five seconds")
        .expect("a datagram");
    assert_eq!(got.len(), payload.len(), "the whole datagram, not a prefix");
    assert_eq!(got, payload);

    // Both, before the drain: a finished stream is still a handle the
    // registration waits on, which `drain` is the one thing that notices.
    drop(stream);
    drop(session);
    drain(halves).await;
}

/// **A stream claiming more than UDP can carry is refused, not assembled.**
/// Nothing this protocol sends is that large, so the only way to see one is a
/// peer choosing how much memory this end should take.
///
/// **The session is held open throughout**, and the first version of this test
/// was worthless for not doing that: `udp_status` drops the lifetime stream
/// when it returns, so the server tore the session down before the oversize
/// stream was read and "the service heard nothing" would have passed with the
/// size check deleted — the delivery would simply have landed on
/// `unknown_session` instead. A good oversize datagram afterwards is what
/// separates "the size was refused" from "there was nothing to deliver to".
#[tokio::test]
async fn a_stream_larger_than_a_datagram_can_be_is_dropped() {
    let (target, mut arrived) = recording_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let mut session = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(
        &mut session,
        &frame::Open::Udp {
            service: "dns".to_owned(),
            session: 43,
            oversize: Some(frame::OversizeOptions::default()),
        },
    )
    .await
    .expect("write the open");
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut session))
            .await
            .expect("the peer answered within five seconds")
            .expect("read the status"),
        frame::Status::Ready,
    );

    let too_big = send_big_datagram(&halves, 43, &vec![0_u8; MAX_STREAM_PAYLOAD + 1]).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(500), arrived.recv())
            .await
            .is_err(),
        "one byte over what UDP can carry delivered nothing",
    );

    // The session is still there and still works, so what was refused was the
    // size rather than the destination.
    let fine = vec![0x5a_u8; 4096];
    let good = send_big_datagram(&halves, 43, &fine).await;
    let got = tokio::time::timeout(Duration::from_secs(5), arrived.recv())
        .await
        .expect("the service heard the good one within five seconds")
        .expect("a datagram");
    assert_eq!(got, fine);

    drop(too_big);
    drop(good);
    drop(session);
    drain(halves).await;
}

/// **A stream that never finishes is given up on, and counted.** The reader
/// holds an `Arc<Sessions>`, and so a `Connection` clone — a handle
/// `RegistrationClose` blocks on, which is the hazard
/// `Sessions::start_with_idle` and `session::Connected::close` both describe.
/// Without a bound, a peer that writes the six-byte head and stops keeps that
/// task parked until the connection dies, and the transport lets it do so a
/// hundred times over.
///
/// Measured on the **client's** `Sessions`, because its counters are the only
/// ones a test can read — hence `Halves::peer_side`, since nothing on the
/// server opens a unidirectional stream until S3.
#[tokio::test]
async fn a_stream_that_never_finishes_is_given_up_on() {
    let target = shouting_datagram_service().await;
    let idle = Duration::from_millis(300);
    let halves = connected_with_idle(Catalogue::new().with("dns", Protocol::Udp, target), idle).await;

    let mut stalled = halves
        .peer_side
        .as_ref()
        .expect("the server side of the connection")
        .open_outbound_stream(StreamType::Unidirectional, false)
        .await
        .expect("open a unidirectional stream towards the client");
    stalled
        .write_all(&frame::big_datagram_head(45))
        .await
        .expect("write the head");
    // And now nothing: no payload, no FIN. Held rather than dropped, because
    // dropping resets the stream and the reader would finish for that reason
    // instead of for the one this test is about.

    // Generously past the deadline, which is `idle` above.
    tokio::time::sleep(idle * 3).await;
    assert_eq!(
        halves
            .sessions()
            .drops
            .stream_lost
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the reader gave up on it rather than waiting for the connection to end",
    );

    drop(stalled);
    drain(halves).await;
}

/// **The path watcher is also how the client learns the peer went away**, and
/// that dual job is load-bearing: a connection's events are a single queue, so
/// `portal-client` cannot both watch paths and separately watch for closure —
/// it dropped its own `closed()` loop for this. If this ever stopped returning,
/// the client would sit with its ports bound over a connection that is gone,
/// accepting connections and answering nothing.
///
/// There is no direct path on a loopback connection, so what is asserted here is
/// only the half a loopback can show. The preferring itself is a hardware check.
#[tokio::test]
async fn the_path_watcher_returns_when_the_connection_ends() {
    let target = shouting_service().await;
    let halves = connected(Catalogue::new().with("db", Protocol::Tcp, target)).await;

    // **One watcher, and the same one throughout.** Spawning a second to check
    // the second half would put two pollers on one event queue, which is the
    // thing this module says must not happen — and a `JoinHandle` dropped after
    // a timeout detaches rather than aborts, so the first would still be there.
    // **The sender is held**, not dropped at the end of the expression. A
    // dropped one makes the first `changed()` answer `Err`, which the watcher
    // reads as "nothing will move this leg again" and stops listening — so the
    // test would pass having exercised the wrong arm. Held, and with a leg in
    // place, it is the state a loopback connection is actually in: a relay
    // that is there and never moves.
    let (_leg, leg) = tokio::sync::watch::channel(Some(
        halves
            .connection()
            .get_remote_addr()
            .expect("a live connection"),
    ));
    let mut watching = tokio::spawn(portal_core::path::keep_on_the_best_path(
        halves.connection().clone(),
        // Its own token, so what ends this is the connection and not the
        // teardown — the cancel arm would pass this test for the wrong reason.
        CancellationToken::new(),
        leg,
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(500), &mut watching)
            .await
            .is_err(),
        "the watcher returned while the connection was still usable",
    );

    drain(halves).await;
    tokio::time::timeout(Duration::from_secs(10), watching)
        .await
        .expect("the watcher noticed the connection end within ten seconds")
        .expect("the watcher did not panic");
}

/// **A TCP service is refused over UDP exactly as an unknown name is**, which
/// is the §4.3 property in the direction 3b added. The stream half of it is
/// asserted above; this is the same question asked with the kinds swapped, and
/// it is a different code path because the catalogue is consulted with a
/// different protocol.
#[tokio::test]
async fn a_tcp_service_is_refused_over_udp_exactly_as_an_unknown_one_is() {
    let target = shouting_service().await;
    let halves = connected(Catalogue::new().with("db", Protocol::Tcp, target)).await;

    let offered_as_tcp = udp_status(&halves, "db", 1).await;
    let never_heard_of = udp_status(&halves, "no-such-thing", 2).await;

    assert_eq!(offered_as_tcp, frame::Status::Refused);
    assert_eq!(
        offered_as_tcp, never_heard_of,
        "a caller must not be able to tell a wrong-protocol service from a missing one",
    );

    drain(halves).await;
}

/// Open a UDP session by hand and read the status byte.
///
/// The stream is dropped on the way out, which ends whatever it opened — so a
/// caller that wants the session to stay open has to hold one itself.
async fn udp_status(halves: &Halves, service: &str, session: u32) -> frame::Status {
    let mut stream = halves
        .connection()
        .open_outbound_stream(StreamType::Bidirectional, false)
        .await
        .expect("open a stream");
    frame::write_open(
        &mut stream,
        &frame::Open::Udp {
            service: service.to_owned(),
            session,
            oversize: None,
        },
    )
    .await
    .expect("write the open");
    tokio::time::timeout(Duration::from_secs(5), frame::read_status(&mut stream))
        .await
        .expect("the peer answered within five seconds")
        .expect("read the status")
}

/// Send five bytes and read five back, on a deadline.
async fn say(client: &UdpSocket, message: &[u8; 5]) -> [u8; 5] {
    client.send(message).await.expect("send");
    read5(client).await
}

async fn read5(client: &UdpSocket) -> [u8; 5] {
    let mut reply = [0_u8; 5];
    let n = tokio::time::timeout(Duration::from_secs(10), client.recv(&mut reply))
        .await
        .expect("the forward answered within ten seconds")
        .expect("recv");
    assert_eq!(n, 5, "the reply was not five bytes");
    reply
}

/// Write five bytes and read five back, on a deadline.
///
/// **Every read here has one.** A forward that never establishes leaves this
/// blocked with nothing to say, and a test that hangs is worse than one that
/// fails — it takes the whole suite with it and says nothing about why.
async fn exchange(client: &mut TcpStream, message: &[u8; 5]) -> [u8; 5] {
    client.write_all(message).await.expect("write");
    let mut reply = [0_u8; 5];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut reply))
        .await
        .expect("the forward answered within ten seconds")
        .expect("read the reply");
    reply
}

/// Release everything, then wait for msquic's handles to close.
///
/// **Takes `Halves` by value**, because waiting while still holding the
/// connection is waiting for something that cannot happen. That used to be
/// spelled out here — clone the `Arc` out, drop the value, wait on what is
/// left — and it is [`isekai_p2p::peer::PeerSession::drain`]'s job now: taking
/// the session by value *is* releasing the connection, and the order it then
/// waits in is msquic's rather than this file's guess at it.
///
/// The cancel stays, because only this test knows which tasks are holding
/// handles. `Halves::drop` does it too, on the path where an assertion failed
/// and this was never reached.
async fn drain(mut halves: Halves) {
    halves.teardown.shutdown.cancel();
    let session = halves.session.take().expect("drained once");
    // Before the wait, not during it: see the fields' own comments.
    drop(halves.sessions.take());
    drop(halves.peer_side.take());
    drop(halves);
    let drained = session.drain(Duration::from_secs(5)).await;
    assert!(drained, "the registration still had live handles after 5s");
}
