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
use portal_core::datagram::MAX_PAYLOAD;
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
    tokio::spawn(async move {
        tokio::select! {
            _ = serving.cancelled() => {}
            accepted = listener.accept() => {
                if let Ok(conn) = accepted {
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

/// **A payload over the limit is dropped and counted, not truncated.** The unit
/// test in `datagram` checks that `encode` refuses one; this checks that the
/// refusal is where the traffic actually is — nothing reaches the service, the
/// session survives it, and the counter says so.
#[tokio::test]
async fn an_oversize_datagram_is_dropped_and_counted() {
    let target = shouting_datagram_service().await;
    let halves = connected(Catalogue::new().with("dns", Protocol::Udp, target)).await;

    let local = udp::forward(
        Arc::clone(halves.sessions()),
        "127.0.0.1:0".parse().unwrap(),
        "dns".to_owned(),
        halves.teardown.shutdown.clone(),
    )
    .await
    .expect("forward a local UDP port");

    let client = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    client.connect(local).await.expect("connect");

    // One byte over, so nothing but the limit itself decides this.
    client
        .send(&vec![b'a'; MAX_PAYLOAD + 1])
        .await
        .expect("send");
    let mut reply = vec![0_u8; 70_000];
    let answered = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut reply)).await;
    assert!(
        answered.is_err(),
        "a payload that will not fit must not arrive in pieces: {answered:?}",
    );
    assert_eq!(
        halves
            .sessions()
            .drops
            .oversize
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "and the drop is counted where an operator can see it",
    );

    // The session is still usable, which is the difference between dropping a
    // datagram and failing a forward.
    assert_eq!(&say(&client, b"after").await, b"AFTER");

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
    // Before the wait, not during it: see the field's own comment.
    drop(halves.sessions.take());
    drop(halves);
    let drained = session.drain(Duration::from_secs(5)).await;
    assert!(drained, "the registration still had live handles after 5s");
}
