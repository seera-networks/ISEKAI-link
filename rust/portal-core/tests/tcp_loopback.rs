//! Bytes reach a TCP service through the forward, and a service that is not
//! offered does not get a connection.
//!
//! Phase 0's question is whether the framing and the stream mapping hold up, so
//! this drives a real QUIC connection between the two halves rather than a
//! mock: the `Open`/status exchange, the stream a forwarded connection lives
//! on, and the copy in both directions.
//!
//! **The registration is shared and drained**, for the reason
//! `camera-core/tests/video_loopback.rs` documents at length: `RegistrationClose`
//! is a synchronous, uninterruptible wait on every handle derived from it, so
//! dropping one while a connection is live hangs the process with no way out.

use std::sync::Arc;
use std::time::Duration;

use msquic_async::StreamType;
use msquic_async::{msquic, Registration};
use portal_core::server::Catalogue;
use portal_core::{client, frame, server, transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
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
    reg: Arc<Registration>,
}

impl Drop for Teardown {
    fn drop(&mut self) {
        // Stops the accept loop and the serve task, which is what holds the
        // `Listener`; `shutdown()` then tells msquic to let its handles go so
        // the close has nothing to wait on. Neither blocks, which is the whole
        // reason they are what `Drop` does and the waiting is not.
        self.shutdown.cancel();
        self.reg.shutdown();
    }
}

impl Halves {
    fn connection(&self) -> &msquic_async::Connection {
        self.session
            .as_ref()
            .expect("the session is only taken by `drain`")
            .connection()
    }
}

/// A portal server offering `catalogue`, and a connection to it.
async fn connected(catalogue: Catalogue) -> Halves {
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
        reg: reg.clone(),
    };

    let serving = shutdown.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = serving.cancelled() => {}
            accepted = listener.accept() => {
                if let Ok(conn) = accepted {
                    let _ = server::serve(conn, catalogue).await;
                }
            }
        }
    });

    // `localhost` is the TLS name only — the dial pins the remote address
    // itself — and validation is off because the listener above is presenting
    // the self-signed fallback.
    let session = tokio::time::timeout(
        DIAL_BUDGET,
        transport::connect(
            Some(reg.clone()),
            "localhost",
            bound.port(),
            transport::ConnectOptions::default(),
            &shutdown,
        ),
    )
    .await
    .expect("the loopback handshake completed inside its budget")
    .expect("dial the portal");
    Halves {
        session: Some(session),
        teardown,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bytes_reach_the_service_and_come_back() {
    let target = shouting_service().await;
    let halves = connected(Catalogue::new().with("db", target)).await;

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

#[tokio::test(flavor = "multi_thread")]
async fn a_service_that_is_not_offered_gets_no_connection() {
    let target = shouting_service().await;
    // The catalogue offers `db`, and the forward below asks for something else.
    let halves = connected(Catalogue::new().with("db", target)).await;

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
        frame::write_open(&mut stream, "not-offered")
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
    drop(halves);
    let drained = session.drain(Duration::from_secs(5)).await;
    assert!(drained, "the registration still had live handles after 5s");
}
