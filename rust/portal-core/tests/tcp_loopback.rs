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
use portal_core::{client, frame, server, spike};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

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

/// **Field order is load-bearing, and `Drop` more so.**
///
/// Fields drop in declaration order, so the connection has to come before the
/// registration or the last `Arc<Registration>` goes first and
/// `RegistrationClose` blocks on the handle still open — forever, with no
/// message. And a failing assertion unwinds, so nothing written after it in the
/// test body runs: the teardown has to be in `Drop` or it is not teardown, it is
/// a happy path.
///
/// This is the trap `camera-core/tests/video_loopback.rs` documents, met from
/// the other side: there the danger is dropping a registration you made, here it
/// is failing before you get to.
struct Halves {
    // Before `reg`, deliberately.
    dialed: isekai_p2p::peer::Dialed,
    shutdown: CancellationToken,
    reg: Arc<Registration>,
}

impl Drop for Halves {
    fn drop(&mut self) {
        // Stops the accept loop and the serve task, which is what holds the
        // `Listener`; `shutdown()` then tells msquic to let its handles go so
        // the close below has nothing to wait on. Neither blocks.
        self.shutdown.cancel();
        self.reg.shutdown();
    }
}

/// A portal server offering `catalogue`, and a connection to it.
async fn connected(catalogue: Catalogue) -> Halves {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let (_reg, listener, bound) = spike::bind(Some(reg.clone()), "127.0.0.1:0".parse().unwrap())
        .expect("bind the portal listener");
    let shutdown = CancellationToken::new();

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

    let dialed = spike::dial(&reg, bound.port())
        .await
        .expect("dial the portal");
    Halves {
        dialed,
        shutdown,
        reg,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn bytes_reach_the_service_and_come_back() {
    let target = shouting_service().await;
    let halves = connected(Catalogue::new().with("db", target)).await;

    let local = client::forward(
        halves.dialed.connection().clone(),
        "127.0.0.1:0".parse().unwrap(),
        "db".to_owned(),
        halves.shutdown.clone(),
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
        halves.dialed.connection().clone(),
        "127.0.0.1:0".parse().unwrap(),
        "not-offered".to_owned(),
        halves.shutdown.clone(),
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
            .dialed
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
/// connection is waiting for something that cannot happen — `Drop` is what
/// cancels the tasks and lets the handles go, and it cannot run until the value
/// does. The `Arc` is cloned out first so there is still a registration to wait
/// on afterwards.
///
/// The wait itself is `isekai_p2p::peer::drain_registration`, which is where
/// that rule lives now — it was never a camera thing. It issues a `shutdown()`
/// of its own, which `Halves::drop` has already done; the second is harmless
/// and saying so is cheaper than arranging for exactly one.
async fn drain(halves: Halves) {
    let reg = Arc::clone(&halves.reg);
    drop(halves);
    // The same rule `camera-core` follows, from the place that now states it.
    let drained = isekai_p2p::peer::drain_registration(&reg, Duration::from_secs(5)).await;
    assert!(drained, "the registration still had live handles after 5s");
}
