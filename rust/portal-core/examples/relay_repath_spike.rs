//! Can a restarted relay be added back as a path? (`docs/relay_repath_plan.md` P0)
//!
//! A relay server restarting takes the leg with it, and today the inner QUIC
//! connection never uses a relay again. The plan is to open a new leg and swap
//! it in over multipath. Five questions decide the shape, and none of them
//! needs a relay to answer: a UDP forwarder on loopback stands in for the
//! client's CONNECT-UDP leg, the relay and the server's bind leg all at once,
//! and killing it is the relay restarting.
//!
//!     cargo run -p portal-core --example relay_repath_spike
//!
//! | # | Question | Why it decides something |
//! | --- | --- | --- |
//! | 1 | Does `add_path` take a **loopback** remote on a connection set up the way `dial` sets one up? | The whole client half rests on it |
//! | 2 | Does `PathAdded` name the new path, and how soon? | The re-attach has to know when it may prefer the new leg |
//! | 3 | **Does the server grow a path with no server-side call at all?** | If yes, `add_bound_addr` and the forward re-pointing leave the plan |
//! | 4 | Does traffic actually cross the new leg once the old one is dead? | A validated path that carries nothing is the failure this exists to avoid |
//! | 5 | Does `remove_path` free a slot, and when? | `QUIC_MAX_PATH_COUNT` is 4 and the plan says the removal is asynchronous |
//!
//! # **Run it more than once**
//!
//! About one run in three fails question 2 and everything after it: `add_path`
//! returns `Ok`, the path count rises, and **no probe is ever sent**, because
//! the new path was given no destination connection id — `connection.c:9363`
//! guards the `PATH_CHALLENGE` on `Path->DestCid != NULL`, and `pathid.c:750`
//! assigns one only while a spare is in the pool. The failure line says which
//! silence it was, by reporting how many datagrams reached the new leg.
//!
//! **That is a finding, not a flaw in the harness** (`relay_repath_plan.md`
//! §0.1.1), and it is why one green run says nothing. The first four runs of
//! this spike all passed, and the plan recorded them as settled fact.
//!
//! **The connection is built by `transport::connect`**, so the answers are
//! about the arrangement portal actually ships: the same settings, the same
//! `share_binding` / `unconnected_socket` / loopback local address, the same
//! multipath.
//!
//! The direct-path candidate offered is deliberately one that cannot validate.
//! Multipath has to be on — it is the prerequisite — but a direct path forming
//! would answer question 3 for the wrong reason, and a session with multipath
//! and no usable direct path is a real case rather than a contrivance.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use msquic_async::{msquic, Connection, ConnectionEvent, Registration};
use portal_core::transport;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// How long any one question waits before it is answered "no".
const PATIENCE: Duration = Duration::from_secs(10);

/// A candidate that cannot validate, so multipath is on and no direct path
/// forms. `192.0.2.0/24` is TEST-NET-1: reserved for documentation, routed
/// nowhere.
const UNREACHABLE: &str = "192.0.2.1:9";

#[tokio::main]
async fn main() -> anyhow::Result<std::convert::Infallible> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "relay_repath_spike=info".into()),
        )
        .init();

    let code = match run().await {
        Ok(failures) if failures.is_empty() => {
            println!("\nall five questions answered");
            0
        }
        Ok(failures) => {
            println!("\nunanswered: {}", failures.join(", "));
            1
        }
        Err(e) => {
            println!("\nthe spike could not be set up: {e:#}");
            1
        }
    };
    // **Leaves rather than returns**, for the reason `portal_core::shutdown`
    // gives: a live connection makes `RegistrationClose` a blocking,
    // uninterruptible wait, and letting the runtime drop underneath it ends in
    // a core dump.
    portal_core::shutdown::leave(code).await
}

async fn run() -> anyhow::Result<Vec<&'static str>> {
    let mut failures = Vec::new();
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);
    let shutdown = CancellationToken::new();

    let (_reg, listener, bound) = transport::bind(
        Some(reg.clone()),
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        None,
    )?;

    // The relay, first time round.
    let first = Bridge::start(bound).await?;
    println!("  relay stand-in 1 at {}", first.front_addr);

    let accepting = tokio::spawn(async move { listener.accept().await });
    let session = tokio::time::timeout(
        PATIENCE,
        transport::connect(
            Some(reg.clone()),
            "127.0.0.1",
            first.front_addr.port(),
            transport::ConnectOptions {
                verify: false,
                pin: None,
                candidate: Some(isekai_p2p::agent::ObservedAddress {
                    local: SocketAddr::from((Ipv4Addr::LOCALHOST, 1)),
                    observed: UNREACHABLE.parse()?,
                }),
            },
            &shutdown,
        ),
    )
    .await
    .map_err(|_| anyhow::anyhow!("the handshake did not complete through the relay stand-in"))??;
    let client = session.connection().clone();
    let server = tokio::time::timeout(PATIENCE, accepting).await???;

    println!(
        "\n  handshake done: client relay path {} -> {}",
        client.get_local_addr()?,
        client.get_remote_addr()?,
    );
    // **Taken here, before anything is asked of either side.** A first draft
    // read it after waiting for the client's `PathAdded` -- by which time the
    // server had already grown its path, so the comparison was against the
    // answer and question 3 reported the opposite of what happened.
    let server_at_handshake = paths(&server)?;
    println!(
        "  paths: client {}  server {server_at_handshake}",
        paths(&client)?,
    );
    let old_pair = (client.get_local_addr()?, client.get_remote_addr()?);

    // **The relay restarts.** The old leg's sockets go with it, exactly as a
    // MASQUE client dying takes its per-source sockets (`from_quic_to_udp`
    // keys them by `(stream, source)` and the table lives inside the client).
    // **The window the destination CIDs arrive in, waited out on purpose.**
    //
    // Both ends generate source CIDs for every path id up to the limit when the
    // handshake completes (`crypto.c:1653` ->
    // `QuicPathIDSetGenerateNewSourceCids`), and the frames then have to
    // travel. Stop the relay inside that window and path id 1 has no
    // destination CID -- so `add_path` opens a path msquic will never probe,
    // because the only code that assigns one runs on the receive path and
    // nothing is arriving any more.
    //
    // **Waited out on purpose**, and this is the whole finding of the spike.
    //
    // At the handshake both ends create path ids up to the limit and generate
    // source CIDs for each (`crypto.c:1653`), and the peer's
    // `PATH_NEW_CONNECTION_ID` frames then have to cross. An LTTng trace of a
    // failing run shows the server queueing its CIDs for path ids 1-3
    // **3.8 microseconds after the last packet arrived** -- the relay was
    // already gone, and the client never gets a destination CID for path id 1.
    // `add_path` then opens a path msquic will never probe, because the only
    // code that assigns one runs on the receive path.
    //
    // Measured under LTTng, alternating with a 0 ms control so a quiet spell
    // could not pass for an effect:
    //
    //     settle      failed
    //     0 ms        6 / 15
    //     5000 ms     0 / 15   (and 0 / 25 separately)
    //
    // `RELAY_REPATH_SETTLE_MS=0` reproduces the race.
    let settle = std::env::var("RELAY_REPATH_SETTLE_MS")
        .ok()
        .and_then(|ms| ms.parse::<u64>().ok())
        .unwrap_or(5000);
    if settle > 0 {
        tokio::time::sleep(Duration::from_millis(settle)).await;
    }
    let first_back = first.back_addr;
    first.stop().await;
    let second = Bridge::start(bound).await?;
    println!(
        "\n  relay stand-in 1 stopped; 2 at {} (the server will see {})",
        second.front_addr, second.back_addr,
    );
    // The one way this experiment can lie about question 3: the kernel handing
    // the replacement the port it just freed, so the server's view of the
    // remote never changes and no path could grow whatever msquic did.
    anyhow::ensure!(
        first_back != second.back_addr,
        "the replacement leg got the port the old one just freed ({}); \
         run again -- this experiment cannot say anything about question 3",
        second.back_addr,
    );

    // ---- 1 ----
    let added = client.add_path(
        SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
        second.front_addr,
    );
    match &added {
        Ok(()) => println!("\nPASS  1. add_path took a loopback remote"),
        Err(e) => {
            println!("\nFAIL  1. add_path refused a loopback remote: {e}");
            failures.push("1");
        }
    }

    // ---- 2 ----
    let began = tokio::time::Instant::now();
    let client_path = match added {
        Ok(()) => wait_for_path_added(&client, second.front_addr).await,
        Err(_) => None,
    };
    match client_path {
        Some(path_id) => println!(
            "PASS  2. PathAdded named it: path_id {path_id} after {:?}",
            began.elapsed(),
        ),
        None => {
            // **Which of the two silences it was.** `add_path` returns `Ok`
            // and raises the path count either way, but no `PATH_CHALLENGE`
            // is queued unless the new path has a destination connection id
            // (`connection.c:9363`, guarded on `Path->DestCid != NULL`), and
            // one is only assigned while a spare is in the pool
            // (`pathid.c:750`). Nothing leaving the client is that case;
            // packets leaving and no answer coming back is a different one.
            println!(
                "FAIL  2. no PathAdded within {PATIENCE:?} -- {} datagram(s) reached \
                 the new leg, so the probe {}",
                second.forwarded(),
                match second.forwarded() {
                    0 => "was never sent (no destination CID for the new path?)",
                    _ => "went out and went unanswered",
                },
            );
            failures.push("2");
        }
    }

    // ---- 3 ----
    //
    // Nothing was called on the server. If a path grew there, it grew from the
    // packets arriving at the binding it already had, from the new leg's new
    // source socket -- which is the one case the core lets a server open a path
    // for (`path.c:358`, server with no server-migration negotiated).
    let grew = wait_until(PATIENCE, || {
        paths(&server).is_ok_and(|n| n > server_at_handshake)
    })
    .await;
    if grew {
        println!(
            "PASS  3. the server grew a path with no server-side call ({} -> {})",
            server_at_handshake,
            paths(&server)?,
        );
    } else {
        println!(
            "FAIL  3. the server still has {server_at_handshake} path(s); \
             add_bound_addr stays in the plan",
        );
        failures.push("3");
    }

    // ---- 4 ----
    //
    // The old leg is dead, so anything that arrives came over the new one.
    let before = second.forwarded();
    let crossed = wait_until(PATIENCE, || second.forwarded() > before + 4).await;
    if crossed {
        println!(
            "PASS  4. traffic crosses the new leg ({} datagrams forwarded)",
            second.forwarded(),
        );
    } else {
        println!("FAIL  4. nothing crossed the new leg within {PATIENCE:?}");
        failures.push("4");
    }

    // ---- 5 ----
    let before = paths(&client)?;
    match client.remove_path(old_pair.0, old_pair.1) {
        Ok(()) => {
            let freed = wait_until(PATIENCE, || paths(&client).is_ok_and(|n| n < before)).await;
            println!(
                "PASS  5. remove_path returned; the slot {} ({} -> {})",
                if freed {
                    "came back"
                } else {
                    "had NOT come back -- asynchronous, as the plan says"
                },
                before,
                paths(&client)?,
            );
        }
        Err(e) => {
            println!("FAIL  5. remove_path refused the old pair: {e}");
            failures.push("5");
        }
    }

    println!(
        "\n  final: client {} path(s), server {} path(s), cap is 4",
        paths(&client)?,
        paths(&server)?,
    );

    shutdown.cancel();
    second.stop().await;
    // Held to the end deliberately: dropping either closes the connection and
    // takes the numbers above with it.
    std::mem::forget(session);
    std::mem::forget(server);
    std::mem::forget(reg);
    Ok(failures)
}

/// How many paths msquic is tracking.
///
/// **An error is not zero.** Reading a baseline as 0 because the call failed
/// turns "no growth" into "grew from nothing", which is the class of
/// mis-measurement this spike has already made once.
fn paths(conn: &Connection) -> anyhow::Result<usize> {
    Ok(conn
        .get_path_statistics()
        .map_err(|e| anyhow::anyhow!("{e}"))?
        .len())
}

/// Wait for `PathAdded` naming `remote`, draining everything else.
async fn wait_for_path_added(conn: &Connection, remote: SocketAddr) -> Option<u32> {
    tokio::time::timeout(PATIENCE, async {
        loop {
            match std::future::poll_fn(|cx| conn.poll_event(cx)).await {
                Ok(ConnectionEvent::PathAdded {
                    path_id,
                    peer_address,
                    ..
                }) if peer_address == remote => return Some(path_id),
                Ok(_) => continue,
                Err(_) => return None,
            }
        }
    })
    .await
    .ok()
    .flatten()
}

/// Poll `ready` until it is true or the patience runs out.
async fn wait_until(limit: Duration, mut ready: impl FnMut() -> bool) -> bool {
    let deadline = tokio::time::Instant::now() + limit;
    loop {
        if ready() {
            return true;
        }
        if tokio::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A UDP forwarder standing in for the client's leg, the relay and the
/// server's bind leg at once.
///
/// **Its back socket is what the server sees as the remote**, and it is a new
/// ephemeral socket every time one of these starts — which is the arrangement
/// `from_quic_to_udp` produces, where a socket is bound per `(stream, source)`
/// and the whole table dies with the MASQUE client.
struct Bridge {
    front_addr: SocketAddr,
    /// What the server sees as the remote. **A new leg has to present a new
    /// one** or no path can grow, and the kernel may hand back a port it just
    /// freed -- so this is reported rather than assumed.
    back_addr: SocketAddr,
    forwarded: Arc<AtomicU64>,
    shutdown: CancellationToken,
    task: tokio::task::JoinHandle<()>,
}

impl Bridge {
    async fn start(target: SocketAddr) -> anyhow::Result<Self> {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let front_addr = front.local_addr()?;
        let back_addr = back.local_addr()?;
        let shutdown = CancellationToken::new();
        let forwarded = Arc::new(AtomicU64::new(0));

        let counter = forwarded.clone();
        let token = shutdown.clone();
        let task = tokio::spawn(async move {
            let mut client: Option<SocketAddr> = None;
            let mut up = vec![0u8; 65_535];
            let mut down = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    r = front.recv_from(&mut up) => match r {
                        Ok((n, src)) => {
                            client = Some(src);
                            // **Counted only when it left.** Counting the
                            // attempt lets question 4 report traffic crossing
                            // a leg that refused every datagram.
                            if back.send_to(&up[..n], target).await.is_ok() {
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => break,
                    },
                    r = back.recv_from(&mut down) => match r {
                        Ok((n, _)) => {
                            if let Some(dst) = client {
                                if front.send_to(&down[..n], dst).await.is_ok() {
                                    counter.fetch_add(1, Ordering::Relaxed);
                                }
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        Ok(Self {
            front_addr,
            back_addr,
            forwarded,
            shutdown,
            task,
        })
    }

    fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    /// Stop forwarding and wait for the sockets to go, which is what makes this
    /// a relay that restarted rather than one that is merely quiet.
    async fn stop(self) {
        self.shutdown.cancel();
        let _ = self.task.await;
    }
}
