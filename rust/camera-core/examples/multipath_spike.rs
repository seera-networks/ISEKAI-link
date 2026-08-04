//! Does multipath solve the decaying direct path, and can it be shipped?
//!
//! `docs/p2p_mode_migration_plan.md` risk #24: a direct path validates, nobody
//! sends on it, and the hairpin NAT mapping it created goes away — so migrating
//! onto it a minute later fails. There is no way to keep a non-active path warm
//! within the standard, because a probing packet may carry only PATH_CHALLENGE,
//! PATH_RESPONSE, NEW_CONNECTION_ID and PADDING. Multipath removes the problem
//! rather than solving it: both paths are active, so both carry traffic.
//!
//! Before any of that reaches the shipping path, four questions decide whether
//! the shape works and whether it can be rolled out one side at a time. This
//! reproduces the relay topology on one host — a loopback bridge standing in for
//! the client's CONNECT-UDP leg, the proxy and the server's bind leg — so every
//! answer comes without a proxy, a relay or a NAT.
//!
//! | # | Question | Fails the run |
//! | --- | --- | --- |
//! | 1 | Does a multipath handshake complete through the bridge? | yes |
//! | 2 | Does the client learn the peer's second address, and does `add_path` on it produce `PathAdded` on both ends? | yes |
//! | 3 | Does declaring a path backup reach the peer as `PathStatusChanged`? | yes |
//! | 4 | **Does a multipath client still connect to a peer without it?** | yes |
//! | 5 | Do both paths still carry traffic after the window a validated path used to decay in? | records |
//!
//! **The harness is not finished.** The peer advertises the listener's own
//! address, and it has to advertise a second socket standing in for the relay
//! leg — shared and unconnected — because that is the only kind of address
//! `add_bound_addr` takes. See the comment at the call.
//!
//! Question 4 is the one that decides the rollout. If a client with multipath
//! cannot talk to a camera without it, the two have to ship together, and every
//! mixed pair in between is broken video.
//!
//! Question 5 is the point of the exercise, and it is recorded rather than
//! enforced: sixty seconds on a loopback bridge is not a NAT, so a pass here is
//! necessary and not sufficient. What would fail on hardware and pass here is a
//! mapping that lapses; what this can still catch is a path that msquic stops
//! using on its own.
//!
//! ```text
//! cargo run --example multipath_spike -p camera-core
//! ```

use std::io::Write as _;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use msquic_async::{msquic, Connection, ConnectionEvent, Listener, Registration};
use std::future::poll_fn;
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

const ALPN: &str = "multipath-spike";

/// How long question 5 watches after both paths are up.
///
/// Longer than the gap that failed on a device — a direct path validated and
/// activated thirty-nine seconds later carried nothing, while fourteen seconds
/// later worked.
const OBSERVE: Duration = Duration::from_secs(60);

/// How often traffic is pushed while watching.
const PUSH_INTERVAL: Duration = Duration::from_millis(200);

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "multipath_spike=info".into()),
        )
        .init();

    let registration = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);

    let mut failures = Vec::new();

    match multipath_round_trip(&registration).await {
        Ok(()) => {}
        Err(e) => {
            println!("FAIL  questions 1-3, 5: {e:#}");
            failures.push("1-3,5");
        }
    }

    match mixed_versions(&registration).await {
        Ok(line) => println!("{line}"),
        Err(e) => {
            println!("FAIL  question 4 (multipath client, plain peer): {e:#}");
            failures.push("4");
        }
    }

    if failures.is_empty() {
        println!("\nall load-bearing questions answered");
        Ok(())
    } else {
        anyhow::bail!("unanswered: {}", failures.join(", "))
    }
}

/// Questions 1, 2, 3 and 5.
async fn multipath_round_trip(reg: &Arc<Registration>) -> anyhow::Result<()> {
    let listener = start_listener(reg, true)
        .await
        .context("multipath listener")?;
    let direct_addr = listener.addr;
    // The relay: the client dials this, and it forwards to the listener. Standing
    // in for the CONNECT-UDP leg, the proxy and the bind leg all at once.
    let bridge = Bridge::start(direct_addr).await.context("bridge")?;

    let client = Connection::new(reg).context("client connection")?;
    // Multipath identifies a connection by its source connection id, which only a
    // shared binding gives a non-zero length. Without this the handshake is
    // refused outright — which is also the first thing to check, because the
    // video connection does not set it today.
    client.set_share_binding(true).context("share binding")?;
    // The connection's own address is left to msquic. Pinning it and then
    // sharing the binding is what `QUIC_STATUS_ADDRESS_IN_USE` came out of.

    let config = client_config(reg, true).context("client config")?;
    let (started, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.start(&config, "127.0.0.1", bridge.front_addr.port()),
            listener.listener.accept(),
        )
    })
    .await
    .context("the multipath handshake did not complete within 10s")?;
    started.context("multipath client start")?;
    let server = accepted.context("multipath accept")?;
    println!(
        "PASS  1. multipath handshake through the bridge (relay path {} -> {})",
        client.get_local_addr()?,
        client.get_remote_addr()?
    );

    // What a camera does: tell the peer where else it can be reached. Here the
    // listener's own address stands in for the address a NAT would report.
    // WRONG, and left here with the reason because it is what this harness has
    // to be rebuilt around.
    //
    // `add_bound_addr` adds a binding to a connection that has only been bound
    // to localhost. What it takes is a local address whose observed address is
    // known — which means the local address of the connection to the proxy,
    // because that is the one the proxy reports a public mapping for. For the
    // video connection to be able to share it, the proxy connection has to be
    // opened with a shared binding and an unconnected socket, which is what
    // `RelayOptions::unconnected` already does in the shipping code.
    //
    // The listener's own address is neither of those things: nothing has told
    // anyone how it is seen from outside, and it is already bound — hence the
    // ADDRESS_IN_USE, which was never about a conflict to work around.
    //
    // So this harness needs a second socket standing in for the relay leg,
    // shared and unconnected, and has to advertise that one. Reproducing it is
    // the next step.
    if let Err(e) = server.add_bound_addr(direct_addr) {
        println!("NOTE  the peer could not claim {direct_addr} as its own: {e}");
    }
    server
        .add_observed_addr(direct_addr, direct_addr)
        .context("advertising the peer's second address")?;
    // And what the viewer does: offer where it can be reached, so the peer
    // probes it. No `add_path` — in this mode msquic opens the path itself once
    // the probe validates.
    client
        .add_candidate_addr(client.get_local_addr()?, client.get_local_addr()?)
        .context("offering a candidate")?;

    // With multipath negotiated, a validated path is added rather than migrated
    // onto, and `PathAdded` is what names it.
    let (client_path, server_path) = tokio::time::timeout(Duration::from_secs(15), async {
        tokio::join!(path_added(&client), path_added(&server))
    })
    .await
    .context("no path was added on either end within 15s")?;
    let client_path = client_path?;
    let server_path = server_path?;
    println!(
        "PASS  2. NAT traversal added a path on both ends without add_path \
         (client path {client_path}, server path {server_path})"
    );

    // Relay as backup, direct as available: the declaration that replaces
    // switching. Path 0 is the connection's first path — the relay one.
    client
        .set_path_status(0, false)
        .context("declaring the relay path backup")?;
    client
        .set_path_status(client_path, true)
        .context("declaring the direct path available")?;

    let changed = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match poll_fn(|cx| server.poll_event(cx)).await {
                Ok(ConnectionEvent::PathStatusChanged {
                    path_id, is_active, ..
                }) => return Ok((path_id, is_active)),
                Ok(_) => continue,
                Err(e) => return Err(anyhow::anyhow!("server event stream ended: {e}")),
            }
        }
    })
    .await
    .context("the peer never reported a path status change")??;
    println!(
        "PASS  3. the peer sees the declaration (path {} active={})",
        changed.0, changed.1
    );

    // Question 5: keep sending, and see whether both paths are still there after
    // the window a validated path used to decay in.
    let started_watching = Instant::now();
    let mut removed = Vec::new();
    let mut pushes = 0u32;
    let mut ticker = tokio::time::interval(PUSH_INTERVAL);
    while started_watching.elapsed() < OBSERVE {
        tokio::select! {
            _ = ticker.tick() => {
                // A datagram rather than a stream: the point is that packets keep
                // leaving, not that anything is delivered in order.
                if client.send_datagram(&bytes::Bytes::from_static(&[0u8; 512])).is_ok() {
                    pushes += 1;
                }
            }
            event = poll_fn(|cx| client.poll_event(cx)) => match event {
                Ok(ConnectionEvent::PathRemoved { path_id, .. }) => removed.push(path_id),
                Ok(_) => {}
                Err(e) => anyhow::bail!("the connection ended while watching: {e}"),
            },
        }
    }
    let verdict = if removed.is_empty() { "PASS" } else { "NOTE" };
    println!(
        "{verdict}  5. after {}s and {pushes} pushes, paths removed: {removed:?} \
         (loopback, so this cannot see a NAT mapping lapse)",
        OBSERVE.as_secs()
    );

    bridge.stop();
    Ok(())
}

/// Question 4: a multipath client against a peer that has never heard of it.
///
/// This is the rollout question. A camera and a viewer are updated separately,
/// so every mixed pair has to keep working — and if it does not, both sides have
/// to ship at once and every user in between has broken video.
async fn mixed_versions(reg: &Arc<Registration>) -> anyhow::Result<String> {
    let listener = start_listener(reg, false).await?;
    let bridge = Bridge::start(listener.addr).await?;

    let client = Connection::new(reg)?;
    client.set_share_binding(true)?;
    let config = client_config(reg, true)?;

    let (started, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.start(&config, "127.0.0.1", bridge.front_addr.port()),
            listener.listener.accept(),
        )
    })
    .await
    .context("a multipath client could not connect to a peer without multipath within 10s")?;
    started.context("start against a peer without multipath")?;
    accepted.context("accept from a client with multipath")?;

    bridge.stop();
    Ok("PASS  4. a multipath client connects to a peer without it".to_owned())
}

async fn path_added(conn: &Connection) -> anyhow::Result<u32> {
    loop {
        match poll_fn(|cx| conn.poll_event(cx)).await {
            Ok(ConnectionEvent::PathAdded { path_id, .. }) => return Ok(path_id),
            Ok(_) => continue,
            Err(e) => anyhow::bail!("event stream ended before the path was added: {e}"),
        }
    }
}

fn client_config(reg: &Registration, multipath: bool) -> anyhow::Result<msquic::Configuration> {
    let alpn = [msquic::BufferRef::from(ALPN)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        .set_PeerUnidiStreamCount(100)
        .set_DatagramReceiveEnabled()
        .set_ReceiveObservedAddressReports()
        // NAT traversal stays. It is what opens a path between two peers that
        // are both behind NATs — hole punching is the whole point — and an
        // application adding paths by hand cannot do that. Multipath goes on
        // top: the path NAT traversal validates becomes another active path
        // rather than somewhere to migrate to.
        //
        // Which also settles why `NotifyRemoteAddressAdded` never arrived. That
        // event is for the application that adds its own paths, and in this mode
        // msquic adds them; asking for both gets the automatic behaviour and no
        // event. There is nothing to aim `add_path` at because nothing needs to.
        .set_AddAddressMode(msquic::AddAddressMode::NatTraversal);
    let settings = if multipath {
        settings.set_MultipathEnabled()
    } else {
        settings
    };
    let config = reg.open_configuration(&alpn, Some(&settings))?;
    config.load_credential(
        &msquic::CredentialConfig::new_client()
            .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION),
    )?;
    Ok(config)
}

struct SpikeListener {
    addr: SocketAddr,
    listener: Listener,
    _reg: Arc<Registration>,
}

async fn start_listener(reg: &Arc<Registration>, multipath: bool) -> anyhow::Result<SpikeListener> {
    let cert = camera_core::tls::dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let alpn = [msquic::BufferRef::from(ALPN)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        .set_PeerUnidiStreamCount(100)
        .set_DatagramReceiveEnabled()
        .set_ReceiveObservedAddressReports()
        .set_AddAddressMode(msquic::AddAddressMode::NatTraversal);
    let settings = if multipath {
        settings.set_MultipathEnabled()
    } else {
        settings
    };
    let config = reg.open_configuration(&alpn, Some(&settings))?;

    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(cert.cert_pem.as_bytes())?;
    let cert_path = cert_file.into_temp_path();
    let mut key_file = tempfile::NamedTempFile::new()?;
    key_file.write_all(cert.key_pem.as_bytes())?;
    let key_path = key_file.into_temp_path();
    config.load_credential(&msquic::CredentialConfig::new().set_credential(
        msquic::Credential::CertificateFile(msquic::CertificateFile::new(
            key_path.to_string_lossy().into_owned(),
            cert_path.to_string_lossy().into_owned(),
        )),
    ))?;

    let listener = Listener::new(reg, config).context("listener new")?;
    listener
        .start(&alpn, Some("127.0.0.1:0".parse()?))
        .context("listener start")?;
    let addr = listener.local_addr().context("listener local_addr")?;
    Ok(SpikeListener {
        addr,
        listener,
        _reg: reg.clone(),
    })
}

/// Two loopback sockets forwarding both ways, standing in for the relay chain.
struct Bridge {
    front_addr: SocketAddr,
    shutdown: CancellationToken,
}

impl Bridge {
    async fn start(target: SocketAddr) -> anyhow::Result<Self> {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let front_addr = front.local_addr()?;
        let shutdown = CancellationToken::new();

        let token = shutdown.clone();
        tokio::spawn(async move {
            let mut client: Option<SocketAddr> = None;
            let mut up = vec![0u8; 65_535];
            let mut down = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    r = front.recv_from(&mut up) => match r {
                        Ok((n, src)) => {
                            client = Some(src);
                            let _ = back.send_to(&up[..n], target).await;
                        }
                        Err(_) => break,
                    },
                    r = back.recv_from(&mut down) => match r {
                        Ok((n, _)) => {
                            if let Some(dst) = client {
                                let _ = front.send_to(&down[..n], dst).await;
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        Ok(Self {
            front_addr,
            shutdown,
        })
    }

    fn stop(self) {
        self.shutdown.cancel();
    }
}
