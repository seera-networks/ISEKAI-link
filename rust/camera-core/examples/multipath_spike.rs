//! Does multipath solve the decaying direct path, and can it be shipped?
//!
//! `docs/p2p_mode_migration_plan.md` risk #24: a direct path validates, nobody
//! sends on it, and the hairpin NAT mapping it created goes away — so migrating
//! onto it a minute later fails. There is no way to keep a non-active path warm
//! within the standard, because a probing packet may carry only PATH_CHALLENGE,
//! PATH_RESPONSE, NEW_CONNECTION_ID and PADDING. Multipath removes the problem
//! rather than solving it: both paths are active, so both carry traffic.
//!
//! Before any of that reaches the shipping path, five questions decide whether
//! the shape works and whether it can be rolled out one side at a time. This
//! reproduces the relay topology on one host — a loopback bridge standing in for
//! the client's CONNECT-UDP leg, the proxy and the server's bind leg, and a
//! relay leg on each side for the addresses that get advertised — so every
//! answer comes without a proxy, a relay or a NAT.
//!
//! | # | Question | Fails the run |
//! | --- | --- | --- |
//! | 1 | Does a multipath handshake complete through the bridge? | yes |
//! | 2 | Does NAT traversal add a path on both ends, and does `PathAdded` name it? | yes |
//! | 3 | Does declaring a path backup reach the peer as `PathStatusChanged`? | yes |
//! | 4 | **Does a multipath client still connect to a peer without it?** | yes |
//! | 5 | Do both paths survive the window a validated path used to decay in, with the application silent? | yes |
//! | 6 | **And the other way round — a plain client against a peer with it?** | yes |
//!
//! The two sides are set up the way the shipping code sets them up, because the
//! answers are only worth having if they are about that arrangement: the viewer
//! makes `prepare_for_migration`'s four calls before `start` — shared binding,
//! unconnected socket, a *loopback* local address, and the leg's address as a
//! candidate — and the camera makes `apply_direct_path`'s two afterwards,
//! claiming the leg's binding and advertising it.
//!
//! Questions 4 and 6 are the ones that decide the rollout, and they are asked
//! in both directions because both happen: cameras and viewers are updated
//! separately, so a mixed pair that cannot talk means shipping both sides at
//! once with every user in between on broken video. Question 6 is the order the
//! video listener's own change lands in — the camera offering multipath to
//! viewers that have never heard of it.
//!
//! Question 5 is the point of the exercise, and it turns on a setting neither
//! side had: `KeepAliveIntervalMs` defaults to 0, which means no PING is ever
//! sent. With multipath negotiated msquic marks *every* in-use path and sends a
//! PING on each in its own datagram — exactly what a path nobody sends on needs
//! — but only if the interval is set, and each connection's timer is driven by
//! its own settings. So both sides set it, and `SPIKE_KEEPALIVE` is there to run
//! the controls.
//!
//! The window is deliberately silent: the application sends nothing for sixty
//! seconds, so the keepalive is the only thing holding either path up, and the
//! 30s idle timeout is the detector. A pass is still necessary and not
//! sufficient — a loopback bridge is not a NAT, so what would fail on hardware
//! and pass here is a mapping that lapses.
//!
//! ```text
//! cargo run --example multipath_spike -p camera-core
//! ```

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
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

/// How often each side sends a keepalive PING.
///
/// Load-bearing, and needed on **both** sides. The default is 0 — no PING is
/// ever sent — and the timer is driven by each connection's own settings, so a
/// camera that does not set it never pings whatever the viewer does. Multipath
/// makes that worse rather than better: with it negotiated, msquic marks *every*
/// in-use path and sends a PING on each in its own datagram, precisely because a
/// path the peer stops hearing from is abandoned. Without the setting there is
/// nothing to mark, and a path nobody sends on is exactly risk #24.
///
/// Below `IdleTimeoutMs` by design, so a run where the PINGs do not happen dies
/// of the idle timeout rather than passing quietly. The shipping value is a
/// separate decision — it has to sit under the shortest NAT mapping lifetime
/// worth surviving, and every ping costs a wakeup on a battery-powered camera.
const KEEP_ALIVE: Duration = Duration::from_secs(5);

/// Which sides send keepalives: `SPIKE_KEEPALIVE=both` (the default), `client`,
/// `server` or `none`. Question 5 reads the difference.
///
/// `none` is the control that makes the setting's absence visible: the
/// connection dies of the idle timeout 30s into a silent window, which is the
/// whole argument for setting it at all.
///
/// What the controls *cannot* settle is whether both sides are required. On
/// loopback there is no mapping to lapse, and a PING is ack-eliciting, so one
/// side pinging still pulls acknowledgements out of the other along the same
/// paths — `client` and `server` pass here just as `both` does. Nor does the
/// relay-path packet count separate them: a side's own PING and its
/// acknowledgement of the peer's ride in the same datagram when the timers line
/// up, so `both` is anywhere from the one-sided count to twice it. The reason to
/// set it on both is structural rather than measured here — the timer is driven
/// by each connection's own settings, so a camera that leaves it at 0 never
/// originates anything and its side of the traffic is only ever a reply.
fn keep_alive_ms(side: Side) -> u32 {
    let setting = std::env::var("SPIKE_KEEPALIVE").unwrap_or_else(|_| "both".to_owned());
    let on = match setting.as_str() {
        "both" => true,
        "client" => side == Side::Client,
        "server" => side == Side::Server,
        "none" => false,
        other => panic!("SPIKE_KEEPALIVE must be both, client, server or none, not {other:?}"),
    };
    if on {
        KEEP_ALIVE.as_millis() as u32
    } else {
        0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Side {
    Client,
    Server,
}

/// How long the teardown may take before it is reported as a failure of its own.
///
/// `RegistrationClose` is a synchronous, uninterruptible wait, so a handle this
/// spike forgot to drop does not surface as an error — it surfaces as a process
/// that prints every answer and then never exits. Waiting here instead means the
/// harness says so.
const TEARDOWN_TIMEOUT: Duration = Duration::from_secs(10);

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

    match mixed_versions(&registration, true, false).await {
        Ok(()) => println!("PASS  4. a multipath client connects to a peer without it"),
        Err(e) => {
            println!("FAIL  question 4 (multipath client, plain peer): {e:#}");
            failures.push("4");
        }
    }

    match mixed_versions(&registration, false, true).await {
        Ok(()) => println!("PASS  6. a plain client connects to a peer with multipath"),
        Err(e) => {
            println!("FAIL  question 6 (plain client, multipath peer): {e:#}");
            failures.push("6");
        }
    }

    // The teardown `docs/registration-wait-idle-design.md` §8 asks for: ask the
    // connections to go away, wait until every handle derived from the
    // registration has actually been closed, and only then let it drop. Nothing
    // above may outlive this — which is why the relay legs are returned and held
    // rather than leaked, and it is the reason the harness now ends.
    registration.shutdown();
    if tokio::time::timeout(TEARDOWN_TIMEOUT, registration.wait_idle())
        .await
        .is_err()
    {
        println!(
            "FAIL  teardown: a handle was still open {}s after shutdown",
            TEARDOWN_TIMEOUT.as_secs()
        );
        failures.push("teardown");
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
    // Somewhere for the legs to be connected to, standing in for the proxy.
    let proxy = start_listener(reg, false).await.context("proxy stand-in")?;
    let listener = start_listener(reg, true)
        .await
        .context("multipath listener")?;
    let direct_addr = listener.addr;
    // The relay: the client dials this, and it forwards to the listener. Standing
    // in for the CONNECT-UDP leg, the proxy and the bind leg all at once.
    let bridge = Bridge::start(direct_addr).await.context("bridge")?;

    // The viewer's leg comes first, because what it is for is to be named as a
    // candidate — and a candidate has to be offered before `start`, which is
    // also the order `prepare_for_migration` fixes in the shipping code.
    let client_leg = relay_leg(reg, &proxy).await.context("the viewer's leg")?;
    let client_leg_addr = client_leg.addr;

    let client = Connection::new(reg).context("client connection")?;
    // The same four calls `prepare_for_migration` makes, in the order it makes
    // them. Multipath adds a reason for the first one: it identifies a
    // connection by its source connection id, which only a shared binding gives
    // a non-zero length.
    client.set_share_binding(true).context("share binding")?;
    client
        .set_unconnected_socket(true)
        .context("unconnected socket")?;
    // Loopback, not the leg's address: this connection's own traffic goes to the
    // bridge on 127.0.0.1, and pinning it to the leg's address is what
    // `QUIC_STATUS_ADDRESS_IN_USE` came out of. The direct path does not need it
    // — `add_candidate_addr` names an address bound elsewhere, and msquic opens
    // the path from the leg's binding once the peer's ADD_ADDRESS arrives.
    client
        .set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("pinning the client to loopback")?;
    // No `add_path`: in NAT-traversal mode msquic opens the path itself once the
    // probe validates, and that is the mode this has to stay in, since it is the
    // only one that can hole-punch.
    client
        .add_candidate_addr(client_leg_addr, client_leg_addr)
        .context("offering the viewer's leg as a candidate")?;

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
    // The camera's side of the advertisement, built the way the shipping code
    // builds it.
    //
    // `add_bound_addr` adds a binding to a connection that has only been bound
    // to localhost, and the address it takes is a local one whose observed
    // address is known — which means the local address of the connection to the
    // proxy, since that is the one a public mapping has been reported for. For
    // the video connection to share it, that connection has to have been opened
    // with a shared binding and an unconnected socket, which is exactly what
    // `RelayOptions::unconnected` does.
    //
    // So the leg comes first, and its address is what is claimed and advertised.
    // Passing the listener's own address instead — as an earlier version of this
    // did — is refused with ADDRESS_IN_USE, because it is neither of those
    // things: already bound, and nothing has said how it looks from outside.
    let server_leg = relay_leg(reg, &proxy).await.context("the camera's leg")?;
    let server_leg_addr = server_leg.addr;
    server.add_bound_addr(server_leg_addr).with_context(|| {
        format!("adding the leg binding {server_leg_addr} to the video connection")
    })?;
    // On loopback the address is its own observed address; a real proxy reports
    // the public mapping instead.
    server
        .add_observed_addr(server_leg_addr, server_leg_addr)
        .context("advertising the leg's address")?;

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

    // Question 5, and the point of the exercise: nobody sends anything. An
    // earlier version pushed a datagram every 200ms, which kept the paths warm
    // with application traffic and so tested everything except the thing risk
    // #24 is about — a path nobody sends on. The application is silent for the
    // whole window instead, which leaves the keepalive PING as the only reason
    // either path stays alive.
    //
    // That silence is what makes the window self-checking. `IdleTimeoutMs` is
    // 30s, so a connection nothing was sent on dies halfway through and
    // `poll_event` says so; surviving twice the idle timeout means PINGs went
    // out. And because the bridge carries the relay path *alone* — the direct
    // path runs leg to leg and bypasses it — packets crossing it while the
    // application is silent say that the *backup* path is being kept warm, not
    // just the one carrying data, which is the per-path keepalive doing its job.
    // How many is not worth reading into: PINGs and acknowledgements coalesce.
    let started_watching = Instant::now();
    let relayed_before = bridge.forwarded();
    let mut removed = Vec::new();
    loop {
        let left = OBSERVE.saturating_sub(started_watching.elapsed());
        if left.is_zero() {
            break;
        }
        match tokio::time::timeout(left, poll_fn(|cx| client.poll_event(cx))).await {
            Err(_) => break,
            Ok(Ok(ConnectionEvent::PathRemoved { path_id, .. })) => removed.push(path_id),
            Ok(Ok(_)) => {}
            Ok(Err(e)) => anyhow::bail!(
                "the connection ended after {:?} with the application silent, so the \
                 keepalive did not carry it: {e}",
                started_watching.elapsed()
            ),
        }
    }
    let relayed = bridge.forwarded() - relayed_before;
    if !removed.is_empty() {
        anyhow::bail!(
            "paths {removed:?} were removed within {}s of silence, even though every \
             path is supposed to be kept alive",
            OBSERVE.as_secs()
        );
    }
    if relayed == 0 {
        anyhow::bail!(
            "no packet crossed the relay path in {}s of silence, so the backup path \
             was not being kept alive",
            OBSERVE.as_secs()
        );
    }
    println!(
        "PASS  5. {}s with the application silent: no path removed, {relayed} packets \
         kept the backup path warm (loopback, so this still cannot see a NAT mapping lapse)",
        OBSERVE.as_secs()
    );

    bridge.stop();
    Ok(())
}

/// Questions 4 and 6: a mixed pair, in both directions.
///
/// This is the rollout question. A camera and a viewer are updated separately,
/// so every mixed pair has to keep working — and if it does not, both sides have
/// to ship at once and every user in between has broken video.
///
/// Both directions are asked because both happen. Question 4 is the viewer
/// updated first; question 6 is the camera updated first, which is the order the
/// video listener's own change lands in, and neither is the other's answer:
/// multipath is negotiated from what each side offers, and only a run says the
/// negotiation actually degrades rather than fails.
async fn mixed_versions(
    reg: &Arc<Registration>,
    client_multipath: bool,
    server_multipath: bool,
) -> anyhow::Result<()> {
    let listener = start_listener(reg, server_multipath).await?;
    let bridge = Bridge::start(listener.addr).await?;

    let client = Connection::new(reg)?;
    client.set_share_binding(true)?;
    let config = client_config(reg, client_multipath)?;

    let (started, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.start(&config, "127.0.0.1", bridge.front_addr.port()),
            listener.listener.accept(),
        )
    })
    .await
    .context("the handshake did not complete within 10s")?;
    started.context("client start")?;
    accepted.context("server accept")?;

    bridge.stop();
    Ok(())
}

/// A connection on its own real-interface binding, shared and unconnected —
/// the relay leg, as `RelayOptions::unconnected` opens it.
///
/// Its only job is to exist: its local address is the one with a known observed
/// address, so it is the one the video connection can claim and advertise.
struct RelayLeg {
    addr: SocketAddr,
    /// Held for the run, and dropped with it. Dropping it early takes the
    /// binding with it and the binding is the whole point; never dropping it —
    /// which an earlier version arranged with `mem::forget` — keeps the
    /// registration's rundown held, so the process prints every answer and then
    /// hangs in `RegistrationClose`.
    _conn: Connection,
}

async fn relay_leg(reg: &Arc<Registration>, proxy: &SpikeListener) -> anyhow::Result<RelayLeg> {
    let local = probe_local_addr()?;
    let conn = Connection::new(reg).context("leg connection")?;
    conn.set_share_binding(true).context("leg share binding")?;
    conn.set_unconnected_socket(true)
        .context("leg unconnected socket")?;
    conn.set_local_addr(local)
        .with_context(|| format!("leg local addr {local}"))?;
    let host = proxy.addr.ip().to_string();
    conn.start(&client_config(reg, true)?, &host, proxy.addr.port())
        .await
        .with_context(|| format!("the leg could not reach the proxy stand-in from {local}"))?;
    let addr = conn.get_local_addr()?;
    Ok(RelayLeg { addr, _conn: conn })
}

/// A source address on a real interface, as the shipping code picks one.
fn probe_local_addr() -> anyhow::Result<SocketAddr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").context("bind the probe socket")?;
    // Never contacted; `connect` only resolves the route and picks a source.
    probe
        .connect("8.8.8.8:53")
        .context("no default route to pick a source address from")?;
    let addr = probe.local_addr()?;
    drop(probe);
    Ok(addr)
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
        // Both sides set it, and each only pings for itself. See `KEEP_ALIVE`.
        .set_KeepAliveIntervalMs(keep_alive_ms(Side::Client))
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
        // Both sides set it, and each only pings for itself. See `KEEP_ALIVE`.
        .set_KeepAliveIntervalMs(keep_alive_ms(Side::Server))
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
///
/// It counts what it forwards, which is what makes question 5 an observation
/// rather than an assumption: the relay path is the only one that goes through
/// here, so a packet crossing it while the application sends nothing can only be
/// a keepalive or its acknowledgement.
struct Bridge {
    front_addr: SocketAddr,
    forwarded: Arc<AtomicU64>,
    shutdown: CancellationToken,
}

impl Bridge {
    async fn start(target: SocketAddr) -> anyhow::Result<Self> {
        let front = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let back = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let front_addr = front.local_addr()?;
        let shutdown = CancellationToken::new();
        let forwarded = Arc::new(AtomicU64::new(0));

        let counter = forwarded.clone();
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
                            counter.fetch_add(1, Ordering::Relaxed);
                        }
                        Err(_) => break,
                    },
                    r = back.recv_from(&mut down) => match r {
                        Ok((n, _)) => {
                            if let Some(dst) = client {
                                let _ = front.send_to(&down[..n], dst).await;
                                counter.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        Ok(Self {
            front_addr,
            forwarded,
            shutdown,
        })
    }

    /// Packets forwarded in either direction since the bridge started.
    fn forwarded(&self) -> u64 {
        self.forwarded.load(Ordering::Relaxed)
    }

    fn stop(self) {
        self.shutdown.cancel();
    }
}
