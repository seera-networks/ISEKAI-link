//! Phase 0 spike for `docs/p2p_mode_migration_plan.md`.
//!
//! The plan's Phase 0 asks a handful of questions that decide whether the
//! adopted design (案B on the client, 案A on the server) actually works. This
//! example answers them mechanically, on one host, with no proxy, no relay and
//! no NAT — so it can run on a CI runner across Linux / Windows / macOS.
//!
//! The topology below stands in for the P2P relay chain. Two loopback sockets
//! bridge the client to the listener, which is what makes the *server* see the
//! connection arriving from a loopback address, exactly as the real
//! `MasqueClientMode::Forward` leg does:
//!
//! ```text
//!   client conn ──▶ 127.0.0.1:R ─┐ bridge ┌─ 127.0.0.1:F ──▶ listener
//!    local = L_c  ◀──────────────┘        └──────────────◀──  (127.0.0.1:V)
//! ```
//!
//! `L_c` is a **real interface address**, obtained the way `tonic-h3`'s
//! `is_unconnected` mode obtains it: `connect()` a throwaway UDP socket at the
//! target (which sends nothing) and read its local address.
//!
//! Each check prints PASS / FAIL / SKIP plus a note. The one marked *required*
//! is the adopted design (案C, check 7b): if it fails the process exits
//! non-zero, because the plan itself has to change. The rest are exploratory —
//! several record why an *earlier* design was abandoned and are expected to
//! fail on some platforms, so they never fail the build.
//!
//! Run with `cargo run -p camera-core --example migration_spike`.

use std::future::poll_fn;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use msquic_async::{msquic, Connection, Listener, Registration, StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

/// ALPN for the spike's QUIC connections. Deliberately not `sample`, so a stray
/// camera app on the same machine cannot be dialed by accident.
const ALPN: &str = "isekai-spike";

/// How long any single check may take before it is declared a failure. CI must
/// not hang on a handshake that never completes.
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);

/// How long to wait for NAT-traversal probing to validate the direct path.
const PATH_VALIDATION_TIMEOUT: Duration = Duration::from_secs(15);

// Raw libc `_exit`: immediate termination without running atexit handlers or
// C++ static destructors. Same reasoning (and same trick) as `isekai-agent`'s
// main: msquic's `MsQuicClose` runs from a process destructor and aborts if it
// races live worker threads.
unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

fn main() -> ! {
    let runtime = tokio::runtime::Runtime::new().expect("failed to build tokio runtime");
    let failed = runtime.block_on(run_all());

    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    // Terminate without running atexit handlers or C++ static destructors, and
    // without joining the runtime. The spike deliberately leaves the whole
    // msquic estate standing — connections, listeners and the relay-leg
    // stand-ins that had to stay alive for the checks to mean anything — so
    // both graceful paths misbehave: returning normally blocks in
    // `RegistrationClose` -> `CxPlatRundownReleaseAndWait`, and
    // `std::process::exit` runs msquic's destructors into that same state and
    // aborts. `isekai-agent` reaches for the same `_exit(2)` when its drain
    // times out. The report on stdout is the only output that matters and is
    // already flushed.
    unsafe { libc_exit(if failed { 1 } else { 0 }) }
}

/// Every check. Returns whether a required one failed.
async fn run_all() -> bool {
    match spike().await {
        Ok(failed) => failed,
        Err(e) => {
            eprintln!("spike could not run: {e:#}");
            true
        }
    }
}

async fn spike() -> anyhow::Result<bool> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let mut report = Report::default();

    // Check 1 needs no msquic at all, so it still answers even if the QUIC
    // stack fails to initialise on this platform.
    // Not required: 案B (pinning the video connection to a real address) was
    // abandoned precisely because this fails on Windows. Kept as the record of
    // why.
    report.record(
        "1",
        Required::No,
        "[案B の前提・不採用] 実 IP を local、loopback を remote とする UDP が双方向に疎通するか (§2.2.1)",
        run(check_os_udp()).await,
    );

    report.record(
        "1b",
        Required::No,
        "ローカルアドレスを固定せず wildcard bind にした場合、1 ソケットで両経路を捌けるか",
        run(check_wildcard_bind()).await,
    );

    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);

    // Every msquic check needs a listener, and the dev certificate path this
    // example uses cannot be loaded on every platform (the Windows branch of
    // `make_msquic_async_listener` imports through an RSA provider, while
    // `dev_cert` generates ECDSA P-256; production passes the proxy's PKCS#12
    // instead and takes the other branch). Probe once and skip rather than
    // report six identical certificate failures as design findings.
    let listener_probe = spawn_listener(&reg, loopback(0)).await;
    if let Err(e) = &listener_probe {
        let reason = format!(
            "この環境では listener を立てられないためスキップ (設計判断ではない): {e:#}"
        );
        for (id, question) in MSQUIC_CHECKS {
            report.skip(id, question, &reason);
        }
        report.print();
        let failed = report.required_failed();
        std::mem::forget(reg);
        return Ok(failed);
    }
    drop(listener_probe);

    report.record(
        "2",
        Required::No,
        "[案B の前提・不採用] set_local_addr(実IP) を pin した msquic クライアントが 127.0.0.1 へハンドシェイクできるか",
        run(check_pinned_local_dial_loopback(&reg)).await,
    );
    report.record(
        "3",
        Required::No,
        "生存中の共有バインディングに 2 本目の接続が相乗りできるか (リスク #1b)",
        run(check_live_shared_binding(&reg)).await,
    );
    report.record(
        "4",
        Required::No,
        "set_local_addr で bind 済みの接続に add_candidate_addr を併用できるか",
        run(check_candidate_with_pinned_local(&reg)).await,
    );
    report.record(
        "5",
        Required::No,
        "サーバ側 add_bound_addr / add_observed_addr をハンドシェイク前後で呼べるか",
        run(check_server_side_advertise(&reg)).await,
    );
    report.record(
        "6a",
        Required::No,
        "リレー型トポロジで直接経路が PathValidated されるか (listener は現行の設定のまま)",
        run(check_direct_path_migration(&reg, false, ClientBinding::PinnedToLeg)).await,
    );
    // The NAT-traversal listener variant builds its configuration by hand and
    // loads it from PEM files, which is the Unix credential path; probe it
    // first so an environment that cannot build it reports SKIP rather than a
    // PASS whose note says "skipped".
    let (id, question) = MSQUIC_CHECKS[5];
    match spawn_listener_variant(&reg, loopback(0), true).await {
        Ok(Some(l)) => {
            drop(l);
            report.record(
                id,
                Required::No,
                question,
                run(check_direct_path_migration(&reg, true, ClientBinding::PinnedToLeg)).await,
            );
        }
        Ok(None) => report.skip(
            id,
            question,
            "このプラットフォームでは listener 設定を差し替えられないためスキップ \
             (設定を手組みする経路が PEM 読み込み前提のため)",
        ),
        Err(e) => report.record(id, Required::No, question, Err(e)),
    }

    report.record(
        "7a",
        Required::No,
        "映像接続を pin せず、MASQUE レグの (L_c, O_c) を add_candidate_addr に渡すだけで直接経路が張れるか",
        run(check_direct_path_migration(&reg, false, ClientBinding::Unpinned)).await,
    );
    // The adopted design (案C). This is the check that gates the build.
    report.record(
        "7b",
        Required::Yes,
        "[採用] 同上 + 映像接続を共有・非接続ソケット (ローカルアドレスは loopback) にした場合",
        run(check_direct_path_migration(
            &reg,
            false,
            ClientBinding::UnpinnedSharedLoopback,
        ))
        .await,
    );

    report.print();
    let failed = report.required_failed();
    if failed {
        eprintln!("the adopted design (案C) does not hold here; the plan needs revising");
    }

    // Deliberately leaked: see the note in `main`.
    std::mem::forget(reg);
    Ok(failed)
}

/// The msquic-dependent checks, named once so the skip path can list them.
const MSQUIC_CHECKS: [(&str, &str); 6] = [
    ("2", "[案B の前提・不採用] set_local_addr(実IP) を pin した msquic クライアントが 127.0.0.1 へハンドシェイクできるか"),
    ("3", "生存中の共有バインディングに 2 本目の接続が相乗りできるか (リスク #1b)"),
    ("4", "set_local_addr で bind 済みの接続に add_candidate_addr を併用できるか"),
    ("5", "サーバ側 add_bound_addr / add_observed_addr をハンドシェイク前後で呼べるか"),
    ("6a", "リレー型トポロジで直接経路が PathValidated されるか (listener は現行の設定のまま)"),
    ("6b", "同上、listener に NAT traversal / observed address 設定を足した場合 (#59 の caveat)"),
];

// ---------------------------------------------------------------------------
// Check 1 — the OS-level question, no msquic involved.
// ---------------------------------------------------------------------------

/// Reproduce the §2.2.1 measurement in Rust, on whatever platform CI runs.
///
/// Mirrors `channel_masque::masque::connect_udp::run_bridge`: the bridge learns
/// its peer from `recv_from` and replies with `send_to`, never inspecting the
/// source address.
async fn check_os_udp() -> anyhow::Result<String> {
    let probe = probe_local_addr().context("could not learn a real interface address")?;
    anyhow::ensure!(
        !probe.ip().is_loopback(),
        "probe returned a loopback address ({probe}); this host has no usable interface address"
    );

    let bridge = UdpSocket::bind("127.0.0.1:0")
        .await
        .context("step 1: bind the loopback bridge")?;
    let bridge_addr = bridge.local_addr()?;

    // Rebind the probe's exact address, as msquic does after `set_local_addr`.
    let video = UdpSocket::bind(probe)
        .await
        .with_context(|| format!("step 2: rebind the probe address {probe}"))?;
    anyhow::ensure!(video.local_addr()? == probe, "rebind landed on another port");

    // Uplink: real-IP source -> loopback destination. This is the step Windows
    // rejects (WSAEADDRNOTAVAIL / os error 10049): a socket bound to a specific
    // non-loopback address cannot reach 127.0.0.1 there.
    video
        .send_to(b"uplink", bridge_addr)
        .await
        .with_context(|| format!("step 3: send from the real address {probe} to {bridge_addr}"))?;
    let mut buf = [0u8; 64];
    let (n, src) = tokio::time::timeout(Duration::from_secs(2), bridge.recv_from(&mut buf))
        .await
        .context("step 4: the bridge never received the uplink datagram (kernel dropped it)")??;
    anyhow::ensure!(&buf[..n] == b"uplink", "uplink payload was corrupted");
    anyhow::ensure!(
        src == probe,
        "the bridge observed source {src}, expected the real interface address {probe}"
    );

    // Downlink: what `run_bridge` does with `last_src`.
    bridge
        .send_to(b"downlink", src)
        .await
        .context("step 5: bridge replies to the real address")?;
    let (n, from) = tokio::time::timeout(Duration::from_secs(2), video.recv_from(&mut buf))
        .await
        .context("step 6: the real-IP socket never received the downlink datagram")??;
    anyhow::ensure!(&buf[..n] == b"downlink", "downlink payload was corrupted");
    anyhow::ensure!(from == bridge_addr, "downlink came from {from}, expected {bridge_addr}");

    // Why `set_unconnected_socket(true)` is mandatory: a connected socket
    // silently drops the direct path's packets.
    let connected = UdpSocket::bind((probe.ip(), 0)).await?;
    let connected_addr = connected.local_addr()?;
    connected.connect(bridge_addr).await?;
    let third_party = UdpSocket::bind((probe.ip(), 0)).await?;
    third_party.send_to(b"direct-path", connected_addr).await?;
    let leaked = tokio::time::timeout(Duration::from_millis(500), connected.recv(&mut buf))
        .await
        .is_ok();
    let connected_note = if leaked {
        "connected ソケットが第三者パケットを受信した (想定外)"
    } else {
        "connected ソケットは第三者パケットを破棄 (unconnected 必須の根拠)"
    };

    Ok(format!(
        "L_c = {probe}, bridge = {bridge_addr}; 上り/下りとも到達; {connected_note}"
    ))
}

/// The fallback shape, for platforms where check 1 fails.
///
/// Instead of pinning the local address to a specific interface address, bind
/// the **wildcard** on a chosen port. One socket then serves both paths and the
/// kernel picks the source per destination: `127.0.0.1` towards the relay
/// bridge, the interface address towards the direct peer. If this works where
/// check 1 does not, 案B survives by pinning only the *port*.
async fn check_wildcard_bind() -> anyhow::Result<String> {
    let probe = probe_local_addr()?;
    let bridge = UdpSocket::bind("127.0.0.1:0").await?;
    let bridge_addr = bridge.local_addr()?;

    let wild = UdpSocket::bind("0.0.0.0:0")
        .await
        .context("step 1: wildcard bind")?;
    let port = wild.local_addr()?.port();
    let mut buf = [0u8; 64];

    // Relay path: wildcard socket -> loopback bridge.
    wild.send_to(b"uplink", bridge_addr)
        .await
        .context("step 2: wildcard socket -> loopback bridge")?;
    let (n, relay_src) = tokio::time::timeout(Duration::from_secs(2), bridge.recv_from(&mut buf))
        .await
        .context("step 3: the bridge never received the uplink datagram")??;
    anyhow::ensure!(&buf[..n] == b"uplink", "uplink payload was corrupted");
    bridge
        .send_to(b"downlink", relay_src)
        .await
        .context("step 4: bridge replies")?;
    tokio::time::timeout(Duration::from_secs(2), wild.recv_from(&mut buf))
        .await
        .context("step 5: the wildcard socket never received the downlink")??;

    // Direct path: a peer on the interface address reaches the same socket.
    let peer = UdpSocket::bind((probe.ip(), 0)).await?;
    let peer_addr = peer.local_addr()?;
    peer.send_to(b"direct-path", SocketAddr::new(probe.ip(), port))
        .await
        .context("step 6: peer -> the wildcard socket's interface address")?;
    let (n, direct_src) = tokio::time::timeout(Duration::from_secs(2), wild.recv_from(&mut buf))
        .await
        .context("step 7: the wildcard socket never received the direct-path datagram")??;
    anyhow::ensure!(&buf[..n] == b"direct-path", "direct-path payload was corrupted");
    anyhow::ensure!(direct_src == peer_addr, "direct path source was {direct_src}");

    Ok(format!(
        "wildcard 0.0.0.0:{port} が両経路を捌ける: リレー側から見た送信元 {relay_src}, \
         直接経路の相手 {peer_addr} からも同一ソケットで受信"
    ))
}

// ---------------------------------------------------------------------------
// Check 2 — the load-bearing 案B assumption.
// ---------------------------------------------------------------------------

/// Pin the client's local address to a real interface address and dial the
/// loopback bridge, as `receive_frames_with` will do (plan §3 Phase 4-3).
async fn check_pinned_local_dial_loopback(reg: &Arc<Registration>) -> anyhow::Result<String> {
    let mut listener = spawn_listener(reg, loopback(0)).await?;
    let bridge = Bridge::start(listener.addr).await?;
    let local = probe_local_addr()?;

    let config = client_config(reg, false)?;
    let conn = Connection::new(reg)?;
    // The order the plan mandates (§7-14): share -> unconnected -> local addr.
    conn.set_share_binding(true).context("set_share_binding")?;
    conn.set_unconnected_socket(true)
        .context("set_unconnected_socket (requires share_binding first)")?;
    conn.set_local_addr(local)
        .with_context(|| format!("set_local_addr({local})"))?;
    conn.start(&config, "127.0.0.1", bridge.front_addr.port())
        .await
        .context("handshake to the loopback bridge with a pinned real local address")?;

    let got_local = conn.get_local_addr()?;
    let got_remote = conn.get_remote_addr()?;
    anyhow::ensure!(
        got_local == local,
        "connection bound {got_local}, expected the pinned {local}"
    );
    anyhow::ensure!(
        got_remote == bridge.front_addr,
        "connection remote is {got_remote}, expected the bridge front {}",
        bridge.front_addr
    );

    // Prove the path actually carries application data, not just a handshake.
    let accepted = listener.accept_one().await?;
    let payload = round_trip(&accepted, &conn).await?;

    bridge.stop();
    Ok(format!(
        "local {got_local} -> remote {got_remote}; サーバから見た remote は {}; {payload} バイト往復",
        accepted.get_remote_addr()?
    ))
}

// ---------------------------------------------------------------------------
// Check 3 — risk #1b: can a second connection join a *live* shared binding?
// ---------------------------------------------------------------------------

/// The recommended client flow keeps the relay leg's H3 connection alive on
/// `L_c` (so the NAT mapping stays warm, risk #13) and has the video connection
/// join that same binding. That only works if msquic hands out an existing
/// shared binding rather than failing to bind.
async fn check_live_shared_binding(reg: &Arc<Registration>) -> anyhow::Result<String> {
    let mut listener = spawn_listener(reg, loopback(0)).await?;
    let bridge_a = Bridge::start(listener.addr).await?;
    let bridge_b = Bridge::start(listener.addr).await?;
    let local = probe_local_addr()?;
    let config = client_config(reg, false)?;

    let first = shared_binding_conn(reg, local)?;
    first
        .start(&config, "127.0.0.1", bridge_a.front_addr.port())
        .await
        .context("first connection on the shared binding")?;
    let _first_accepted = listener.accept_one().await?;

    // The first connection is still alive here — that is the whole point.
    let second = shared_binding_conn(reg, local)?;
    let result = second
        .start(&config, "127.0.0.1", bridge_b.front_addr.port())
        .await;

    bridge_a.stop();
    bridge_b.stop();
    match result {
        Ok(()) => {
            let second_local = second.get_local_addr()?;
            anyhow::ensure!(
                second_local == local,
                "second connection bound {second_local}, expected the shared {local}"
            );
            Ok(format!(
                "相乗り可: 2 本の接続が同時に {local} を共有 (推奨の «相乗り方式» が使える)"
            ))
        }
        Err(e) => Err(anyhow::anyhow!(
            "相乗り不可: {e:?} — Phase 4-5 は «probe & drop» 方式にフォールバックし、\
             リスク #13 (NAT マッピング維持) の対策が別途必要"
        )),
    }
}

// ---------------------------------------------------------------------------
// Check 4 — add_candidate_addr on an already-pinned connection.
// ---------------------------------------------------------------------------

/// Direct mode calls `add_candidate_addr` on a connection that has *not* been
/// pinned; 案B pins it first. If `HostAddress` means "bind here" the two could
/// conflict, so check they compose.
async fn check_candidate_with_pinned_local(reg: &Arc<Registration>) -> anyhow::Result<String> {
    let mut listener = spawn_listener(reg, loopback(0)).await?;
    let bridge = Bridge::start(listener.addr).await?;
    let local = probe_local_addr()?;

    let config = client_config(reg, true)?;
    let conn = shared_binding_conn(reg, local)?;
    // No NAT on a CI runner, so the observed address is the local one.
    conn.add_candidate_addr(local, local)
        .context("add_candidate_addr after set_local_addr")?;
    conn.start(&config, "127.0.0.1", bridge.front_addr.port())
        .await
        .context("handshake with both set_local_addr and add_candidate_addr in effect")?;
    let got_local = conn.get_local_addr()?;
    let _accepted = listener.accept_one().await?;

    bridge.stop();
    Ok(format!("併用可: local {got_local} のままハンドシェイク成立"))
}

// ---------------------------------------------------------------------------
// Check 5 — server-side advertisement timing.
// ---------------------------------------------------------------------------

/// In P2P mode the relay bind leg — and therefore the observed address — may
/// only exist *after* the video connection has been accepted (the operator
/// pastes the connection id by hand). So the server has to advertise **late**.
///
/// This reproduces that ordering exactly: the video connection is established
/// and carries data first, and only then does a shared binding appear at `L_s`
/// and get advertised. Advertising the *same* address twice would fail with
/// `ADDRESS_IN_USE` for reasons that have nothing to do with timing, so each
/// call here uses its own address.
async fn check_server_side_advertise(reg: &Arc<Registration>) -> anyhow::Result<String> {
    let mut proxy = spawn_proxy_stand_in(reg).await?;
    let mut listener = spawn_listener(reg, loopback(0)).await?;
    let bridge = Bridge::start(listener.addr).await?;

    let config = client_config(reg, true)?;
    let conn = shared_binding_conn(reg, probe_local_addr()?)?;
    conn.start(&config, "127.0.0.1", bridge.front_addr.port())
        .await?;
    let accepted = listener.accept_one().await?;

    // (a) at accept time, with a binding that already exists — Direct mode's
    //     ordering, where the MASQUE channel is up long before any client.
    let early = RelayLeg::start(reg, &mut proxy).await?;
    let early_bound = describe(accepted.add_bound_addr(early.addr));
    let early_observed = describe(accepted.add_observed_addr(early.addr, early.addr));

    // (b) after the connection has carried application data — the P2P case,
    //     where the bind leg only comes up once the operator binds.
    round_trip(&accepted, &conn).await?;
    let late = RelayLeg::start(reg, &mut proxy).await?;
    let late_bound = describe(accepted.add_bound_addr(late.addr));
    let late_observed = describe(accepted.add_observed_addr(late.addr, late.addr));

    bridge.stop();
    Ok(format!(
        "既存バインディング {} を accept 時に広告: add_bound_addr {early_bound} / add_observed_addr {early_observed}; \
         データ往復後に現れたバインディング {} を遅延広告: add_bound_addr {late_bound} / add_observed_addr {late_observed}",
        early.addr, late.addr
    ))
}

// ---------------------------------------------------------------------------
// Check 6 — the whole thing, end to end.
// ---------------------------------------------------------------------------

/// The whole shape, faithful to production: the video listener sits on
/// **loopback** (as `bind_video_listener` binds it), the relay path runs through
/// the bridge, and each side's direct-path address is a *separate* shared
/// binding standing in for its MASQUE leg — `L_s` on the server, `L_c` on the
/// client. With no NAT in the way, the observed address equals the local one on
/// both sides, so this isolates msquic's mechanics from NAT behaviour.
///
/// `natt_listener` selects the listener's settings: `false` is exactly what
/// `make_msquic_async_listener` builds today, `true` adds the NAT-traversal and
/// observed-address knobs. Running both answers #59's open caveat — whether the
/// listener needs tuning for `add_observed_addr` to take effect.
/// How the client's *video* connection is bound, which is the whole question
/// this spike now turns on.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ClientBinding {
    /// 案B: pin the video connection itself to the relay leg's real address.
    /// Works on Linux/macOS, impossible on Windows (§2.2.2).
    PinnedToLeg,
    /// Leave the video connection where msquic puts it — loopback, facing the
    /// bridge — and only *name* the relay leg's address as a candidate.
    /// `add_candidate_addr` does not require the address to be bound yet: the
    /// path is opened when the peer's ADD_ADDRESS arrives.
    Unpinned,
    /// As `Unpinned`, but with the shared/unconnected socket knobs and an
    /// explicit *loopback* local address — which satisfies the "a specific,
    /// non-wildcard local address" rule an unconnected socket carries, without
    /// ever asking a real-IP socket to reach loopback.
    UnpinnedSharedLoopback,
}

impl ClientBinding {
    fn label(self) -> &'static str {
        match self {
            ClientBinding::PinnedToLeg => "pinned",
            ClientBinding::Unpinned => "unpinned",
            ClientBinding::UnpinnedSharedLoopback => "unpinned+shared(loopback)",
        }
    }
}

async fn check_direct_path_migration(
    reg: &Arc<Registration>,
    natt_listener: bool,
    binding: ClientBinding,
) -> anyhow::Result<String> {
    let mut listener = spawn_listener_variant(reg, loopback(0), natt_listener)
        .await?
        .context("this platform cannot build the requested listener variant")?;
    let mut proxy = spawn_proxy_stand_in(reg).await?;
    let bridge = Bridge::start(listener.addr).await?;

    // The server's MASQUE bind leg stand-in: a live shared binding on a real
    // address, which is what `add_bound_addr` will hand to the video connection.
    let server_leg = RelayLeg::start(reg, &mut proxy).await?;
    // The client's CONNECT-UDP leg stand-in, for the same reason.
    let client_leg = RelayLeg::start(reg, &mut proxy).await?;

    let conn = match binding {
        ClientBinding::PinnedToLeg => shared_binding_conn(reg, client_leg.addr)?,
        ClientBinding::Unpinned => Connection::new(reg)?,
        ClientBinding::UnpinnedSharedLoopback => shared_binding_conn(reg, loopback(0))?,
    };
    // No NAT on a CI runner, so the relay leg's observed address is its local
    // one. The address is not bound *by this connection* in the unpinned
    // variants — that is the point.
    conn.add_candidate_addr(client_leg.addr, client_leg.addr)
        .context("add_candidate_addr with the relay leg's address")?;
    conn.start(&client_config(reg, true)?, "127.0.0.1", bridge.front_addr.port())
        .await
        .context("relay-path handshake")?;
    let relay_path = (conn.get_local_addr()?, conn.get_remote_addr()?);

    let accepted = listener.accept_one().await?;
    // The server half of 案A: advertise the address the client should punch to.
    let bound = describe(accepted.add_bound_addr(server_leg.addr));
    let observed = describe(accepted.add_observed_addr(server_leg.addr, server_leg.addr));

    // Wait for NAT-traversal probing to validate anything but the relay path.
    let direct = tokio::time::timeout(PATH_VALIDATION_TIMEOUT, async {
        loop {
            match poll_fn(|cx| conn.poll_event(cx)).await {
                Ok(msquic_async::ConnectionEvent::PathValidated {
                    local_address,
                    remote_address,
                }) if (local_address, remote_address) != relay_path => {
                    return anyhow::Ok((local_address, remote_address));
                }
                Ok(other) => tracing::info!("client event: {other:?}"),
                Err(e) => anyhow::bail!("connection ended while waiting for a direct path: {e}"),
            }
        }
    })
    .await;

    // A run that never validates a direct path is a FAIL, not a PASS carrying
    // prose that says otherwise — the context below records what was in play.
    let context = format!(
        "client={}, listener natt={natt_listener}; relay path {} -> {}; \
         server leg {} / client leg {}; add_bound_addr {bound} / add_observed_addr {observed}",
        binding.label(),
        relay_path.0,
        relay_path.1,
        server_leg.addr,
        client_leg.addr
    );
    let outcome = match direct {
        Ok(Ok(direct)) => {
            conn.activate_path(direct.0, direct.1)
                .context("activate_path onto the validated direct path")?;
            // Application data must keep flowing across the switch.
            round_trip(&accepted, &conn).await?;
            let now = (conn.get_local_addr()?, conn.get_remote_addr()?);
            format!(
                "直接経路 {} -> {} が検証され、activate_path 後も往復成立 (現在の経路 {} -> {})",
                direct.0, direct.1, now.0, now.1
            )
        }
        Ok(Err(e)) => {
            bridge.stop();
            return Err(e.context(format!("直接経路の検証に失敗 ({context})")));
        }
        Err(_) => {
            bridge.stop();
            anyhow::bail!("{PATH_VALIDATION_TIMEOUT:?} 以内に PathValidated が来ず ({context})");
        }
    };

    bridge.stop();
    Ok(format!("{context}; {outcome}"))
}

/// The proxy a relay leg connects to, on a **real interface address**.
///
/// The real MASQUE leg dials the proxy over the network, so both ends of that
/// connection are interface addresses. A loopback stand-in would instead force
/// the leg to send from a real address to `127.0.0.1` — the one operation
/// Windows refuses (§2.2.2) — and the harness would fail where production would
/// not.
async fn spawn_proxy_stand_in(reg: &Arc<Registration>) -> anyhow::Result<SpikeListener> {
    let addr = SocketAddr::new(probe_local_addr()?.ip(), 0);
    spawn_listener(reg, addr).await
}

/// A live QUIC connection held open purely to own a shared, unconnected binding
/// at a real interface address — the spike's stand-in for a MASQUE relay leg.
struct RelayLeg {
    addr: SocketAddr,
    _conn: Connection,
    _peer: Connection,
}

impl RelayLeg {
    /// Bind a fresh real address and keep a connection to `peer` alive on it.
    async fn start(reg: &Arc<Registration>, peer: &mut SpikeListener) -> anyhow::Result<Self> {
        let addr = probe_local_addr()?;
        let conn = shared_binding_conn(reg, addr)?;
        // Dial the proxy stand-in at its interface address, as the real leg
        // dials the real proxy — never loopback (see `spawn_proxy_stand_in`).
        let peer_ip = peer.addr.ip().to_string();
        conn.start(&client_config(reg, false)?, &peer_ip, peer.addr.port())
            .await
            .with_context(|| {
                format!("relay-leg stand-in could not reach the proxy stand-in from {addr}")
            })?;
        let accepted = peer.accept_one().await?;
        anyhow::ensure!(
            conn.get_local_addr()? == addr,
            "relay-leg stand-in landed on another address"
        );
        Ok(Self {
            addr,
            _conn: conn,
            _peer: accepted,
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Learn a real interface address the way `tonic-h3`'s `is_unconnected` mode
/// does: `connect()` a UDP socket (which sends nothing) and read the local
/// address the kernel picked, then release it.
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

/// A client connection set up the way 案B prescribes, short of starting it.
fn shared_binding_conn(reg: &Arc<Registration>, local: SocketAddr) -> anyhow::Result<Connection> {
    let conn = Connection::new(reg)?;
    conn.set_share_binding(true)?;
    conn.set_unconnected_socket(true)?;
    conn.set_local_addr(local)?;
    Ok(conn)
}

/// The video client's configuration, optionally in NAT-traversal mode — the
/// same knobs `camera-client`'s Direct mode uses.
fn client_config(reg: &Registration, enable_natt: bool) -> anyhow::Result<msquic::Configuration> {
    let alpn = [msquic::BufferRef::from(ALPN)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        .set_DestCidUpdateIdleTimeoutMs(0)
        .set_PeerUnidiStreamCount(100)
        .set_StreamMultiReceiveEnabled()
        .set_ReceiveObservedAddressReports();
    let settings = if enable_natt {
        settings.set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
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

/// A listener the checks accept from on demand.
///
/// The listener is held here rather than driven by a background task: an
/// aborted accept loop would drop the `Listener` from an arbitrary point and
/// leave msquic tearing down while the registration drains.
struct SpikeListener {
    addr: SocketAddr,
    listener: Listener,
    _reg: Arc<Registration>,
}

impl SpikeListener {
    /// The next accepted connection.
    async fn accept_one(&mut self) -> anyhow::Result<Connection> {
        self.listener
            .accept()
            .await
            .context("the spike listener failed to accept a connection")
    }
}

/// A listener with production settings — literally `make_msquic_async_listener`,
/// the same call `bind_video_listener` makes.
async fn spawn_listener(reg: &Arc<Registration>, addr: SocketAddr) -> anyhow::Result<SpikeListener> {
    let cert = camera_core::tls::dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let (reg, listener): (Arc<Registration>, Listener) =
        isekai_link_utils::make_msquic_async_listener(
            Some(reg.clone()),
            ALPN,
            Some(addr),
            &cert.cert_pem,
            &cert.key_pem,
            cert.pkcs12.as_deref(),
        )?;
    Ok(wrap_listener(reg, listener)?)
}

/// A listener whose settings can be varied, to answer #59's caveat about
/// whether the listener needs NAT-traversal / address-discovery tuning.
///
/// `natt = false` reproduces `make_msquic_async_listener`'s settings exactly.
/// `natt = true` adds `AddAddressMode::NatTraversal` and
/// `ReceiveObservedAddressReports`. Returns `Ok(None)` where the variant cannot
/// be built — on Windows the production helper loads credentials through the
/// schannel cert store, which this example does not reimplement.
async fn spawn_listener_variant(
    reg: &Arc<Registration>,
    addr: SocketAddr,
    natt: bool,
) -> anyhow::Result<Option<SpikeListener>> {
    if !natt {
        return spawn_listener(reg, addr).await.map(Some);
    }
    #[cfg(windows)]
    {
        let _ = addr;
        return Ok(None);
    }
    #[cfg(not(windows))]
    {
        use std::io::Write as _;

        let cert = camera_core::tls::dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
        let alpn = [msquic::BufferRef::from(ALPN)];
        // Identical to make_msquic_async_listener's settings, plus the two
        // knobs under test.
        let config = reg.open_configuration(
            &alpn,
            Some(
                &msquic::Settings::new()
                    .set_IdleTimeoutMs(30_000)
                    .set_MaximumMtu(1200)
                    .set_KeepAliveIntervalMs(10_000)
                    .set_DestCidUpdateIdleTimeoutMs(0)
                    .set_PeerBidiStreamCount(100)
                    .set_PeerUnidiStreamCount(100)
                    .set_DatagramReceiveEnabled()
                    .set_StreamMultiReceiveEnabled()
                    .set_ReceiveObservedAddressReports()
                    .set_AddAddressMode(msquic::AddAddressMode::NatTraversal),
            ),
        )?;

        let mut cert_file = tempfile::NamedTempFile::new()?;
        cert_file.write_all(cert.cert_pem.as_bytes())?;
        let cert_path = cert_file.into_temp_path();
        let mut key_file = tempfile::NamedTempFile::new()?;
        key_file.write_all(cert.key_pem.as_bytes())?;
        let key_path = key_file.into_temp_path();
        config.load_credential(
            &msquic::CredentialConfig::new().set_credential(msquic::Credential::CertificateFile(
                msquic::CertificateFile::new(
                    key_path.to_string_lossy().into_owned(),
                    cert_path.to_string_lossy().into_owned(),
                ),
            )),
        )?;

        let listener = Listener::new(reg, config)?;
        listener.start(&alpn, Some(addr))?;
        wrap_listener(reg.clone(), listener).map(Some)
    }
}

/// Pair a started listener with the registration that must outlive it.
fn wrap_listener(reg: Arc<Registration>, listener: Listener) -> anyhow::Result<SpikeListener> {
    let addr = listener.local_addr()?;
    Ok(SpikeListener {
        addr,
        listener,
        _reg: reg,
    })
}

/// Two loopback sockets forwarding datagrams both ways, standing in for the
/// whole relay chain (the client's CONNECT-UDP bridge, the proxy, and the
/// server's bind-leg forward socket).
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
            // `last_src` semantics, exactly as `run_bridge` has them: whatever
            // spoke last is where replies go. The source address is never
            // checked, so a real-IP source is fine.
            let mut client: Option<SocketAddr> = None;
            // One buffer per direction: `select!` borrows both arms' futures at
            // once, so they cannot share a single `&mut`.
            let mut up = vec![0u8; 65_535];
            let mut down = vec![0u8; 65_535];
            loop {
                tokio::select! {
                    _ = token.cancelled() => break,
                    r = front.recv_from(&mut up) => match r {
                        Ok((n, src)) => {
                            client = Some(src);
                            if let Err(e) = back.send_to(&up[..n], target).await {
                                tracing::debug!("bridge uplink failed: {e}");
                            }
                        }
                        Err(e) => { tracing::debug!("bridge front recv failed: {e}"); break; }
                    },
                    r = back.recv_from(&mut down) => match r {
                        Ok((n, _)) => {
                            if let Some(dst) = client {
                                if let Err(e) = front.send_to(&down[..n], dst).await {
                                    tracing::debug!("bridge downlink failed: {e}");
                                }
                            }
                        }
                        Err(e) => { tracing::debug!("bridge back recv failed: {e}"); break; }
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

/// Push one unidirectional stream server -> client and read it back, proving
/// the path carries application data. Returns the byte count.
async fn round_trip(server: &Connection, client: &Connection) -> anyhow::Result<usize> {
    const PAYLOAD: &[u8] = b"isekai-spike-frame";
    let mut out = server
        .open_outbound_stream(StreamType::Unidirectional, false)
        .await?;
    out.write_all(PAYLOAD).await?;
    poll_fn(|cx| out.poll_finish_write(cx)).await?;

    let mut inbound = tokio::time::timeout(
        Duration::from_secs(10),
        client.accept_inbound_uni_stream(),
    )
    .await
    .context("no inbound stream arrived on the active path")??;
    let mut got = Vec::new();
    inbound.read_to_end(&mut got).await?;
    anyhow::ensure!(got == PAYLOAD, "payload mismatch across the path");
    Ok(got.len())
}

/// Render a fallible msquic call as a short PASS/FAIL token for the report.
fn describe<E: std::fmt::Debug>(result: Result<(), E>) -> String {
    match result {
        Ok(()) => "OK".to_owned(),
        Err(e) => format!("ERR({e:?})"),
    }
}

/// Run a check under a timeout, so a wedged handshake reports rather than hangs.
async fn run<F: std::future::Future<Output = anyhow::Result<String>>>(
    f: F,
) -> anyhow::Result<String> {
    match tokio::time::timeout(CHECK_TIMEOUT, f).await {
        Ok(r) => r,
        Err(_) => Err(anyhow::anyhow!("timed out after {CHECK_TIMEOUT:?}")),
    }
}

// ---------------------------------------------------------------------------
// Reporting
// ---------------------------------------------------------------------------

#[derive(PartialEq, Eq, Clone, Copy)]
enum Required {
    Yes,
    No,
}

/// PASS / FAIL / SKIP. A skip is "this environment could not ask the question",
/// which must never read as an answer — and must never fail the build either.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Verdict {
    Pass,
    Fail,
    Skip,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Skip => "SKIP",
        }
    }
}

#[derive(Default)]
struct Report {
    rows: Vec<(String, Required, String, Verdict, String)>,
}

impl Report {
    fn record(
        &mut self,
        id: &str,
        required: Required,
        question: &str,
        result: anyhow::Result<String>,
    ) {
        let (verdict, note) = match result {
            Ok(note) => (Verdict::Pass, note),
            Err(e) => (Verdict::Fail, format!("{e:#}")),
        };
        self.push(id, required, question, verdict, note);
    }

    fn skip(&mut self, id: &str, question: &str, reason: &str) {
        self.push(id, Required::No, question, Verdict::Skip, reason.to_owned());
    }

    fn push(
        &mut self,
        id: &str,
        required: Required,
        question: &str,
        verdict: Verdict,
        note: String,
    ) {
        println!(
            "[check {id}] {} — {question}\n            {note}",
            verdict.label()
        );
        self.rows
            .push((id.to_owned(), required, question.to_owned(), verdict, note));
    }

    fn required_failed(&self) -> bool {
        self.rows
            .iter()
            .any(|(_, req, _, v, _)| *req == Required::Yes && *v == Verdict::Fail)
    }

    /// A Markdown table, so CI can paste it straight into the job summary.
    fn print(&self) {
        println!("\n## Phase 0 spike ({} / {})\n", std::env::consts::OS, std::env::consts::ARCH);
        println!("| # | 必須 | 問い | 結果 | 備考 |");
        println!("| --- | --- | --- | --- | --- |");
        for (id, required, question, verdict, note) in &self.rows {
            let required = if *required == Required::Yes { "必須" } else { "参考" };
            let note = note.replace('|', "\\|").replace('\n', " ");
            println!(
                "| {id} | {required} | {question} | **{}** | {note} |",
                verdict.label()
            );
        }
        println!();
    }
}
