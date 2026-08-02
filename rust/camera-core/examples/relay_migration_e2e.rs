//! End-to-end check of **path migration** in P2P mode against a live proxy.
//!
//! Extends `relay_e2e`: after frames are flowing over the relay, wait for the
//! peers to punch a direct path, switch to it, and prove frames still arrive on
//! the other side of the switch. That last part is the whole point — a
//! migration that drops the stream is not a migration.
//!
//! Both parties run in one process, as in `relay_e2e`, so the "direct" path is
//! between two relay legs on the same host. That still exercises everything
//! that matters: the observed-address exchange, `add_candidate_addr`, the
//! peer's `add_bound_addr` / `add_observed_addr`, `PathValidated` and
//! `activate_path`. What it does not exercise is NAT punching itself, which
//! needs two machines.
//!
//! ```sh
//! AUTH0_TOKEN=<jwt> \
//! IDENTITY_URL=https://identity.isekai.tools:9443 \
//! PROXY_URL=https://tokyo.link.isekai.tools:8443 \
//! cargo run -p camera-core --example relay_migration_e2e
//! ```
//!
//! `REGISTER=1`/`0` overrides whether the Endpoint is registered before a token
//! is issued; by default only a freshly generated key is registered, since the
//! Identity API answers a repeat registration with 409.
//!
//! Exits 0 on success, 1 on failure.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use camera_core::{
    load_or_generate_key, InitiatorSession, P2pConfig, PathEvent, ServerCommand, VideoRecvOptions,
};
use isekai_p2p::agent::RelayOptions;
use msquic_async::{msquic, Registration};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// How long to wait for the peers to validate a direct path.
const DIRECT_PATH_TIMEOUT: Duration = Duration::from_secs(30);
/// Frames to see before and again after the switch.
const FRAMES_PER_LEG: usize = 5;
/// Frame size, in bytes. A camera JPEG at 640x480/q80 is tens of kilobytes, so
/// a payload that fits in a single QUIC packet proves nothing about the path
/// that actually has to carry video. Override with FRAME_BYTES.
const DEFAULT_FRAME_BYTES: usize = 30_000;

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

fn should_register(key_path: &std::path::Path) -> bool {
    match std::env::var("REGISTER") {
        Ok(value) => matches!(value.trim(), "1" | "true" | "yes" | "on"),
        Err(_) => !key_path.exists(),
    }
}

fn config(auth0: &str, identity: &str, proxy: &str, protocol: &str, key_path: &str) -> P2pConfig {
    let key_path = std::path::Path::new(key_path);
    let register = should_register(key_path);
    P2pConfig {
        identity_url: identity.to_owned(),
        identity_http3: false,
        proxy_url: proxy.to_owned(),
        auth0_token: auth0.to_owned(),
        protocol: protocol.to_owned(),
        register,
        device_name: Some("relay-migration-e2e".to_owned()),
        token_ttl: None,
        key: load_or_generate_key(key_path).expect("load/generate key"),
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("SEERA_LOG"))
        .with_writer(std::io::stderr)
        .init();
    std::env::set_var("ISEKAI_INSECURE_SKIP_VERIFY", "1");

    let auth0 = std::env::var("AUTH0_TOKEN").expect("AUTH0_TOKEN is required");
    let identity = env_or("IDENTITY_URL", "https://identity.isekai.tools:9443");
    let proxy = env_or("PROXY_URL", "https://tokyo.link.isekai.tools:8443");
    let protocol = env_or("PROTOCOL", "isekai-validator-v1");

    let code = match run(&auth0, &identity, &proxy, &protocol).await {
        Ok(report) => {
            println!("PASS: {report}");
            0
        }
        Err(e) => {
            eprintln!("FAIL: {e:#}");
            1
        }
    };
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // As in relay_e2e: skip msquic's teardown, which blocks and then aborts.
    unsafe { libc_exit(code) }
}

unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

async fn run(auth0: &str, identity: &str, proxy: &str, protocol: &str) -> anyhow::Result<String> {
    let shutdown = CancellationToken::new();
    // One registration for everything: msquic looks bindings up per
    // registration, so the video connection and the relay legs have to share
    // one for a direct path to be openable at all.
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);

    // --- Target side ---
    let server_cfg = config(auth0, identity, proxy, protocol, "e2e-server.pem");
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let server =
        camera_core::spawn_p2p_server(Some(reg.clone()), server_cfg, frame_rx, camera_core::AcceptPolicy::Manual, shutdown.clone())
            .await?;
    println!(
        "server ready: listener={} endpoint={} video={}",
        server.info.listener_id, server.info.endpoint_id, server.info.video_addr
    );

    // --- Initiator side ---
    let client_cfg = config(auth0, identity, proxy, protocol, "e2e-client.pem");
    let client_endpoint = client_cfg.endpoint_id();

    let capability = command(&server.commands, |reply| ServerCommand::IssueCapability {
        allowed_endpoint: client_endpoint.clone(),
        ttl: None,
        reply,
    })
    .await?;
    println!("issued capability for {client_endpoint}");

    // The connect leg goes on a shared, unconnected socket so a direct path can
    // be opened from its binding, and on the shared registration.
    let session = InitiatorSession::connect_with_options(
        &client_cfg,
        &capability,
        &server.info.listener_id,
        &[],
        "127.0.0.1:0".parse().unwrap(),
        RelayOptions {
            unconnected: true,
            registration: Some(reg.clone()),
        },
    )
    .await?;
    let connection_id = session.connection_id().to_owned();
    let local_addr = session.local_addr;
    let (video_host, verify) = match session.video_host() {
        Some(host) => (host.to_string(), true),
        None => ("127.0.0.1".to_string(), false),
    };
    let video_port = local_addr.port();
    println!(
        "initiator connected: connection={connection_id} local={local_addr} \
         host={video_host} verify={verify}"
    );

    command(&server.commands, |reply| ServerCommand::Bind {
        connection_id: connection_id.clone(),
        reply,
    })
    .await?;
    println!("server bound the relay; streaming");

    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let (path_tx, mut path_rx) = mpsc::channel::<PathEvent>(16);
    let (migrate_tx, migrate_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(4);
    let recv_shutdown = shutdown.clone();
    let observed = session.observed_address();
    let receiver = tokio::spawn(async move {
        camera_core::receive_frames_with(
            &video_host,
            video_port,
            recv_tx,
            recv_shutdown,
            VideoRecvOptions {
                registration: Some(reg),
                verify,
                observed: Some(observed),
                path_events: Some(path_tx),
                migrate: Some(migrate_rx),
                ..Default::default()
            },
        )
        .await
    });

    // --- Leg 1: frames over the relay ---
    let relay_frames = pump_until(&frame_tx, &mut recv_rx, FRAMES_PER_LEG, "relay").await?;
    println!("received {relay_frames} frames over the relay");

    // --- Wait for the direct path ---
    let (relay_path, direct) = collect_paths(&mut path_rx).await?;
    println!("relay path: {} -> {}", relay_path.0, relay_path.1);
    println!("direct path: {} -> {}", direct.0, direct.1);

    // --- Switch, and keep streaming ---
    migrate_tx
        .send(direct)
        .await
        .map_err(|_| anyhow::anyhow!("the video task stopped before the switch"))?;
    let activated = tokio::time::timeout(Duration::from_secs(10), async {
        while let Some(event) = path_rx.recv().await {
            if let PathEvent::Activated { local, remote } = event {
                return Some((local, remote));
            }
        }
        None
    })
    .await
    .map_err(|_| anyhow::anyhow!("activate_path never reported back"))?
    .ok_or_else(|| anyhow::anyhow!("the path event channel closed before activation"))?;
    println!("activated {} -> {}", activated.0, activated.1);

    let direct_frames = pump_until(&frame_tx, &mut recv_rx, FRAMES_PER_LEG, "direct").await?;

    let result = Ok(format!(
        "{relay_frames} frames over the relay ({} -> {}), then {direct_frames} more \
         after migrating to the direct path ({} -> {})",
        relay_path.0, relay_path.1, direct.0, direct.1
    ));

    shutdown.cancel();
    let _ = receiver.await;
    std::mem::forget(session);
    std::mem::forget(server);
    result
}

/// Push frames until `target` of them come back, or give up.
///
/// The server fans out only to connected clients and the relay handshake
/// completes asynchronously, so frames are resent rather than sent once.
async fn pump_until(
    frame_tx: &mpsc::Sender<Bytes>,
    recv_rx: &mut mpsc::Receiver<(u64, Bytes)>,
    target: usize,
    leg: &str,
) -> anyhow::Result<usize> {
    tokio::time::timeout(Duration::from_secs(30), async {
        let mut sent = 0usize;
        let mut received = 0usize;
        loop {
            sent += 1;
            let _ = frame_tx.send(frame(leg, sent)).await;
            match tokio::time::timeout(Duration::from_millis(300), recv_rx.recv()).await {
                Ok(Some(_)) => {
                    received += 1;
                    if received >= target {
                        return Ok(received);
                    }
                }
                Ok(None) => anyhow::bail!("frame receiver closed on the {leg} path"),
                Err(_) => {} // nothing yet; resend
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("no frames arrived on the {leg} path within the timeout"))?
}

/// A frame of realistic size, tagged so it is identifiable in a capture.
fn frame(leg: &str, seq: usize) -> Bytes {
    let size = std::env::var("FRAME_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_FRAME_BYTES);
    let mut body = format!("{leg}-frame-{seq}:").into_bytes();
    body.resize(size.max(body.len()), b'.');
    Bytes::from(body)
}

/// Read path events until both the relay path and a validated direct path are
/// known.
async fn collect_paths(
    path_rx: &mut mpsc::Receiver<PathEvent>,
) -> anyhow::Result<((SocketAddr, SocketAddr), (SocketAddr, SocketAddr))> {
    let mut relay = None;
    let mut direct = None;
    tokio::time::timeout(DIRECT_PATH_TIMEOUT, async {
        while let Some(event) = path_rx.recv().await {
            match event {
                PathEvent::Relay { local, remote } => relay = Some((local, remote)),
                PathEvent::DirectValidated { local, remote } => direct = Some((local, remote)),
                PathEvent::Activated { .. } => {}
            }
            if let (Some(relay), Some(direct)) = (relay, direct) {
                return Some((relay, direct));
            }
        }
        None
    })
    .await
    .map_err(|_| {
        anyhow::anyhow!(
            "no direct path validated within {DIRECT_PATH_TIMEOUT:?} \
             (relay path so far: {relay:?})"
        )
    })?
    .ok_or_else(|| anyhow::anyhow!("the path event channel closed before a direct path appeared"))
}

async fn command<T>(
    commands: &mpsc::Sender<ServerCommand>,
    make: impl FnOnce(oneshot::Sender<anyhow::Result<T>>) -> ServerCommand,
) -> anyhow::Result<T> {
    let (reply, rx) = oneshot::channel();
    commands
        .send(make(reply))
        .await
        .map_err(|_| anyhow::anyhow!("P2P server command channel closed"))?;
    rx.await
        .map_err(|_| anyhow::anyhow!("P2P server dropped the reply"))?
}
