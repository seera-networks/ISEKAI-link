//! Gap variant of `relay_e2e`: the initiator starts dialing the video QUIC
//! *before* the target binds its relay leg, then the bind happens after a delay
//! (simulating the human pasting the connection id into the server). This is the
//! scenario `dial_video` targets — the initial video handshake must ride across
//! the bind gap on a single connection (a long `HandshakeIdleTimeoutMs`) and
//! complete once both relay legs are up. Run with a `GAP_SECS` larger than a few
//! seconds to exercise it.
//!
//! ```sh
//! GAP_SECS=12 AUTH0_TOKEN=<jwt> IDENTITY_URL=https://127.0.0.1:9443 \
//! PROXY_URL=https://127.0.0.1:8443 \
//! cargo run -p camera-core --example relay_gap_e2e
//! ```
//!
//! `REGISTER=1`/`0` overrides whether the Endpoint is registered before a token
//! is issued; by default only a freshly generated key is registered, since the
//! Identity API answers a repeat registration with 409.

use std::time::Duration;

use bytes::Bytes;
use camera_core::{load_or_generate_key, InitiatorSession, P2pConfig, ServerCommand};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// Beside whatever key path this harness was given, and stable across runs:
/// a fresh video key spends one of the Endpoint's five issuances a week.
fn video_key_path() -> std::path::PathBuf {
    std::path::PathBuf::from(
        std::env::var("VIDEO_KEY_PATH").unwrap_or_else(|_| "video-tls-key.pem".to_owned()),
    )
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}


/// Whether to register the Endpoint before asking for a token.
///
/// A key that was already on disk was registered on an earlier run, and the
/// Identity API answers a repeat registration with 409
/// `endpoint-already-registered`. So register a freshly generated key and not an
/// existing one; `REGISTER=1`/`0` forces the issue either way.
fn should_register(key_path: &std::path::Path) -> bool {
    match std::env::var("REGISTER") {
        Ok(value) => matches!(value.trim(), "1" | "true" | "yes" | "on"),
        Err(_) => !key_path.exists(),
    }
}

fn config(auth0: &str, identity: &str, proxy: &str, protocol: &str, key_path: &str) -> P2pConfig {
    let key_path = std::path::Path::new(key_path);
    // Read before load_or_generate_key creates the file.
    let register = should_register(key_path);
    P2pConfig {
        identity_url: identity.to_owned(),
        identity_http3: false,
        proxy_url: proxy.to_owned(),
        auth0_token: auth0.to_owned(),
        protocol: protocol.to_owned(),
        register,
        device_name: Some("relay-gap-e2e".to_owned()),
        token_ttl: None,
        auth0: None,
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
    let identity = env_or("IDENTITY_URL", "https://127.0.0.1:9443");
    let proxy = env_or("PROXY_URL", "https://127.0.0.1:8443");
    let protocol = env_or("PROTOCOL", "isekai-validator-v1");
    let gap_secs: u64 = env_or("GAP_SECS", "12").parse().unwrap_or(12);

    let code = match run(&auth0, &identity, &proxy, &protocol, gap_secs).await {
        Ok(n) => {
            println!("PASS: received {n} frames over the relay after a {gap_secs}s bind gap");
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
    unsafe { libc_exit(code) }
}

unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

async fn run(
    auth0: &str,
    identity: &str,
    proxy: &str,
    protocol: &str,
    gap_secs: u64,
) -> anyhow::Result<usize> {
    let shutdown = CancellationToken::new();

    let server_cfg = config(auth0, identity, proxy, protocol, "gap-server.pem");
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(16);
    let server =
        camera_core::spawn_p2p_server(None, server_cfg, &video_key_path(), frame_rx, camera_core::AcceptPolicy::Manual, shutdown.clone()).await?;
    println!(
        "server ready: listener={} endpoint={} video={}",
        server.info.listener_id, server.info.endpoint_id, server.info.video_addr
    );

    let client_cfg = config(auth0, identity, proxy, protocol, "gap-client.pem");
    let client_endpoint = client_cfg.endpoint_id();

    let capability = command(&server.commands, |reply| ServerCommand::IssueCapability {
        allowed_endpoint: client_endpoint.clone(),
        ttl: None,
        reply,
    })
    .await?;

    let session = InitiatorSession::connect(
        &client_cfg,
        &capability,
        &server.info.listener_id,
        &[],
        "127.0.0.1:0".parse().unwrap(),
    )
    .await?;
    let connection_id = session.connection_id().to_owned();
    let local_addr = session.local_addr;
    let (video_host, verify) = match session.video_host() {
        Some(host) => (host.to_string(), true),
        None => ("127.0.0.1".to_string(), false),
    };
    let video_port = local_addr.port();
    println!("initiator connected: connection={connection_id} local={local_addr}");

    // KEY DIFFERENCE vs relay_e2e: start dialing the video QUIC *now*, before the
    // server binds — exactly what the camera-client GUI does after connect. The
    // relay leg is half-open, so the handshake must ride across the gap until the
    // bind lands.
    let (recv_tx, mut recv_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let recv_shutdown = shutdown.clone();
    let receiver = tokio::spawn(async move {
        camera_core::receive_frames(
            None,
            &video_host,
            video_port,
            verify,
            recv_tx,
            recv_shutdown,
        )
        .await
    });
    println!("initiator is dialing the video QUIC BEFORE the bind (retry must bridge the gap)");

    // Simulate the operator taking a while to paste the connection id and bind.
    println!("simulating a {gap_secs}s operator delay before the server binds...");
    tokio::time::sleep(Duration::from_secs(gap_secs)).await;

    command(&server.commands, |reply| ServerCommand::Bind {
        connection_id: connection_id.clone(),
        reply,
    })
    .await?;
    println!("server bound the relay after the gap; streaming");

    const TARGET: usize = 5;
    let outcome = tokio::time::timeout(Duration::from_secs(30), async {
        let mut sent = 0usize;
        let mut received = Vec::new();
        loop {
            sent += 1;
            let _ = frame_tx.send(Bytes::from(format!("frame-{sent}"))).await;
            match tokio::time::timeout(Duration::from_millis(300), recv_rx.recv()).await {
                Ok(Some((_seq, data))) => {
                    received.push(data);
                    if received.len() >= TARGET {
                        return Ok::<usize, anyhow::Error>(received.len());
                    }
                }
                Ok(None) => anyhow::bail!("frame receiver closed"),
                Err(_) => {}
            }
        }
    })
    .await;

    let result = match outcome {
        Ok(Ok(n)) => Ok(n),
        Ok(Err(e)) => Err(e),
        Err(_) => Err(anyhow::anyhow!(
            "no frames received within the timeout (did the video handshake recover after the bind?)"
        )),
    };

    shutdown.cancel();
    let _ = receiver.await;
    std::mem::forget(session);
    std::mem::forget(server);
    result
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
