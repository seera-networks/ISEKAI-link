//! A camera server that streams generated frames — the peer to point a viewer
//! at when you have no camera, no OpenCV, and possibly no Unix.
//!
//! `camera-server` needs OpenCV, and `relay_e2e` drives both halves inside one
//! process, so neither can act as the other end for the iOS app. This does the
//! server half only, and being OpenCV-free it builds anywhere the workspace
//! does, Windows included.
//!
//! It talks to whoever is driving the four-value exchange over stdin, or over a
//! line-based TCP socket for an automated harness:
//!
//! ```text
//! hello                  -> ok listener=… endpoint=… identity=… proxy=… protocol=… insecure=… token=…
//! issue <endpoint_id>    -> ok capability=…
//! bind <connection_id>   -> ok
//! quit                   -> ok
//! ```
//!
//! `hello` hands out the Auth0 token so an automated client needs no
//! configuration of its own beyond the port. That is only tolerable because the
//! control socket binds loopback — keep it that way.
//!
//! ```sh
//! AUTH0_TOKEN=<jwt> cargo run -p camera-core --example synthetic_server
//! # against a local stack rather than the live endpoints:
//! AUTH0_TOKEN=<jwt> IDENTITY_URL=https://127.0.0.1:9443 \
//! PROXY_URL=https://127.0.0.1:8443 ISEKAI_INSECURE_SKIP_VERIFY=1 \
//! cargo run -p camera-core --example synthetic_server -- --control 127.0.0.1:57345
//! ```

use std::net::SocketAddr;
use std::time::Duration;

use bytes::Bytes;
use camera_core::{load_or_generate_key, P2pConfig, ServerCommand};
use jpeg_encoder::{ColorType, Encoder};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;

/// The port the iOS test harness looks for. Nothing else depends on the value.
const DEFAULT_CONTROL_ADDR: &str = "127.0.0.1:57345";

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

#[derive(Clone)]
struct Control {
    listener_id: String,
    endpoint_id: String,
    identity_url: String,
    proxy_url: String,
    protocol: String,
    auth0_token: String,
    insecure_skip_verify: bool,
    commands: mpsc::Sender<ServerCommand>,
    shutdown: CancellationToken,
}

impl Control {
    /// Handle one command line. The reply is always a single line: `ok …` or
    /// `err …`, so a line-oriented client never has to frame anything.
    async fn handle(&self, line: &str) -> String {
        let mut parts = line.split_whitespace();
        match parts.next() {
            None => "err empty command".to_owned(),
            // Everything a client needs to reach the same deployment as this
            // server, so an automated one is configured by the port alone.
            Some("hello") => format!(
                "ok listener={} endpoint={} identity={} proxy={} protocol={} insecure={} token={}",
                self.listener_id,
                self.endpoint_id,
                self.identity_url,
                self.proxy_url,
                self.protocol,
                u8::from(self.insecure_skip_verify),
                self.auth0_token,
            ),
            Some("issue") => match parts.next() {
                Some(endpoint) => match self.issue(endpoint).await {
                    Ok(capability) => format!("ok capability={capability}"),
                    Err(e) => format!("err {e:#}"),
                },
                None => "err usage: issue <endpoint_id>".to_owned(),
            },
            Some("bind") => match parts.next() {
                Some(connection) => match self.bind(connection).await {
                    Ok(()) => "ok".to_owned(),
                    Err(e) => format!("err {e:#}"),
                },
                None => "err usage: bind <connection_id>".to_owned(),
            },
            Some("quit") => {
                self.shutdown.cancel();
                "ok".to_owned()
            }
            Some(other) => format!("err unknown command: {other}"),
        }
    }

    async fn issue(&self, allowed_endpoint: &str) -> anyhow::Result<String> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::IssueCapability {
                allowed_endpoint: allowed_endpoint.to_owned(),
                ttl: None,
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("server stopped"))?;
        rx.await?
    }

    async fn bind(&self, connection_id: &str) -> anyhow::Result<()> {
        let (reply, rx) = oneshot::channel();
        self.commands
            .send(ServerCommand::Bind {
                connection_id: connection_id.to_owned(),
                reply,
            })
            .await
            .map_err(|_| anyhow::anyhow!("server stopped"))?;
        rx.await?
    }
}

/// A sweeping bar over a drifting gradient: enough for a viewer to tell at a
/// glance that frames are live, in order, and not a still.
fn render(frame: u64, width: u16, height: u16) -> Vec<u8> {
    let (w, h) = (width as usize, height as usize);
    let mut rgb = vec![0u8; w * h * 3];
    let bar = (frame as usize * 7) % w;
    let half_bar = (w / 24).max(2);
    let tint = (frame % 256) as u8;

    for y in 0..h {
        for x in 0..w {
            let i = (y * w + x) * 3;
            if x.abs_diff(bar) < half_bar {
                rgb[i] = 255;
                rgb[i + 1] = 255;
                rgb[i + 2] = 255;
            } else {
                rgb[i] = (x * 255 / w) as u8;
                rgb[i + 1] = (y * 255 / h) as u8;
                rgb[i + 2] = tint;
            }
        }
    }

    let mut jpeg = Vec::new();
    Encoder::new(&mut jpeg, 80)
        .encode(&rgb, width, height, ColorType::Rgb)
        .expect("encoding a generated RGB buffer cannot fail");
    jpeg
}

#[cfg(test)]
mod tests {
    use super::render;

    /// The viewer decodes these with ImageIO, so "it is a JPEG" is the contract
    /// that matters — and the reason this example does not just send bytes the
    /// way relay_e2e does.
    #[test]
    fn renders_decodable_jpeg_frames() {
        let frame = render(3, 64, 48);
        assert_eq!(&frame[..2], &[0xFF, 0xD8], "missing JPEG start-of-image");
        assert_eq!(
            &frame[frame.len() - 2..],
            &[0xFF, 0xD9],
            "missing JPEG end-of-image"
        );
        assert_ne!(render(0, 64, 48), frame, "frames should not be identical");
    }
}

async fn serve_control_conn(control: Control, stream: TcpStream) {
    let (read_half, mut write_half) = stream.into_split();
    let mut lines = BufReader::new(read_half).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let mut reply = control.handle(&line).await;
        reply.push('\n');
        if write_half.write_all(reply.as_bytes()).await.is_err() {
            break;
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_env("SEERA_LOG"))
        .with_writer(std::io::stderr)
        .init();

    let mut control_addr: Option<String> = None;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control" => {
                control_addr = Some(args.next().unwrap_or_else(|| DEFAULT_CONTROL_ADDR.to_owned()))
            }
            "-h" | "--help" => {
                println!("usage: synthetic_server [--control [addr]]");
                println!("env: AUTH0_TOKEN (required), IDENTITY_URL, PROXY_URL, PROTOCOL,");
                println!("     REGISTER (default: only for a newly generated key),");
                println!("     KEY_PATH, FPS, WIDTH, HEIGHT");
                return Ok(());
            }
            other => anyhow::bail!("unknown argument: {other}"),
        }
    }

    let auth0_token = std::env::var("AUTH0_TOKEN")
        .map_err(|_| anyhow::anyhow!("AUTH0_TOKEN is required"))?;
    let identity_url = env_or("IDENTITY_URL", "https://identity.isekai.tools:9443");
    let proxy_url = env_or("PROXY_URL", "https://link.isekai.tools:8443");
    let protocol = env_or("PROTOCOL", "isekai-validator-v1");
    let key_path = env_or("KEY_PATH", "synthetic-server-endpoint.pem");
    let fps: u64 = env_or("FPS", "10").parse().unwrap_or(10);
    let width: u16 = env_or("WIDTH", "640").parse().unwrap_or(640);
    let height: u16 = env_or("HEIGHT", "480").parse().unwrap_or(480);

    let key_path = std::path::Path::new(&key_path);
    // Read before load_or_generate_key creates the file.
    let register = should_register(key_path);
    let cfg = P2pConfig {
        identity_url: identity_url.clone(),
        identity_http3: false,
        proxy_url: proxy_url.clone(),
        auth0_token: auth0_token.clone(),
        protocol: protocol.clone(),
        register,
        device_name: Some("synthetic-server".to_owned()),
        token_ttl: None,
        key: load_or_generate_key(key_path)?,
    };

    let shutdown = CancellationToken::new();
    let (frame_tx, frame_rx) = mpsc::channel::<Bytes>(4);
    let server = camera_core::spawn_p2p_server(None, cfg, frame_rx, shutdown.clone()).await?;

    println!(
        "listener={} endpoint={} video={}",
        server.info.listener_id, server.info.endpoint_id, server.info.video_addr
    );

    let control = Control {
        listener_id: server.info.listener_id.clone(),
        endpoint_id: server.info.endpoint_id.clone(),
        identity_url,
        proxy_url,
        protocol,
        auth0_token,
        insecure_skip_verify: std::env::var_os("ISEKAI_INSECURE_SKIP_VERIFY").is_some(),
        commands: server.commands.clone(),
        shutdown: shutdown.clone(),
    };

    if let Some(addr) = control_addr {
        let addr: SocketAddr = addr.parse()?;
        anyhow::ensure!(
            addr.ip().is_loopback(),
            "the control socket hands out the Auth0 token; it must bind loopback (got {addr})"
        );
        let listener = TcpListener::bind(addr).await?;
        println!("control={}", listener.local_addr()?);
        let control = control.clone();
        let shutdown = shutdown.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = shutdown.cancelled() => return,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, _)) => {
                            tokio::spawn(serve_control_conn(control.clone(), stream));
                        }
                        Err(e) => tracing::warn!("control accept failed: {e}"),
                    },
                }
            }
        });
    }

    // Frames start flowing immediately; nothing reaches the peer until it has
    // connected and the relay leg is bound.
    let frame_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_micros(1_000_000 / fps.max(1)));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let mut frame = 0u64;
        loop {
            tokio::select! {
                _ = frame_shutdown.cancelled() => return,
                _ = ticker.tick() => {}
            }
            // Rendering is milliseconds at 640x480, but it is still CPU work on
            // a runtime thread — keep it off the async workers.
            let jpeg = match tokio::task::spawn_blocking(move || render(frame, width, height)).await
            {
                Ok(jpeg) => jpeg,
                Err(e) => {
                    tracing::error!("frame render panicked: {e}");
                    return;
                }
            };
            if frame_tx.send(Bytes::from(jpeg)).await.is_err() {
                return;
            }
            frame += 1;
        }
    });

    // stdin is the interactive path: paste the viewer's Endpoint ID, then its
    // Connection ID, the same exchange the desktop GUI drives with buttons.
    let stdin_control = control.clone();
    let stdin_shutdown = shutdown.clone();
    tokio::spawn(async move {
        let mut lines = BufReader::new(tokio::io::stdin()).lines();
        loop {
            let line = tokio::select! {
                _ = stdin_shutdown.cancelled() => return,
                line = lines.next_line() => line,
            };
            match line {
                Ok(Some(line)) => println!("{}", stdin_control.handle(&line).await),
                // EOF: an automated harness redirects stdin from /dev/null and
                // drives the control socket instead. Keep serving.
                Ok(None) => return,
                Err(e) => {
                    tracing::warn!("stdin closed: {e}");
                    return;
                }
            }
        }
    });

    println!("ready");
    tokio::select! {
        _ = shutdown.cancelled() => {}
        r = tokio::signal::ctrl_c() => {
            if r.is_ok() {
                shutdown.cancel();
            }
        }
    }
    Ok(())
}
