//! The camera video transport over QUIC (`sample` ALPN): MJPEG frames, one per
//! unidirectional stream. This is the same wire protocol the camera apps
//! already use; here it is factored out so it works over any address — a public
//! one (legacy) or the P2P relay's loopback address.

use std::future::poll_fn;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use msquic_async::{msquic, Connection, Listener, Registration, StreamType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use isekai_p2p::agent::CertBundle;

use crate::tls::dev_cert;

/// ALPN for the camera video protocol.
pub const VIDEO_ALPN: &str = "sample";

/// Bind a video QUIC listener on `addr`.
///
/// With `cert` (the per-endpoint bundle downloaded from the proxy) the listener
/// presents that certificate, so the initiator — dialing the matching loopback
/// FQDN — can validate it. Without one it falls back to a generated dev
/// certificate (dev only; the initiator then skips validation).
///
/// Returns the registration (created when `reg` is `None`), the listener, and
/// its bound local address — for P2P, pass that address to the relay bind leg.
pub fn bind_video_listener(
    reg: Option<Arc<Registration>>,
    addr: SocketAddr,
    cert: Option<&CertBundle>,
) -> anyhow::Result<(Arc<Registration>, Listener, SocketAddr)> {
    let (cert_pem, key_pem) = match cert {
        Some(bundle) => (bundle.cert_pem.clone(), bundle.key_pem.clone()),
        None => {
            let dev = dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
            (dev.cert_pem, dev.key_pem)
        }
    };
    let (reg, listener) = isekai_link_utils::make_msquic_async_listener(
        reg,
        VIDEO_ALPN,
        Some(addr),
        &cert_pem,
        &key_pem,
        None,
    )?;
    let local = listener
        .local_addr()
        .context("read listener local address")?;
    Ok((reg, listener, local))
}

/// Accept video connections and fan every frame from `frame_rx` out to each
/// connected client as a unidirectional stream. Runs until `shutdown` fires or
/// the frame source closes.
pub async fn serve_frames(
    listener: Listener,
    mut frame_rx: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
) {
    let mut senders: Vec<mpsc::Sender<Bytes>> = Vec::new();
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            accepted = listener.accept() => match accepted {
                Ok(conn) => {
                    let (tx, rx) = mpsc::channel::<Bytes>(100);
                    senders.push(tx);
                    tokio::spawn(push_frames(conn, rx));
                }
                Err(e) => {
                    tracing::error!("video accept failed: {e}");
                    break;
                }
            },
            frame = frame_rx.recv() => match frame {
                Some(frame) => {
                    // Drop connections whose push task has ended.
                    senders.retain(|s| !s.is_closed());
                    for s in &senders {
                        let _ = s.send(frame.clone()).await;
                    }
                }
                None => break,
            },
        }
    }
}

async fn push_frames(conn: Connection, mut rx: mpsc::Receiver<Bytes>) {
    while let Some(frame) = rx.recv().await {
        if let Err(e) = push_one(&conn, &frame).await {
            tracing::debug!("video push ended: {e}");
            break;
        }
    }
}

async fn push_one(conn: &Connection, frame: &[u8]) -> anyhow::Result<()> {
    let mut stream = conn
        .open_outbound_stream(StreamType::Unidirectional, false)
        .await?;
    stream.write_all(frame).await?;
    poll_fn(|cx| stream.poll_finish_write(cx)).await?;
    Ok(())
}

/// Dial a video QUIC connection at `host:port` and deliver inbound frames —
/// tagged with the stream id as a monotonically increasing sequence — to
/// `frame_tx`. Runs until `shutdown` fires or the connection ends.
///
/// `host` is used both to resolve the address (a P2P loopback FQDN resolves to
/// `127.0.0.1`) and as the TLS server name. With `verify` the peer's
/// certificate is validated against `host`; without it, validation is skipped
/// (dev only, for the self-signed [`dev_cert`]).
pub async fn receive_frames(
    reg: Option<Arc<Registration>>,
    host: &str,
    port: u16,
    verify: bool,
    frame_tx: mpsc::Sender<(u64, Bytes)>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let (reg, config) = video_client_config(reg, verify)?;
    let conn = Connection::new(&reg)?;
    conn.start(&config, host, port).await?;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            stream = conn.accept_inbound_uni_stream() => {
                let mut stream = stream?;
                let seq = stream.id().unwrap_or(0);
                let mut buf = Vec::new();
                stream.read_to_end(&mut buf).await?;
                // Full/closed receiver: drop the frame (UDP-like semantics).
                let _ = frame_tx.try_send((seq, Bytes::from(buf)));
            }
        }
    }
    Ok(())
}

/// Video client config: ALPN `sample`. With `verify` the peer's certificate is
/// validated against the dialed server name (the per-endpoint relay cert);
/// without it validation is **disabled** — dev only, for the self-signed
/// [`dev_cert`].
fn video_client_config(
    reg: Option<Arc<Registration>>,
    verify: bool,
) -> anyhow::Result<(Arc<Registration>, msquic::Configuration)> {
    let reg = match reg {
        Some(reg) => reg,
        None => Arc::new(Registration::new(&msquic::RegistrationConfig::default())?),
    };
    let alpn = [msquic::BufferRef::from(VIDEO_ALPN)];
    let config = reg.open_configuration(
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                // Cap the MTU so a video QUIC packet (a QUIC Initial is padded
                // to 1200) plus CONNECT-UDP encapsulation fits inside the relay
                // tunnel's HTTP datagram. Matches the listener (see
                // `make_msquic_async_listener`). Without it the default 1500-MTU
                // packets overflow the tunnel and are dropped as `TooLarge`.
                .set_MaximumMtu(1200)
                .set_PeerUnidiStreamCount(100)
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;
    let mut cred = msquic::CredentialConfig::new_client();
    if !verify {
        cred = cred.set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    }
    config.load_credential(&cred)?;
    Ok((reg, config))
}
