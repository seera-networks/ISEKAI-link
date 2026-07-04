/// masque-h3-server — expose a local HTTP/3 server through a MASQUE UDP proxy.
///
/// Architecture:
///
/// ```text
///   Remote QUIC/H3 client
///        ↕  QUIC
///   MASQUE proxy server  (bound-udp-server)
///        ↕  CONNECT-UDP tunnel over H3 (msquic)
///   MasqueClient  (this process — channel-masque)
///        ↕  local UDP (loopback)
///   quinn H3 server  (this process — h3 + quinn)
/// ```
///
/// The `from_quic_to_udp` worker inside `MasqueClient` creates one ephemeral
/// UDP socket per remote QUIC connection, connects it to the quinn server's
/// local address, and forwards QUIC packets over the loopback interface.
/// The `from_udp_to_quic` worker listens on the same sockets and sends the
/// quinn server's responses back through the MASQUE tunnel.
///
/// Usage:
///   masque-h3-server [--target <url>] [--jwt <token>]
use argh::FromArgs;
use bytes::Bytes;
use h3_util::msquic_async::{H3MsQuicAsyncConnector, h3_msquic_async::msquic};
use http::{
    Request, Uri,
    header::{HeaderName, HeaderValue},
    uri::{Authority, Scheme},
};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::{convert::Infallible, io::BufReader, net::SocketAddr, sync::Arc};
use tokio_stream::wrappers::ReceiverStream;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::{auth::AddAuthorizationLayer, set_header::SetRequestHeaderLayer};
use tracing_subscriber::EnvFilter;

// ── MASQUE client (msquic) setup ─────────────────────────────────────────────

fn make_msquic_async_reg_and_config(
    registration: Option<Arc<msquic::Registration>>,
    is_qmux: bool,
) -> anyhow::Result<(Arc<msquic::Registration>, Arc<msquic::Configuration>)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = if !is_qmux {
        [msquic::BufferRef::from("h3")]
    } else {
        [msquic::BufferRef::from("h3qx-01")]
    };
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &&msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_KeepAliveIntervalMs(10_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;
    Ok((registration, Arc::new(configuration)))
}

// ── quinn / H3 server setup ──────────────────────────────────────────────────

/// Load DER-encoded certificates from a PEM string.
fn load_certs_from_str(pem: &str) -> anyhow::Result<Vec<CertificateDer<'static>>> {
    let mut reader = BufReader::new(pem.as_bytes());

    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("failed to load certificates: {}", e))
        .map(|certs| certs.into_iter().map(|c| c.into()).collect())
}

/// Load a DER-encoded private key from a PEM string, trying multiple PEM block types.
fn load_key_from_str(pem: &str) -> anyhow::Result<PrivateKeyDer<'static>> {
    let mut reader = BufReader::new(pem.as_bytes());

    loop {
        match rustls_pemfile::read_one(&mut reader).unwrap() {
            Some(rustls_pemfile::Item::Pkcs8Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Pkcs1Key(key)) => return Ok(key.into()),
            Some(rustls_pemfile::Item::Sec1Key(key)) => return Ok(key.into()),
            Some(_) => continue,
            None => anyhow::bail!("no private key found in PEM"),
        }
    }
}

/// Build a quinn `ServerConfig` backed by a fresh self-signed TLS certificate.
fn make_quinn_server_config(cert_pem: &str, key_pem: &str) -> anyhow::Result<quinn::ServerConfig> {
    let certs = load_certs_from_str(cert_pem)?;
    let key = load_key_from_str(key_pem)?;

    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    // Allow 0-RTT so that quinn/h3 can use it if desired.
    tls_config.max_early_data_size = u32::MAX;
    // Advertise HTTP/3.
    tls_config.alpn_protocols = vec![b"h3".to_vec()];

    let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(
        quic_server_config,
    )))
}

/// Handle a single HTTP/3 request and respond with a simple HTML page.
async fn handle_request<T>(req: http::Request<()>, mut stream: h3::server::RequestStream<T, Bytes>)
where
    T: h3::quic::BidiStream<Bytes>,
{
    let method = req.method().clone();
    let path = req.uri().path().to_owned();
    tracing::info!("H3 request: {} {}", method, path);

    let body = Bytes::from(format!(
        "<!DOCTYPE html><html><body>\
         <h1>Hello from masque-h3-server!</h1>\
         <p>Method: {method}</p>\
         <p>Path: {path}</p>\
         </body></html>"
    ));

    let resp = http::Response::builder()
        .status(200)
        .header("content-type", "text/html; charset=utf-8")
        .header("content-length", body.len().to_string())
        .body(())
        .expect("failed to build HTTP response");

    if let Err(e) = stream.send_response(resp).await {
        tracing::error!("send_response error: {e}");
        return;
    }
    if let Err(e) = stream.send_data(body).await {
        tracing::error!("send_data error: {e}");
        return;
    }
    if let Err(e) = stream.finish().await {
        tracing::error!("stream finish error: {e}");
    }
}

/// Accept HTTP/3 requests on a single QUIC connection until it closes.
async fn handle_h3_connection(conn: quinn::Connection) {
    let peer = conn.remote_address();
    tracing::info!("new QUIC connection from {peer}");

    let mut h3_conn = match h3::server::Connection::new(h3_quinn::Connection::new(conn)).await {
        Ok(c) => c,
        Err(e) => {
            tracing::error!("H3 handshake failed from {peer}: {e}");
            return;
        }
    };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                tokio::spawn(async move {
                    match resolver.resolve_request().await {
                        Ok((req, stream)) => handle_request(req, stream).await,
                        Err(e) => tracing::error!("resolve_request error: {e}"),
                    }
                });
            }
            Ok(None) => {
                tracing::info!("connection from {peer} closed");
                break;
            }
            Err(e) => {
                tracing::error!("H3 connection error from {peer}: {e}");
                break;
            }
        }
    }
}

#[derive(Debug, serde::Deserialize)]
struct CertificateResponse {
    hostname: String,
    cert_pem: String,
    key_pem: String,
}

/// Body for `PUT /udp_mode`.
///
/// `mode` must be `"shared"`, `"dedicated"`, or `null` / omitted to reset
/// to the server default.
#[derive(serde::Serialize)]
struct UdpModeSettingRequest {
    mode: Option<String>,
}

#[derive(serde::Deserialize)]
struct UdpModeSettingResponse {
    /// `"shared"`, `"dedicated"`, or `null` (server default).
    mode: Option<String>,
}

async fn create_normal_channel(
    uri: Uri,
    reg: Arc<msquic::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
) -> anyhow::Result<channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>> {
    let connector = H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), reg);
    let channel = channel_masque::H3Channel::<_, Full<Bytes>>::new(connector, uri.clone(), None);
    Ok(channel)
}

/// Fetch a TLS certificate from the MASQUE server by making an HTTP/3 request over msquic.
async fn get_public_address(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<SocketAddr> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/public_address")
        .build()?;
    let request = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = channel
        .ready()
        .await
        .map_err(|e| {
            tracing::error!("channel ready error: {e}");
            anyhow::anyhow!("channel ready error: {e}")
        })?
        .call(request)
        .await
        .map_err(|e| {
            tracing::error!("channel call error: {e}");
            anyhow::anyhow!("channel call error: {e}")
        })?;
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            tracing::error!("response body collect error: {e}");
            anyhow::anyhow!("response body collect error: {e}")
        })?
        .to_bytes();
    Ok(String::from_utf8(data.to_vec())?.parse()?)
}

/// Fetch a TLS certificate from the MASQUE server by making an HTTP/3 request over msquic.
async fn get_certificate_response(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<CertificateResponse> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/certificate")
        .build()?;
    let request = Request::builder()
        .uri(uri)
        .body(Full::new(Bytes::new()))
        .unwrap();

    let response = channel
        .ready()
        .await
        .map_err(|e| {
            tracing::error!("channel ready error: {e}");
            anyhow::anyhow!("channel ready error: {e}")
        })?
        .call(request)
        .await
        .map_err(|e| {
            tracing::error!("channel call error: {e}");
            anyhow::anyhow!("channel call error: {e}")
        })?;
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            tracing::error!("response body collect error: {e}");
            anyhow::anyhow!("response body collect error: {e}")
        })?
        .to_bytes();
    Ok(serde_json::from_slice::<CertificateResponse>(&data)?)
}

/// Set the UDP mode on the MASQUE server by making an HTTP/3 request over msquic.
async fn set_udp_mode(
    uri: Uri,
    jwt: &str,
    is_shared: bool,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<()> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/udp_mode")
        .build()?;
    let request = Request::builder()
        .uri(uri.clone())
        .body(Full::new(Bytes::new()))?;

    let response = channel
        .ready()
        .await
        .map_err(|e| {
            tracing::error!("channel ready error: {e}");
            anyhow::anyhow!("channel ready error: {e}")
        })?
        .call(request)
        .await
        .map_err(|e| {
            tracing::error!("channel call error: {e}");
            anyhow::anyhow!("channel call error: {e}")
        })?;
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            tracing::error!("response body collect error: {e}");
            anyhow::anyhow!("response body collect error: {e}")
        })?
        .to_bytes();
    let udp_mode_response = serde_json::from_slice::<UdpModeSettingResponse>(&data)?;
    let need_to_set = match udp_mode_response.mode {
        Some(mode) if mode == "shared" => !is_shared,
        Some(mode) if mode == "dedicated" => is_shared,
        Some(mode) => anyhow::bail!("unexpected UDP mode in response: {mode}"),
        None => true,
    };
    if !need_to_set {
        tracing::info!("UDP mode already set to desired value, no change needed");
        return Ok(());
    } else {
        tracing::info!(
            "UDP mode needs to be changed to {}, sending request",
            if is_shared { "shared" } else { "dedicated" }
        );
    }

    let udp_mode_request = serde_json::json!(UdpModeSettingRequest {
        mode: Some(if is_shared {
            "shared".to_string()
        } else {
            "dedicated".to_string()
        }),
    });

    let request = Request::builder()
        .uri(uri.clone())
        .method("PUT")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(udp_mode_request.to_string())))?;

    let response = channel
        .ready()
        .await
        .map_err(|e| {
            tracing::error!("channel ready error: {e}");
            anyhow::anyhow!("channel ready error: {e}")
        })?
        .call(request)
        .await
        .map_err(|e| {
            tracing::error!("channel call error: {e}");
            anyhow::anyhow!("channel call error: {e}")
        })?;
    let data = response
        .into_body()
        .collect()
        .await
        .map_err(|e| {
            tracing::error!("response body collect error: {e}");
            anyhow::anyhow!("response body collect error: {e}")
        })?
        .to_bytes();

    let udp_mode_response = serde_json::from_slice::<UdpModeSettingResponse>(&data)?;
    let failed_to_set = match &udp_mode_response.mode {
        Some(mode) if mode == "shared" => !is_shared,
        Some(mode) if mode == "dedicated" => is_shared,
        Some(mode) => anyhow::bail!("unexpected UDP mode in response: {mode}"),
        None => true,
    };
    if failed_to_set {
        anyhow::bail!(
            "failed to set UDP mode to desired value: server responded with {:?}",
            udp_mode_response.mode
        );
    }

    Ok(())
}

// ── CLI ──────────────────────────────────────────────────────────────────────
#[derive(FromArgs, Clone)]
/// masque-h3-server: serve HTTP/3 behind a MASQUE UDP proxy
pub struct CmdOptions {
    /// target address of the MASQUE server
    #[argh(option, default = "String::from(\"https://127.0.0.1:8443\")")]
    target: String,
    /// JWT for authentication, if the server requires it
    #[argh(option, default = "String::from(\"\")")]
    jwt: String,

    /// log target: "file" (default) or "stdout"
    ///
    /// When set to "stdout" logs are written to standard output instead of
    /// a rolling log file.  This is the recommended setting for container
    /// environments.  The value of the SEERA_LOG_TARGET environment variable
    /// takes precedence over this flag.
    #[argh(option, default = "String::from(\"file\")")]
    log_target: String,

    /// enable shared mode to accept connections from 443 port
    #[argh(switch)]
    shared_mode: bool,
}

// ── main ─────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("failed to install rustls CryptoProvider: provider may already be installed");
    let cmd_opts: CmdOptions = argh::from_env();

    // Determine log target: env var takes precedence over CLI flag.
    let filter = EnvFilter::try_from_env("SEERA_LOG").unwrap_or_else(|_| EnvFilter::new("info"));
    let use_stdout = std::env::var("SEERA_LOG_TARGET")
        .as_deref()
        .unwrap_or(cmd_opts.log_target.as_str())
        == "stdout";

    if use_stdout {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(true)
            .init();
    } else {
        let file_appender = tracing_appender::rolling::RollingFileAppender::builder()
            .rotation(tracing_appender::rolling::Rotation::DAILY)
            .filename_prefix("masque-h3-server")
            .filename_suffix("log")
            .build("./logs")
            .expect("Failed to create log file appender");

        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_ansi(false)
            .with_writer(file_appender)
            .init();
    }

    // ── Set up the MASQUE client (msquic → CONNECT-UDP) ──────────────────────
    let uri: Uri = cmd_opts.target.parse()?;
    let (reg, config) = make_msquic_async_reg_and_config(None, false)?;
    let (reg, config_qmux) = make_msquic_async_reg_and_config(Some(reg), true)?;

    let channel = create_normal_channel(uri.clone(), reg.clone(), config.clone(), config_qmux.clone()).await?;

    // ── Fetch the public address assigned by the MASQUE server for this client.
    let public_addr = get_public_address(uri.clone(), &cmd_opts.jwt, channel.clone()).await?;
    tracing::info!("public address assigned by MASQUE server: {public_addr}");

    // ── Fetch a TLS certificate from the MASQUE server to use for the local quinn/H3 server.
    let cert_res = get_certificate_response(uri.clone(), &cmd_opts.jwt, channel.clone()).await?;
    tracing::info!(
        "fetched certificate for {} from MASQUE server",
        cert_res.hostname
    );

    set_udp_mode(uri.clone(), &cmd_opts.jwt, cmd_opts.shared_mode, channel).await?;

    // ── Start the local quinn H3 server on a loopback address ────────────────
    let server_config = make_quinn_server_config(&cert_res.cert_pem, &cert_res.key_pem)?;
    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let h3_server_addr = endpoint.local_addr()?;
    tracing::info!("H3 server bound at {h3_server_addr} (local, behind MASQUE)");

    // Accept QUIC connections and handle each on its own task.
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => handle_h3_connection(conn).await,
                    Err(e) => tracing::error!("QUIC accept error: {e}"),
                }
            });
        }
        tracing::info!("quinn endpoint closed");
    });

    // ── Connect to MASQUE proxy, registering the H3 server's local address ───
    let connector =
        h3_util::msquic_async::H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), reg.clone());
    let channel = channel_masque::H3Channel::<
        _,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >::new(connector, uri, None);

    let sni_header_value = HeaderValue::from_str(&cert_res.hostname)?;
    let channel = ServiceBuilder::new()
        .option_layer(
            (!cmd_opts.jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(&cmd_opts.jwt)),
        )
        .option_layer((cmd_opts.shared_mode).then(|| {
            SetRequestHeaderLayer::appending(
                HeaderName::from_static("seera-sni-claim"),
                sni_header_value,
            )
        }))
        .service(channel);

    println!("Server is running. Press Ctrl-C to stop.");
    let authority: Authority = if cmd_opts.shared_mode {
        cert_res.hostname.parse()?
    } else {
        format!("{}:{}", cert_res.hostname, public_addr.port()).parse()?
    };
    let server_uri = Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(authority)
        .path_and_query("/")
        .build()?;
    println!("You can connect to the H3 server through the MASQUE proxy at: {server_uri}");

    let mut client = channel_masque::MasqueClient::new(channel, None);
    let proxy_handle = tokio::spawn(async move {
        let mut events = client
            .start(channel_masque::MasqueClientMode::Forward(h3_server_addr))
            .await
            .map_err(|e| {
                tracing::error!("MasqueClient start failed: {e:?}");
                anyhow::anyhow!("MasqueClient start failed: {e:?}")
            })?;
        while let Some(event) = events.recv().await {
            match event {
                channel_masque::MasqueClientEvent::PublicAddresses(public_addrs) => {
                    tracing::info!("public addresses: {:?}", public_addrs);
                }
                channel_masque::MasqueClientEvent::NewRemoteHost(
                    remote_addr,
                    mapped_remote_addr,
                ) => {
                    tracing::info!("new remote host: {remote_addr}, mapped: {mapped_remote_addr}");
                }
                channel_masque::MasqueClientEvent::ResponseBodyEnded => {
                    tracing::info!("response body ended");
                }
                channel_masque::MasqueClientEvent::ResponseBodyReceiveError(error) => {
                    tracing::warn!("response body receive error: {error}");
                }
                channel_masque::MasqueClientEvent::NotificationChannelClosed => {
                    tracing::warn!("notification channel closed");
                }
                channel_masque::MasqueClientEvent::SocketRegistrationFailed {
                    remote_addr,
                    error,
                } => {
                    tracing::warn!("socket registration failed for {remote_addr}: {error}");
                }
                channel_masque::MasqueClientEvent::ContextIdRegistrationFailed {
                    context_id,
                    remote_addr,
                    stage,
                    error,
                } => {
                    tracing::warn!(
                        "context_id registration failed \
                         (context_id={context_id}, remote={remote_addr}, \
                         stage={stage:?}): {error}"
                    );
                }
                channel_masque::MasqueClientEvent::CompressionAssignSendFailed {
                    context_id,
                    remote_addr,
                    error,
                } => {
                    tracing::warn!(
                        "compression assign send failed \
                         (context_id={context_id}, remote={remote_addr}): {error}"
                    );
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });

    let mut pinned_proxy_handle = std::pin::pin!(proxy_handle);
    loop {
        tokio::select! {
            _ = &mut pinned_proxy_handle => {
                tracing::info!("MasqueClient proxy task finished");
                break;
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down");
                break;
            }
        }
    }
    if !pinned_proxy_handle.is_finished() {
        pinned_proxy_handle.abort();
        tracing::info!("aborted MasqueClient proxy task");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await; // give it a moment to shut down gracefully
    }

    Ok(())
}
