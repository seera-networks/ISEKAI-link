use argh::FromArgs;
use axum::response::{Html, IntoResponse};
use bytes::Bytes;
use h3_util::msquic_async::{
    H3MsQuicAsyncAcceptor, H3MsQuicAsyncConnector,
    h3_msquic_async::{msquic, msquic_async},
};
use http::{
    Request, StatusCode, Uri,
    header::{HeaderName, HeaderValue},
    uri::Authority,
    uri::Scheme,
};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::task::{JoinHandle, JoinSet};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::{auth::AddAuthorizationLayer, set_header::SetRequestHeaderLayer};
use tracing_subscriber::EnvFilter;

fn make_msquic_async_client_config(
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
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    let cred_config = msquic::CredentialConfig::new_client();
    configuration.load_credential(&cred_config)?;
    Ok((registration, Arc::new(configuration)))
}

fn make_msquic_async_listner(
    registration: Option<Arc<msquic::Registration>>,
    is_qmux: bool,
    addr: Option<SocketAddr>,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<(Arc<msquic::Registration>, msquic_async::Listener)> {
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
            &&&msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_MaximumMtu(1200)
                .set_KeepAliveIntervalMs(10_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    #[cfg(not(windows))]
    {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let mut cert_file = NamedTempFile::new()?;
        cert_file.write_all(cert_pem.as_bytes())?;
        let cert_path = cert_file.into_temp_path();
        let cert_path = cert_path.to_string_lossy().into_owned();

        let mut key_file = NamedTempFile::new()?;
        key_file.write_all(key_pem.as_bytes())?;
        let key_path = key_file.into_temp_path();
        let key_path = key_path.to_string_lossy().into_owned();

        let cred_config =
            msquic::CredentialConfig::new().set_credential(msquic::Credential::CertificateFile(
                msquic::CertificateFile::new(key_path.to_string(), cert_path.to_string()),
            ));
        configuration.load_credential(&cred_config)?;
    }

    let listener = msquic_async::Listener::new(&registration, configuration)?;
    listener.start(&alpn, addr)?;
    Ok((registration, listener))
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

async fn create_signaling_session(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<String> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/create_session")
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
    Ok(String::from_utf8(data.to_vec())?)
}

#[derive(Debug, serde::Deserialize)]
struct CertificateResponse {
    hostname: String,
    cert_pem: String,
    key_pem: String,
}

/// Fetch a TLS certificate from the MASQUE server by making an HTTP/3 request over msquic.
async fn get_certificate(
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

async fn create_h3_server(
    acceptor: H3MsQuicAsyncAcceptor,
    router: axum::Router,
    shutdown_token: CancellationToken,
) -> anyhow::Result<JoinHandle<()>> {
    let handle = tokio::spawn(async move {
        let _ = axum_h3::H3Router::new(router)
            .serve_with_shutdown(acceptor, async move { shutdown_token.cancelled().await })
            .await;
    });
    Ok(handle)
}

async fn create_masque_channel(
    uri: Uri,
    reg: Arc<msquic::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
) -> anyhow::Result<
    channel_masque::H3Channel<
        h3_util::msquic_async::H3MsQuicAsyncConnector,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >,
> {
    let connector = h3_util::msquic_async::H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), reg);
    let channel = channel_masque::H3Channel::<
        _,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >::new(connector, uri.clone(), None);
    Ok(channel)
}

async fn create_webrtc_masque_connection(
    jwt: &str,
    session_id: &str,
    channel: channel_masque::H3Channel<
        h3_util::msquic_async::H3MsQuicAsyncConnector,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >,
    tasks: &mut JoinSet<Result<(), anyhow::Error>>,
) -> anyhow::Result<()> {
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(jwt))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-prefer-temporary-public-address"),
            HeaderValue::from_str("?1")?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-signaling-session-id"),
            HeaderValue::from_str(session_id)?,
        ))
        .service(channel);

    let mut client = channel_masque::MasqueClient::new(channel, None);

    tasks.spawn(async move {
        let mut events = client
            .start(channel_masque::MasqueClientMode::WebRTC)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start MasqueClient: {e:?}");
                anyhow::anyhow!("Failed to start MasqueClient: {e:?}")
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
                    tracing::info!(
                        "new remote host event: {remote_addr}, mapped address: {mapped_remote_addr}"
                    );
                }
                channel_masque::MasqueClientEvent::ResponseBodyEnded => {
                    tracing::info!("response body ended event");
                }
                channel_masque::MasqueClientEvent::ResponseBodyReceiveError(error) => {
                    tracing::warn!("response body receive error event: {error}");
                }
                channel_masque::MasqueClientEvent::NotificationChannelClosed => {
                    tracing::warn!("notification channel closed event");
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
                        "context_id registration failed (context_id={context_id}, remote={remote_addr}, stage={stage:?}): {error}"
                    );
                }
                channel_masque::MasqueClientEvent::CompressionAssignSendFailed {
                    context_id,
                    remote_addr,
                    error,
                } => {
                    tracing::warn!(
                        "compression assign send failed (context_id={context_id}, remote={remote_addr}): {error}"
                    );
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    Ok(())
}

async fn create_forward_masque_connection(
    jwt: &str,
    listen_addr: SocketAddr,
    channel: channel_masque::H3Channel<
        h3_util::msquic_async::H3MsQuicAsyncConnector,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >,
    tasks: &mut JoinSet<Result<(), anyhow::Error>>,
) -> anyhow::Result<()> {
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(jwt))
        .service(channel);

    let mut client = channel_masque::MasqueClient::new(channel, None);

    tasks.spawn(async move {
        let mut events = client
            .start(channel_masque::MasqueClientMode::Forward(listen_addr))
            .await
            .map_err(|e| {
                tracing::error!("Failed to start MasqueClient: {e:?}");
                anyhow::anyhow!("Failed to start MasqueClient: {e:?}")
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
                    tracing::info!(
                        "new remote host event: {remote_addr}, mapped address: {mapped_remote_addr}"
                    );
                }
                channel_masque::MasqueClientEvent::ResponseBodyEnded => {
                    tracing::info!("response body ended event");
                }
                channel_masque::MasqueClientEvent::ResponseBodyReceiveError(error) => {
                    tracing::warn!("response body receive error event: {error}");
                }
                channel_masque::MasqueClientEvent::NotificationChannelClosed => {
                    tracing::warn!("notification channel closed event");
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
                        "context_id registration failed (context_id={context_id}, remote={remote_addr}, stage={stage:?}): {error}"
                    );
                }
                channel_masque::MasqueClientEvent::CompressionAssignSendFailed {
                    context_id,
                    remote_addr,
                    error,
                } => {
                    tracing::warn!(
                        "compression assign send failed (context_id={context_id}, remote={remote_addr}): {error}"
                    );
                }
            }
        }
        Ok::<(), anyhow::Error>(())
    });
    Ok(())
}

pub(crate) async fn share_page(
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    Html(include_str!("../html/share_page.html"))
}

#[derive(FromArgs, Clone)]
/// server args
pub struct CmdOptions {
    /// target address of the MASQUE server
    #[argh(option, default = "String::from(\"https://127.0.0.1:8443\")")]
    target: String,
    /// JWT for authentication, if the server requires it
    #[argh(option, default = "String::from(\"\")")]
    jwt: String,
    /// number of MASQUE connections to establish (default: 2)
    #[argh(option, default = "2")]
    num_connections: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("SEERA_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();
    let cmd_opts: CmdOptions = argh::from_env();

    let uri: Uri = cmd_opts.target.parse()?;
    let (reg, config) = make_msquic_async_client_config(None, false)?;
    let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), true)?;

    let normal_channel = create_normal_channel(uri.clone(), reg.clone(), config.clone(), config_qmux.clone()).await?;
    let session_id =
        create_signaling_session(uri.clone(), &cmd_opts.jwt, normal_channel.clone()).await?;
    tracing::info!("created signaling session with ID: {}", session_id);

    let public_addr =
        get_public_address(uri.clone(), &cmd_opts.jwt, normal_channel.clone()).await?;

    let cert_info = get_certificate(uri.clone(), &cmd_opts.jwt, normal_channel).await?;
    tracing::info!(
        "got certificate for hostname {}, public address: {}",
        cert_info.hostname,
        public_addr
    );

    let mut tasks = JoinSet::new();

    let listen_addr = "127.0.0.1:0".parse()?;
    let (reg, listener) = make_msquic_async_listner(
        Some(reg),
        false,
        Some(listen_addr),
        &cert_info.cert_pem,
        &cert_info.key_pem,
    )?;
    let listen_addr = listener.local_addr()?;
    tracing::info!("service h3 listening on: {}", listen_addr);
    let acceptor = H3MsQuicAsyncAcceptor::new(listener);

    let server_token = CancellationToken::new();

    let router = axum::Router::new()
        .route("/", axum::routing::get(|| async { "Hello, World!" }))
        // Health check — no authentication required
        .route(
            "/health",
            axum::routing::get(|| async { (StatusCode::OK, "OK") }),
        )
        .route("/s/{session_id}", axum::routing::get(share_page));

    let handle_svc_h3 = create_h3_server(acceptor, router, server_token.clone()).await?;

    let channel = create_masque_channel(uri.clone(), reg.clone(), config, config_qmux.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create MASQUE channel: {e:?}");
            anyhow::anyhow!("Failed to create MASQUE channel: {e:?}")
        })?;

    create_forward_masque_connection(&cmd_opts.jwt, listen_addr, channel.clone(), &mut tasks)
        .await?;

    for _ in 0..cmd_opts.num_connections {
        create_webrtc_masque_connection(&cmd_opts.jwt, &session_id, channel.clone(), &mut tasks)
            .await?;
    }

    let authority: Authority = format!("{}:{}", cert_info.hostname, public_addr.port()).parse()?;
    let share_uri = Uri::builder()
        .scheme(Scheme::HTTPS)
        .authority(authority)
        .path_and_query(format!("/s/{session_id}"))
        .build()?;
    tracing::info!("share URI: {:?}", share_uri);

    loop {
        tokio::select! {
            _ = tasks.join_next(), if !tasks.is_empty() => {
                tracing::info!("MasqueClient proxy tasks finished");
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("received Ctrl-C, shutting down");
                break;
            }
        }
        if tasks.is_empty() {
            tracing::info!("all MasqueClient proxy tasks finished");
            break;
        }
    }
    server_token.cancel(); // trigger shutdown of the H3 server
    if let Err(e) = handle_svc_h3.await {
        tracing::error!("H3 server task error: {e:?}");
    } else {
        tracing::info!("H3 server task finished");
    }

    if !tasks.is_empty() {
        tracing::info!("aborting remaining tasks...");
        tasks.shutdown().await;
    }
    std::mem::drop(channel); // close the channel to trigger graceful shutdown of MasqueClient
    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // give it a moment to shut down gracefully

    anyhow::Ok(())
}
