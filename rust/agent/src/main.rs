use anyhow::Context;
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
    registration: Option<Arc<msquic_async::Registration>>,
    is_qmux: bool,
) -> anyhow::Result<(Arc<msquic_async::Registration>, Arc<msquic::Configuration>)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = if !is_qmux {
        [msquic::BufferRef::from("h3")]
    } else {
        [msquic::BufferRef::from("h3qx-01")]
    };
    let configuration = registration.open_configuration(
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                // Keep the connection from going idle into the timeout above.
                // Ten seconds leaves two attempts inside it.
                //
                // The peer usually pings too, and one side's keepalive is enough to
                // hold both ends open — a PING is ack-eliciting, so it resets the
                // receiver's idle timer and the sender's alike. This is here so that
                // staying up does not depend on the peer being configured that way.
                .set_KeepAliveIntervalMs(10_000)
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
    registration: Option<Arc<msquic_async::Registration>>,
    is_qmux: bool,
    addr: Option<SocketAddr>,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<(Arc<msquic_async::Registration>, msquic_async::Listener)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = if !is_qmux {
        [msquic::BufferRef::from("h3")]
    } else {
        [msquic::BufferRef::from("h3qx-01")]
    };
    let configuration = registration.open_configuration(
        &alpn,
        Some(
            &&&msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                // 1248, because that is what this asks for: msquic clamps
                // `MaximumMtu` up to QUIC_DPLPMTUD_MIN_MTU, so the 1200 written
                // here was silently 1248 and only misled whoever read it.
                //
                // **The floor is too low, and is left that way on purpose.**
                // This connection carries CONNECT-UDP for a peer, and a
                // full-size relayed inner QUIC packet costs ~1292 on the wire —
                // see the arithmetic on `isekai_p2p_core::transport`'s
                // `MinimumMtu`, which is 1350 for exactly that. This binary is
                // the WebRTC one and is not being maintained, so raising it
                // belongs to whoever next works on it rather than to a change
                // that was only correcting comments.
                //
                // Whoever that is: the symptom of leaving it is that full-size
                // packets vanish while ACKs get through, so the path looks lossy
                // rather than misconfigured.
                .set_MaximumMtu(1248)
                .set_KeepAliveIntervalMs(10_000)
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
    reg: Arc<msquic_async::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
) -> anyhow::Result<channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>> {
    let connector = H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), false, reg);
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
    reg: Arc<msquic_async::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
) -> anyhow::Result<
    channel_masque::H3Channel<
        h3_util::msquic_async::H3MsQuicAsyncConnector,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >,
> {
    let connector = h3_util::msquic_async::H3MsQuicAsyncConnector::new(
        uri.clone(),
        config,
        Some(config_qmux),
        false,
        reg,
    );
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
    shutdown_token: CancellationToken,
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
            .start(channel_masque::MasqueClientMode::WebRTC, shutdown_token)
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
        tracing::debug!("MasqueClient WebRTC event loop exited");
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
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(jwt))
        .service(channel);

    let mut client = channel_masque::MasqueClient::new(channel, None);

    tasks.spawn(async move {
        let mut events = client
            .start(
                channel_masque::MasqueClientMode::Forward(listen_addr),
                shutdown_token,
            )
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
        tracing::debug!("MasqueClient forward event loop exited");
        Ok::<(), anyhow::Error>(())
    });
    Ok(())
}

pub(crate) async fn share_page(
    axum::extract::State(page): axum::extract::State<std::sync::Arc<String>>,
    axum::extract::Path(_id): axum::extract::Path<String>,
) -> impl IntoResponse {
    Html((*page).clone())
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
    /// where the browser should open the signalling WebSocket, as a full
    /// origin (`wss://host:port`). Defaults to --target's host and port.
    ///
    /// **It has to be reachable from the viewer's machine, not from this
    /// one.** The share page is opened by whoever the link was given to, so a
    /// --target that is a private route to the control plane -- loopback, a
    /// VPN address, an internal name -- makes the default wrong: the page
    /// would send that browser to its own network. Set this to the control
    /// plane's public name in that case; the agent warns when it can tell.
    ///
    /// Also set it when the control plane's browser-facing listener is not
    /// where --target points. A control plane serving QMUX on its TCP port
    /// speaks only `h3qx-01` there, which no browser understands, so it offers
    /// h2 on a separate port instead -- and that port is what belongs here.
    #[argh(option)]
    signaling_origin: Option<String>,
}

/// What the page's `__SIGNALING_ORIGIN__` is replaced with.
const SIGNALING_ORIGIN_PLACEHOLDER: &str = "__SIGNALING_ORIGIN__";

/// Where the browser should open the signalling WebSocket.
///
/// **Derived from `--target` rather than named in the page.** The page used to
/// carry one deployment's host, so an agent pointed anywhere else served a
/// browser a WebSocket to a host it was not itself talking to. The default
/// here is "the same place this agent reaches the control plane", which is what
/// the page meant to say; `--signaling-origin` is for the deployment where it
/// is not true.
fn signaling_origin(target: &Uri, override_: Option<&str>) -> anyhow::Result<String> {
    if let Some(given) = override_ {
        let uri: Uri = given
            .parse()
            .with_context(|| format!("--signaling-origin is not a URI: {given}"))?;
        // Compared without case, because a URI scheme has none -- and `Uri`
        // keeps whatever was typed for a scheme it does not know, so
        // `WSS://cp.example` arrives as `Some("WSS")`. Refusing that would
        // reject an origin a browser is perfectly happy with.
        let scheme = uri.scheme_str().unwrap_or_default().to_ascii_lowercase();
        // Refused rather than corrected: a browser handed `https://` here
        // fails inside `new WebSocket`, which is a long way from the flag.
        if scheme != "ws" && scheme != "wss" {
            anyhow::bail!(
                "--signaling-origin must be ws:// or wss://, not {}",
                uri.scheme_str().unwrap_or("a URI with no scheme")
            );
        }
        let authority = uri
            .authority()
            .context("--signaling-origin has no host")?
            .clone();
        // **An authority is not a host.** `wss://:8444` parses, and its
        // `host()` is `Some("")` rather than `None`, so asking only whether
        // there is an authority lets a port with nothing in front of it
        // through -- and the page then makes every viewer's browser throw
        // `SyntaxError: Failed to construct 'WebSocket'`, which is the failure
        // the refusals here exist to move to the flag. Plausible exactly in
        // the documented case: same control plane, different port.
        if uri.host().unwrap_or_default().is_empty() {
            anyhow::bail!("--signaling-origin has no host: {given}");
        }
        // **Refused, not trimmed.** Only the scheme and authority are used, so
        // a path here would be dropped and the page would open
        // `wss://host/sessions/...` instead of whatever prefix was meant --
        // a handshake failure with nothing pointing back at the flag, which is
        // the thing the scheme check above exists to avoid.
        match uri.path_and_query().map(|p| p.as_str()).unwrap_or("") {
            "" | "/" => {}
            path => anyhow::bail!(
                "--signaling-origin takes an origin, not a path: drop `{path}` from {given}"
            ),
        }
        // Userinfo would be copied verbatim into the page, which puts a
        // credential in front of every viewer.
        if authority.as_str().contains('@') {
            anyhow::bail!("--signaling-origin must not carry userinfo: {given}");
        }
        return Ok(format!("{scheme}://{authority}"));
    }
    // Same trap as above: `https://:8443` yields `Some("")`.
    let host = target.host().filter(|h| !h.is_empty()).context(
        "--target has no host, so there is nothing to point the browser at;          pass --signaling-origin",
    )?;
    // `http` only so a local control plane without TLS is not silently dialled
    // as `wss`, which fails in the browser with nothing pointing here.
    let scheme = match target.scheme_str() {
        Some("http") => "ws",
        _ => "wss",
    };
    match target.port_u16() {
        Some(port) => Ok(format!("{scheme}://{host}:{port}")),
        None => Ok(format!("{scheme}://{host}")),
    }
}

/// Whether this origin only works for a viewer on this machine.
fn is_loopback_origin(host: &str) -> bool {
    let host = host.trim_start_matches('[').trim_end_matches(']');
    host.eq_ignore_ascii_case("localhost")
        || host
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback())
}

/// Say, next to the share URI, when the page cannot work for whoever opens it.
///
/// **A browser gets no useful error for either of these**, which is why they
/// are said here. Serving the page anyway is deliberate: both are correct when
/// the viewer is on this machine, which is how this is usually tried first.
fn warn_if_the_viewer_cannot_use_it(origin: &str) {
    let Ok(uri) = origin.parse::<Uri>() else {
        return;
    };
    let Some(host) = uri.host() else { return };
    if is_loopback_origin(host) {
        tracing::warn!(
            "{origin} is a loopback address: only a browser on this machine can use it, and anyone else opening the share link will dial their own computer. Pass --signaling-origin with the control plane's public name."
        );
    } else if uri.scheme_str() == Some("ws") {
        // The page is served over HTTPS, so a plaintext WebSocket to anything
        // but a loopback host is refused as mixed content before a connection
        // is attempted -- and the browser blames the page, not the origin.
        tracing::warn!(
            "{origin} is plaintext and the share page is served over HTTPS, which browsers block as mixed content. Pass --signaling-origin with a wss:// origin."
        );
    }
}

/// The share page, with the signalling origin written into it.
fn share_page_html(origin: &str) -> String {
    include_str!("../html/share_page.html").replace(SIGNALING_ORIGIN_PLACEHOLDER, origin)
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
    let signaling = signaling_origin(&uri, cmd_opts.signaling_origin.as_deref())?;
    tracing::info!("the share page will point the browser at {signaling}");
    warn_if_the_viewer_cannot_use_it(&signaling);
    let (reg, config) = make_msquic_async_client_config(None, false)?;
    let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), true)?;

    let normal_channel = create_normal_channel(
        uri.clone(),
        reg.clone(),
        config.clone(),
        config_qmux.clone(),
    )
    .await?;
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

    let shutdown_token = CancellationToken::new();

    let router = axum::Router::new()
        .route("/", axum::routing::get(|| async { "Hello, World!" }))
        // Health check — no authentication required
        .route(
            "/health",
            axum::routing::get(|| async { (StatusCode::OK, "OK") }),
        )
        .route("/s/{session_id}", axum::routing::get(share_page))
        .with_state(std::sync::Arc::new(share_page_html(&signaling)));

    let handle_svc_h3 = create_h3_server(acceptor, router, shutdown_token.clone()).await?;

    let channel = create_masque_channel(uri.clone(), reg.clone(), config, config_qmux.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create MASQUE channel: {e:?}");
            anyhow::anyhow!("Failed to create MASQUE channel: {e:?}")
        })?;

    create_forward_masque_connection(
        &cmd_opts.jwt,
        listen_addr,
        channel.clone(),
        &mut tasks,
        shutdown_token.clone(),
    )
    .await?;

    for _ in 0..cmd_opts.num_connections {
        create_webrtc_masque_connection(
            &cmd_opts.jwt,
            &session_id,
            channel.clone(),
            &mut tasks,
            shutdown_token.clone(),
        )
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
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) => tracing::info!("MasqueClient task finished"),
                    Some(Ok(Err(err))) => tracing::error!("MasqueClient task failed: {err:?}"),
                    Some(Err(err)) => tracing::error!("MasqueClient task join error: {err:?}"),
                    None => {}
                }
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
    shutdown_token.cancel();

    while let Some(result) = tasks.join_next().await {
        match result {
            Ok(Ok(())) => tracing::info!("MasqueClient task shut down cleanly"),
            Ok(Err(err)) => tracing::error!("MasqueClient task failed during shutdown: {err:?}"),
            Err(err) => tracing::error!("MasqueClient task join error during shutdown: {err:?}"),
        }
    }

    if let Err(e) = handle_svc_h3.await {
        tracing::error!("H3 server task error: {e:?}");
    } else {
        tracing::info!("H3 server task finished");
    }

    anyhow::Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn target(s: &str) -> Uri {
        s.parse().expect("target")
    }

    /// The default is "the same place this agent reaches the control plane",
    /// which is what the page was trying to say when it named a host outright.
    #[test]
    fn the_origin_follows_the_target() {
        assert_eq!(
            signaling_origin(&target("https://cp.example:8443"), None).unwrap(),
            "wss://cp.example:8443"
        );
        assert_eq!(
            signaling_origin(&target("https://cp.example"), None).unwrap(),
            "wss://cp.example",
            "no port in, no port out -- the browser's default is the right one"
        );
    }

    /// A plaintext control plane must not be dialled as `wss`: it fails inside
    /// `new WebSocket`, where nothing points back at the flag that caused it.
    #[test]
    fn a_plaintext_target_is_not_dialled_as_tls() {
        assert_eq!(
            signaling_origin(&target("http://127.0.0.1:8443"), None).unwrap(),
            "ws://127.0.0.1:8443"
        );
    }

    /// **The case this exists for.** A control plane whose TCP port is QMUX
    /// offers the browser h2 somewhere else, and that is not derivable from
    /// `--target`.
    #[test]
    fn an_override_wins_and_is_taken_whole() {
        assert_eq!(
            signaling_origin(
                &target("https://cp.example:8443"),
                Some("wss://cp.example:8444")
            )
            .unwrap(),
            "wss://cp.example:8444"
        );
    }

    /// Refused rather than corrected, for the same reason as above: the error
    /// has to arrive at the flag, not at the browser.
    #[test]
    fn an_override_that_is_not_a_websocket_origin_is_refused() {
        for bad in ["https://cp.example:8444", "cp.example:8444"] {
            let err = signaling_origin(&target("https://cp.example:8443"), Some(bad))
                .expect_err(bad)
                .to_string();
            assert!(
                err.contains("ws:// or wss://"),
                "{bad} should be refused by scheme: {err}"
            );
        }
    }

    /// **That the substitution happens at all.** `str::replace` on a
    /// placeholder that is no longer in the page does nothing and says nothing,
    /// so renaming one side would serve a browser a page with no origin in it.
    /// Asserting the origin is present is what catches that.
    #[test]
    fn the_page_carries_the_origin_it_was_given() {
        let page = share_page_html("wss://cp.example:8444");
        assert!(
            page.contains("wss://cp.example:8444"),
            "the origin never reached the page -- is the placeholder still there?"
        );
        assert!(
            !page.contains(SIGNALING_ORIGIN_PLACEHOLDER),
            "an unsubstituted placeholder is a page that cannot connect"
        );
    }

    /// **The default is right in the shape this is deployed in** -- where
    /// `--target` is the control plane's public name -- and wrong when it is a
    /// private route to it. The agent cannot tell the difference in general,
    /// but it can tell loopback, which is both the stock default and the case
    /// where a shared link sends the viewer to their own computer.
    #[test]
    fn a_loopback_origin_is_recognised_as_local_only() {
        for host in ["127.0.0.1", "::1", "[::1]", "localhost", "LOCALHOST"] {
            assert!(is_loopback_origin(host), "{host}");
        }
        for host in ["cp.example", "10.0.0.5", "masque.seera-networks.com"] {
            assert!(!is_loopback_origin(host), "{host}");
        }
    }

    /// Dropped silently, a path would turn into a handshake failure in
    /// somebody else's browser. Refused, it is a line at startup.
    #[test]
    fn an_override_with_a_path_is_refused_rather_than_trimmed() {
        let err = signaling_origin(
            &target("https://cp.example:8443"),
            Some("wss://cp.example:8444/signal"),
        )
        .expect_err("a path should be refused")
        .to_string();
        assert!(err.contains("/signal"), "{err}");
        // A bare origin and one with a single trailing slash are the same
        // thing, and both are fine.
        assert_eq!(
            signaling_origin(
                &target("https://cp.example"),
                Some("wss://cp.example:8444/")
            )
            .unwrap(),
            "wss://cp.example:8444"
        );
    }

    /// A credential in the origin is copied into a page every viewer reads.
    #[test]
    fn an_override_with_userinfo_is_refused() {
        let err = signaling_origin(
            &target("https://cp.example:8443"),
            Some("wss://user:pass@cp.example:8444"),
        )
        .expect_err("userinfo should be refused")
        .to_string();
        assert!(err.contains("userinfo"), "{err}");
    }

    /// A scheme has no case, and `Uri` keeps the one that was typed for a
    /// scheme it does not recognise -- so refusing `WSS://` would reject an
    /// origin every browser accepts.
    #[test]
    fn an_override_scheme_is_matched_without_case() {
        assert_eq!(
            signaling_origin(
                &target("https://cp.example:8443"),
                Some("WSS://cp.example:8444")
            )
            .unwrap(),
            "wss://cp.example:8444",
            "and it comes back lowercased"
        );
    }

    /// **An authority is not a host.** `wss://:8444` parses, and its `host()`
    /// is `Some("")`, so a check for "is there an authority" lets a bare port
    /// through -- into a page where every viewer's browser throws
    /// `SyntaxError: Failed to construct 'WebSocket'`.
    #[test]
    fn an_origin_with_no_host_is_refused_on_both_paths() {
        let err = signaling_origin(&target("https://cp.example:8443"), Some("wss://:8444"))
            .expect_err("an empty host should be refused")
            .to_string();
        assert!(err.contains("no host"), "{err}");

        let err = signaling_origin(&target("https://:8443"), None)
            .expect_err("and the same on the derived path")
            .to_string();
        assert!(err.contains("no host"), "{err}");
    }

    /// The host the page used to name. A page that dials one deployment
    /// whatever `--target` says is the bug this replaced; naming it here is
    /// what stops it coming back.
    #[test]
    fn the_page_names_no_deployment_of_its_own() {
        let page = share_page_html("wss://cp.example:8444");
        assert!(!page.contains("masque.seera-networks.com"), "{page}");
    }
}
