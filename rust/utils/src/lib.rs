use bytes::Bytes;
use h3_util::msquic_async::{
    h3_msquic_async::{msquic, msquic_async},
    H3MsQuicAsyncConnector,
};
use http::{Request, Uri};
use http_body::Frame;
use http_body_util::{BodyExt, Full, StreamBody};
use std::{convert::Infallible, net::SocketAddr, sync::Arc};
use tokio::{sync::mpsc, task::JoinSet};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tower::{Service, ServiceBuilder, ServiceExt};
use tower_http::auth::AddAuthorizationLayer;

#[derive(Debug, serde::Deserialize)]
pub struct CertificateResponse {
    pub hostname: String,
    pub cert_pem: String,
    pub key_pem: String,
    pub pkcs12: String,
}

/// Body for `PUT /udp_mode`.
///
/// `mode` must be `"shared"`, `"dedicated"`, or `null` / omitted to reset
/// to the server default.
#[derive(Debug, serde::Serialize)]
pub struct UdpModeSettingRequest {
    pub mode: Option<String>,
}

#[derive(Debug, serde::Deserialize)]
pub struct UdpModeSettingResponse {
    /// `"shared"`, `"dedicated"`, or `null` (server default).
    pub mode: Option<String>,
}

pub fn make_msquic_async_client_config(
    registration: Option<Arc<msquic_async::Registration>>,
    alpn: &str,
) -> anyhow::Result<(Arc<msquic_async::Registration>, Arc<msquic::Configuration>)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = [msquic::BufferRef::from(alpn)];
    let configuration = registration.open_configuration(
        &alpn,
        Some(
            &msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled()
                // Accept observed-address reports from the peer so the caller
                // can learn how its address is seen (e.g. the MASQUE relay's
                // view of this server's public address).
                .set_ReceiveObservedAddressReports(),
        ),
    )?;

    let cred_config = msquic::CredentialConfig::new_client();
    configuration.load_credential(&cred_config)?;
    Ok((registration, Arc::new(configuration)))
}

/// How long a path may go without sending before it gets a PING.
///
/// Matches the video client's `DIRECT_PATH_KEEPALIVE`, which documents why this
/// is `PathKeepAliveIntervalMs` and not the connection keepalive next to it.
const PATH_KEEP_ALIVE_INTERVAL_MS: u32 = 10_000;

/// Listener settings that only some callers want.
#[derive(Debug, Default, Clone, Copy)]
pub struct ListenerOptions {
    /// Offer the multipath transport parameter.
    ///
    /// Both ends have to offer it for it to be negotiated, and a peer that does
    /// not simply gets the connection it always got — so this is safe to turn on
    /// before the other side has it. What it buys is that a validated path
    /// becomes an *additional* active path rather than somewhere to migrate to,
    /// which is how a direct path stops decaying while it waits
    /// (`docs/p2p_mode_migration_plan.md` risk #24).
    ///
    /// Off by default: the legacy direct mode already migrates the way it always
    /// has, and this is not the change that fixes anything there.
    pub multipath: bool,
}

pub fn make_msquic_async_listener(
    registration: Option<Arc<msquic_async::Registration>>,
    alpn: &str,
    addr: Option<SocketAddr>,
    cert_pem: &str,
    key_pem: &str,
    pkcs12: Option<&str>,
) -> anyhow::Result<(Arc<msquic_async::Registration>, msquic_async::Listener)> {
    make_msquic_async_listener_with(
        registration,
        alpn,
        addr,
        cert_pem,
        key_pem,
        pkcs12,
        ListenerOptions::default(),
    )
}

pub fn make_msquic_async_listener_with(
    registration: Option<Arc<msquic_async::Registration>>,
    alpn: &str,
    addr: Option<SocketAddr>,
    cert_pem: &str,
    key_pem: &str,
    pkcs12: Option<&str>,
    options: ListenerOptions,
) -> anyhow::Result<(Arc<msquic_async::Registration>, msquic_async::Listener)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = [msquic::BufferRef::from(alpn)];
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        // 1248 is msquic's floor (QUIC_DPLPMTUD_MIN_MTU); a smaller
        // request is silently clamped up to it. Stated explicitly so
        // the cap the listener applies is the one it appears to apply.
        // Matches the video client (see `camera_core::video`), so the
        // relay tunnel carries the same packet size in both directions.
        .set_MaximumMtu(1248)
        // Keeps the *connection* from going idle. It does not keep a path warm:
        // it is re-armed by any activity anywhere on the connection, so on a
        // connection that is carrying traffic it never fires at all. Keeping an
        // idle path alive is `PathKeepAliveIntervalMs` below.
        .set_KeepAliveIntervalMs(10_000)
        .set_PeerBidiStreamCount(100)
        .set_PeerUnidiStreamCount(100)
        .set_DatagramReceiveEnabled()
        .set_StreamMultiReceiveEnabled();
    let settings = if options.multipath {
        settings
            .set_MultipathEnabled()
            // How long a path may go without sending before it gets a PING,
            // counted per path and reset by nothing. Both ends have to set it —
            // each connection's timer runs off its own settings, and the default
            // is 0, which sends no PING at all.
            //
            // **The peer's half of this is also how a camera knows its viewer is
            // still there.** Once the video moves to the direct path, these
            // PINGs are the only thing left crossing the relay leg, and
            // `ListenerSession::renew_connections` renews that connection's
            // lease only while something is. Dropping the setting on either end
            // would look like a keepalive tidy-up and show up as viewers cut off
            // one connect TTL into watching.
            .set_PathKeepAliveIntervalMs(PATH_KEEP_ALIVE_INTERVAL_MS)
    } else {
        settings
    };
    let configuration = registration.open_configuration(&alpn, Some(&settings))?;

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

    #[cfg(windows)]
    {
        use base64::{engine::general_purpose, Engine as _};
        use schannel::cert_context::{CertContext, KeySpec};
        use schannel::cert_store::{CertAdd, Memory};
        use schannel::crypt_prov::{AcquireOptions, ProviderType};
        use schannel::RawPointer;
        use windows::core::PCWSTR;
        use windows::Win32::Security::Cryptography::{
            CertEnumCertificatesInStore, PFXImportCertStore, CRYPT_INTEGER_BLOB,
            PKCS12_PREFER_CNG_KSP,
        };

        if let Some(pkcs12) = pkcs12 {
            let pkcs12_bytes = general_purpose::STANDARD.decode(pkcs12)?;
            let mut blob = CRYPT_INTEGER_BLOB {
                cbData: pkcs12_bytes.len() as u32,
                pbData: pkcs12_bytes.as_ptr() as *mut u8,
            };
            let store = unsafe {
                PFXImportCertStore(&mut blob, PCWSTR::null(), PKCS12_PREFER_CNG_KSP)
                    .map_err(|e| anyhow::anyhow!("Failed to import PKCS#12 store: {e:?}"))?
            };
            let cert_ctx_ptr = unsafe { CertEnumCertificatesInStore(store, None) };
            if cert_ctx_ptr.is_null() {
                return Err(anyhow::anyhow!("No certificates found in PKCS#12 store"));
            }
            let cred_config = msquic::CredentialConfig::new().set_credential(
                msquic::Credential::CertificateContext(cert_ctx_ptr as *const _ as *mut _),
            );
            configuration.load_credential(&cred_config)?;
        } else {
            let mut store = Memory::new()
                .map_err(|e| anyhow::anyhow!("Failed to create memory store: {e:?}"))?
                .into_store();

            let name = String::from("ISEKAI-link-temp-cert");

            let cert_ctx = CertContext::from_pem(cert_pem)
                .map_err(|e| anyhow::anyhow!("Failed to execute CertContext::from_pem: {e:?}"))?;

            let mut options = AcquireOptions::new();
            options.container(&name);

            let type_ = ProviderType::rsa_full();

            let mut container = match options.acquire(type_) {
                Ok(container) => container,
                Err(_) => options
                    .new_keyset(true)
                    .acquire(type_)
                    .map_err(|e| anyhow::anyhow!("Failed to acquire new keyset: {e:?}"))?,
            };
            let key = key_pem.as_bytes();
            println!("{}", String::from_utf8_lossy(&key[..100]));
            container
                .import()
                .import_pkcs8_pem(key_pem.as_bytes())
                .map_err(|e| anyhow::anyhow!("Failed to import PKCS8 PEM: {e:?}"))?;

            cert_ctx
                .set_key_prov_info()
                .container(&name)
                .type_(type_)
                .keep_open(true)
                .key_spec(KeySpec::key_exchange())
                .set()
                .map_err(|e| anyhow::anyhow!("Failed to set key provider info: {e:?}"))?;

            let context = store
                .add_cert(&cert_ctx, CertAdd::Always)
                .map_err(|e| anyhow::anyhow!("Failed to add certificate to store: {e:?}"))?;

            let cred_config = msquic::CredentialConfig::new().set_credential(
                msquic::Credential::CertificateContext(unsafe { context.as_ptr() }),
            );

            configuration.load_credential(&cred_config)?;
        }
    }

    let listener = msquic_async::Listener::new(&registration, configuration)?;
    listener.start(&alpn, addr)?;
    Ok((registration, listener))
}

pub async fn create_normal_channel(
    uri: Uri,
    reg: Arc<msquic_async::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
    is_unconnected: bool,
) -> anyhow::Result<channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>> {
    let connector =
        H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), is_unconnected, reg);
    let channel = channel_masque::H3Channel::<_, Full<Bytes>>::new(connector, uri.clone(), None);
    Ok(channel)
}

/// Fetch a TLS certificate from the MASQUE server by making an HTTP/3 request over msquic.
pub async fn get_certificate(
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
    response.status().is_success().then(|| ()).ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to get certificate: HTTP status {}",
            response.status()
        )
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
    Ok(serde_json::from_slice::<CertificateResponse>(&data)
        .map_err(|e| anyhow::anyhow!("Failed to parse certificate response: {e}"))?)
}

pub async fn get_public_address(
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
    response.status().is_success().then(|| ()).ok_or_else(|| {
        anyhow::anyhow!(
            "Failed to get public address: HTTP status {}",
            response.status()
        )
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
    Ok(String::from_utf8(data.to_vec())
        .map_err(|e| anyhow::anyhow!("Failed to convert response body to UTF-8 string: {e}"))?
        .parse()
        .map_err(|e| anyhow::anyhow!("Failed to parse public address: {e}"))?)
}

pub async fn get_udp_mode(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
) -> anyhow::Result<UdpModeSettingResponse> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/udp_mode")
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

    response.status().is_success().then(|| ()).ok_or_else(|| {
        anyhow::anyhow!("Failed to get udp mode: HTTP status {}", response.status())
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
    Ok(serde_json::from_slice::<UdpModeSettingResponse>(&data)
        .map_err(|e| anyhow::anyhow!("Failed to parse UDP mode setting response: {e}"))?)
}

pub async fn set_udp_mode(
    uri: Uri,
    jwt: &str,
    channel: channel_masque::H3Channel<H3MsQuicAsyncConnector, Full<Bytes>>,
    mode: &str,
) -> anyhow::Result<UdpModeSettingResponse> {
    let mut channel = ServiceBuilder::new()
        .option_layer((!jwt.is_empty()).then(|| AddAuthorizationLayer::bearer(jwt)))
        .service(channel);
    let uri = Uri::builder()
        .scheme(uri.scheme().cloned().expect("URI scheme is required"))
        .authority(uri.authority().cloned().expect("URI authority is required"))
        .path_and_query("/udp_mode")
        .build()?;
    let udp_mode_setting_request = UdpModeSettingRequest {
        mode: Some(mode.to_string()),
    };
    let request = Request::builder()
        .uri(uri)
        .method("PUT")
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(
            &udp_mode_setting_request,
        )?)))
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
    response.status().is_success().then(|| ()).ok_or_else(|| {
        anyhow::anyhow!("Failed to set udp mode: HTTP status {}", response.status())
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
    Ok(serde_json::from_slice::<UdpModeSettingResponse>(&data)
        .map_err(|e| anyhow::anyhow!("Failed to parse UDP mode setting response: {e}"))?)
}

pub async fn create_masque_channel(
    uri: Uri,
    reg: Arc<msquic_async::Registration>,
    config: Arc<msquic::Configuration>,
    config_qmux: Arc<msquic::Configuration>,
    is_unconnected: bool,
    conn_tx: Option<mpsc::Sender<msquic_async::Connection>>,
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
        is_unconnected,
        reg,
    );
    // Optionally hand the underlying QUIC connection back to the caller so it
    // can poll connection events (e.g. observed-address reports).
    let connector = if let Some(conn_tx) = conn_tx {
        connector.with_channel(conn_tx)
    } else {
        connector
    };
    let channel = channel_masque::H3Channel::<
        _,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >::new(connector, uri.clone(), None);
    Ok(channel)
}

pub async fn create_forward_masque_connection(
    jwt: &str,
    listen_addr: SocketAddr,
    channel: channel_masque::H3Channel<
        h3_util::msquic_async::H3MsQuicAsyncConnector,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >,
    tasks: &mut JoinSet<Result<(), anyhow::Error>>,
    shutdown_token: CancellationToken,
    public_addresses_out: Option<std::sync::Arc<std::sync::Mutex<Option<String>>>>,
) -> anyhow::Result<()> {
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(jwt))
        .service(channel);

    let mut client = channel_masque::MasqueClient::new(channel, None);

    tasks.spawn(async move {
        let mut events = client
            .start(channel_masque::MasqueClientMode::Forward(listen_addr), shutdown_token)
            .await
            .map_err(|e| {
                tracing::error!("Failed to start MasqueClient: {e:?}");
                anyhow::anyhow!("Failed to start MasqueClient: {e:?}")
            })?;
        while let Some(event) = events.recv().await {
            match event {
                channel_masque::MasqueClientEvent::PublicAddresses(public_addrs) => {
                    tracing::info!("public addresses: {:?}", public_addrs);
                    if let Some(ref out) = public_addresses_out {
                        let formatted = public_addrs
                            .iter()
                            .map(|a| a.to_string())
                            .collect::<Vec<_>>()
                            .join(", ");
                        *out.lock().unwrap() = Some(formatted);
                    }
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
        tracing::debug!("MasqueClient event loop exited");
        Ok::<(), anyhow::Error>(())
    });
    Ok(())
}
