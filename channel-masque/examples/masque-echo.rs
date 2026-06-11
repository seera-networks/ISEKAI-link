use argh::FromArgs;
use bytes::Bytes;
use h3_util::msquic_async::h3_msquic_async::msquic;
use http::Uri;
use http_body::Frame;
use http_body_util::StreamBody;
use std::{convert::Infallible, sync::Arc};
use tokio::net::UdpSocket;
use tokio_stream::wrappers::ReceiverStream;
use tower::ServiceBuilder;
use tower_http::auth::AddAuthorizationLayer;

fn make_msquic_async_reg_and_config()
-> anyhow::Result<(Arc<msquic::Registration>, Arc<msquic::Configuration>)> {
    let registration = msquic::Registration::new(&msquic::RegistrationConfig::default())?;
    let alpn = [msquic::BufferRef::from("h3")];
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

    let cred_config = msquic::CredentialConfig::new_client()
        .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION);
    configuration.load_credential(&cred_config)?;
    Ok((Arc::new(registration), Arc::new(configuration)))
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
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .with_max_level(tracing::Level::DEBUG)
        .init();
    let cmd_opts: CmdOptions = argh::from_env();

    let uri: Uri = cmd_opts.target.parse()?;
    let (reg, config) = make_msquic_async_reg_and_config()?;
    let connector =
        h3_util::msquic_async::H3MsQuicAsyncConnector::new(uri.clone(), config, reg.clone());
    // let (conn_sender, mut conn_receiver) = mpsc::channel(1);
    // let connector = connector.with_channel(conn_sender);
    let channel = channel_masque::H3Channel::<
        _,
        StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>,
    >::new(connector, uri.clone(), None);
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(&cmd_opts.jwt))
        .service(channel);

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_addr = socket.local_addr()?;
    let mut client = channel_masque::MasqueClient::new(channel, None);

    let proxy_handle = tokio::spawn(async move {
        let mut events = client
            .start(channel_masque::MasqueClientMode::Forward(local_addr))
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

    let mut buf = [0; 65535];
    let mut proxy_handle = std::pin::pin!(proxy_handle);
    loop {
        tokio::select! {
            _ = &mut proxy_handle => {
                tracing::info!("MasqueClient proxy task finished");
                break;
            }
            res = socket.recv_from(&mut buf) => {
                let (len, addr) = match res {
                    Ok(res) => res,
                    Err(e) => {
                        tracing::error!("udp receive error: {}", e);
                        break;
                    }
                };
                tracing::debug!("received {} bytes from {}", len, addr);
                socket.send_to(&buf[..len], addr).await?;
            }
        }
    }
    // tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    Ok(())
}
