//! MASQUE bind session for P2P relay (feature `msquic`).
//!
//! After `POST /v1/peer/connect` returns a connection id, each peer opens a
//! MASQUE CONNECT-UDP **bind** session tagged with that id. The proxy then binds
//! a public edge socket and injects its address into the connection as a `relay`
//! candidate (server side, phase 3b-2), which the peer learns via the connection
//! views. Inbound relay UDP is forwarded to the local P2P application.
//!
//! The bind session runs on the MASQUE data path, which authenticates with the
//! **Auth0** token (not the Endpoint Token); its `sub` must own the connection.
//! We use `Forward` mode — unlike `WebRTC` mode it does **not** send
//! `seera-session-create`, so no WebRTC signaling session is created; only the
//! caller-set `seera-signaling-session-id` header ties the edge address to the
//! P2P connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use channel_masque::{H3Channel, MasqueClient, MasqueClientEvent, MasqueClientMode};
use h3_util::msquic_async::H3MsQuicAsyncConnector;
use http::Uri;
use http::header::{HeaderName, HeaderValue};
use http_body::Frame;
use http_body_util::StreamBody;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::sync::CancellationToken;
use tower::ServiceBuilder;
use tower_http::auth::AddAuthorizationLayer;
use tower_http::set_header::SetRequestHeaderLayer;

use crate::transport::make_client_config;

/// A running MASQUE bind session. Keep it alive for the duration of the P2P
/// connection; dropping it cancels the session.
pub struct BindSession {
    /// MASQUE client events (e.g. [`MasqueClientEvent::PublicAddresses`] carries
    /// this Endpoint's edge/relay addresses).
    pub events: mpsc::Receiver<MasqueClientEvent>,
    shutdown: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl BindSession {
    /// Cancel the session and wait for it to wind down.
    pub async fn close(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for BindSession {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Open a MASQUE bind session tagged with `connection_id`, forwarding inbound
/// relay UDP to `forward_to` (the local P2P application).
pub fn open_bind_session(
    target: &str,
    auth0_token: &str,
    connection_id: &str,
    forward_to: SocketAddr,
) -> anyhow::Result<BindSession> {
    let uri: Uri = target.parse().context("invalid proxy target URI")?;
    let (registration, config) = make_client_config(None, false)?;
    let (registration, config_qmux) = make_client_config(Some(registration), true)?;
    let connector =
        H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), registration);
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );

    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(auth0_token))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-prefer-temporary-public-address"),
            HeaderValue::from_static("?1"),
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-signaling-session-id"),
            HeaderValue::from_str(connection_id).context("invalid connection id header value")?,
        ))
        .service(channel);

    let shutdown = CancellationToken::new();
    let (out_tx, out_rx) = mpsc::channel(32);
    let session_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut client = MasqueClient::new(channel, None);
        match client
            .start(MasqueClientMode::Forward(forward_to), session_shutdown)
            .await
        {
            Ok(mut events) => {
                // Keep the client alive and forward events until it ends.
                while let Some(event) = events.recv().await {
                    if out_tx.send(event).await.is_err() {
                        break;
                    }
                }
            }
            Err(e) => tracing::error!("failed to start MASQUE bind session: {e:?}"),
        }
    });

    Ok(BindSession {
        events: out_rx,
        shutdown,
        task: Some(task),
    })
}

/// A running CONNECT-UDP forward-proxy relay leg (the **initiator** side). Keep
/// it alive for the duration of the P2P connection; dropping it cancels the
/// session.
pub struct ConnectRelay {
    /// The local UDP address the application should send its traffic to.
    pub local_addr: SocketAddr,
    shutdown: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl ConnectRelay {
    /// Cancel the relay and wait for it to wind down.
    pub async fn close(mut self) {
        self.shutdown.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for ConnectRelay {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Open the initiator relay leg: a concrete-target CONNECT-UDP session to
/// `masque_uri` through the proxy at `proxy_url`, bridging a local UDP socket
/// bound at `local_bind` (the local application sends/receives there).
///
/// The H3 connection targets `proxy_url` (the proxy we already dial); only the
/// **path** of `masque_uri` is used as the CONNECT-UDP target, since the
/// masque_uri authority may differ from `proxy_url`. The session carries
/// `seera-signaling-session-id: <session_id>` so the proxy binds this leg to the
/// relay rendezvous (ephemeral loopback source). Returns the bound local
/// address.
pub async fn open_connect_relay(
    proxy_url: &str,
    auth0_token: &str,
    session_id: &str,
    masque_uri: &str,
    local_bind: SocketAddr,
) -> anyhow::Result<ConnectRelay> {
    let masque: Uri = masque_uri.parse().context("invalid masque_uri")?;
    let target_path = masque
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| masque.path().to_owned());

    let uri: Uri = proxy_url.parse().context("invalid proxy target URI")?;
    let (registration, config) = make_client_config(None, false)?;
    let (registration, config_qmux) = make_client_config(Some(registration), true)?;
    let connector =
        H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), registration);
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(auth0_token))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-signaling-session-id"),
            HeaderValue::from_str(session_id).context("invalid session id header value")?,
        ))
        .service(channel);

    let socket = Arc::new(
        tokio::net::UdpSocket::bind(local_bind)
            .await
            .context("failed to bind local relay socket")?,
    );
    let local_addr = socket
        .local_addr()
        .context("failed to read local relay socket address")?;

    let shutdown = CancellationToken::new();
    let session_shutdown = shutdown.clone();
    let task = tokio::spawn(async move {
        let mut client = MasqueClient::new(channel, None);
        if let Err(e) = client
            .start_connect_udp(&target_path, Vec::new(), socket, session_shutdown.clone())
            .await
        {
            tracing::error!("failed to start CONNECT-UDP relay leg: {e:?}");
            return;
        }
        // Keep the client (and its H3 connection) alive until shutdown.
        session_shutdown.cancelled().await;
    });

    Ok(ConnectRelay {
        local_addr,
        shutdown,
        task: Some(task),
    })
}
