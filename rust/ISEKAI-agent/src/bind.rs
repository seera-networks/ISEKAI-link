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
