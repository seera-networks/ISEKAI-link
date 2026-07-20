//! MASQUE bind session for P2P relay (feature `msquic`).
//!
//! After `POST /v1/peer/connect` returns a connection id, each peer opens a
//! MASQUE CONNECT-UDP **bind** session tagged with that id. The proxy then binds
//! a public edge socket and injects its address into the connection as a `relay`
//! candidate (server side, phase 3b-2), which the peer learns via the connection
//! views. Inbound relay UDP is forwarded to the local P2P application.
//!
//! The bind session runs on the MASQUE data path, which authenticates the same
//! way as the control plane (spec §13): `Authorization` carries the **Endpoint
//! Token** — no Auth0 token, the Endpoint Token's `sub` is the user identity —
//! plus `X-Endpoint-Id` and the PoP headers. The proxy authorizes the relay
//! edge against the Endpoint that signed the request, so this Endpoint must be
//! a party of the connection.
//!
//! The PoP signature covers an empty body (spec §8.0, CONNECT-UDP variant): a
//! CONNECT-UDP body is the capsule stream and is not known at request time.
//!
//! We use `Forward` mode — unlike `WebRTC` mode it does **not** send
//! `seera-session-create`, so no WebRTC signaling session is created; only the
//! caller-set `seera-signaling-session-id` header ties the edge address to the
//! P2P connection.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context as _;
use bytes::Bytes;
use channel_masque::{
    CONNECT_UDP_BIND_PATH, H3Channel, MasqueClient, MasqueClientEvent, MasqueClientMode,
};
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

use crate::endpoint::EndpointKey;
use crate::pop;
use crate::transport::make_client_config;

/// The PoP proof for the single CONNECT-UDP request a session issues: a
/// signature over `path` with an empty body (spec §8.0, CONNECT-UDP variant).
///
/// Signing once as the session is opened matches that request, since each
/// session makes exactly one. The proxy allows ±60 s of timestamp skew, so the
/// request must go out promptly after this.
fn sign_connect_udp(key: &EndpointKey, path: &str) -> pop::PopHeaders {
    pop::sign_request(key, "CONNECT", path, b"")
}

fn header_value(value: &str) -> anyhow::Result<HeaderValue> {
    HeaderValue::from_str(value).context("PoP header value is not a valid HTTP header value")
}

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
///
/// `endpoint_token` and `key` must belong to the Endpoint that is a party of
/// the connection: the proxy authorizes the relay edge against the Endpoint the
/// PoP signature proves possession of, not against the user.
pub fn open_bind_session(
    target: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    connection_id: &str,
    forward_to: SocketAddr,
) -> anyhow::Result<BindSession> {
    let uri: Uri = target.parse().context("invalid proxy target URI")?;
    let pop = sign_connect_udp(key, CONNECT_UDP_BIND_PATH);
    let (registration, config) = make_client_config(None, false)?;
    let (registration, config_qmux) = make_client_config(Some(registration), true)?;
    let connector =
        H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), registration);
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );

    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(endpoint_token))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_ENDPOINT_ID),
            header_value(&pop.endpoint_id)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_NONCE),
            header_value(&pop.nonce)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_TIMESTAMP),
            header_value(&pop.timestamp)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_SIGNATURE),
            header_value(&pop.signature)?,
        ))
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
/// `seera-signaling-session-id: <connection_id>` so the proxy binds this leg to
/// the relay rendezvous (ephemeral loopback source) — the same identifier the
/// target's bind leg uses. Returns the bound local address.
///
/// Authenticated with the initiator's Endpoint Token + PoP, like the bind leg.
pub async fn open_connect_relay(
    proxy_url: &str,
    endpoint_token: &str,
    key: &EndpointKey,
    connection_id: &str,
    masque_uri: &str,
    local_bind: SocketAddr,
) -> anyhow::Result<ConnectRelay> {
    let masque: Uri = masque_uri.parse().context("invalid masque_uri")?;
    let target_path = masque
        .path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| masque.path().to_owned());
    // Signed over the path actually sent as `:path`, which is the masque_uri's
    // path — not the proxy URL we dial.
    let pop = sign_connect_udp(key, &target_path);

    let uri: Uri = proxy_url.parse().context("invalid proxy target URI")?;
    let (registration, config) = make_client_config(None, false)?;
    let (registration, config_qmux) = make_client_config(Some(registration), true)?;
    let connector =
        H3MsQuicAsyncConnector::new(uri.clone(), config, Some(config_qmux), registration);
    let channel = H3Channel::<_, StreamBody<ReceiverStream<Result<Frame<Bytes>, Infallible>>>>::new(
        connector, uri, None,
    );
    let channel = ServiceBuilder::new()
        .layer(AddAuthorizationLayer::bearer(endpoint_token))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_ENDPOINT_ID),
            header_value(&pop.endpoint_id)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_NONCE),
            header_value(&pop.nonce)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_TIMESTAMP),
            header_value(&pop.timestamp)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static(pop::HEADER_POP_SIGNATURE),
            header_value(&pop.signature)?,
        ))
        .layer(SetRequestHeaderLayer::appending(
            HeaderName::from_static("seera-signaling-session-id"),
            HeaderValue::from_str(connection_id).context("invalid connection id header value")?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::Verifier;

    /// What the proxy verifies: the signature covers `CONNECT`, the exact path
    /// on the wire, and an empty body — never the capsule stream.
    #[test]
    fn connect_udp_pop_is_verifiable_over_an_empty_body() {
        let key = EndpointKey::generate();
        let pop = sign_connect_udp(&key, CONNECT_UDP_BIND_PATH);

        assert_eq!(pop.endpoint_id, key.endpoint_id());
        let canonical = pop::canonical_pop_string(
            "CONNECT",
            CONNECT_UDP_BIND_PATH,
            &pop.endpoint_id,
            &pop.timestamp,
            &pop.nonce,
            b"",
        );
        let sig = Signature::from_der(&URL_SAFE_NO_PAD.decode(&pop.signature).unwrap()).unwrap();
        let public = p256::PublicKey::from_jwk_str(&key.public_jwk().to_string()).unwrap();
        assert!(
            p256::ecdsa::VerifyingKey::from(public)
                .verify(canonical.as_bytes(), &sig)
                .is_ok()
        );
        // A signature made for the bind path must not verify for a relay leg's
        // concrete target: the path is bound by the signature.
        let other = pop::canonical_pop_string(
            "CONNECT",
            "/.well-known/masque/udp/127.0.0.1/30001/",
            &pop.endpoint_id,
            &pop.timestamp,
            &pop.nonce,
            b"",
        );
        assert_ne!(canonical, other);
    }

    /// Every PoP value must survive as an HTTP header value.
    #[test]
    fn pop_values_are_valid_header_values() {
        let key = EndpointKey::generate();
        let pop = sign_connect_udp(&key, "/.well-known/masque/udp/127.0.0.1/30001/");
        for (_, value) in pop.as_pairs() {
            header_value(value).expect("PoP value is a valid header value");
        }
    }
}
