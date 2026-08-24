//! UniFFI-exported wrapper around the upstream `portal-core`'s pairing +
//! `session::connect` + forward, for the Android app.
//!
//! Rewritten onto phases 6+ of `docs/portal_plan.md` (#150-176, merged
//! upstream while this crate was still on the phase-1 spike): pairing now
//! yields a standing Grant keyed by `(server, client, protocol)` with no
//! listener id in it, so `PortalConfig` no longer carries one and a
//! `portal-server` restart does not invalidate an existing pairing. Moving
//! onto a direct path is automatic via [`portal_core::path::keep_on_the_best_path`],
//! run for the life of the session — there is no more `enable_migration` flag.
//!
//! Deliberately does not depend on `isekai-client-ffi`/`camera-core`, same as
//! before: this mirrors `portal-client/src/main.rs`'s own direct use of
//! `isekai_p2p` and `portal_core`. The `connect()`/session-holds-its-own-runtime
//! shape is unchanged from the phase-1 version, which is the proven way to
//! expose an async Rust session as a synchronous UniFFI call that returns fast
//! and keeps working in the background.

use std::net::SocketAddr;
use std::sync::Arc;

use isekai_p2p::agent::{pairing_code_from_input, EndpointKey};
use isekai_p2p::{P2pConfig, PeerDirectory};
use portal_core::session::{connect as session_connect, Reach};
use tokio::runtime::Runtime;
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

#[derive(Debug, Clone, thiserror::Error, uniffi::Error)]
pub enum PortalError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("pairing failed: {0}")]
    Pair(String),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// Mirrors isekai-client-ffi's `ClientConfig`, with `service` in place of
/// video-specific fields.
///
/// No more `listener_id`: a Grant finds its listener fresh on every connect
/// (that is the whole point of the upstream rewrite this was migrated onto —
/// it is what makes a `portal-server` restart not require re-pairing). No
/// more `enable_migration`/`insecure_skip_verify`: multipath is unconditional
/// now, and `portal_core::session::connect` picks TLS verification itself
/// from what the peer's relay certificate says (`session.rs`'s
/// `open_the_peer_connection`).
#[derive(Debug, Clone, uniffi::Record)]
pub struct PortalConfig {
    pub identity_url: String,
    pub proxy_url: String,
    pub protocol: String,
    pub auth0_token: String,
    pub service: String,
    pub expected_endpoint: String,
    pub register: bool,
}

#[uniffi::export]
pub fn generate_endpoint_key_pem() -> Result<String, PortalError> {
    EndpointKey::generate()
        .to_pkcs8_pem()
        .map_err(|e| PortalError::InvalidKey(e.to_string()))
}

#[uniffi::export]
pub fn endpoint_id_of(pem: String) -> Result<String, PortalError> {
    EndpointKey::from_pkcs8_pem(&pem)
        .map(|k| k.endpoint_id())
        .map_err(|e| PortalError::InvalidKey(e.to_string()))
}

fn build_p2p_config(config: &PortalConfig, key: EndpointKey, register: bool) -> P2pConfig {
    P2pConfig {
        identity_url: config.identity_url.clone(),
        identity_http3: false,
        proxy_url: config.proxy_url.clone(),
        auth0_token: config.auth0_token.clone(),
        // Kotlin already refreshes the access token itself (`AuthStore`,
        // mirroring the camera app) and passes a current one in on every
        // call, so there is no need for portal-core's own
        // `RefreshingAuth0Token` source here — that exists for the headless
        // CLI, which has no GUI session to refresh from.
        auth0: None,
        protocol: config.protocol.clone(),
        register,
        device_name: Some("portal-client-android".to_owned()),
        token_ttl: None,
        key,
    }
}

/// Redeem a pairing code and return `config` updated with the resulting
/// `expected_endpoint` (the server's Endpoint ID). Registers the Endpoint
/// first if `config.register` is set, same ordering as before: registration
/// happens at most once per key, explicitly, before anything else touches
/// this config, since a second attempt is a 409. The returned config always
/// has `register: false`, since after this call the key is registered either
/// way.
#[uniffi::export]
pub fn pair_with_code(
    config: PortalConfig,
    endpoint_key_pem: String,
    code: String,
) -> Result<PortalConfig, PortalError> {
    let key = EndpointKey::from_pkcs8_pem(&endpoint_key_pem)
        .map_err(|e| PortalError::InvalidKey(e.to_string()))?;
    let runtime = Runtime::new().map_err(|e| PortalError::Runtime(e.to_string()))?;
    let register = config.register;

    runtime.block_on(async {
        let cfg = build_p2p_config(&config, key, register);
        if cfg.register {
            isekai_p2p::issue_endpoint_token(&cfg)
                .await
                .map_err(|e| PortalError::Pair(format!("{e:#}")))?;
        }
        let cfg = P2pConfig {
            register: false,
            ..cfg
        };

        // Accepts whatever the user scanned, pasted or typed: a pairing URI,
        // or the eight characters with or without their dash — same
        // normalization `portal-client --pair` applies.
        let code = pairing_code_from_input(&code);

        let pd = PeerDirectory::open(&cfg)
            .await
            .map_err(|e| PortalError::Pair(format!("{e:#}")))?;
        let grant = pd
            .pair(&code, Some("portal-client-android"))
            .await
            .map_err(|e| PortalError::Pair(format!("{e:#}")))?;

        Ok(PortalConfig {
            expected_endpoint: grant.owner_endpoint,
            register: false,
            ..config
        })
    })
}

/// A live portal tunnel: a local TCP port forwarding to `config.service` on
/// the paired peer, over the real P2P relay + direct-path multipath
/// connection. Holds its own Tokio runtime for as long as it lives — dropping
/// it (or calling `disconnect()`) tears the tunnel down.
#[derive(uniffi::Object)]
pub struct PortalSession {
    #[allow(dead_code)]
    runtime: Runtime,
    shutdown: CancellationToken,
    local_port: u16,
}

#[uniffi::export]
impl PortalSession {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    pub fn disconnect(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for PortalSession {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Connect on the standing Grant from a prior [`pair_with_code`] (or `None`
/// peer if `config.expected_endpoint` is empty — fine as long as this key is
/// paired with only one server), and forward a local TCP port to
/// `config.service`. Returns once the port is bound; the forward and the
/// automatic best-path switch keep running in the background for the life of
/// the returned `PortalSession`.
#[uniffi::export]
pub fn connect(
    config: PortalConfig,
    endpoint_key_pem: String,
) -> Result<Arc<PortalSession>, PortalError> {
    let key = EndpointKey::from_pkcs8_pem(&endpoint_key_pem)
        .map_err(|e| PortalError::InvalidKey(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| PortalError::Runtime(e.to_string()))?;

    let shutdown = CancellationToken::new();
    let cfg = build_p2p_config(&config, key, false);
    let service = config.service.clone();
    let peer = (!config.expected_endpoint.is_empty()).then_some(config.expected_endpoint.clone());

    let local_port = runtime.block_on({
        let shutdown = shutdown.clone();
        async move {
            let connected = session_connect(&cfg, Reach::Grant { peer: peer.as_deref() }, &shutdown)
                .await
                .map_err(|e| PortalError::Connect(format!("{e:#}")))?;

            let conn = connected.peer.connection().clone();
            let local: SocketAddr = "127.0.0.1:0".parse().unwrap();
            let bound = portal_core::client::forward(conn, local, service, shutdown.clone())
                .await
                .map_err(|e| PortalError::Connect(format!("{e:#}")))?;

            // Both ways this can end without us: the proxy withdrawing the
            // session (a revoked Grant), or the peer connection going away —
            // watching only one is the mistake `portal-client/src/main.rs`
            // documents (the forwarded port would stay bound over nothing).
            // `keep_on_the_best_path` is also what moves the forward onto a
            // direct path once one validates; it returns when the connection
            // is no longer usable, which doubles as the "peer gone" signal.
            let ended = connected.session.ended();
            let peer_conn = connected.peer.connection().clone();
            let watch_shutdown = shutdown.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = watch_shutdown.cancelled() => {}
                    _ = ended.cancelled() => {
                        tracing::warn!("the session ended; the forward is going with it");
                    }
                    _ = portal_core::path::keep_on_the_best_path(peer_conn, watch_shutdown.clone()) => {
                        tracing::warn!("the peer connection closed; the forward is going with it");
                    }
                }
                watch_shutdown.cancel();
                connected.close().await;
            });

            Ok::<u16, PortalError>(bound.port())
        }
    })?;

    Ok(Arc::new(PortalSession {
        runtime,
        shutdown,
        local_port,
    }))
}
