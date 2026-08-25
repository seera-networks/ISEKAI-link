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
use std::sync::{Arc, Mutex};
use std::time::Duration;

use isekai_p2p::agent::{pairing_code_from_input, EndpointKey};
use isekai_p2p::auth::Auth0TokenSource;
use isekai_p2p::auth0::{Auth0Config, Auth0Tokens, RefreshingAuth0Token};
use isekai_p2p::{P2pConfig, PeerDirectory};
use portal_core::session::{connect as session_connect, Reach};
use tokio::runtime::Runtime;
use tokio::sync::watch;
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

fn build_p2p_config(
    config: &PortalConfig,
    key: EndpointKey,
    register: bool,
    auth0: Option<Arc<dyn Auth0TokenSource>>,
) -> P2pConfig {
    P2pConfig {
        identity_url: config.identity_url.clone(),
        identity_http3: false,
        proxy_url: config.proxy_url.clone(),
        auth0_token: config.auth0_token.clone(),
        auth0,
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
///
/// No `auth0` source here, unlike `connect()` — this is a single call, not a
/// long-lived session with token renewals to keep current, so the fresh
/// token Kotlin already passed in `config.auth0_token` is all it needs.
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
        let cfg = build_p2p_config(&config, key, register, None);
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

/// How long [`PortalSession::disconnect`]/`Drop` wait for the session to
/// actually report itself closed before giving up and shutting the runtime
/// down anyway. Same order of magnitude as `portal_core::session::Connected
/// ::close`'s own `DRAIN_TIMEOUT`, which this waits on indirectly.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// A live portal tunnel: a local TCP port forwarding to `config.service` on
/// the paired peer, over the real P2P relay + direct-path multipath
/// connection.
///
/// Call [`PortalSession::disconnect`] to tear it down and *wait* for that to
/// actually finish, rather than just dropping the last reference — see
/// `close_and_wait` for why the difference matters here. `Drop` runs the same
/// bounded wait as a safety net for a reference that goes away without an
/// explicit `disconnect()`, but UniFFI frees this object from a cleaner
/// thread, at a time the app does not choose, so `disconnect()` is the one to
/// call from code that knows it is done with the session.
#[derive(uniffi::Object)]
pub struct PortalSession {
    // `None` once closed — `close_and_wait` takes it, so a second call (or
    // `Drop`, after an explicit `disconnect()`) finds nothing left to do
    // rather than waiting twice or shutting the same runtime down twice.
    runtime: Mutex<Option<Runtime>>,
    shutdown: CancellationToken,
    // Flips to `true` once the background task's `connected.close().await`
    // has actually returned — not merely that `shutdown` was cancelled. A
    // `watch` rather than a one-shot `Notify`/oneshot pair because it does
    // not matter whether `close_and_wait` starts watching before or after
    // the flip: `wait_for` returns immediately if it already happened.
    closed: watch::Receiver<bool>,
    local_port: u16,
}

impl PortalSession {
    /// Cancels the forward, waits (bounded) for the background task to
    /// report the underlying session actually closed, and then shuts this
    /// session's runtime down explicitly instead of leaving that to an
    /// implicit drop.
    ///
    /// **Why this cannot just be "cancel and let it drop"**: `Runtime::drop`
    /// does not let a spawned task finish — it aborts whatever is still
    /// running. For a task with nothing left to do that is harmless; for one
    /// still mid-`close()` it is a real bug. `connected.close()` reports the
    /// connection closed to the proxy before returning — abort it early and
    /// the relay leg stays reserved until the proxy's own lease expires it,
    /// unreported. Worse, `Connected` holds the last `Arc<Registration>`
    /// (msquic's own handle), and dropping that without `wait_idle()` ever
    /// having run triggers `RegistrationClose`, a **synchronous,
    /// uninterruptible wait** deep in msquic — exactly what #176 hit on
    /// `portal-server`'s own shutdown path (fixed there by leaking the
    /// registration on an unbounded-wait teardown, since closing it properly
    /// needed a wait that path could not afford). On a phone, that wait would
    /// land on whichever cleaner thread UniFFI happens to free this object
    /// from, at a time nobody chose, and it would recur on every
    /// connect/disconnect cycle.
    ///
    /// Waiting here, bounded, is the fix: give the real close a real chance
    /// to finish and be reported, then reclaim the runtime's threads either
    /// way — `shutdown_timeout` still forcefully cancels stragglers past the
    /// bound, so this cannot hang the caller, only fail to wait the full
    /// story if something is genuinely stuck.
    fn close_and_wait(&self) {
        let Some(runtime) = self.runtime.lock().unwrap().take() else {
            return; // already closed by an earlier call (disconnect(), or Drop)
        };
        self.shutdown.cancel();
        let mut closed = self.closed.clone();
        let finished = runtime.block_on(async {
            tokio::time::timeout(CLOSE_TIMEOUT, closed.wait_for(|done| *done)).await
        });
        if finished.is_err() {
            tracing::warn!(
                "the session did not report closed within {CLOSE_TIMEOUT:?}; \
                 shutting the runtime down anyway",
            );
        }
        runtime.shutdown_timeout(CLOSE_TIMEOUT);
    }
}

#[uniffi::export]
impl PortalSession {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Tears the tunnel down and waits for that to actually finish — see
    /// `close_and_wait` for why. Safe to call more than once, and safe not to
    /// call at all (`Drop` runs the same wait as a safety net), but calling
    /// it explicitly is what lets the app control *when* this potentially
    /// blocking-for-up-to-`CLOSE_TIMEOUT` work happens rather than leaving it
    /// to whenever the last Kotlin reference happens to be collected — call
    /// it from a background dispatcher, the same as `pairWithCode`/`connect`.
    pub fn disconnect(&self) {
        self.close_and_wait();
    }
}

impl Drop for PortalSession {
    fn drop(&mut self) {
        self.close_and_wait();
    }
}

/// Connect on the standing Grant from a prior [`pair_with_code`] (or `None`
/// peer if `config.expected_endpoint` is empty — fine as long as this key is
/// paired with only one server), and forward a local TCP port to
/// `config.service`. Returns once the port is bound; the forward and the
/// automatic best-path switch keep running in the background for the life of
/// the returned `PortalSession`.
///
/// `refresh_token`/`access_token_expires_at_unix`: when present, wired into a
/// `RefreshingAuth0Token` so the session's periodic Endpoint Token renewals
/// (every few minutes, for as long as the session runs) keep working past
/// `config.auth0_token`'s own expiry. Without this, `P2pConfig.auth0` stays
/// `None` and renewal starts failing a few minutes after that token expires —
/// fine for the one-shot `pair_with_code` call, wrong for a session meant to
/// keep running. `None`/`0` (the manual-paste-token fallback, which has no
/// refresh token at all) keeps the old "works until it expires" behaviour,
/// same as before this parameter existed.
#[uniffi::export]
pub fn connect(
    config: PortalConfig,
    endpoint_key_pem: String,
    refresh_token: Option<String>,
    access_token_expires_at_unix: u64,
) -> Result<Arc<PortalSession>, PortalError> {
    let key = EndpointKey::from_pkcs8_pem(&endpoint_key_pem)
        .map_err(|e| PortalError::InvalidKey(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| PortalError::Runtime(e.to_string()))?;

    let auth0: Option<Arc<dyn Auth0TokenSource>> = refresh_token.map(|refresh_token| {
        let tokens = Auth0Tokens {
            access_token: config.auth0_token.clone(),
            refresh_token: Some(refresh_token),
            expires_at_unix: access_token_expires_at_unix,
        };
        // `None` store path: Kotlin's own `SecureStore`/`AuthStore` already
        // persists the session (and refreshes it independently for the
        // Pair/Connect calls themselves) — a second on-disk copy here would
        // be a store this crate then has to keep in sync with that one for
        // no benefit, since nothing else reads it.
        RefreshingAuth0Token::new(Auth0Config::default(), tokens, None)
            as Arc<dyn Auth0TokenSource>
    });

    let shutdown = CancellationToken::new();
    let cfg = build_p2p_config(&config, key, false, auth0);
    let service = config.service.clone();
    let peer = (!config.expected_endpoint.is_empty()).then_some(config.expected_endpoint.clone());

    let (closed_tx, closed_rx) = watch::channel(false);

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
                // Told *after* close() returns, not before -- close_and_wait
                // on the FFI side is waiting for the real teardown (the
                // proxy report, msquic's drain) to have actually happened,
                // not just for this task to have started winding down.
                let _ = closed_tx.send(true);
            });

            Ok::<u16, PortalError>(bound.port())
        }
    })?;

    Ok(Arc::new(PortalSession {
        runtime: Mutex::new(Some(runtime)),
        shutdown,
        closed: closed_rx,
        local_port,
    }))
}
