//! FFI viewer API for the iOS camera-client (Phase 1).
//!
//! Wraps `camera-core`'s initiator path — `InitiatorSession::connect` plus
//! `receive_frames` — behind UniFFI so a Swift app can:
//!
//! 1. generate / inspect an Endpoint key (ECDSA P-256),
//! 2. connect to the proxy over the P2P relay with an Endpoint Token / capability,
//! 3. receive MJPEG frames (one JPEG per callback) and connection-state updates.
//!
//! Decode, display, key storage (Keychain) and Auth0 login stay on the Swift
//! side; this crate is deliberately headless. See
//! `docs/ios_camera_client_plan.md`.

use std::sync::Arc;

use bytes::Bytes;
use camera_core::{receive_frames, InitiatorSession, P2pConfig};
use isekai_p2p_core::endpoint::EndpointKey;
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

uniffi::setup_scaffolding!();

/// Errors surfaced across the FFI boundary.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum ClientError {
    #[error("invalid endpoint key: {0}")]
    InvalidKey(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    #[error("connect failed: {0}")]
    Connect(String),
    #[error("runtime error: {0}")]
    Runtime(String),
}

/// Lifecycle of the viewer connection, reported to the Swift `FrameSink`.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
pub enum ConnectionState {
    /// Establishing the control-plane connection and relay leg.
    Connecting,
    /// The relay leg is up; waiting for the peer to bind and the video to flow.
    Connected,
    /// Video frames are arriving.
    Streaming,
    /// The session was closed by the app.
    Closed,
    /// The session failed (see the accompanying detail string).
    Failed,
}

/// Connection settings (mirrors the desktop GUI's P2P fields).
#[derive(Debug, Clone, uniffi::Record)]
pub struct ClientConfig {
    pub identity_url: String,
    pub proxy_url: String,
    pub protocol: String,
    pub capability: String,
    pub listener_id: String,
    /// Register the Endpoint with the Identity API before issuing a token.
    pub register: bool,
    /// **Dev only** — accept self-signed proxy/Identity certificates. Never true
    /// in production; leave the proxy's real certificate validation on.
    pub insecure_skip_verify: bool,
}

/// Swift-implemented callback that receives frames and state changes.
///
/// Called from the Rust runtime's worker threads; the implementation must be
/// thread-safe and should hand work back to the main thread for UI updates.
#[uniffi::export(callback_interface)]
pub trait FrameSink: Send + Sync {
    /// A decoded-on-arrival JPEG frame and its stream-derived sequence number.
    fn on_frame(&self, jpeg: Vec<u8>, seq: u64);
    /// A connection-state transition, with an optional human-readable detail.
    fn on_state(&self, state: ConnectionState, detail: String);
}

/// A live viewer session. Hold it for the duration of viewing; drop or
/// [`ViewerSession::disconnect`] to tear down the relay leg and tasks.
#[derive(uniffi::Object)]
pub struct ViewerSession {
    // Owning the runtime keeps the spawned receive/bridge tasks alive; dropping
    // it (or cancelling `shutdown`) stops them. Held for its lifetime, not read.
    #[allow(dead_code)]
    runtime: Runtime,
    shutdown: CancellationToken,
    connection_id: String,
}

#[uniffi::export]
impl ViewerSession {
    /// The connection id to hand to the camera server so it can bind its relay
    /// leg (out of band — copy/paste or QR).
    pub fn connection_id(&self) -> String {
        self.connection_id.clone()
    }

    /// Tear down the session (idempotent).
    pub fn disconnect(&self) {
        self.shutdown.cancel();
    }
}

impl Drop for ViewerSession {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Generate a fresh Endpoint key, returned as a PKCS#8 PEM string.
///
/// The caller (Swift) must persist this securely — the iOS Keychain, device-only
/// and non-synchronizing. It is long-lived key material that must never leave the
/// device.
#[uniffi::export]
pub fn generate_endpoint_key_pem() -> Result<String, ClientError> {
    EndpointKey::generate()
        .to_pkcs8_pem()
        .map_err(|e| ClientError::InvalidKey(e.to_string()))
}

/// Derive the Endpoint ID (`ep:...`) from a PKCS#8 PEM key — the value the
/// camera server authorizes when issuing a capability.
#[uniffi::export]
pub fn endpoint_id_of(pem: String) -> Result<String, ClientError> {
    EndpointKey::from_pkcs8_pem(&pem)
        .map(|k| k.endpoint_id())
        .map_err(|e| ClientError::InvalidKey(e.to_string()))
}

/// Connect over the P2P relay and start streaming.
///
/// Blocks only for the control-plane exchange and relay-leg setup (fast); frames
/// then arrive on `sink` from a background task. Returns a [`ViewerSession`] to
/// hold for the duration and its `connection_id`.
///
/// `auth0_token` is the user's Auth0 access token (obtained via the app's
/// login); `endpoint_key_pem` is the PKCS#8 PEM from the Keychain.
#[uniffi::export]
pub fn connect(
    config: ClientConfig,
    endpoint_key_pem: String,
    auth0_token: String,
    sink: Box<dyn FrameSink>,
) -> Result<Arc<ViewerSession>, ClientError> {
    let sink: Arc<dyn FrameSink> = Arc::from(sink);

    // Dev-only self-signed acceptance is read from this env var by the transport
    // layer. Production leaves it unset so real certificates are validated.
    if config.insecure_skip_verify {
        // SAFETY: set once, before any transport connects; process-wide by design.
        unsafe { std::env::set_var("ISEKAI_INSECURE_SKIP_VERIFY", "1") };
    }

    let key = EndpointKey::from_pkcs8_pem(&endpoint_key_pem)
        .map_err(|e| ClientError::InvalidKey(e.to_string()))?;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ClientError::Runtime(e.to_string()))?;

    let shutdown = CancellationToken::new();

    sink.on_state(ConnectionState::Connecting, String::new());

    let cfg = P2pConfig {
        identity_url: config.identity_url,
        identity_http3: false,
        proxy_url: config.proxy_url,
        auth0_token,
        protocol: config.protocol,
        register: config.register,
        device_name: Some("ios-camera-client".to_owned()),
        token_ttl: None,
        key,
    };

    let local_bind = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| ClientError::InvalidArgument(e.to_string()))?;

    // Establish the control plane + initiator relay leg (fast); this returns
    // before video flows.
    let session = runtime
        .block_on(InitiatorSession::connect(
            &cfg,
            &config.capability,
            &config.listener_id,
            &[],
            local_bind,
        ))
        .map_err(|e| ClientError::Connect(format!("{e:#}")))?;

    let connection_id = session.connection_id().to_owned();
    let video_port = session.local_addr.port();
    // Dial the per-endpoint relay FQDN with validation when the proxy issued a
    // relay certificate; otherwise fall back to 127.0.0.1 unvalidated (dev).
    let (video_host, verify) = match session.video_host() {
        Some(host) => (host.to_string(), true),
        None => ("127.0.0.1".to_string(), false),
    };

    sink.on_state(ConnectionState::Connected, connection_id.clone());

    // Frame channel: `receive_frames` produces (seq, jpeg); we bridge to `sink`.
    let (frame_tx, mut frame_rx) = mpsc::channel::<(u64, Bytes)>(16);

    // Receiver: dials the video QUIC over the relay and delivers frames.
    let recv_shutdown = shutdown.clone();
    let recv_sink = Arc::clone(&sink);
    runtime.spawn(async move {
        if let Err(e) =
            receive_frames(None, &video_host, video_port, verify, frame_tx, recv_shutdown).await
        {
            recv_sink.on_state(ConnectionState::Failed, format!("{e:#}"));
        }
    });

    // Bridge: forward frames to the Swift sink; first frame flips to Streaming.
    let bridge_sink = Arc::clone(&sink);
    runtime.spawn(async move {
        let mut streaming = false;
        while let Some((seq, jpeg)) = frame_rx.recv().await {
            if !streaming {
                streaming = true;
                bridge_sink.on_state(ConnectionState::Streaming, String::new());
            }
            bridge_sink.on_frame(jpeg.to_vec(), seq);
        }
    });

    // Hold the initiator session (and its relay leg) alive until shutdown.
    let hold_shutdown = shutdown.clone();
    let hold_sink = Arc::clone(&sink);
    runtime.spawn(async move {
        hold_shutdown.cancelled().await;
        session.close().await;
        hold_sink.on_state(ConnectionState::Closed, String::new());
    });

    Ok(Arc::new(ViewerSession {
        runtime,
        shutdown,
        connection_id,
    }))
}
