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

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use camera_core::{
    new_registration, receive_frames_with, InitiatorSession, P2pConfig, PathEvent, RelayOptions,
    VideoRecvOptions,
};
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

/// One end-to-end route the video can take.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PathInfo {
    pub local: String,
    pub remote: String,
}

impl PathInfo {
    fn new(local: SocketAddr, remote: SocketAddr) -> Self {
        Self {
            local: local.to_string(),
            remote: remote.to_string(),
        }
    }
}

/// Which route the video is on, and which one it could move to.
///
/// `direct` stays `None` where no direct path can be established — a symmetric
/// NAT, say. That is not a failure: the stream runs over the relay and
/// [`ViewerSession::migrate`] simply has nothing to switch to.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PathStatus {
    /// Over the Isekai Link relay. Present from the moment video starts.
    pub relay: Option<PathInfo>,
    /// Straight to the peer, once one has been validated.
    pub direct: Option<PathInfo>,
    /// Whether the traffic is on the relay right now.
    pub on_relay: bool,
    /// Whether [`ViewerSession::migrate`] would do anything.
    pub can_migrate: bool,
}

/// The paths a session knows about, kept in step with what the connection
/// reports rather than with what was last asked for — so a switch that fails
/// does not leave the UI claiming a route the traffic is not on.
#[derive(Default)]
struct Paths {
    relay: Option<(SocketAddr, SocketAddr)>,
    direct: Option<(SocketAddr, SocketAddr)>,
    on_relay: bool,
}

impl Paths {
    fn apply(&mut self, event: PathEvent) {
        match event {
            PathEvent::Relay { local, remote } => {
                self.relay = Some((local, remote));
                self.on_relay = true;
            }
            PathEvent::DirectValidated { local, remote } => self.direct = Some((local, remote)),
            PathEvent::Activated { local, remote } => {
                self.on_relay = Some((local, remote)) == self.relay
            }
        }
    }

    fn status(&self) -> PathStatus {
        PathStatus {
            relay: self.relay.map(|(l, r)| PathInfo::new(l, r)),
            direct: self.direct.map(|(l, r)| PathInfo::new(l, r)),
            on_relay: self.on_relay,
            can_migrate: self.relay.is_some() && self.direct.is_some(),
        }
    }

    /// Where a migrate request should go: away from the relay if on it, back to
    /// it otherwise.
    fn migration_target(&self) -> Option<(SocketAddr, SocketAddr)> {
        if self.on_relay {
            self.direct
        } else {
            self.relay
        }
    }
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
    /// The set of paths changed: one appeared, or the traffic moved.
    fn on_path(&self, status: PathStatus);
    /// A round-trip time sample, in milliseconds, about once a second.
    fn on_rtt(&self, rtt_ms: f64);
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
    paths: Arc<Mutex<Paths>>,
    migrate: mpsc::Sender<(SocketAddr, SocketAddr)>,
    // The video connection and the relay leg share this, and a direct path is
    // opened from the leg's binding — msquic looks bindings up per
    // registration, so they have to be the same one. Held, not read.
    #[allow(dead_code)]
    registration: Arc<msquic_async::Registration>,
}

#[uniffi::export]
impl ViewerSession {
    /// The connection id to hand to the camera server so it can bind its relay
    /// leg (out of band — copy/paste or QR).
    pub fn connection_id(&self) -> String {
        self.connection_id.clone()
    }

    /// The paths this session knows about right now.
    pub fn path_status(&self) -> PathStatus {
        self.paths.lock().expect("path mutex poisoned").status()
    }

    /// Switch between the relay path and a validated direct path.
    ///
    /// Returns whether a switch was requested — `false` when there is nothing to
    /// switch to, which is the normal state until a direct path is validated and
    /// the permanent state where none can be.
    ///
    /// The request is asynchronous: the switch has taken effect when
    /// [`FrameSink::on_path`] reports it, not when this returns. If the new path
    /// turns out to carry nothing, the session falls back to the relay on its
    /// own after a few seconds.
    pub fn migrate(&self) -> bool {
        let target = self
            .paths
            .lock()
            .expect("path mutex poisoned")
            .migration_target();
        match target {
            Some(path) => self.migrate.try_send(path).is_ok(),
            None => false,
        }
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

    // One registration for the relay leg and the video connection: the direct
    // path is opened from the leg's binding, and msquic looks bindings up per
    // registration.
    let registration = new_registration().map_err(|e| ClientError::Runtime(format!("{e:#}")))?;

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
    // The leg goes on a shared, unconnected socket so a direct path can be
    // opened from its binding, and reports the address to offer as a candidate.
    let session = runtime
        .block_on(InitiatorSession::connect_with_options(
            &cfg,
            &config.capability,
            &config.listener_id,
            &[],
            local_bind,
            RelayOptions {
                unconnected: true,
                registration: Some(Arc::clone(&registration)),
            },
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

    // Frame channel: the receiver produces (seq, jpeg); we bridge to `sink`.
    let (frame_tx, mut frame_rx) = mpsc::channel::<(u64, Bytes)>(16);
    let (path_tx, mut path_rx) = mpsc::channel::<PathEvent>(16);
    let (rtt_tx, mut rtt_rx) = mpsc::channel::<f64>(16);
    let (migrate_tx, migrate_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(4);
    let paths = Arc::new(Mutex::new(Paths::default()));
    let observed = session.observed_address();

    // Receiver: dials the video QUIC over the relay and delivers frames.
    let recv_shutdown = shutdown.clone();
    let recv_sink = Arc::clone(&sink);
    let recv_registration = Arc::clone(&registration);
    runtime.spawn(async move {
        if let Err(e) = receive_frames_with(
            &video_host,
            video_port,
            frame_tx,
            recv_shutdown,
            VideoRecvOptions {
                registration: Some(recv_registration),
                verify,
                observed: Some(observed),
                path_events: Some(path_tx),
                migrate: Some(migrate_rx),
                rtt: Some(rtt_tx),
            },
        )
        .await
        {
            recv_sink.on_state(ConnectionState::Failed, format!("{e:#}"));
        }
    });

    // Paths: keep the session's view in step with what the connection reports,
    // and tell Swift each time it changes.
    let path_paths = Arc::clone(&paths);
    let path_sink = Arc::clone(&sink);
    runtime.spawn(async move {
        while let Some(event) = path_rx.recv().await {
            let status = {
                let mut paths = path_paths.lock().expect("path mutex poisoned");
                paths.apply(event);
                paths.status()
            };
            path_sink.on_path(status);
        }
    });

    // RTT samples, for whatever the app wants to show.
    let rtt_sink = Arc::clone(&sink);
    runtime.spawn(async move {
        while let Some(rtt_ms) = rtt_rx.recv().await {
            rtt_sink.on_rtt(rtt_ms);
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
        paths,
        migrate: migrate_tx,
        registration,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 10], port))
    }

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// Nothing to offer until both paths are known, so the button stays inert
    /// rather than sending a request that cannot go anywhere.
    #[test]
    fn cannot_migrate_before_a_direct_path_exists() {
        let mut paths = Paths::default();
        assert!(!paths.status().can_migrate);

        paths.apply(PathEvent::Relay {
            local: loopback(1),
            remote: loopback(2),
        });
        let status = paths.status();
        assert!(status.on_relay);
        assert!(!status.can_migrate, "only the relay is known");
        assert_eq!(paths.migration_target(), None);
    }

    /// Once a direct path is validated, migrating means leaving the relay — and
    /// once on it, migrating means going back.
    #[test]
    fn migration_target_flips_with_the_active_path() {
        let mut paths = Paths::default();
        paths.apply(PathEvent::Relay {
            local: loopback(1),
            remote: loopback(2),
        });
        paths.apply(PathEvent::DirectValidated {
            local: addr(3),
            remote: addr(4),
        });
        assert!(paths.status().can_migrate);
        assert_eq!(paths.migration_target(), Some((addr(3), addr(4))));

        paths.apply(PathEvent::Activated {
            local: addr(3),
            remote: addr(4),
        });
        assert!(!paths.status().on_relay);
        assert_eq!(paths.migration_target(), Some((loopback(1), loopback(2))));
    }

    /// `on_relay` follows what was actually activated, not what was asked for,
    /// so the automatic fallback to the relay is reflected without the app
    /// having to ask.
    #[test]
    fn falling_back_to_the_relay_is_reported_as_such() {
        let mut paths = Paths::default();
        paths.apply(PathEvent::Relay {
            local: loopback(1),
            remote: loopback(2),
        });
        paths.apply(PathEvent::DirectValidated {
            local: addr(3),
            remote: addr(4),
        });
        paths.apply(PathEvent::Activated {
            local: addr(3),
            remote: addr(4),
        });
        assert!(!paths.status().on_relay);

        paths.apply(PathEvent::Activated {
            local: loopback(1),
            remote: loopback(2),
        });
        assert!(paths.status().on_relay, "the fallback put us back on the relay");
    }
}
