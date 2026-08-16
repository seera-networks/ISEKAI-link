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
    /// The camera answered as an Endpoint other than the one it was paired as.
    ///
    /// Apart from [`Self::Connect`] because it is not a transient failure and
    /// retrying it is wrong: it says the introduction changed, and it will say
    /// so again every time until the pairing is redone.
    #[error("{0}")]
    WrongPeer(String),
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
    /// Empty connects on a standing grant, which is what pairing creates.
    /// Filled in, the capability is carried and used instead.
    pub capability: String,
    /// The camera to reach, from [`list_cameras`] or typed in by hand.
    pub listener_id: String,
    /// The Endpoint that camera is expected to be, from [`list_cameras`].
    ///
    /// Checked against the Endpoint the proxy answers with, but only when this
    /// device paired with it — see [`camera_core::paired`]. Empty for a camera
    /// reached by a hand-carried capability, which brings no pairing to check
    /// against.
    pub expected_endpoint: String,
    /// Register the Endpoint with the Identity API before issuing a token.
    pub register: bool,
    /// **Dev only** — accept self-signed proxy/Identity certificates. Never true
    /// in production; leave the proxy's real certificate validation on.
    pub insecure_skip_verify: bool,
    /// Offer a direct path and allow migrating off the relay.
    ///
    /// Turning this off makes the session relay-only: the leg goes on an
    /// ordinary connected socket, no candidate is offered, and
    /// [`ViewerSession::migrate`] has nothing to do. Useful when a network
    /// cannot support a direct path, and as a way to tell a migration problem
    /// apart from a relay one.
    pub enable_migration: bool,
    /// Log filter for the Rust core, in `RUST_LOG` syntax — e.g.
    /// `camera_core=debug,isekai_p2p_core=debug`. Empty disables logging.
    ///
    /// This crate's own records are added at `info` unless the filter names it,
    /// because what says whether the pairing check ran and whether the key was
    /// pinned comes from here — see [`with_own_records`].
    ///
    /// Records go to [`FrameSink::on_log`]. A phone has no console to read
    /// `RUST_LOG` on, so this is the only way to see what the core is doing.
    pub log_filter: String,
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
/// Both are live once both are here. A path that is not carrying the video is
/// still open and still kept warm, so `on_relay` says where the traffic is, not
/// which path exists.
///
/// `direct` stays `None` where no direct path can be established — a symmetric
/// NAT, say. That is not a failure: the stream runs over the relay and
/// [`ViewerSession::migrate`] simply has nothing else to choose.
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
    /// One formatted log line from the Rust core.
    ///
    /// Only called when [`ClientConfig::log_filter`] is non-empty. Arrives on
    /// core threads and can be frequent — buffer it, do not block.
    fn on_log(&self, line: String);
}

/// The privacy policy this build carries, for the screen shown before anything
/// else.
///
/// Comes from the core rather than a copy in the app bundle so the three
/// applications cannot end up asking agreement to three slightly different
/// documents.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PrivacyPolicy {
    /// What was agreed to. Store it with the answer: agreement to one text is
    /// not agreement to the next, and comparing this is how a revised policy
    /// gets asked again.
    pub version: String,
    /// The canonical, always-current copy of each rendering. The text below is
    /// what is shown and what works with no network; these stay current, and
    /// are per language so the link matches what is on screen.
    pub url_ja: String,
    pub url_en: String,
    pub text_ja: String,
    pub text_en: String,
}

/// The policy to show, and the version to record alongside the answer.
#[uniffi::export]
pub fn privacy_policy() -> PrivacyPolicy {
    PrivacyPolicy {
        version: camera_core::privacy::VERSION.to_owned(),
        url_ja: camera_core::privacy::URL_JA.to_owned(),
        url_en: camera_core::privacy::URL_EN.to_owned(),
        text_ja: camera_core::privacy::TEXT_JA.to_owned(),
        text_en: camera_core::privacy::TEXT_EN.to_owned(),
    }
}

/// How long a connection this app is not watching survives, in seconds.
///
/// For the one question a suspended app can answer about a connection it could
/// not observe: it knows how long it was away, and longer than this means the
/// connection is gone whatever handle is still held. Read from `camera-core`
/// rather than written down again on the Swift side — the same number in two
/// places is the same number until somebody moves one of them.
#[uniffi::export]
pub fn video_idle_timeout_seconds() -> u32 {
    camera_core::VIDEO_IDLE_TIMEOUT.as_secs() as u32
}

/// Where the core gets a *current* Auth0 access token.
///
/// The one handed to [`connect`] is a snapshot, and it stops working after a few
/// hours. That matters because the Endpoint Token behind every proxy call lasts
/// minutes and is reissued for the life of the session — and the Identity API
/// requires Auth0 authentication state on each issue, not just the first. Once
/// the snapshot lapses, renewal stops, and with it the ability to open anything
/// new on the connection.
///
/// So a session that outlives one access token has to be able to ask for
/// another. Swift already knows how — `AuthStore` refreshes against Auth0 — and
/// this is where the core asks.
#[uniffi::export(callback_interface)]
pub trait Auth0TokenProvider: Send + Sync {
    /// The access token to use right now.
    ///
    /// Called every few minutes for the life of the session, from a core worker
    /// thread. **Return what is cached and refresh in the background** rather
    /// than blocking here on the network. A token that is briefly stale costs
    /// one failed renewal, retried within the minute, while the video keeps
    /// flowing — whereas a blocked worker stalls the session itself.
    ///
    /// Return the last token known when there is nothing better; an empty
    /// string is treated as "no token" and reported as a failed renewal.
    fn current_token(&self) -> String;
}

/// Adapts the Swift callback to the core's token source.
struct SwiftAuth0Tokens(Box<dyn Auth0TokenProvider>);

impl camera_core::Auth0TokenSource for SwiftAuth0Tokens {
    fn auth0_token(
        &self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = anyhow::Result<String>> + Send + '_>>
    {
        let token = self.0.current_token();
        Box::pin(async move {
            if token.is_empty() {
                // Expected once per access-token expiry: the app withholds a
                // token it knows is spent and refreshes behind this call, so
                // the retry a few seconds later gets the new one. Worth saying
                // plainly, because the alternative — handing over the expired
                // token — turns this into an opaque 401 from the Identity API.
                anyhow::bail!(
                    "the app is refreshing its Auth0 token; the next renewal will use it"
                );
            }
            Ok(token)
        })
    }
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

    /// Choose which of the known paths carries the video: the relay one, or a
    /// validated direct one.
    ///
    /// Nothing is torn down. Both paths stay open, validated and kept warm by a
    /// per-path keepalive, and this only declares which one traffic goes on — so
    /// coming back is the same call again and costs nothing. That is what stops
    /// a direct path decaying while it waits to be used, which is the failure
    /// this replaced (`docs/p2p_mode_migration_plan.md` risk #24).
    ///
    /// Returns whether a change was requested — `false` when there is no other
    /// path to choose, which is the normal state until a direct path is
    /// validated and the permanent state where none can be.
    ///
    /// The request is asynchronous: it has taken effect when
    /// [`FrameSink::on_path`] reports it, not when this returns. If the chosen
    /// path turns out to carry nothing, the session goes back to the relay on
    /// its own after a few seconds.
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
        // Stop logging into a sink whose session is gone.
        *LOG_SINK.lock().expect("log sink mutex poisoned") = None;
    }
}

impl Drop for ViewerSession {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// The sink the tracing bridge currently writes to.
///
/// A global because `tracing`'s subscriber is process-wide and can only be
/// installed once, while sinks come and go with sessions. Cleared on
/// disconnect so a dead session stops receiving.
static LOG_SINK: Mutex<Option<Arc<dyn FrameSink>>> = Mutex::new(None);
/// Guards the one-time subscriber installation.
static LOG_INIT: std::sync::Once = std::sync::Once::new();
/// Applies a new filter to the installed subscriber.
///
/// A subscriber can only be installed once per process, but the filter is the
/// setting being adjusted — narrowing it down is how a field problem gets found,
/// and on a phone the only way to try another one is to reconnect. Without this
/// every filter after the first would be silently ignored, which is worse than
/// not offering the setting at all.
#[allow(clippy::type_complexity)]
static LOG_FILTER: Mutex<Option<Box<dyn Fn(&str) + Send>>> = Mutex::new(None);

/// Writes formatted log lines to whichever sink is current.
struct SinkWriter;

impl std::io::Write for SinkWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(sink) = LOG_SINK.lock().expect("log sink mutex poisoned").clone() {
            sink.on_log(String::from_utf8_lossy(buf).trim_end().to_owned());
        }
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for SinkWriter {
    type Writer = SinkWriter;
    fn make_writer(&'a self) -> Self::Writer {
        SinkWriter
    }
}

/// This crate's own records, added to a filter that does not mention it.
///
/// What says whether the pairing check ran and whether the peer's key was
/// pinned is emitted from here, while the equivalent on the desktop comes from
/// `camera_client` — so a filter carried over from there, or the example in
/// [`ClientConfig::log_filter`], leaves exactly the two lines worth reading
/// invisible, and a connection with no protection looks like one with it.
///
/// A filter that names this crate is left alone: someone who asked for
/// `isekai_client_ffi=warn` meant it.
fn with_own_records(filter: &str) -> String {
    if filter.contains("isekai_client_ffi") {
        return filter.to_owned();
    }
    format!("{filter},isekai_client_ffi=info")
}

/// Point the core's logging at `sink`, installing the subscriber on first use.
///
/// The filter cannot be changed afterwards — `tracing` allows one global
/// subscriber per process — so the first session's `log_filter` is the one that
/// applies for the life of the app.
fn install_logging(filter: &str, sink: &Arc<dyn FrameSink>) {
    if filter.is_empty() {
        return;
    }
    let filter = &with_own_records(filter);
    *LOG_SINK.lock().expect("log sink mutex poisoned") = Some(Arc::clone(sink));
    LOG_INIT.call_once(|| {
        use tracing_subscriber::layer::SubscriberExt as _;
        use tracing_subscriber::util::SubscriberInitExt as _;

        let (layer, handle) =
            tracing_subscriber::reload::Layer::new(tracing_subscriber::EnvFilter::new(filter));
        let installed = tracing_subscriber::registry()
            .with(layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(SinkWriter)
                    .with_ansi(false),
            )
            .try_init();
        match installed {
            Ok(()) => {
                *LOG_FILTER.lock().expect("log filter mutex poisoned") =
                    Some(Box::new(move |filter: &str| {
                        let _ = handle.reload(tracing_subscriber::EnvFilter::new(filter));
                    }));
            }
            // Something else already installed one; logging simply goes there.
            Err(e) => sink.on_log(format!("could not install the log bridge: {e}")),
        }
    });
    // Runs on every connect, so a filter changed in the app takes effect on the
    // next one rather than needing the app restarted. Through the same addition,
    // or editing the field would be a way to switch those records back off.
    if let Some(reload) = LOG_FILTER
        .lock()
        .expect("log filter mutex poisoned")
        .as_ref()
    {
        reload(filter);
    }
}

/// A camera this Endpoint may connect to (spec §8.10).
///
/// One row per camera, not per listener: a grant is against the Endpoint, so
/// the proxy answers with every listener that Endpoint is running, and a camera
/// that crashed without withdrawing its old one runs two — only one of which
/// connects. See [`camera_core::one_per_camera`].
#[derive(Debug, Clone, uniffi::Record)]
pub struct Camera {
    /// What to hand to [`connect`] as `listener_id`.
    pub listener_id: String,
    /// The device itself. Unlike `listener_id` this survives its restarting, so
    /// it is what a saved selection should be keyed on.
    pub owner_endpoint: String,
    /// The name its owner gave it, or the listener id when it has none.
    pub label: String,
}

impl From<camera_core::ReachableListener> for Camera {
    fn from(l: camera_core::ReachableListener) -> Self {
        let label = camera_core::display_name(&l)
            .unwrap_or(&l.listener_id)
            .to_owned();
        Self {
            listener_id: l.listener_id,
            owner_endpoint: l.owner_endpoint,
            label,
        }
    }
}

/// What one pairing produced.
///
/// The list comes back with it because the caller needs it either way, and
/// asking for it separately would mean a second Endpoint Token and a second
/// QUIC connection to the proxy for one action.
#[derive(Debug, Clone, uniffi::Record)]
pub struct Paired {
    /// The camera to select — `None` when its owner is not running a listener
    /// at the moment. **That is a success, not a failure**: the code has been
    /// spent and the grant stands, so the camera appears and connects as soon
    /// as it is running again (spec §8.9.1).
    pub camera: Option<Camera>,
    /// The Endpoint the grant is against. Known whether or not it is listening.
    pub owner_endpoint: String,
    /// Everything reachable as of the pairing, this one included.
    pub cameras: Vec<Camera>,
    /// Why the Endpoint could not be written down, when it could not be.
    ///
    /// Pairing still succeeded — the grant stands — but every later connection
    /// to this camera will report itself unchecked, so the reason has to reach
    /// somebody. It cannot do that through the log: [`install_logging`] runs on
    /// connect, so at pairing time there may be no subscriber at all, and on a
    /// phone there is no console behind it either.
    pub not_remembered: Option<String>,
}

/// Turn on dev-only certificate acceptance, at most once in a process.
///
/// `std::env::set_var` is unsafe because another thread reading the environment
/// while it is written is undefined behaviour, and by the time a session is
/// streaming there are threads doing exactly that. Writing once removes the
/// repeat; what it cannot do is order that write against a session that already
/// exists, so the flag takes effect from the first call that asks for it and
/// turning it off afterwards needs a restart. It is a development switch and
/// production never sets it.
fn apply_insecure_skip_verify(enabled: bool) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    if enabled {
        ONCE.call_once(|| {
            // SAFETY: runs at most once per process, and no earlier than the
            // first call that asks for it.
            unsafe { std::env::set_var("ISEKAI_INSECURE_SKIP_VERIFY", "1") };
        });
    }
}

/// The control-plane settings shared by the calls that do not stream.
fn directory_config(
    config: &ClientConfig,
    endpoint_key_pem: &str,
) -> Result<P2pConfig, ClientError> {
    apply_insecure_skip_verify(config.insecure_skip_verify);
    Ok(P2pConfig {
        identity_url: config.identity_url.clone(),
        identity_http3: false,
        proxy_url: config.proxy_url.clone(),
        auth0_token: String::new(),
        protocol: config.protocol.clone(),
        register: config.register,
        device_name: Some("ios-camera-client".to_owned()),
        token_ttl: None,
        auth0: None,
        key: EndpointKey::from_pkcs8_pem(endpoint_key_pem)
            .map_err(|e| ClientError::InvalidKey(e.to_string()))?,
    })
}

/// Run one control-plane call on a runtime of its own.
///
/// These are one-shot and infrequent — a list, a pairing — so they do not
/// justify keeping a runtime alive between them, and building one here keeps
/// them independent of whether a session is running.
fn on_a_runtime<T>(
    f: impl std::future::Future<Output = Result<T, ClientError>>,
) -> Result<T, ClientError> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(|e| ClientError::Runtime(e.to_string()))?
        .block_on(f)
}

/// The cameras this Endpoint may connect to.
///
/// What replaces reading a Listener ID off the camera's screen. Empty is a
/// normal answer: it means nothing has been paired with yet, not that anything
/// failed.
#[uniffi::export]
pub fn list_cameras(
    config: ClientConfig,
    endpoint_key_pem: String,
    auth0_token: String,
) -> Result<Vec<Camera>, ClientError> {
    let mut cfg = directory_config(&config, &endpoint_key_pem)?;
    cfg.auth0_token = auth0_token;
    on_a_runtime(async move {
        let directory = camera_core::PeerDirectory::open(&cfg)
            .await
            .map_err(|e| ClientError::Connect(format!("{e:#}")))?;
        let found = directory
            .reachable()
            .await
            .map_err(|e| ClientError::Connect(format!("{e:#}")))?;
        Ok(camera_core::one_per_camera(found)
            .into_iter()
            .map(Camera::from)
            .collect())
    })
}

/// Redeem a pairing code the camera displayed, and answer with the camera it
/// let this Endpoint in to (spec §8.9.2).
///
/// `code` may be what was read off the screen or what a QR scan produced — the
/// scanned value is a `isekai://pair?code=...` URI and both are accepted, so a
/// scanner's output can be handed straight here.
///
/// The camera does not have to be running. A code grants access to the Endpoint
/// behind it, so pairing with one that has just been switched off works, and
/// connecting succeeds when it comes back — which is why a camera that is not
/// listening comes back as [`Paired::camera`] being `None` rather than as an
/// error. Reporting it as a failure would invite the caller to try the code
/// again, and a code works once.
#[uniffi::export]
pub fn pair_with_code(
    config: ClientConfig,
    endpoint_key_pem: String,
    auth0_token: String,
    code: String,
    label: String,
) -> Result<Paired, ClientError> {
    let mut cfg = directory_config(&config, &endpoint_key_pem)?;
    cfg.auth0_token = auth0_token;
    let code = camera_core::pairing_code_from_input(&code);
    if code.is_empty() {
        return Err(ClientError::InvalidArgument("no pairing code".to_owned()));
    }
    let label = (!label.trim().is_empty()).then_some(label);
    on_a_runtime(async move {
        let directory = camera_core::PeerDirectory::open(&cfg)
            .await
            .map_err(|e| ClientError::Connect(format!("{e:#}")))?;
        let grant = directory
            .pair(&code, label.as_deref())
            .await
            .map_err(|e| ClientError::Connect(format!("{e:#}")))?;
        // Pairing is the one moment an Endpoint ID arrives from outside the
        // proxy — it was read off the camera and typed in here. Remembered now
        // because there is no later chance to learn it the same way.
        //
        // A device that cannot write the list still pairs: refusing would turn
        // a check that was not there yesterday into a reason pairing fails.
        let not_remembered = camera_core::paired::remember(&grant.owner_endpoint)
            .err()
            .map(|e| {
                tracing::warn!(
                    "paired, but could not remember which Endpoint: {e:#}; later \
                     connections to this camera cannot be checked against it",
                );
                format!("{e:#}")
            });
        // The grant names the Endpoint, not a listener, so the camera to offer
        // comes from reading the list back — which is also where its name is,
        // and which the caller wants anyway.
        let found = directory
            .reachable()
            .await
            .map_err(|e| ClientError::Connect(format!("{e:#}")))?;
        let cameras: Vec<Camera> = camera_core::one_per_camera(found)
            .into_iter()
            .map(Camera::from)
            .collect();
        Ok(Paired {
            camera: cameras
                .iter()
                .find(|c| c.owner_endpoint == grant.owner_endpoint)
                .cloned(),
            owner_endpoint: grant.owner_endpoint,
            cameras,
            not_remembered,
        })
    })
}

/// The pairing code in a scanned QR, or `None` when it is not one of ours.
///
/// A camera pointed at the world reads posters, wifi codes and links. Handing
/// any of that to [`pair_with_code`] would spend a request to be told it is not
/// a code, so a scanner should ask here first and keep looking when the answer
/// is `None`. What counts is the `isekai://pair?code=...` a camera puts in its
/// own QR, and the prefix is defined once, in the core.
///
/// A code someone read off the screen and typed goes straight to
/// [`pair_with_code`], which takes bare codes as well.
#[uniffi::export]
pub fn pairing_code_in_scan(scanned: String) -> Option<String> {
    camera_core::pairing_code_in_uri(&scanned).map(str::to_owned)
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
///
/// `auth0_provider` is what keeps the session alive past that token's few hours —
/// see [`Auth0TokenProvider`]. Passing `None` keeps the old behaviour, where the
/// session works until the snapshot expires and then cannot renew.
#[uniffi::export]
pub fn connect(
    config: ClientConfig,
    endpoint_key_pem: String,
    auth0_token: String,
    auth0_provider: Option<Box<dyn Auth0TokenProvider>>,
    sink: Box<dyn FrameSink>,
) -> Result<Arc<ViewerSession>, ClientError> {
    let sink: Arc<dyn FrameSink> = Arc::from(sink);
    install_logging(&config.log_filter, &sink);

    // Dev-only self-signed acceptance is read from this env var by the transport
    // layer. Production leaves it unset so real certificates are validated.
    apply_insecure_skip_verify(config.insecure_skip_verify);

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
        // What makes the session survive its own access token: every Endpoint
        // Token renewal asks the app for a current one.
        auth0: auth0_provider
            .map(|t| Arc::new(SwiftAuth0Tokens(t)) as Arc<dyn camera_core::Auth0TokenSource>),
        key,
    };

    let local_bind = "127.0.0.1:0"
        .parse()
        .map_err(|e: std::net::AddrParseError| ClientError::InvalidArgument(e.to_string()))?;

    // Establish the control plane + initiator relay leg (fast); this returns
    // before video flows.
    // The leg goes on a shared, unconnected socket so a direct path can be
    // opened from its binding, and reports the address to offer as a candidate.
    //
    // `unconnected` and the candidate below are a pair: the candidate names this
    // leg's binding, so without the shared, unconnected socket there is nothing
    // for a direct path to be opened from. They are switched together.
    let relay_options = RelayOptions {
        unconnected: config.enable_migration,
        registration: Some(Arc::clone(&registration)),
    };
    // An empty capability means there is nothing to present, which is the point
    // of a grant: the proxy already holds the authorization, so only the
    // camera's listener id is needed. A filled one still uses the capability,
    // so the hand-carried flow is unchanged.
    let session = runtime
        .block_on(async {
            if camera_core::connects_on_grant(&config.capability) {
                InitiatorSession::connect_with_grant(
                    &cfg,
                    &config.listener_id,
                    &[],
                    local_bind,
                    relay_options,
                )
                .await
            } else {
                InitiatorSession::connect_with_options(
                    &cfg,
                    &config.capability,
                    &config.listener_id,
                    &[],
                    local_bind,
                    relay_options,
                )
                .await
            }
        })
        .map_err(|e| ClientError::Connect(format!("{e:#}")))?;

    // Who answered, against who was meant. The pin below proves the peer holds
    // the key its Endpoint signed for; this is what says that Endpoint is the
    // camera the user paired with, and the proxy names both.
    match camera_core::paired::check(
        &config.expected_endpoint,
        session.connection.peer_endpoint.as_deref(),
    ) {
        // Said either way. A connection that was held against a pairing and one
        // that had nothing to be held against both go on to stream, and only
        // one of them is protected.
        Ok(outcome @ camera_core::paired::Checked::AgainstPairing) => {
            tracing::info!(peer = %config.expected_endpoint, "{outcome}")
        }
        Ok(outcome) => tracing::info!("{outcome}"),
        Err(e) => {
            // Tell the proxy the connection is over before returning. The task
            // that owns the only other `close` is not spawned yet, and dropping
            // the session does not close it — so the camera would go on holding
            // a relay
            // leg for a viewer that has already refused it, on every retry.
            runtime.block_on(session.close());
            return Err(ClientError::WrongPeer(e.to_string()));
        }
    }

    let connection_id = session.connection_id().to_owned();
    let video_port = session.local_addr.port();
    // Dial the per-endpoint relay FQDN with validation when the proxy issued a
    // relay certificate; otherwise fall back to 127.0.0.1 unvalidated (dev).
    // Said either way. "Pinned" and "nothing to pin" look identical from
    // outside, and only one of them is protected.
    let pin = match camera_core::AttestedPeer::from_connection(&session.connection) {
        Ok(pin) => {
            tracing::info!(
                peer = %pin.peer_endpoint,
                "the peer signed for its video key; the handshake has to present it",
            );
            Some(pin)
        }
        Err(why) => {
            tracing::info!("{why}");
            None
        }
    };
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
    let observed = config.enable_migration.then(|| session.observed_address());

    // Receiver: dials the video QUIC over the relay and delivers frames.
    let recv_shutdown = shutdown.clone();
    let recv_sink = Arc::clone(&sink);
    let recv_registration = Arc::clone(&registration);
    // Watched alongside the receive rather than left to the leg being torn
    // down: a session on a direct path is not carried by the leg, and one that
    // is would go quiet and time out half a minute later without ever saying
    // why.
    let ended = session.ended();
    let recv_shutdown_on_end = shutdown.clone();
    runtime.spawn(async move {
        tokio::select! {
            received = receive_frames_with(
                &video_host,
                video_port,
                frame_tx,
                recv_shutdown,
                VideoRecvOptions {
                    registration: Some(recv_registration),
                    verify,
                    pin,
                    observed,
                    path_events: Some(path_tx),
                    migrate: Some(migrate_rx),
                    rtt: Some(rtt_tx),
                },
            ) => {
                if let Err(e) = received {
                    recv_sink.on_state(ConnectionState::Failed, format!("{e:#}"));
                }
            }
            () = ended.cancelled() => {
                recv_sink.on_state(
                    ConnectionState::Failed,
                    "the proxy no longer allows this endpoint on the connection; \
                     the session has ended"
                        .to_owned(),
                );
                // Nothing else stops the session: the task holding it waits on
                // this token, so without the cancel it keeps a dead session,
                // its runtime and the msquic registration alive for as long as
                // the app runs.
                recv_shutdown_on_end.cancel();
            }
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

    /// The example filter in the field's own documentation hides this crate,
    /// which is where the pairing check and the pin report themselves.
    #[test]
    fn a_filter_that_does_not_mention_this_crate_gains_its_records() {
        assert_eq!(
            with_own_records("camera_core=debug,isekai_p2p_core=debug"),
            "camera_core=debug,isekai_p2p_core=debug,isekai_client_ffi=info",
        );
    }

    /// Someone who asked for less than `info` from here meant it.
    #[test]
    fn a_filter_that_mentions_this_crate_is_left_alone() {
        assert_eq!(
            with_own_records("isekai_client_ffi=warn"),
            "isekai_client_ffi=warn",
        );
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
        assert!(
            paths.status().on_relay,
            "the fallback put us back on the relay"
        );
    }
}
