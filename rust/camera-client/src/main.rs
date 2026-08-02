use bytes::Bytes;
use camera_core::{P2pConfig, PathEvent, RelayOptions, VideoRecvOptions};
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use msquic_async::msquic;
use opencv::{core::AlgorithmHint, imgcodecs, prelude::*};
use std::{
    collections::VecDeque,
    future::poll_fn,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::sync::CancellationToken;

fn make_msquic_async_client_config(
    registration: Option<Arc<msquic_async::Registration>>,
    alpn: &str,
    disable_verification: bool,
    enable_natt: bool,
) -> anyhow::Result<(Arc<msquic_async::Registration>, Arc<msquic::Configuration>)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = [msquic::BufferRef::from(alpn)];
    // Accept observed-address reports so the peer tells us our public address,
    // which we feed to `add_candidate_addr` to enable path migration.
    let settings = msquic::Settings::new()
        .set_IdleTimeoutMs(30_000)
        .set_DestCidUpdateIdleTimeoutMs(0)
        .set_PeerBidiStreamCount(100)
        .set_PeerUnidiStreamCount(100)
        .set_DatagramReceiveEnabled()
        .set_StreamMultiReceiveEnabled()
        .set_ReceiveObservedAddressReports();
    // NAT-traversal mode advertises candidate addresses so the connection can
    // probe and migrate to a direct path.
    let settings = if enable_natt {
        settings.set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
    } else {
        settings
    };
    let configuration = registration.open_configuration(&alpn, Some(&settings))?;

    let cred_config = msquic::CredentialConfig::new_client();
    let cred_config = if disable_verification {
        cred_config.set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION)
    } else {
        cred_config
    };
    configuration.load_credential(&cred_config)?;
    Ok((registration, Arc::new(configuration)))
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let reg = camera_core::new_registration().expect("open the msquic registration");

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 1000.0]),
        ..Default::default()
    };
    let res = eframe::run_native(
        "Camera Client App",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new(Arc::clone(&reg))))),
    );

    // `run_native` has returned, so the app — and with it every connection it
    // was running — is dropped. Give msquic a moment to close what those tasks
    // held, then leave without running destructors: returning would drop the
    // registration, and `RegistrationClose` blocks on anything still open.
    if let Err(e) = &res {
        tracing::error!("camera client exited with an error: {e}");
    }
    camera_core::shutdown_and_exit(&reg, MSQUIC_DRAIN_TIMEOUT, i32::from(res.is_err())).await
}

/// How long to wait for msquic handles to close before leaving anyway.
const MSQUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Draw the rolling RTT history as a line plot (values in milliseconds).
fn show_rtt_plot(ui: &mut egui::Ui, rtt_history: &VecDeque<f64>) {
    let points: PlotPoints<'_> = rtt_history
        .iter()
        .enumerate()
        .map(|(i, rtt)| [i as f64, *rtt])
        .collect();

    let line = Line::new("RTT", points);

    Plot::new("rtt_plot").height(200.0).show(ui, |plot_ui| {
        plot_ui.line(line);
    });
}

/// How the client reaches the server.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    /// Legacy: dial the server's public address directly.
    Direct,
    /// P2P Connect: reach the server over the MASQUE relay.
    P2p,
}

/// One row per camera, not per listener.
///
/// A grant is against the Endpoint, so the proxy answers with every listener
/// that Endpoint is running — and a camera that crashed without withdrawing its
/// listener runs two until the old lease ends, one of which cannot be connected
/// to. The operator has one camera and should be offered one entry; the live
/// one is the listener with the later deadline, since both were leased for the
/// same span and the survivor was leased later.
fn one_per_camera(
    mut listeners: Vec<camera_core::ReachableListener>,
) -> Vec<camera_core::ReachableListener> {
    // Latest deadline first, so the first row seen for an owner is the keeper.
    listeners.sort_by(|a, b| {
        b.expires_at
            .cmp(&a.expires_at)
            .then_with(|| a.listener_id.cmp(&b.listener_id))
    });
    let mut seen = std::collections::HashSet::new();
    listeners.retain(|l| seen.insert(l.owner_endpoint.clone()));
    listeners
}

/// What to call a camera on screen: the name its owner gave it, falling back to
/// the listener id, which is at least unambiguous.
fn display_name(camera: &camera_core::ReachableListener) -> Option<&str> {
    camera
        .metadata
        .as_ref()
        .and_then(|m| m.get("label"))
        .and_then(|l| l.as_str())
}

/// The proxy control plane, kept open between the actions that use it.
///
/// [`PeerDirectory::open`](camera_core::PeerDirectory::open) issues an Endpoint
/// Token from the Identity API and opens a QUIC connection to the proxy. Doing
/// that per button press means a token and a connection per press, and the
/// connect that follows a listing would make a second one — which is what the
/// directory exists to avoid. One is kept here and handed to whichever of
/// listing, pairing and connecting runs next.
struct ControlPlane {
    directory: camera_core::PeerDirectory,
    /// When to stop using it. Short of the token's real expiry, so a call does
    /// not start on a token that runs out partway through.
    good_until: Instant,
}

/// How far ahead of a token's expiry to replace it.
const TOKEN_MARGIN: Duration = Duration::from_secs(30);

/// The open control plane, opening one first if there is none or the token it
/// holds is nearly out.
async fn control_plane<'a>(
    slot: &'a mut Option<ControlPlane>,
    cfg: &P2pConfig,
) -> anyhow::Result<&'a camera_core::PeerDirectory> {
    if slot
        .as_ref()
        .is_none_or(|held| held.good_until <= Instant::now())
    {
        let token = camera_core::issue_endpoint_token(cfg).await?;
        let life = Duration::from_secs(token.expires_in.max(0) as u64);
        *slot = Some(ControlPlane {
            directory: camera_core::PeerDirectory::open_with_token(cfg, &token.endpoint_token)?,
            good_until: Instant::now() + life.saturating_sub(TOKEN_MARGIN),
        });
    }
    Ok(&slot.as_ref().expect("just filled").directory)
}

/// Shared runtime state of a P2P connection, updated by the async task and read
/// by the UI.
#[derive(Default)]
struct P2pShared {
    status: String,
    connection_id: Option<String>,
}

struct MyApp {
    /// One registration for every connection this app makes. msquic looks
    /// bindings up per registration, so the video connection and the relay leg
    /// have to share one for a direct path to be openable at all.
    reg: Arc<msquic_async::Registration>,
    mode: Mode,
    // Direct 接続設定
    server_addr: String,
    server_port: String,

    // P2P 接続設定
    identity_url: String,
    proxy_url: String,
    auth0_token: String,
    key_path: String,
    protocol: String,
    register: bool,
    capability: String,
    listener_id: String,
    /// Cameras this Endpoint may connect to, or `None` before the proxy has
    /// been asked. "no cameras" and "not asked yet" have to look different on
    /// screen: someone who paired a camera yesterday should not be shown a bare
    /// "none" and conclude it has been lost.
    cameras: Arc<Mutex<Option<Vec<camera_core::ReachableListener>>>>,
    /// Whether the automatic first listing has been asked for, so it happens
    /// once rather than every frame.
    cameras_requested: bool,
    /// A pairing code being typed or pasted in, and what the last attempt said.
    pairing_code: String,
    pairing_status: Arc<Mutex<Option<String>>>,
    /// The control plane, held open across button presses. See [`ControlPlane`].
    control_plane: Arc<tokio::sync::Mutex<Option<ControlPlane>>>,
    my_endpoint_id: Option<String>,
    p2p_shared: Arc<Mutex<P2pShared>>,

    connected: bool,
    rx: Option<mpsc::Receiver<(u64, Bytes)>>,
    conn_task: Option<tokio::task::AbortHandle>,
    shutdown: Option<CancellationToken>,
    texture: Option<egui::TextureHandle>,
    rtt_rx: Option<mpsc::Receiver<f64>>,
    rtt_history: VecDeque<f64>,

    // Path migration — both modes report through the same channel and share
    // this state, so the UI has one code path rather than one per mode.
    /// true while on the initial (relay) path, false once migrated to the
    /// direct path. Follows what the connection *reports*, not what was asked
    /// for, so a failed switch does not leave the label lying.
    is_isekai_link: bool,
    /// The path the connection started on — over Isekai Link.
    isekai_link_path: Option<(SocketAddr, SocketAddr)>,
    /// A validated direct path, once one is available.
    p2p_path: Option<(SocketAddr, SocketAddr)>,
    /// Path changes reported by the connection task.
    path_rx: Option<mpsc::Receiver<PathEvent>>,
    /// Requests the connection task migrate to the given (local, remote) path.
    migrate_tx: Option<mpsc::Sender<(SocketAddr, SocketAddr)>>,
}

impl MyApp {
    fn new(reg: Arc<msquic_async::Registration>) -> Self {
        Self {
            reg,
            mode: Mode::Direct,
            server_addr: "161.33.142.214".to_string(),
            server_port: "16205".to_string(),
            identity_url: "https://identity.isekai.tools:9443".to_string(),
            proxy_url: "https://link.isekai.tools:8443".to_string(),
            auth0_token: String::new(),
            key_path: "camera-client-endpoint.pem".to_string(),
            protocol: "isekai-validator-v1".to_string(),
            register: true,
            capability: String::new(),
            listener_id: String::new(),
            cameras: Arc::new(Mutex::new(None)),
            cameras_requested: false,
            pairing_code: String::new(),
            pairing_status: Arc::new(Mutex::new(None)),
            control_plane: Arc::new(tokio::sync::Mutex::new(None)),
            my_endpoint_id: None,
            p2p_shared: Arc::new(Mutex::new(P2pShared::default())),
            connected: false,
            rx: None,
            conn_task: None,
            shutdown: None,
            texture: None,
            rtt_rx: None,
            rtt_history: VecDeque::new(),
            is_isekai_link: true,
            isekai_link_path: None,
            p2p_path: None,
            path_rx: None,
            migrate_tx: None,
        }
    }

    fn connect(&mut self) {
        match self.mode {
            Mode::Direct => self.connect_direct(),
            Mode::P2p => self.connect_p2p(),
        }
    }

    fn connect_direct(&mut self) {
        let (tx, rx) = mpsc::channel::<(u64, Bytes)>(100);
        let (rtt_tx, rtt_rx) = mpsc::channel::<f64>(100);
        self.rtt_rx = Some(rtt_rx);
        let addr = self.server_addr.clone();
        let port: u16 = self.server_port.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "Invalid port '{}', falling back to default 15640",
                self.server_port
            );
            15640
        });

        let (migrate_tx, mut migrate_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(10);
        let (path_tx, path_rx) = mpsc::channel::<PathEvent>(16);
        let reg_direct = Arc::clone(&self.reg);
        let handle = tokio::spawn(async move {
            // Phase 1: reach the relay to discover our observed (public) address.
            let (reg, config_h3) =
                make_msquic_async_client_config(Some(reg_direct), "h3", false, false)?;
            let conn = msquic_async::Connection::new(&reg)?;
            conn.start(&config_h3, "tokyo.link.isekai.tools", 8443)
                .await
                .map_err(|e| {
                    tracing::error!("Failed to connect to tokyo.link.isekai.tools:8443: {e:?}");
                    anyhow::anyhow!("Failed to connect to tokyo.link.isekai.tools:8443: {e:?}")
                })?;
            let Ok(msquic_async::ConnectionEvent::NotifyObservedAddress {
                local_address,
                observed_address,
            }) = poll_fn(|cx| conn.poll_event(cx)).await
            else {
                anyhow::bail!("Failed to get observed address from relay");
            };
            tracing::info!("Observed address: {observed_address}");
            std::mem::drop(conn);

            // Phase 2: connect to the server with the observed address as a
            // migration candidate, so the path can later move to a direct one.
            let (reg, configuration) =
                make_msquic_async_client_config(Some(reg), "sample", true, true)?;
            let conn = msquic_async::Connection::new(&reg)?;
            conn.add_candidate_addr(local_address, observed_address)?;
            tracing::info!("Starting connection to {addr}:{port}");
            conn.start(&configuration, &addr, port).await.map_err(|e| {
                tracing::error!("Failed to start connection to {addr}:{port}: {e:?}");
                anyhow::anyhow!("Failed to start connection to {addr}:{port}: {e:?}")
            })?;
            let local_addr = conn
                .get_local_addr()
                .map_err(|e| anyhow::anyhow!("Failed to get local address: {e:?}"))?;
            let remote_addr = conn
                .get_remote_addr()
                .map_err(|e| anyhow::anyhow!("Failed to get remote address: {e:?}"))?;
            let _ = path_tx
                .send(PathEvent::Relay {
                    local: local_addr,
                    remote: remote_addr,
                })
                .await;
            let orig_path = (local_addr, remote_addr);

            // Sample RTT once a second while draining inbound frames and
            // handling migration events.
            let mut rtt_interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                tokio::select! {
                    _ = rtt_interval.tick() => {
                        match conn.get_stats() {
                            // Rtt is reported in microseconds; plot milliseconds.
                            Ok(stats) => {
                                let _ = rtt_tx.try_send(stats.Rtt as f64 / 1000.0);
                            }
                            Err(e) => {
                                tracing::error!("Failed to get connection stats: {:?}", e);
                            }
                        }
                    }
                    res = poll_fn(|cx| conn.poll_event(cx)) => {
                        match res {
                            Ok(event) => {
                                tracing::info!("Connection event: {event:?}");
                                match event {
                                    msquic_async::ConnectionEvent::PathValidated {
                                        local_address,
                                        remote_address,
                                    } => {
                                        // A newly validated path other than the
                                        // original one is the direct P2P path.
                                        if (local_address, remote_address) != orig_path {
                                            let _ = path_tx.send(PathEvent::DirectValidated {
                                                local: local_address,
                                                remote: remote_address,
                                            }).await;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                            Err(e) => {
                                tracing::error!("Connection error: {e:?}");
                                break;
                            }
                        }
                    }
                    ret = migrate_rx.recv() => {
                        if let Some((local_addr, remote_addr)) = ret {
                            tracing::info!("Migrating to path: local {local_addr}, remote {remote_addr}");
                            match conn.activate_path(local_addr, remote_addr) {
                                Ok(()) => {
                                    let _ = path_tx.send(PathEvent::Activated {
                                        local: local_addr,
                                        remote: remote_addr,
                                    }).await;
                                }
                                // Not fatal: the stream keeps running on the
                                // path it is already on.
                                Err(e) => tracing::error!("Failed to activate path: {e}"),
                            }
                        } else {
                            tracing::info!("Migration channel closed");
                            break;
                        }
                    }
                    res = conn.accept_inbound_uni_stream() => {
                        match res {
                            Ok(mut stream) => {
                                let stream_id = stream.id().unwrap();
                                tracing::debug!("Inbound stream {stream_id} accepted");
                                let mut data = Vec::new();
                                if let Err(e) = stream.read_to_end(&mut data).await {
                                    tracing::error!("Failed to read stream {stream_id}: {:?}", e);
                                    continue;
                                }
                                tracing::debug!("Inbound stream {stream_id} read {} bytes", data.len());
                                match tx.try_send((stream_id, Bytes::copy_from_slice(&data))) {
                                    Ok(_) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        tracing::debug!("Frame channel full, dropping frame {stream_id}");
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        break;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::error!("Failed to accept inbound stream: {:?}", e);
                                break;
                            }
                        }
                    }
                }
            }
            anyhow::Ok(())
        });

        self.conn_task = Some(handle.abort_handle());
        self.migrate_tx = Some(migrate_tx);
        self.path_rx = Some(path_rx);
        self.rx = Some(rx);
        self.connected = true;
    }

    /// Load (or generate) the Endpoint key and show its id, so the operator can
    /// give it to the server before it issues a capability.
    fn load_endpoint_id(&mut self) {
        match camera_core::load_or_generate_key(std::path::Path::new(&self.key_path)) {
            Ok(key) => self.my_endpoint_id = Some(key.endpoint_id()),
            Err(e) => self.p2p_shared.lock().unwrap().status = format!("key error: {e:#}"),
        }
    }

    fn connect_p2p(&mut self) {
        // Before anything is wired up, so a bad key path leaves the app in the
        // state it was already in rather than half-connected.
        let cfg = match self.p2p_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                self.p2p_shared.lock().unwrap().status = format!("key error: {e:#}");
                return;
            }
        };
        let (tx, rx) = mpsc::channel::<(u64, Bytes)>(100);
        let (rtt_tx, rtt_rx) = mpsc::channel::<f64>(100);
        let (path_tx, path_rx) = mpsc::channel::<PathEvent>(16);
        let (migrate_tx, migrate_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(10);
        self.rtt_rx = Some(rtt_rx);
        self.path_rx = Some(path_rx);
        self.migrate_tx = Some(migrate_tx);
        let reg = Arc::clone(&self.reg);
        let shutdown = CancellationToken::new();
        self.shutdown = Some(shutdown.clone());
        *self.p2p_shared.lock().unwrap() = P2pShared {
            status: "P2P: connecting...".to_string(),
            connection_id: None,
        };

        let shared = Arc::clone(&self.p2p_shared);
        let plane = Arc::clone(&self.control_plane);
        let capability = self.capability.trim().to_string();
        let listener_id = self.listener_id.trim().to_string();

        let handle = tokio::spawn(async move {
            // The relay leg goes on a shared, unconnected socket so a direct
            // path can be opened from its binding, and on the app's
            // registration so the video connection can share it.
            let local_bind = "127.0.0.1:0".parse().expect("valid loopback addr");
            let relay_options = RelayOptions {
                unconnected: true,
                registration: Some(Arc::clone(&reg)),
            };
            // An empty capability means there is nothing to present, which is
            // the point of a grant: the proxy already holds the authorization,
            // so only the listener's id is needed. Leaving the field filled
            // still uses the capability, so the old flow is unchanged.
            let connect = if capability.is_empty() {
                // Over the control plane that listed this camera, so acting on
                // the answer does not cost a second Endpoint Token and a second
                // QUIC connection to the proxy. The lock is held only for as
                // long as the connect takes to set up.
                let mut slot = plane.lock().await;
                match control_plane(&mut slot, &cfg).await {
                    Ok(dir) => {
                        dir.connect(&cfg, &listener_id, &[], local_bind, relay_options)
                            .await
                    }
                    Err(e) => Err(e),
                }
            } else {
                camera_core::InitiatorSession::connect_with_options(
                    &cfg,
                    &capability,
                    &listener_id,
                    &[],
                    local_bind,
                    relay_options,
                )
                .await
            };
            let session = match connect {
                Ok(session) => session,
                Err(e) => {
                    shared.lock().unwrap().status = format!("connect error: {e:#}");
                    return;
                }
            };
            let local_port = session.local_addr.port();
            // Dial the peer's loopback FQDN (which resolves to 127.0.0.1) so the
            // per-endpoint relay certificate can be validated. When the proxy has
            // relay certificates disabled, fall back to 127.0.0.1 unvalidated.
            let (video_host, verify) = match session.video_host() {
                Some(host) => (host.to_string(), true),
                None => ("127.0.0.1".to_string(), false),
            };
            {
                let mut s = shared.lock().unwrap();
                s.connection_id = Some(session.connection_id().to_string());
                s.status = format!(
                    "connected; give connection id to the server, then it streams: {}",
                    session.connection_id()
                );
            }

            // Receiving establishes once the server binds the relay for this
            // connection id. `receive_frames` retries the video handshake across
            // that gap (the server may bind seconds later, when a human pastes
            // the connection id), so dialing now is safe. The `session` stays
            // alive to hold the relay leg.
            if let Err(e) = camera_core::receive_frames_with(
                &video_host,
                local_port,
                tx,
                shutdown,
                VideoRecvOptions {
                    registration: Some(reg),
                    verify,
                    observed: Some(session.observed_address()),
                    path_events: Some(path_tx),
                    migrate: Some(migrate_rx),
                    rtt: Some(rtt_tx),
                },
            )
            .await
            {
                shared.lock().unwrap().status = format!("receive error: {e:#}");
            }
            session.close().await;
        });

        self.conn_task = Some(handle.abort_handle());
        self.rx = Some(rx);
        self.connected = true;
    }

    fn disconnect(&mut self) {
        if let Some(token) = self.shutdown.take() {
            token.cancel();
        }
        if let Some(handle) = self.conn_task.take() {
            handle.abort();
        }
        self.rx = None;
        self.rtt_rx = None;
        self.path_rx = None;
        self.migrate_tx = None;
        self.is_isekai_link = true;
        self.isekai_link_path = None;
        self.p2p_path = None;
        self.connected = false;
        self.texture = None;
        *self.p2p_shared.lock().unwrap() = P2pShared::default();
    }

    /// Ask the connection to switch between the Isekai Link path and a
    /// validated direct path. Works in both modes.
    ///
    /// The label is *not* flipped here: `is_isekai_link` follows the
    /// `Activated` event, so a switch that fails leaves the UI telling the
    /// truth about where the traffic actually is.
    fn migrate(&mut self) {
        let Some(migrate_tx) = self.migrate_tx.as_ref() else {
            return;
        };
        let target = if self.is_isekai_link {
            self.p2p_path
        } else {
            self.isekai_link_path
        };
        match target {
            Some((local_addr, remote_addr)) => {
                tracing::info!("Requesting migration to local {local_addr}, remote {remote_addr}");
                let _ = migrate_tx.try_send((local_addr, remote_addr));
            }
            None => tracing::warn!("No path available to migrate to"),
        }
    }

    /// Apply the path changes the connection task reported.
    fn drain_path_events(&mut self) {
        let Some(path_rx) = &mut self.path_rx else {
            return;
        };
        while let Ok(event) = path_rx.try_recv() {
            match event {
                PathEvent::Relay { local, remote } => self.isekai_link_path = Some((local, remote)),
                PathEvent::DirectValidated { local, remote } => {
                    self.p2p_path = Some((local, remote))
                }
                PathEvent::Activated { local, remote } => {
                    self.is_isekai_link = Some((local, remote)) == self.isekai_link_path;
                }
            }
        }
    }

    /// The config the control-plane calls need. Same values the connect uses;
    /// built here so listing and pairing do not have to wait for a connection.
    fn p2p_config(&self) -> anyhow::Result<P2pConfig> {
        let key = camera_core::load_or_generate_key(std::path::Path::new(&self.key_path))?;
        Ok(P2pConfig {
            identity_url: self.identity_url.clone(),
            identity_http3: false,
            proxy_url: self.proxy_url.clone(),
            auth0_token: self.auth0_token.clone(),
            protocol: self.protocol.clone(),
            register: self.register,
            device_name: Some("camera-client".to_string()),
            token_ttl: None,
            key,
        })
    }

    /// Ask the proxy which cameras this device may connect to.
    fn refresh_cameras(&self) {
        let cfg = match self.p2p_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                *self.pairing_status.lock().unwrap() = Some(format!("key error: {e:#}"));
                return;
            }
        };
        let plane = Arc::clone(&self.control_plane);
        let cameras = Arc::clone(&self.cameras);
        let status = Arc::clone(&self.pairing_status);
        tokio::spawn(async move {
            let mut slot = plane.lock().await;
            let dir = match control_plane(&mut slot, &cfg).await {
                Ok(dir) => dir,
                Err(e) => {
                    *status.lock().unwrap() = Some(format!("control plane: {e:#}"));
                    return;
                }
            };
            match dir.reachable().await {
                Ok(found) => {
                    *cameras.lock().unwrap() = Some(one_per_camera(found));
                    *status.lock().unwrap() = None;
                }
                Err(e) => *status.lock().unwrap() = Some(format!("list failed: {e:#}")),
            }
        });
    }

    /// Redeem a code the camera displayed. Nothing goes back the other way.
    fn pair(&self, code: String) {
        let cfg = match self.p2p_config() {
            Ok(cfg) => cfg,
            Err(e) => {
                *self.pairing_status.lock().unwrap() = Some(format!("key error: {e:#}"));
                return;
            }
        };
        let plane = Arc::clone(&self.control_plane);
        let cameras = Arc::clone(&self.cameras);
        let status = Arc::clone(&self.pairing_status);
        tokio::spawn(async move {
            let mut slot = plane.lock().await;
            let dir = match control_plane(&mut slot, &cfg).await {
                Ok(dir) => dir,
                Err(e) => {
                    *status.lock().unwrap() = Some(format!("control plane: {e:#}"));
                    return;
                }
            };
            match dir.pair(&code, Some("camera-client")).await {
                Ok(grant) => {
                    // Read the list back straight away rather than making the
                    // operator work out that a refresh is now needed — and it
                    // is also where the camera's own name comes from, which is
                    // what they will recognise it by.
                    let mut named = None;
                    if let Ok(found) = dir.reachable().await {
                        // Matched on the owner Endpoint, not the listener id:
                        // the grant is against the device, and the listener it
                        // is running is whichever one it started most recently.
                        let found = one_per_camera(found);
                        named = found
                            .iter()
                            .find(|c| c.owner_endpoint == grant.owner_endpoint)
                            .and_then(display_name)
                            .map(str::to_owned);
                        *cameras.lock().unwrap() = Some(found);
                    }
                    let name = named.unwrap_or(grant.owner_endpoint);
                    *status.lock().unwrap() = Some(format!("paired with {name}"));
                }
                // The proxy answers every pairing failure the same way, so
                // there is nothing more specific to report than this.
                Err(e) => *status.lock().unwrap() = Some(format!("pairing failed: {e:#}")),
            }
        });
    }

    /// Cameras to pick from, and how to add one.
    fn cameras_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Cameras");
        let cameras = self.cameras.lock().unwrap().clone();
        let cameras = match &cameras {
            None => {
                ui.label("not read yet");
                &[][..]
            }
            Some(cameras) if cameras.is_empty() => {
                ui.label("none — pair with a camera below");
                &[][..]
            }
            Some(cameras) => cameras.as_slice(),
        };
        for camera in cameras {
            ui.horizontal(|ui| {
                let name = display_name(camera).unwrap_or(&camera.listener_id);
                let selected = self.listener_id == camera.listener_id;
                if ui.selectable_label(selected, name).clicked() {
                    // Selecting a camera is all the connect needs: a grant is
                    // already in place, so there is no capability to go with it.
                    self.listener_id = camera.listener_id.clone();
                    self.capability.clear();
                }
            });
        }
        ui.horizontal(|ui| {
            if ui.button("Refresh").clicked() {
                self.refresh_cameras();
            }
            ui.label("Pairing code:");
            ui.text_edit_singleline(&mut self.pairing_code);
            if ui.button("Pair").clicked() {
                // Whatever a scanner put in the field, or what someone read off
                // the camera's screen — both arrive here.
                let code = camera_core::pairing_code_from_input(&self.pairing_code);
                if !code.is_empty() {
                    self.pair(code);
                    self.pairing_code.clear();
                }
            }
        });
        if let Some(status) = self.pairing_status.lock().unwrap().as_ref() {
            ui.label(egui::RichText::new(status).small().weak());
        }
    }

    fn p2p_settings_ui(&mut self, ui: &mut egui::Ui) {
        let enabled = !self.connected;
        let field = |ui: &mut egui::Ui, label: &str, value: &mut String, password: bool| {
            ui.horizontal(|ui| {
                ui.label(label);
                ui.add_enabled(
                    enabled,
                    egui::TextEdit::singleline(value)
                        .desired_width(320.0)
                        .password(password),
                )
            })
            .inner
        };
        field(ui, "Identity URL:", &mut self.identity_url, false);
        field(ui, "Proxy URL:   ", &mut self.proxy_url, false);
        let token_field = field(ui, "Auth0 token: ", &mut self.auth0_token, true);
        field(ui, "Key path:    ", &mut self.key_path, false);
        field(ui, "Protocol:    ", &mut self.protocol, false);
        ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut self.register, "Register endpoint on connect"),
        );
        // As soon as there is a credential to ask with — and not while it is
        // still being typed — find out what this device can reach. Waiting for
        // someone to press Refresh means the list below reads "none" to a
        // person who paired a camera yesterday.
        if !self.cameras_requested
            && !self.auth0_token.trim().is_empty()
            && !token_field.has_focus()
        {
            self.cameras_requested = true;
            self.refresh_cameras();
        }
        ui.add_enabled_ui(enabled, |ui| self.cameras_ui(ui));
        ui.separator();
        // The values a camera used to have to read out. Still here for a proxy
        // without grants, and for working around anything the automatic path
        // gets wrong.
        egui::CollapsingHeader::new("Enter a listener by hand")
            .default_open(false)
            .show(ui, |ui| {
                field(ui, "Capability:  ", &mut self.capability, false);
                field(ui, "Listener ID: ", &mut self.listener_id, false);
                ui.label(
                    egui::RichText::new(
                        "An empty Capability connects on a standing grant, which is what \
                         pairing creates.",
                    )
                    .small()
                    .weak(),
                );
                // Step 1 of that exchange: reveal this Endpoint's id, which the
                // camera needs before it can issue a capability. Pairing does
                // not need it — the code carries the introduction instead.
                if ui
                    .add_enabled(enabled, egui::Button::new("Show my Endpoint ID"))
                    .clicked()
                {
                    self.load_endpoint_id();
                }
                if let Some(endpoint_id) = &self.my_endpoint_id {
                    ui.horizontal(|ui| {
                        ui.label("My Endpoint ID:");
                        ui.monospace(endpoint_id.as_str());
                    });
                }
            });
    }

    /// Which path the traffic is on, and what it could move to. Mode-agnostic:
    /// both Direct and P2P report the same events.
    fn path_status_ui(&self, ui: &mut egui::Ui) {
        let show = |ui: &mut egui::Ui,
                    label: &str,
                    path: Option<(SocketAddr, SocketAddr)>,
                    active: bool| {
            let text = match path {
                Some((local, remote)) => format!("{local} -> {remote}"),
                None => "not available".to_owned(),
            };
            ui.horizontal(|ui| {
                ui.label(if active {
                    format!("▶ {label}:")
                } else {
                    format!("   {label}:")
                });
                ui.monospace(text);
            });
        };
        show(
            ui,
            "Isekai Link path",
            self.isekai_link_path,
            self.is_isekai_link,
        );
        show(ui, "Direct path     ", self.p2p_path, !self.is_isekai_link);
    }

    fn p2p_status_ui(&self, ui: &mut egui::Ui) {
        let (status, connection_id) = {
            let shared = self.p2p_shared.lock().unwrap();
            (shared.status.clone(), shared.connection_id.clone())
        };
        if !status.is_empty() {
            ui.label(format!("P2P: {status}"));
        }
        // Step 3: reveal the connection id for the server to bind.
        if let Some(connection_id) = connection_id {
            ui.horizontal(|ui| {
                ui.label("Connection ID:");
                ui.monospace(connection_id.as_str());
            });
        }
    }
}

impl Drop for MyApp {
    fn drop(&mut self) {
        // Closing the window drops the app, which is the only chance to stop
        // the connection task. Without this its msquic handles stay open and
        // the drain in `main` times out.
        self.disconnect();
    }
}

impl eframe::App for MyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // 新しいフレーム受信（最新のみ使う）
        // Drain first, decode once: decoding inside the drain loop livelocks
        // when one decode takes longer than the frame period — a new frame is
        // always ready by the time the previous one is decoded, so the loop
        // (and update()) never returns and the window stops responding.
        if let Some(rx) = &mut self.rx {
            let mut largest_seq = 0u64;
            let mut latest: Option<Bytes> = None;
            while let Ok((seq, data)) = rx.try_recv() {
                if seq > largest_seq || largest_seq == 0 {
                    largest_seq = seq;
                    latest = Some(data);
                } else {
                    tracing::debug!("Discarding old frame with seq {seq}");
                }
            }
            let new_image = latest.map(|data| {
                let mat = imgcodecs::imdecode(
                    &opencv::core::Vector::from_slice(&data),
                    imgcodecs::IMREAD_COLOR,
                )
                .unwrap();

                let mut rgb = opencv::core::Mat::default();
                opencv::imgproc::cvt_color(
                    &mat,
                    &mut rgb,
                    opencv::imgproc::COLOR_BGR2RGB,
                    0,
                    AlgorithmHint::ALGO_HINT_DEFAULT,
                )
                .unwrap();

                egui::ColorImage::from_rgb(
                    [rgb.cols() as usize, rgb.rows() as usize],
                    rgb.data_bytes().unwrap(),
                )
            });
            if let Some(image) = new_image {
                if let Some(tex) = &mut self.texture {
                    tex.set(image, egui::TextureOptions::default());
                } else {
                    self.texture =
                        Some(ctx.load_texture("camera", image, egui::TextureOptions::default()));
                }
            }
        }

        if let Some(rtt_rx) = &mut self.rtt_rx {
            while let Ok(rtt) = rtt_rx.try_recv() {
                self.rtt_history.push_back(rtt);
                if self.rtt_history.len() > 300 {
                    self.rtt_history.pop_front();
                }
            }
        }

        self.drain_path_events();

        let mut connect_clicked = false;
        let mut disconnect_clicked = false;
        let mut migrate_clicked = false;

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("📷 Camera Stream");

            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.add_enabled_ui(!self.connected, |ui| {
                    ui.selectable_value(&mut self.mode, Mode::Direct, "Direct (legacy)");
                    ui.selectable_value(&mut self.mode, Mode::P2p, "P2P");
                });
            });

            match self.mode {
                Mode::Direct => {
                    ui.horizontal(|ui| {
                        ui.label("Server:");
                        ui.add_enabled(
                            !self.connected,
                            egui::TextEdit::singleline(&mut self.server_addr),
                        );
                        ui.label("Port:");
                        ui.add_enabled(
                            !self.connected,
                            egui::TextEdit::singleline(&mut self.server_port),
                        );
                    });
                }
                Mode::P2p => {
                    self.p2p_settings_ui(ui);
                }
            }

            ui.horizontal(|ui| {
                if self.connected {
                    if ui.button("Disconnect").clicked() {
                        disconnect_clicked = true;
                    }
                } else if ui.button("Connect").clicked() {
                    connect_clicked = true;
                }

                // Path migration, in either mode: enabled once both the
                // initial path and a validated direct path are known.
                if ui
                    .add_enabled(
                        self.connected
                            && self.isekai_link_path.is_some()
                            && self.p2p_path.is_some(),
                        egui::Button::new(if self.is_isekai_link {
                            "Migrate to P2P"
                        } else {
                            "Migrate to Isekai Link"
                        }),
                    )
                    .clicked()
                {
                    migrate_clicked = true;
                }
            });

            if self.mode == Mode::P2p {
                self.p2p_status_ui(ui);
            }

            if self.connected {
                self.path_status_ui(ui);
            }

            ui.separator();

            show_rtt_plot(ui, &self.rtt_history);

            ui.separator();

            egui::ScrollArea::both().show(ui, |ui| {
                if let Some(texture) = &self.texture {
                    ui.image(texture);
                } else if self.connected {
                    ui.label("Waiting for camera feed...");
                } else {
                    ui.label("Not connected.");
                }
            });
        });

        if connect_clicked {
            self.connect();
        }
        if disconnect_clicked {
            self.disconnect();
        }
        if migrate_clicked {
            self.migrate();
        }

        ctx.request_repaint();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(id: &str, owner: &str, expires_at: &str) -> camera_core::ReachableListener {
        camera_core::ReachableListener {
            listener_id: id.to_owned(),
            owner_endpoint: owner.to_owned(),
            protocol: "mjpeg".to_owned(),
            metadata: None,
            expires_at: expires_at.to_owned(),
        }
    }

    /// A camera that restarted without withdrawing its old listener is still
    /// one camera. Offering both would mean half the rows do not connect.
    #[test]
    fn a_restarted_camera_is_one_row_and_it_is_the_live_one() {
        let rows = one_per_camera(vec![
            listener("pl_old", "ep:B", "2026-08-02T09:00:00Z"),
            listener("pl_new", "ep:B", "2026-08-02T10:00:00Z"),
            listener("pl_other", "ep:C", "2026-08-02T09:30:00Z"),
        ]);
        assert_eq!(
            rows.iter()
                .map(|l| l.listener_id.as_str())
                .collect::<Vec<_>>(),
            ["pl_new", "pl_other"],
            "the later deadline is the listener that is actually up"
        );
    }

    /// Two listeners leased in the same second must still resolve the same way
    /// on every refresh, or the selected camera moves under the operator.
    #[test]
    fn an_exact_tie_is_broken_the_same_way_every_time() {
        let same = "2026-08-02T10:00:00Z";
        let first = one_per_camera(vec![
            listener("pl_b", "ep:B", same),
            listener("pl_a", "ep:B", same),
        ]);
        let second = one_per_camera(vec![
            listener("pl_a", "ep:B", same),
            listener("pl_b", "ep:B", same),
        ]);
        assert_eq!(first[0].listener_id, "pl_a");
        assert_eq!(first[0].listener_id, second[0].listener_id);
    }
}
