use bytes::Bytes;
use camera_core::P2pConfig;
use eframe::egui;
use msquic_async::msquic;
use opencv::{core::AlgorithmHint, imgcodecs, prelude::*};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::{io::AsyncReadExt, sync::mpsc};
use tokio_util::sync::CancellationToken;

/// How long to wait for the server to bind its relay leg after we hand over the
/// connection id. Generous because it spans the human step of pasting the id
/// into the server GUI.
const PEER_RELAY_TIMEOUT: Duration = Duration::from_secs(120);

fn make_msquic_async_client_config(
    registration: Option<Arc<msquic_async::Registration>>,
) -> anyhow::Result<(Arc<msquic_async::Registration>, Arc<msquic::Configuration>)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic_async::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = [msquic::BufferRef::from("sample")];
    let configuration = registration.open_configuration(
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
    Ok((registration, Arc::new(configuration)))
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Camera Client App",
        options,
        Box::new(|_cc| Box::new(MyApp::new())),
    )
}

/// How the client reaches the server.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    /// Legacy: dial the server's public address directly.
    Direct,
    /// P2P Connect: reach the server over the MASQUE relay.
    P2p,
}

/// Shared runtime state of a P2P connection, updated by the async task and read
/// by the UI.
#[derive(Default)]
struct P2pShared {
    status: String,
    connection_id: Option<String>,
}

struct MyApp {
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
    my_endpoint_id: Option<String>,
    p2p_shared: Arc<Mutex<P2pShared>>,

    connected: bool,
    rx: Option<mpsc::Receiver<(u64, Bytes)>>,
    conn_task: Option<tokio::task::AbortHandle>,
    shutdown: Option<CancellationToken>,
    texture: Option<egui::TextureHandle>,
}

impl MyApp {
    fn new() -> Self {
        Self {
            mode: Mode::Direct,
            server_addr: "153.127.33.247".to_string(),
            server_port: "15640".to_string(),
            identity_url: "https://identity.isekai.tools:9443".to_string(),
            proxy_url: "https://link.isekai.tools:8443".to_string(),
            auth0_token: String::new(),
            key_path: "camera-client-endpoint.pem".to_string(),
            protocol: "isekai-validator-v1".to_string(),
            register: true,
            capability: String::new(),
            listener_id: String::new(),
            my_endpoint_id: None,
            p2p_shared: Arc::new(Mutex::new(P2pShared::default())),
            connected: false,
            rx: None,
            conn_task: None,
            shutdown: None,
            texture: None,
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
        let addr = self.server_addr.clone();
        let port: u16 = self.server_port.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "Invalid port '{}', falling back to default 15640",
                self.server_port
            );
            15640
        });

        let handle = tokio::spawn(async move {
            let (registration, configuration) = make_msquic_async_client_config(None)?;
            let conn = msquic_async::Connection::new(&registration)?;
            conn.start(&configuration, &addr, port).await?;
            loop {
                match conn.accept_inbound_uni_stream().await {
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
            anyhow::Ok(())
        });

        self.conn_task = Some(handle.abort_handle());
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
        let (tx, rx) = mpsc::channel::<(u64, Bytes)>(100);
        let shutdown = CancellationToken::new();
        self.shutdown = Some(shutdown.clone());
        *self.p2p_shared.lock().unwrap() = P2pShared {
            status: "P2P: connecting...".to_string(),
            connection_id: None,
        };

        let shared = Arc::clone(&self.p2p_shared);
        let identity_url = self.identity_url.clone();
        let proxy_url = self.proxy_url.clone();
        let auth0_token = self.auth0_token.clone();
        let protocol = self.protocol.clone();
        let register = self.register;
        let key_path = self.key_path.clone();
        let capability = self.capability.trim().to_string();
        let listener_id = self.listener_id.trim().to_string();

        let handle = tokio::spawn(async move {
            let key = match camera_core::load_or_generate_key(std::path::Path::new(&key_path)) {
                Ok(key) => key,
                Err(e) => {
                    shared.lock().unwrap().status = format!("key error: {e:#}");
                    return;
                }
            };
            let cfg = P2pConfig {
                identity_url,
                identity_http3: false,
                proxy_url,
                auth0_token,
                protocol,
                register,
                device_name: Some("camera-client".to_string()),
                token_ttl: None,
                key,
            };
            // Relay-only: no candidates, ephemeral loopback bind.
            let local_bind = "127.0.0.1:0".parse().expect("valid loopback addr");
            let session = match camera_core::InitiatorSession::connect(
                &cfg,
                &capability,
                &listener_id,
                &[],
                local_bind,
            )
            .await
            {
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

            // Readiness barrier: wait until the server has bound its relay leg
            // before dialing the video QUIC. Dialing earlier hits a half-open
            // relay edge and stalls the tunneled handshake until its ~10s idle
            // timeout (CONNECTION_IDLE). The wait spans the human step of pasting
            // the connection id into the server, so allow generous time.
            if let Err(e) = session.wait_for_peer_relay(PEER_RELAY_TIMEOUT).await {
                shared.lock().unwrap().status = format!("relay not ready: {e:#}");
                session.close().await;
                return;
            }

            // Receiving establishes once the server binds the relay for this
            // connection id. The `session` stays alive to hold the relay leg.
            if let Err(e) =
                camera_core::receive_frames(None, &video_host, local_port, verify, tx, shutdown)
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
        self.connected = false;
        self.texture = None;
        *self.p2p_shared.lock().unwrap() = P2pShared::default();
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
                );
            });
        };
        field(ui, "Identity URL:", &mut self.identity_url, false);
        field(ui, "Proxy URL:   ", &mut self.proxy_url, false);
        field(ui, "Auth0 token: ", &mut self.auth0_token, true);
        field(ui, "Key path:    ", &mut self.key_path, false);
        field(ui, "Protocol:    ", &mut self.protocol, false);
        ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut self.register, "Register endpoint on connect"),
        );
        field(ui, "Capability:  ", &mut self.capability, false);
        field(ui, "Listener ID: ", &mut self.listener_id, false);

        // Step 1 of the exchange: reveal this Endpoint's id for the server.
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

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
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

        let mut connect_clicked = false;
        let mut disconnect_clicked = false;

        egui::CentralPanel::default().show(ctx, |ui| {
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
            });

            if self.mode == Mode::P2p {
                self.p2p_status_ui(ui);
            }

            ui.separator();

            if let Some(texture) = &self.texture {
                ui.image(texture);
            } else if self.connected {
                ui.label("Waiting for camera feed...");
            } else {
                ui.label("Not connected.");
            }
        });

        if connect_clicked {
            self.connect();
        }
        if disconnect_clicked {
            self.disconnect();
        }

        ctx.request_repaint();
    }
}
