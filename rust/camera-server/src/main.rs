use bytes::Bytes;
use camera_core::{ObservedAddressWatch, P2pConfig, ServerCommand, ServerInfo};
use eframe::egui;
use http::Uri;
use isekai_link_utils::{
    create_forward_masque_connection, create_masque_channel, create_normal_channel,
    get_certificate, get_public_address, get_udp_mode, make_msquic_async_client_config,
    make_msquic_async_listener, set_udp_mode,
};
use msquic_async::msquic;
use opencv::{
    core::{self, AlgorithmHint},
    imgcodecs, imgproc,
    prelude::*,
    videoio,
};
use std::{
    future::poll_fn,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};
use tokio::sync::oneshot;
use tokio::{io::AsyncWriteExt, task::JoinSet};
use tokio_util::sync::CancellationToken;

async fn run_isekai_connection(
    reg: Arc<msquic_async::Registration>,
    target: String,
    jwt: String,
    mut mjpeg_rx: tokio::sync::mpsc::Receiver<Bytes>,
    public_address_out: Arc<Mutex<Option<String>>>,
    log_out: Arc<Mutex<String>>,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    let uri: Uri = target.parse()?;

    let (reg, config) = make_msquic_async_client_config(Some(reg), "h3")?;
    let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), "h3qx-01")?;

    let normal_channel = create_normal_channel(
        uri.clone(),
        reg.clone(),
        config.clone(),
        config_qmux.clone(),
        false,
    )
    .await?;
    let public_addr = get_public_address(uri.clone(), &jwt, normal_channel.clone()).await?;

    let udp_mode = get_udp_mode(uri.clone(), &jwt, normal_channel.clone()).await?;
    tracing::info!("got udp mode: {:?}", udp_mode);
    if udp_mode.mode != Some("dedicated".to_string()) {
        set_udp_mode(uri.clone(), &jwt, normal_channel.clone(), "dedicated").await?;
    }

    let cert_info = get_certificate(uri.clone(), &jwt, normal_channel).await?;
    tracing::info!(
        "got certificate for hostname {}, public address: {}",
        cert_info.hostname,
        public_addr
    );

    *log_out.lock().unwrap() = format!(
        "Connected. Hostname: {}  Public IP: {}",
        cert_info.hostname, public_addr
    );

    let mut tasks = JoinSet::new();

    let listen_addr: SocketAddr = "127.0.0.1:0".parse()?;
    let (reg, listener) = make_msquic_async_listener(
        Some(reg),
        "sample",
        Some(listen_addr),
        &cert_info.cert_pem,
        &cert_info.key_pem,
        Some(&cert_info.pkcs12),
    )?;
    let listen_addr = listener.local_addr()?;
    tracing::info!("camera server local listening on: {}", listen_addr);

    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel::<msquic_async::Connection>(16);
    let channel = create_masque_channel(
        uri.clone(),
        reg.clone(),
        config,
        config_qmux.clone(),
        true,
        Some(conn_tx),
    )
    .await
    .map_err(|e| {
        tracing::error!("Failed to create MASQUE channel: {e:?}");
        anyhow::anyhow!("Failed to create MASQUE channel: {e:?}")
    })?;

    create_forward_masque_connection(
        &jwt,
        listen_addr,
        channel,
        &mut tasks,
        shutdown_token.clone(),
        Some(Arc::clone(&public_address_out)),
    )
    .await?;

    // Observed address the MASQUE relay reports for this server; applied to
    // accepted client connections so they can migrate to our direct path.
    let migrating_addr: Arc<Mutex<Option<(SocketAddr, SocketAddr)>>> = Arc::new(Mutex::new(None));
    let mut txs = Vec::new();
    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                tracing::debug!("shutdown signal received, exiting ISEKAI connection task");
                break;
            }
            conn = conn_rx.recv() => {
                match conn {
                    Some(conn) => {
                        // The MASQUE relay reports the address it observes for this
                        // server; poll the connection's events to receive it and
                        // remember it for migrating accepted client connections.
                        let shutdown_token = shutdown_token.clone();
                        let migrating_addr = Arc::clone(&migrating_addr);
                        tasks.spawn(async move {
                            loop {
                                tokio::select! {
                                    _ = shutdown_token.cancelled() => break,
                                    event = poll_fn(|cx| conn.poll_event(cx)) => {
                                        match event {
                                            Ok(msquic_async::ConnectionEvent::NotifyObservedAddress {
                                                local_address,
                                                observed_address,
                                            }) => {
                                                tracing::info!(
                                                    "observed address reported: local {local_address}, observed {observed_address}"
                                                );
                                                migrating_addr
                                                    .lock()
                                                    .unwrap()
                                                    .replace((local_address, observed_address));
                                            }
                                            Ok(other) => {
                                                tracing::debug!("connection event: {other:?}");
                                            }
                                            Err(err) => {
                                                tracing::debug!("connection event stream ended: {err}");
                                                break;
                                            }
                                        }
                                    }
                                }
                            }
                            anyhow::Ok(())
                        });
                    }
                    None => {
                        tracing::error!("conn_rx closed");
                        break;
                    }
                }
            }
            conn = listener.accept() => {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(100);
                txs.push(tx);
                match conn {
                    Ok(conn) => {
                        // Advertise our observed (public) address to the client so
                        // it can validate and migrate to a direct path.
                        if let Some((local_addr, observed_addr)) = *migrating_addr.lock().unwrap() {
                            if let Err(e) = conn.add_bound_addr(local_addr) {
                                tracing::error!("Failed to add bound address: {e}");
                            }
                            if let Err(e) = conn.add_observed_addr(local_addr, observed_addr) {
                                tracing::error!("Failed to add observed address: {e}");
                            }
                        }
                        tokio::spawn(async move {
                            while let Some(jpeg_data) = rx.recv().await {
                                tracing::debug!("sending jpeg data to client, size: {}", jpeg_data.len());
                                let mut stream = conn.open_outbound_stream(msquic_async::StreamType::Unidirectional, false).await?;
                                stream.write_all(&jpeg_data).await?;
                                poll_fn(|cx| stream.poll_finish_write(cx)).await?;
                            }
                            anyhow::Ok(())
                        });
                    }
                    Err(err) => {
                        tracing::error!("error on accept connection: {}", err);
                        break;
                    }
                }
            }
            jpeg_data = mjpeg_rx.recv() => {
                if let Some(jpeg_data) = jpeg_data {
                    txs.retain(|tx| !tx.is_closed());
                    for tx in &txs {
                        if tx.send(jpeg_data.clone()).await.is_err() {
                            tracing::error!("failed to send jpeg data to client");
                        }
                    }
                } else {
                    tracing::error!("mjpeg_rx closed");
                    break;
                }
            }
        }
    }

    tracing::debug!("ISEKAI connection task shutting down, waiting for tasks to finish");
    tasks.join_all().await;
    tracing::debug!("ISEKAI connection task exiting");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Give some time for tasks to finish

    anyhow::Ok(())
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let reg =
        Arc::new(msquic_async::Registration::new(&msquic::RegistrationConfig::default()).unwrap());

    // Bounded: the UI drains this only while the window repaints (egui stops
    // updating when occluded/minimized), so an unbounded channel accumulates
    // ~27MB/s of raw frames and freezes the app. Keep at most 2 frames and
    // drop the rest — the preview only ever needs the latest.
    let (tx, rx) = mpsc::sync_channel::<([usize; 2], Bytes)>(2);
    // CAMERA_AUTOSTART=1 starts capture immediately (debug/automation aid).
    let is_streaming = Arc::new(AtomicBool::new(
        std::env::var_os("CAMERA_AUTOSTART").is_some(),
    ));
    let is_streaming_camera = Arc::clone(&is_streaming);
    let is_terminated = Arc::new(AtomicBool::new(false));
    let is_terminated_camera = Arc::clone(&is_terminated);

    let mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>> =
        Arc::new(Mutex::new(None));
    let mjpeg_tx_holder_camera = Arc::clone(&mjpeg_tx_holder);

    // ✅ カメラスレッド起動
    let camera_task_handle = tokio::task::spawn_blocking(move || {
        let mut cam = videoio::VideoCapture::new(0, videoio::CAP_ANY).unwrap();
        cam.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0)?;
        cam.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0)?;

        loop {
            if is_terminated_camera.load(Ordering::Relaxed) {
                tracing::debug!("camera task terminating");
                break;
            }
            if !is_streaming_camera.load(Ordering::Relaxed) {
                thread::sleep(std::time::Duration::from_millis(33));
                continue;
            }

            let mut frame = Mat::default();
            cam.read(&mut frame).unwrap();

            if frame.empty() {
                // Grab failed (e.g. device busy); back off instead of busy-looping.
                thread::sleep(std::time::Duration::from_millis(33));
                continue;
            }

            // BGR → RGB
            let mut rgb = Mat::default();
            imgproc::cvt_color(
                &frame,
                &mut rgb,
                imgproc::COLOR_BGR2RGB,
                0,
                AlgorithmHint::ALGO_HINT_DEFAULT,
            )
            .unwrap();

            let size = [rgb.cols() as usize, rgb.rows() as usize];
            let data = Bytes::copy_from_slice(rgb.data_bytes().unwrap());

            // ✅ UIへ送信（満杯なら最新性を優先してドロップ）
            match tx.try_send((size, data)) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    // UI isn't repainting (e.g. window occluded); drop the frame.
                }
                Err(mpsc::TrySendError::Disconnected(_)) => {
                    tracing::error!("failed to send frame to UI");
                    break;
                }
            }

            let mut buf = core::Vector::<u8>::new();
            let params = core::Vector::from(vec![
                imgcodecs::IMWRITE_JPEG_QUALITY,
                80, // 品質 (0-100)
            ]);
            imgcodecs::imencode(".jpg", &frame, &mut buf, &params).unwrap();
            let jpeg_data = Bytes::copy_from_slice(buf.as_slice());

            // ✅ MASQUEチャンネルへ送信（接続中のみ）
            if let Some(sender) = mjpeg_tx_holder_camera.lock().unwrap().as_ref() {
                match sender.try_send(jpeg_data) {
                    Ok(()) => {}
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // Drop this frame under backpressure.
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        tracing::error!("mjpeg sender closed");
                    }
                }
            }

            // FPS制御
            thread::sleep(std::time::Duration::from_millis(33));
        }
        anyhow::Ok(())
    });

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 1000.0]),
        ..Default::default()
    };
    let res = eframe::run_native(
        "Camera Stream App",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new(
            Arc::clone(&reg),
            rx,
            is_streaming,
            mjpeg_tx_holder,
        )))),
    );
    tracing::debug!("eframe exited, stopping camera task");
    is_terminated.store(true, Ordering::Relaxed);
    camera_task_handle.await.unwrap().unwrap();
    tracing::debug!("camera task finished");

    // `run_native` has returned, so the app — and with it the listener and any
    // relay session it was running — is dropped. Draining msquic before leaving
    // `main` is what makes the process actually exit: dropping the registration
    // with a handle still open blocks in `RegistrationClose` forever.
    if !camera_core::shutdown_msquic_stack(reg, MSQUIC_DRAIN_TIMEOUT).await {
        // Something is still holding a handle. Returning would drop the tokio
        // runtime and msquic's statics into that state and hang or abort, so
        // leave without running destructors — there is nothing left to save.
        use std::io::Write as _;
        let _ = std::io::stdout().flush();
        let _ = std::io::stderr().flush();
        unsafe { libc_exit(if res.is_ok() { 0 } else { 1 }) }
    }
    res
}

/// How long to wait for msquic handles to close before exiting hard.
const MSQUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

// Raw libc `_exit`: terminate now, skipping atexit handlers and C++ static
// destructors. Only reached when the drain timed out, where running them would
// race msquic's still-live worker threads.
unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

/// How the camera stream reaches clients.
#[derive(PartialEq, Eq, Clone, Copy)]
enum Mode {
    /// Legacy: proxy-issued cert + public address, client dials it directly.
    Direct,
    /// P2P Connect: stream over the MASQUE relay (no public address).
    P2p,
}

/// Shared runtime state of a running P2P server, updated by the async task and
/// read by the UI.
#[derive(Default)]
struct P2pShared {
    info: Option<ServerInfo>,
    capability: Option<String>,
    status: String,
    /// How the proxy sees our relay bind leg. This is the address advertised to
    /// each video client as a direct path, so showing it makes a migration that
    /// never happens diagnosable: empty means the leg has not reported yet.
    observed: Option<ObservedAddressWatch>,
}

struct MyApp {
    // 接続設定
    mode: Mode,
    target: String,
    jwt: String,
    is_open: bool,

    // P2P 接続設定
    identity_url: String,
    proxy_url: String,
    auth0_token: String,
    key_path: String,
    protocol: String,
    register: bool,
    client_endpoint_id: String,
    client_connection_id: String,

    reg: Arc<msquic_async::Registration>,
    // 非同期タスクとの共有状態
    open_task: Option<tokio::task::AbortHandle>,
    shutdown_token: Option<CancellationToken>,
    mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    public_address: Arc<Mutex<Option<String>>>,
    log_shared: Arc<Mutex<String>>,

    // P2P 実行時の共有状態
    p2p_shared: Arc<Mutex<P2pShared>>,
    p2p_commands: Arc<Mutex<Option<tokio::sync::mpsc::Sender<ServerCommand>>>>,

    // カメラ表示
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: Arc<AtomicBool>,

    // ログ表示用ローカルコピー
    log: String,
}

impl MyApp {
    fn new(
        reg: Arc<msquic_async::Registration>,
        rx: mpsc::Receiver<([usize; 2], Bytes)>,
        is_streaming: Arc<AtomicBool>,
        mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    ) -> Self {
        Self {
            reg,
            mode: Mode::Direct,
            target: "https://tokyo.link.isekai.tools:8443".to_string(),
            jwt: String::new(),
            is_open: false,
            identity_url: "https://identity.isekai.tools:9443".to_string(),
            proxy_url: "https://tokyo.link.isekai.tools:8443".to_string(),
            auth0_token: String::new(),
            key_path: "camera-server-endpoint.pem".to_string(),
            protocol: "isekai-validator-v1".to_string(),
            register: true,
            client_endpoint_id: String::new(),
            client_connection_id: String::new(),
            open_task: None,
            shutdown_token: None,
            mjpeg_tx_holder,
            public_address: Arc::new(Mutex::new(None)),
            log_shared: Arc::new(Mutex::new("Ready.".to_string())),
            p2p_shared: Arc::new(Mutex::new(P2pShared::default())),
            p2p_commands: Arc::new(Mutex::new(None)),
            rx,
            texture: None,
            is_streaming,
            log: "Ready.".to_string(),
        }
    }

    fn open(&mut self) {
        match self.mode {
            Mode::Direct => self.open_direct(),
            Mode::P2p => self.open_p2p(),
        }
    }

    fn open_direct(&mut self) {
        let (mjpeg_tx, mjpeg_rx) = tokio::sync::mpsc::channel::<Bytes>(100);
        *self.mjpeg_tx_holder.lock().unwrap() = Some(mjpeg_tx);

        let target = self.target.clone();
        let jwt = self.jwt.clone();
        let public_address = Arc::clone(&self.public_address);
        let log_shared = Arc::clone(&self.log_shared);

        *log_shared.lock().unwrap() = "Connecting...".to_string();

        let shutdown_token = CancellationToken::new();
        let shutdown_token_clone = shutdown_token.clone();
        let reg = Arc::clone(&self.reg);
        let handle = tokio::spawn(async move {
            let log_for_error = Arc::clone(&log_shared);
            if let Err(e) = run_isekai_connection(
                reg,
                target,
                jwt,
                mjpeg_rx,
                public_address,
                log_shared,
                shutdown_token_clone,
            )
            .await
            {
                tracing::error!("ISEKAI connection failed: {e:?}");
                *log_for_error.lock().unwrap() = format!("Error: {e}");
            }
            tracing::debug!("ISEKAI connection task finished");
        });
        self.open_task = Some(handle.abort_handle());
        self.shutdown_token = Some(shutdown_token);
        self.is_open = true;
    }

    fn open_p2p(&mut self) {
        let (mjpeg_tx, mjpeg_rx) = tokio::sync::mpsc::channel::<Bytes>(100);
        *self.mjpeg_tx_holder.lock().unwrap() = Some(mjpeg_tx);

        let shutdown = CancellationToken::new();
        self.shutdown_token = Some(shutdown.clone());
        *self.p2p_shared.lock().unwrap() = P2pShared {
            status: "P2P: connecting...".to_string(),
            ..Default::default()
        };
        *self.p2p_commands.lock().unwrap() = None;

        let reg = Arc::clone(&self.reg);
        let shared = Arc::clone(&self.p2p_shared);
        let cmd_holder = Arc::clone(&self.p2p_commands);
        let identity_url = self.identity_url.clone();
        let proxy_url = self.proxy_url.clone();
        let auth0_token = self.auth0_token.clone();
        let protocol = self.protocol.clone();
        let register = self.register;
        let key_path = self.key_path.clone();

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
                device_name: Some("camera-server".to_string()),
                token_ttl: None,
                key,
            };
            match camera_core::spawn_p2p_server(Some(reg), cfg, mjpeg_rx, shutdown).await {
                Ok(server) => {
                    {
                        let mut s = shared.lock().unwrap();
                        s.status = format!(
                            "listener {} ready (endpoint {})",
                            server.info.listener_id, server.info.endpoint_id
                        );
                        s.info = Some(server.info);
                        s.observed = Some(server.observed);
                    }
                    *cmd_holder.lock().unwrap() = Some(server.commands);
                }
                Err(e) => {
                    shared.lock().unwrap().status = format!("P2P error: {e:#}");
                }
            }
        });
        self.open_task = Some(handle.abort_handle());
        self.is_open = true;
    }

    /// Ask the running P2P server for a capability for `allowed_endpoint`, then
    /// store it for display. No-op if the server isn't up yet.
    fn issue_capability(&self, allowed_endpoint: String) {
        let Some(cmd_tx) = self.p2p_commands.lock().unwrap().clone() else {
            self.p2p_shared.lock().unwrap().status = "P2P server not ready".to_string();
            return;
        };
        let shared = Arc::clone(&self.p2p_shared);
        tokio::spawn(async move {
            let (reply, rx) = oneshot::channel();
            let cmd = ServerCommand::IssueCapability {
                allowed_endpoint,
                ttl: None,
                reply,
            };
            if cmd_tx.send(cmd).await.is_err() {
                shared.lock().unwrap().status = "P2P server stopped".to_string();
                return;
            }
            match rx.await {
                Ok(Ok(capability)) => shared.lock().unwrap().capability = Some(capability),
                Ok(Err(e)) => shared.lock().unwrap().status = format!("capability failed: {e:#}"),
                Err(_) => {}
            }
        });
    }

    /// Attach the relay bind leg for `connection_id`. No-op if the server isn't
    /// up yet.
    fn bind_connection(&self, connection_id: String) {
        let Some(cmd_tx) = self.p2p_commands.lock().unwrap().clone() else {
            self.p2p_shared.lock().unwrap().status = "P2P server not ready".to_string();
            return;
        };
        let shared = Arc::clone(&self.p2p_shared);
        tokio::spawn(async move {
            let (reply, rx) = oneshot::channel();
            let cmd = ServerCommand::Bind {
                connection_id,
                reply,
            };
            if cmd_tx.send(cmd).await.is_err() {
                shared.lock().unwrap().status = "P2P server stopped".to_string();
                return;
            }
            match rx.await {
                Ok(Ok(())) => shared.lock().unwrap().status = "relay bound; streaming".to_string(),
                Ok(Err(e)) => shared.lock().unwrap().status = format!("bind failed: {e:#}"),
                Err(_) => {}
            }
        });
    }

    fn close(&mut self) {
        if let Some(token) = self.shutdown_token.take() {
            token.cancel();
        }
        // if let Some(handle) = self.open_task.take() {
        //     handle.abort();
        // }
        *self.mjpeg_tx_holder.lock().unwrap() = None;
        *self.public_address.lock().unwrap() = None;
        *self.p2p_commands.lock().unwrap() = None;
        *self.p2p_shared.lock().unwrap() = P2pShared {
            status: "Closed.".to_string(),
            ..Default::default()
        };
        *self.log_shared.lock().unwrap() = "Closed.".to_string();
        self.is_open = false;
    }

    fn p2p_settings_ui(&mut self, ui: &mut egui::Ui) {
        let enabled = !self.is_open;
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
            egui::Checkbox::new(&mut self.register, "Register endpoint on open"),
        );
    }

    fn p2p_status_ui(&mut self, ui: &mut egui::Ui) {
        let (status, info, capability, observed) = {
            let shared = self.p2p_shared.lock().unwrap();
            (
                shared.status.clone(),
                shared.info.clone(),
                shared.capability.clone(),
                // Read through the watch while the lock is held; the value is a
                // pair of addresses, so copying it out is cheap.
                shared.observed.as_ref().and_then(|w| *w.borrow()),
            )
        };
        if !status.is_empty() {
            ui.label(format!("P2P: {status}"));
        }
        ui.horizontal(|ui| {
            ui.label("Direct path offered:");
            match observed {
                Some(address) => ui.monospace(format!("{} (as {})", address.local, address.observed)),
                // Until a leg is bound and the proxy reports, clients are told
                // nothing and stay on the relay.
                None => ui.label("not yet — bind a relay first"),
            };
        });
        let Some(info) = info else {
            return;
        };
        ui.horizontal(|ui| {
            ui.label("Endpoint ID:");
            ui.monospace(info.endpoint_id.as_str());
        });
        ui.horizontal(|ui| {
            ui.label("Listener ID:");
            ui.monospace(info.listener_id.as_str());
        });

        // Step 2 of the exchange: mint a capability for the client's Endpoint ID.
        ui.horizontal(|ui| {
            ui.label("Client Endpoint ID:");
            ui.text_edit_singleline(&mut self.client_endpoint_id);
        });
        if ui.button("Issue capability").clicked() {
            let endpoint = self.client_endpoint_id.trim().to_string();
            if !endpoint.is_empty() {
                self.issue_capability(endpoint);
            }
        }
        if let Some(cap) = capability {
            ui.horizontal(|ui| {
                ui.label("Capability:");
                ui.monospace(cap.as_str());
            });
        }

        // Step 4: bind the relay once the client reports its connection id.
        ui.horizontal(|ui| {
            ui.label("Client Connection ID:");
            ui.text_edit_singleline(&mut self.client_connection_id);
        });
        if ui.button("Bind relay").clicked() {
            let connection = self.client_connection_id.trim().to_string();
            if !connection.is_empty() {
                self.bind_connection(connection);
            }
        }
    }
}

impl Drop for MyApp {
    fn drop(&mut self) {
        // Closing the window drops the app, which is the only chance to stop
        // whatever it was running. Without this the listener and relay sessions
        // keep their msquic handles open and the drain in `main` times out.
        self.close();
    }
}

impl eframe::App for MyApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        // ✅ 新しいフレーム受信（最新のみ使う）
        // Drain first, convert once: converting inside the drain loop livelocks
        // when one conversion takes longer than the camera period — a new frame
        // is always ready by the time the previous one is converted, so the
        // loop (and update()) never returns and the window stops responding.
        let mut latest = None;
        while let Ok(frame) = self.rx.try_recv() {
            latest = Some(frame);
        }
        if let Some((size, data)) = latest {
            let image = egui::ColorImage::from_rgb(size, &data);

            if let Some(tex) = &mut self.texture {
                tex.set(image, egui::TextureOptions::default());
            } else {
                self.texture =
                    Some(ctx.load_texture("camera", image, egui::TextureOptions::default()));
            }
        }

        // ✅ 共有ログを同期（変更があった場合のみ更新）
        {
            let shared = self.log_shared.lock().unwrap();
            if *shared != self.log {
                self.log = shared.clone();
            }
        }

        let mut open_clicked = false;
        let mut close_clicked = false;

        egui::CentralPanel::default().show_inside(ui, |ui| {
            ui.heading("📷 Camera Stream");

            ui.separator();

            // ✅ 接続モード
            ui.horizontal(|ui| {
                ui.label("Mode:");
                ui.add_enabled_ui(!self.is_open, |ui| {
                    ui.selectable_value(&mut self.mode, Mode::Direct, "Direct (legacy)");
                    ui.selectable_value(&mut self.mode, Mode::P2p, "P2P");
                });
            });

            // ✅ 接続設定
            match self.mode {
                Mode::Direct => {
                    ui.horizontal(|ui| {
                        ui.label("Target:");
                        ui.add_enabled(
                            !self.is_open,
                            egui::TextEdit::singleline(&mut self.target).desired_width(300.0),
                        );
                    });
                    ui.horizontal(|ui| {
                        ui.label("JWT:   ");
                        ui.add_enabled(
                            !self.is_open,
                            egui::TextEdit::singleline(&mut self.jwt)
                                .desired_width(300.0)
                                .password(true),
                        );
                    });
                }
                Mode::P2p => {
                    self.p2p_settings_ui(ui);
                }
            }

            // ✅ Open / Closeボタン
            ui.horizontal(|ui| {
                if !self.is_open {
                    if ui.button("🔌 Open").clicked() {
                        open_clicked = true;
                    }
                } else if ui.button("⏏ Close").clicked() {
                    close_clicked = true;
                }
            });

            // ✅ 接続後の状態表示
            match self.mode {
                Mode::Direct => {
                    if let Some(addr) = self.public_address.lock().unwrap().as_ref() {
                        ui.label(format!("Public Address: {}", addr));
                    }
                }
                Mode::P2p => {
                    self.p2p_status_ui(ui);
                }
            }

            ui.separator();

            // ✅ 状態表示
            ui.label(format!(
                "Status: {}",
                if self.is_streaming.load(Ordering::Relaxed) {
                    "Streaming"
                } else {
                    "Stopped"
                }
            ));

            ui.separator();

            // ✅ Start / Stopボタン
            if !self.is_streaming.load(Ordering::Relaxed) {
                if ui.button("▶ Start").clicked() {
                    self.is_streaming.store(true, Ordering::Relaxed);
                    *self.log_shared.lock().unwrap() = "Streaming started.".to_string();
                }
            } else if ui.button("■ Stop").clicked() {
                self.is_streaming.store(false, Ordering::Relaxed);
                *self.log_shared.lock().unwrap() = "Streaming stopped.".to_string();
            }

            ui.separator();

            // ✅ ログ表示
            ui.label("Log:");
            ui.text_edit_multiline(&mut self.log);

            ui.separator();

            egui::ScrollArea::both().show(ui, |ui| {
                if let Some(texture) = &self.texture {
                    ui.image(texture);
                } else {
                    ui.label("Loading camera feed...");
                }
            });
        });

        if open_clicked {
            self.open();
        }
        if close_clicked {
            self.close();
        }

        ctx.request_repaint();
    }
}
