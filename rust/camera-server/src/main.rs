use bytes::Bytes;
use camera_core::{
    Grant, ObservedAddressWatch, P2pConfig, PairingCode, ServerCommand, ServerInfo, SignalingEvent,
};
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
    collections::VecDeque,
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
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{broadcast, oneshot};
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

    let reg = camera_core::new_registration().expect("open the msquic registration");

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

    // Filled in when a session starts, taken after the window closes. See
    // `ServerHandle::finished`.
    let p2p_finished: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>> = Arc::new(Mutex::new(None));

    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 1000.0]),
        ..Default::default()
    };
    let res = eframe::run_native(
        "Camera Stream App",
        options,
        Box::new(|_cc| {
            Ok(Box::new(MyApp::new(
                Arc::clone(&reg),
                rx,
                is_streaming,
                mjpeg_tx_holder,
                Arc::clone(&p2p_finished),
            )))
        }),
    );
    tracing::debug!("eframe exited, stopping camera task");
    is_terminated.store(true, Ordering::Relaxed);
    camera_task_handle.await.unwrap().unwrap();
    tracing::debug!("camera task finished");

    // Closing the window dropped the app, which cancelled the P2P session; what
    // that starts is a request to withdraw the listener, over the same msquic
    // registration drained below. Leaving without waiting means the drain ends
    // the process first and the listener stays up for the rest of its lease —
    // in every paired peer's list, as something that looks connectable and is
    // not. The handle is taken out of the lock before the await rather than
    // held across it.
    let finished = p2p_finished.lock().unwrap().take();
    if let Some(finished) = finished {
        match tokio::time::timeout(P2P_SHUTDOWN_TIMEOUT, finished).await {
            Ok(Ok(())) => tracing::debug!("P2P session shut down"),
            Ok(Err(e)) => tracing::warn!("P2P session shutdown task failed: {e}"),
            Err(_) => tracing::warn!(
                "P2P session did not shut down within {P2P_SHUTDOWN_TIMEOUT:?}; \
                 its listener will lapse with its lease"
            ),
        }
    }

    // `run_native` has returned, so the app — and with it the listener and any
    // relay session it was running — is dropped. Give msquic a moment to close
    // what those tasks held, then leave without running destructors: returning
    // would drop the registration, and `RegistrationClose` blocks on anything
    // still open.
    if let Err(e) = &res {
        tracing::error!("camera server exited with an error: {e}");
    }
    camera_core::shutdown_and_exit(&reg, MSQUIC_DRAIN_TIMEOUT, i32::from(res.is_err())).await
}

/// How long to wait for msquic handles to close before leaving anyway.
const MSQUIC_DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// How long to wait for the P2P session to shut down and withdraw its listener.
///
/// Longer than the withdrawal's own timeout inside `ListenerSession::close`, so
/// that a slow proxy is decided by that bound rather than by this one racing it.
const P2P_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(6);

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
    /// The code currently on screen. Shown until it expires so the operator can
    /// see it running out rather than find out by having someone fail to pair.
    pairing_code: Option<PairingCode>,
    /// Who is allowed to connect, or `None` before the first answer came back.
    /// Only what the last refresh said — the proxy decides, and this is a view
    /// of it. The distinction matters on screen: "nobody may connect" and "not
    /// asked yet" look the same to an operator who has just paired a device.
    grants: Option<Vec<Grant>>,
    /// What the session's automatic binding did, newest last. Bounded, because
    /// it is a log on a screen and nobody scrolls back an hour.
    activity: VecDeque<String>,
    /// Last error from a control-plane action, shown until the next one.
    error: Option<String>,
}

/// How many lines of binding activity the UI keeps.
const ACTIVITY_LINES: usize = 20;

/// One line of binding activity, in the terms an operator thinks in.
fn describe(event: &SignalingEvent) -> String {
    match event {
        SignalingEvent::Bound { peer_endpoint, .. } => format!("{peer_endpoint} connected"),
        SignalingEvent::Unbound { connection_id } => format!("{connection_id} disconnected"),
        SignalingEvent::AtCapacity { peer_endpoint, .. } => format!(
            "{peer_endpoint} is waiting — already serving {} peers",
            camera_core::MAX_CONCURRENT_PEERS
        ),
        SignalingEvent::Waiting { peer_endpoint, .. } => format!("{peer_endpoint} is waiting"),
        SignalingEvent::BindFailed { error, .. } => format!("could not connect a peer: {error}"),
        SignalingEvent::RenewFailed { error, .. } => {
            format!("could not keep a peer's connection alive: {error}")
        }
        SignalingEvent::Truncated => "more peers are waiting than the proxy will list".to_string(),
    }
}

/// What a pairing code has left to live.
#[derive(Debug, PartialEq, Eq)]
enum CodeLife {
    Left(Duration),
    Expired,
    /// The proxy said something this cannot read. The code is still shown —
    /// dropping a working code because its timestamp was unfamiliar would be
    /// the worse failure — but without a countdown that would be made up.
    Unknown,
}

/// Read who may connect and put the answer on screen.
///
/// A free function because the UI is not the only thing that asks: the session
/// asks once when it starts, and again whenever a peer binds, so a device that
/// has just paired appears without anyone pressing Refresh.
async fn load_grants(
    cmd_tx: tokio::sync::mpsc::Sender<ServerCommand>,
    shared: Arc<Mutex<P2pShared>>,
) {
    let (reply, rx) = tokio::sync::oneshot::channel();
    if cmd_tx
        .send(ServerCommand::ListGrants { reply })
        .await
        .is_err()
    {
        return;
    }
    match rx.await {
        Ok(Ok(grants)) => {
            let mut s = shared.lock().unwrap();
            s.grants = Some(grants);
            s.error = None;
        }
        Ok(Err(e)) => shared.lock().unwrap().error = Some(format!("grants: {e:#}")),
        Err(_) => {}
    }
}

/// How long a pairing code has left, from the deadline the proxy set.
///
/// Not from when the response arrived: that clock starts a round trip late and
/// would keep counting to whatever this end assumed the lifetime was, which is
/// a number the proxy is free to change. Reading `expires_at` means the screen
/// is wrong only by the difference between the two machines' clocks.
fn code_remaining(expires_at: &str, now: OffsetDateTime) -> CodeLife {
    let Ok(deadline) = OffsetDateTime::parse(expires_at, &Rfc3339) else {
        return CodeLife::Unknown;
    };
    match (deadline - now).try_into() {
        Ok(left) if !Duration::is_zero(&left) => CodeLife::Left(left),
        // A negative span does not convert; a zero one does, and a code that
        // has exactly reached its deadline is no more usable than one past it.
        _ => CodeLife::Expired,
    }
}

/// Render a pairing URI as a QR image.
///
/// Scanning beats typing eight characters into a phone. The quiet zone matters:
/// without a border, scanners frequently will not see the code at all.
fn qr_image(text: &str) -> Option<egui::ColorImage> {
    const SCALE: usize = 6;
    const QUIET: usize = 4;
    let code = qrcode::QrCode::new(text.as_bytes()).ok()?;
    let width = code.width();
    let modules = code.to_colors();
    let side = (width + QUIET * 2) * SCALE;
    let mut pixels = vec![egui::Color32::WHITE; side * side];
    for (i, module) in modules.iter().enumerate() {
        if *module != qrcode::Color::Dark {
            continue;
        }
        let (mx, my) = (i % width + QUIET, i / width + QUIET);
        for dy in 0..SCALE {
            for dx in 0..SCALE {
                let (x, y) = (mx * SCALE + dx, my * SCALE + dy);
                pixels[y * side + x] = egui::Color32::BLACK;
            }
        }
    }
    Some(egui::ColorImage {
        size: [side, side],
        pixels,
        source_size: egui::vec2(side as f32, side as f32),
    })
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
    /// Where a device sign-in's tokens are kept, so a restart does not need
    /// another one. Beside the Endpoint key and guarded the same way.
    auth0_store_path: String,
    /// The device sign-in, and what to show the operator while it runs.
    auth0_login: camera_core::auth0::DeviceSignIn,
    /// Set once tokens exist, from a sign-in or from `auth0_store_path`. This is
    /// what keeps the session alive past the access token's few hours: the
    /// Endpoint Token is reissued every few minutes and each issue needs a
    /// current Auth0 token.
    auth0_source: Option<Arc<camera_core::auth0::RefreshingAuth0Token>>,
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
    /// The current pairing code's QR, uploaded once and dropped when the code
    /// changes or lapses — a stale image would invite someone to scan a code
    /// that no longer works.
    qr_texture: Option<egui::TextureHandle>,
    p2p_commands: Arc<Mutex<Option<tokio::sync::mpsc::Sender<ServerCommand>>>>,
    /// The running session's shutdown, for `main` to wait on after the window
    /// closes. Shared rather than owned because this app is dropped inside
    /// `run_native`, and what has to be awaited outlives it.
    p2p_finished: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,

    // カメラ表示
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: Arc<AtomicBool>,

    // ログ表示用ローカルコピー
    log: String,
}

use camera_core::auth0::SignInState as Auth0State;

impl MyApp {
    fn new(
        reg: Arc<msquic_async::Registration>,
        rx: mpsc::Receiver<([usize; 2], Bytes)>,
        is_streaming: Arc<AtomicBool>,
        mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
        p2p_finished: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
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
            auth0_store_path: "camera-server-auth0.json".to_string(),
            auth0_login: camera_core::auth0::DeviceSignIn::default(),
            // Filled in below from whatever a previous sign-in left behind.
            auth0_source: None,
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
            qr_texture: None,
            p2p_commands: Arc::new(Mutex::new(None)),
            p2p_finished,
            rx,
            texture: None,
            is_streaming,
            log: "Ready.".to_string(),
        }
        .with_stored_auth0()
    }

    /// Pick up the tokens a previous sign-in left, so a camera that has been
    /// signed in once comes back up signed in.
    ///
    /// A missing or unreadable file is the normal first-run state, not an error
    /// to report: the operator signs in and it appears.
    fn with_stored_auth0(mut self) -> Self {
        let path = std::path::Path::new(&self.auth0_store_path);
        if let Ok(tokens) = camera_core::auth0::RefreshingAuth0Token::load(path) {
            self.auth0_source = Some(camera_core::auth0::RefreshingAuth0Token::new(
                camera_core::auth0::Auth0Config::default(),
                tokens,
                Some(path.to_path_buf()),
            ));
            self.auth0_login = camera_core::auth0::DeviceSignIn::restored();
        }
        self
    }

    /// Start the device authorization grant, and keep the UI told about it.
    ///
    /// The operator types a short code into a browser on any device; this polls
    /// until that lands. What comes back includes a refresh token, which is what
    /// makes the sign-in last beyond the access token's few hours.
    fn sign_in_to_auth0(&mut self) {
        self.auth0_login.start(
            camera_core::auth0::Auth0Config::default(),
            Some(std::path::PathBuf::from(&self.auth0_store_path)),
        );
    }

    /// Move a finished sign-in onto `self`, which the UI thread owns.
    ///
    /// The polling task cannot build the source itself — it has no `&mut self` —
    /// so it leaves the tokens behind and this picks them up on the next frame.
    fn take_finished_sign_in(&mut self) {
        if let Some(tokens) = self.auth0_login.take_tokens() {
            self.auth0_source = Some(camera_core::auth0::RefreshingAuth0Token::new(
                camera_core::auth0::Auth0Config::default(),
                tokens,
                Some(std::path::PathBuf::from(&self.auth0_store_path)),
            ));
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
        let finished_holder = Arc::clone(&self.p2p_finished);
        let identity_url = self.identity_url.clone();
        let proxy_url = self.proxy_url.clone();
        let auth0_token = self.auth0_token.clone();
        // The refreshing source when the operator has signed in, which is what
        // lets the session outlive one access token. Without it the pasted token
        // is all there is, and renewal stops when it expires.
        let auth0 = self
            .auth0_source
            .clone()
            .map(|s| s as Arc<dyn camera_core::Auth0TokenSource>);
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
                auth0,
                key,
            };
            // Automatic, since the proxy has already checked that a grant
            // authorizes the peer and this is what removes the operator from
            // the connection path. The UI shows who is connected.
            match camera_core::spawn_p2p_server(
                Some(reg),
                cfg,
                mjpeg_rx,
                camera_core::AcceptPolicy::AutoNotify,
                shutdown,
            )
            .await
            {
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
                    // Follow what the automatic binding does, so the operator
                    // can see who connected without having done anything.
                    let activity_shared = Arc::clone(&shared);
                    let activity_cmd = server.commands.clone();
                    let mut events = server.signaling.subscribe();
                    tokio::spawn(async move {
                        loop {
                            match events.recv().await {
                                Ok(event) => {
                                    {
                                        let mut s = activity_shared.lock().unwrap();
                                        s.activity.push_back(describe(&event));
                                        while s.activity.len() > ACTIVITY_LINES {
                                            s.activity.pop_front();
                                        }
                                    }
                                    // A peer that just bound may have paired a
                                    // moment ago, so this is when the list of
                                    // who may connect is most likely stale.
                                    if matches!(event, SignalingEvent::Bound { .. }) {
                                        load_grants(
                                            activity_cmd.clone(),
                                            Arc::clone(&activity_shared),
                                        )
                                        .await;
                                    }
                                }
                                // Falling behind loses the oldest lines, which
                                // is the right trade for a log on a screen.
                                Err(broadcast::error::RecvError::Lagged(n)) => {
                                    let mut s = activity_shared.lock().unwrap();
                                    s.activity.push_back(format!("({n} events missed)"));
                                }
                                Err(broadcast::error::RecvError::Closed) => break,
                            }
                        }
                    });
                    let commands = server.commands.clone();
                    *cmd_holder.lock().unwrap() = Some(server.commands);
                    // What `main` waits on so the listener is withdrawn before
                    // the process drains msquic out from under the request.
                    *finished_holder.lock().unwrap() = Some(server.finished);
                    // Before the operator can look at an empty list and read it
                    // as "the devices I paired are gone". After the commands are
                    // published, so the buttons work while this is in flight.
                    load_grants(commands, shared).await;
                }
                Err(e) => {
                    shared.lock().unwrap().status = format!("P2P error: {e:#}");
                }
            }
        });
        self.open_task = Some(handle.abort_handle());
        self.is_open = true;
    }

    /// Ask the session for a pairing code and put it on screen.
    fn show_pairing_code(&self) {
        let Some(cmd_tx) = self.p2p_commands.lock().unwrap().clone() else {
            self.p2p_shared.lock().unwrap().status = "P2P server not ready".to_string();
            return;
        };
        let shared = Arc::clone(&self.p2p_shared);
        tokio::spawn(async move {
            let (reply, rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(ServerCommand::ShowPairingCode { ttl: None, reply })
                .await
                .is_err()
            {
                return;
            }
            match rx.await {
                Ok(Ok(code)) => {
                    let mut s = shared.lock().unwrap();
                    s.pairing_code = Some(code);
                    s.error = None;
                }
                Ok(Err(e)) => shared.lock().unwrap().error = Some(format!("pairing code: {e:#}")),
                Err(_) => {}
            }
        });
    }

    /// Refresh the list of who may connect.
    fn refresh_grants(&self) {
        let Some(cmd_tx) = self.p2p_commands.lock().unwrap().clone() else {
            return;
        };
        let shared = Arc::clone(&self.p2p_shared);
        tokio::spawn(load_grants(cmd_tx, shared));
    }

    /// Withdraw one. Takes effect on that peer's next connect; what is
    /// streaming now keeps streaming.
    fn revoke_grant(&self, grant_id: String) {
        let Some(cmd_tx) = self.p2p_commands.lock().unwrap().clone() else {
            return;
        };
        let shared = Arc::clone(&self.p2p_shared);
        tokio::spawn(async move {
            let (reply, rx) = tokio::sync::oneshot::channel();
            if cmd_tx
                .send(ServerCommand::RevokeGrant { grant_id, reply })
                .await
                .is_err()
            {
                return;
            }
            match rx.await {
                Ok(Ok(())) => {
                    // Ask again rather than editing the local copy: the proxy
                    // is what decides, and this keeps the screen its view.
                    load_grants(cmd_tx, shared).await;
                }
                Ok(Err(e)) => shared.lock().unwrap().error = Some(format!("revoke: {e:#}")),
                Err(_) => {}
            }
        });
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
        self.auth0_ui(ui, enabled);
        field(ui, "Key path:    ", &mut self.key_path, false);
        field(ui, "Protocol:    ", &mut self.protocol, false);
        ui.add_enabled(
            enabled,
            egui::Checkbox::new(&mut self.register, "Register endpoint on open"),
        );
    }

    /// Signing in, and the pasted token that used to be the only way.
    ///
    /// The paste is kept because it is the only thing that works without a
    /// browser anywhere in reach — but it is the short-lived option now: an
    /// access token lasts hours and the Endpoint Token it issues lasts minutes,
    /// so a pasted token stops the camera admitting new viewers when it expires.
    /// Signing in is what makes that stop happening.
    fn auth0_ui(&mut self, ui: &mut egui::Ui, enabled: bool) {
        self.take_finished_sign_in();
        let state = self.auth0_login.state();
        ui.horizontal(|ui| {
            ui.label("Auth0:       ");
            match &state {
                Auth0State::SignedIn => {
                    ui.label("signed in — the token renews itself");
                    if ui
                        .add_enabled(enabled, egui::Button::new("Sign out"))
                        .clicked()
                    {
                        let _ = std::fs::remove_file(&self.auth0_store_path);
                        self.auth0_source = None;
                        self.auth0_login.sign_out();
                    }
                }
                Auth0State::Waiting { user_code, url } => {
                    ui.label("enter this code:");
                    ui.monospace(user_code);
                    ui.hyperlink_to("open the page", url);
                }
                Auth0State::SignedOut | Auth0State::Failed(_) => {
                    if ui
                        .add_enabled(enabled, egui::Button::new("Sign in"))
                        .clicked()
                    {
                        self.sign_in_to_auth0();
                    }
                }
            }
        });
        if let Auth0State::Failed(e) = &state {
            ui.colored_label(egui::Color32::LIGHT_RED, format!("sign-in failed: {e}"));
        }
        if !matches!(state, Auth0State::SignedIn) {
            ui.horizontal(|ui| {
                ui.label("Auth0 token: ");
                ui.add_enabled(
                    enabled,
                    egui::TextEdit::singleline(&mut self.auth0_token)
                        .desired_width(320.0)
                        .password(true),
                );
                ui.label("(expires; sign in instead)");
            });
        }
    }

    fn p2p_status_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
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
                Some(address) => {
                    ui.monospace(format!("{} (as {})", address.local, address.observed))
                }
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

        ui.separator();
        self.pairing_ui(ui, &ctx);
        ui.separator();
        self.grants_ui(ui);
        ui.separator();
        self.activity_ui(ui);

        // The exchange this replaces. Kept for a proxy without grants, and for
        // when something in the automatic path needs to be worked around.
        ui.separator();
        egui::CollapsingHeader::new("Manual exchange (capability + connection id)")
            .default_open(false)
            .show(ui, |ui| {
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
            });
    }

    /// Show a code for someone to scan or type. Nothing comes back the other
    /// way, which is what makes this one-directional exchange work.
    fn pairing_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.heading("Add a device");
        let shown = self.p2p_shared.lock().unwrap().pairing_code.clone();
        match shown {
            Some(code) => match code_remaining(&code.expires_at, OffsetDateTime::now_utc()) {
                CodeLife::Expired => {
                    self.p2p_shared.lock().unwrap().pairing_code = None;
                    self.qr_texture = None;
                    ui.label("that code has expired");
                }
                life => {
                    ui.label("Scan this, or type the code into the viewer:");
                    // The QR carries a URI, not the eight characters: a scan of
                    // the bare code shows a phone user some text and leaves them
                    // to find the app themselves.
                    if self.qr_texture.is_none()
                        && let Some(image) = qr_image(&camera_core::pairing_uri(&code.code))
                    {
                        self.qr_texture = Some(ctx.load_texture(
                            "pairing-qr",
                            image,
                            egui::TextureOptions::NEAREST,
                        ));
                    }
                    if let Some(texture) = &self.qr_texture {
                        ui.image((texture.id(), texture.size_vec2()));
                    }
                    ui.label(egui::RichText::new(&code.code).monospace().size(24.0));
                    match life {
                        CodeLife::Left(left) => {
                            ui.label(format!("expires in {}s", left.as_secs()));
                            // The code stops working on its own, so the
                            // countdown has to keep moving without anything
                            // else happening.
                            ctx.request_repaint_after(Duration::from_secs(1));
                        }
                        _ => {
                            ui.label(format!("expires at {}", code.expires_at));
                        }
                    }
                }
            },
            None => {
                ui.label("A device that pairs once can connect whenever it likes afterwards.");
            }
        }
        if ui.button("Show a pairing code").clicked() {
            // Any previous code stops working the moment a new one is issued,
            // so the old image must not stay on screen.
            self.qr_texture = None;
            self.show_pairing_code();
        }
    }

    /// Who may connect, and how to stop them.
    fn grants_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Allowed devices");
        let grants = self.p2p_shared.lock().unwrap().grants.clone();
        let grants = match &grants {
            None => {
                ui.label("not read yet");
                &[][..]
            }
            Some(grants) if grants.is_empty() => {
                ui.label("none yet — pair a device to add one");
                &[][..]
            }
            Some(grants) => grants.as_slice(),
        };
        let mut revoke = None;
        for grant in grants {
            ui.horizontal(|ui| {
                let name = grant.label.as_deref().unwrap_or(&grant.allowed_endpoint);
                ui.label(name);
                ui.label(
                    egui::RichText::new(match grant.origin.as_str() {
                        "pairing" => "paired",
                        "owner_match" => "same account",
                        _ => "added by hand",
                    })
                    .small()
                    .weak(),
                );
                if ui.button("Remove").clicked() {
                    revoke = Some(grant.grant_id.clone());
                }
            });
        }
        if let Some(grant_id) = revoke {
            self.revoke_grant(grant_id);
        }
        if ui.button("Refresh").clicked() {
            self.refresh_grants();
        }
    }

    /// What the session did without being asked, so it is not invisible.
    fn activity_ui(&mut self, ui: &mut egui::Ui) {
        ui.heading("Connections");
        let (activity, error) = {
            let s = self.p2p_shared.lock().unwrap();
            (s.activity.clone(), s.error.clone())
        };
        if let Some(error) = error {
            ui.colored_label(egui::Color32::RED, error);
        }
        if activity.is_empty() {
            ui.label("nothing yet");
        }
        for line in &activity {
            ui.label(line);
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
            // The window runs out of room long before the content does — a QR,
            // a device list, an activity log and a video preview do not fit on a
            // laptop screen at once — and what fell off the bottom simply could
            // not be reached. `auto_shrink` off so the area still claims the
            // whole panel when the content is short.
            egui::ScrollArea::vertical()
                .auto_shrink([false, false])
                .show(ui, |ui| {
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
                                    egui::TextEdit::singleline(&mut self.target)
                                        .desired_width(300.0),
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

                    // Drawn straight into the page, not in a scroll area of its
                    // own. A nested one takes whatever height is left and
                    // scrolls inside it, so the outer area believes the content
                    // ends where the video starts — the page stops scrolling and
                    // the picture is cut off at the window's edge with no way to
                    // reach the rest of it.
                    //
                    // Fitting to the available width keeps the whole frame on
                    // screen without a second axis to scroll.
                    if let Some(texture) = &self.texture {
                        ui.add(egui::Image::new(texture).max_width(ui.available_width()));
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

#[cfg(test)]
mod tests {
    use super::*;

    fn at(rfc3339: &str) -> OffsetDateTime {
        OffsetDateTime::parse(rfc3339, &Rfc3339).expect("test timestamp")
    }

    /// The countdown comes from the proxy's deadline, so it does not drift with
    /// whatever this end assumed the lifetime was.
    #[test]
    fn a_pairing_code_counts_down_to_the_deadline_the_proxy_set() {
        let now = at("2026-08-02T12:00:00Z");
        assert_eq!(
            code_remaining("2026-08-02T12:04:00Z", now),
            CodeLife::Left(Duration::from_secs(240))
        );
        // The instant it passes, and after.
        assert_eq!(
            code_remaining("2026-08-02T12:00:00Z", now),
            CodeLife::Expired
        );
        assert_eq!(
            code_remaining("2026-08-02T11:59:59Z", now),
            CodeLife::Expired
        );
    }

    /// An unreadable deadline must not take a working code off the screen.
    #[test]
    fn an_unparsable_deadline_leaves_the_code_up_without_a_countdown() {
        let now = at("2026-08-02T12:00:00Z");
        assert_eq!(code_remaining("soon", now), CodeLife::Unknown);
        assert_eq!(code_remaining("", now), CodeLife::Unknown);
    }

    /// The QR has to carry the URI a scan can act on, and come out square with
    /// its quiet zone intact — without one, scanners often will not see it.
    #[test]
    fn the_pairing_qr_is_square_and_bordered() {
        let image = qr_image(&camera_core::pairing_uri("K7M2-QX4P")).expect("encodes");
        assert_eq!(image.size[0], image.size[1]);
        assert_eq!(image.pixels.len(), image.size[0] * image.size[1]);
        // Every corner is inside the quiet zone.
        let side = image.size[0];
        for corner in [0, side - 1, side * (side - 1), side * side - 1] {
            assert_eq!(image.pixels[corner], egui::Color32::WHITE);
        }
        assert!(image.pixels.contains(&egui::Color32::BLACK));
    }
}
