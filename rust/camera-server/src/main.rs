use bytes::Bytes;
use eframe::egui;
use futures::stream::{self, StreamExt};
use futures_concurrency::stream::StreamGroup;
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
};
use tokio::{io::AsyncWriteExt, task::JoinSet};
use tokio_util::sync::CancellationToken;

async fn run_isekai_connection(
    reg: Arc<msquic::Registration>,
    target: String,
    jwt: String,
    mut mjpeg_rx: tokio::sync::mpsc::Receiver<Bytes>,
    public_address_out: Arc<Mutex<Option<String>>>,
    log_out: Arc<Mutex<String>>,
    shutdown_token: CancellationToken,
) -> anyhow::Result<()> {
    let uri: Uri = target.parse()?;

    let (reg, config) = make_msquic_async_client_config(Some(reg), "h3", false, false)?;
    let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), "h3qx-01", false, false)?;

    let normal_channel = create_normal_channel(
        uri.clone(),
        reg.clone(),
        config.clone(),
        config_qmux.clone(),
    )
    .await?;
    let public_addr = get_public_address(uri.clone(), &jwt, normal_channel.clone()).await?;
    let udp_mode = get_udp_mode(uri.clone(), &jwt, normal_channel.clone()).await?;
    tracing::info!(
        "got public address: {}, udp mode: {:?}",
        public_addr,
        udp_mode
    );
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

    let (conn_tx, mut conn_rx) = tokio::sync::mpsc::channel(100);
    let channel = create_masque_channel(
        uri.clone(),
        reg.clone(),
        config,
        config_qmux.clone(),
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

    let mut conn_event_group = StreamGroup::new();
    let mut txs = Vec::new();
    let mut migrating_addr = None;
    loop {
        let shutdown_token_clone = shutdown_token.clone(); 
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                tracing::debug!("shutdown signal received, exiting ISEKAI connection task");
                break;
            }
            conn = conn_rx.recv() => {
                if let Some(conn) = conn {
                    let conn_event = Box::pin(stream::unfold(
                        conn,
                        |conn| async move {
                            match poll_fn(|cx| conn.poll_event(cx)).await {
                                Ok(event) => Some((event, conn)),
                                Err(err) => {
                                    tracing::error!("error on connection event: {}", err);
                                    None
                                }
                            }
                        },
                    ));
                    conn_event_group.insert(conn_event);
                } else {
                    tracing::error!("conn_rx closed");
                    break;
                }
            }
            ret = conn_event_group.next(), if !conn_event_group.is_empty() => {
                match ret {
                    Some(event) => {
                        tracing::info!("connection event: {:?}", event);
                        match event {
                            msquic_async::ConnectionEvent::NotifyObservedAddress{ local_address, observed_address } => {
                                migrating_addr = Some((local_address, observed_address));
                            }
                            _ => {},
                        }
                    }
                    None => {
                        tracing::debug!("connection event stream closed");
                        break;
                    }
                }
            }
            conn = listener.accept() => {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(100);
                txs.push(tx);
                match conn {
                    Ok(conn) => {
                        if let Some((local_addr, observed_addr)) = &migrating_addr {
                            tracing::info!("Add bound address: {}", local_addr);
                            conn.add_bound_addr(local_addr.clone())?;
                            tracing::info!("Add observed address: {}", observed_addr);
                            conn.add_observed_addr(local_addr.clone(), observed_addr.clone())?;
                        }
                        tasks.spawn(async move {
                            loop {
                                tokio::select! {
                                    _ = shutdown_token_clone.cancelled() => {
                                        tracing::debug!("shutdown signal received, exiting ISEKAI per connection task");
                                        break;
                                    }
                                    ret = poll_fn(|cx| conn.poll_event(cx)) => {
                                        match ret {
                                            Ok(event) => {
                                                tracing::info!("connection event: {:?}", event);
                                            }
                                            Err(err) => {
                                                tracing::error!("error on connection event: {}", err);
                                                break;
                                            }
                                        }
                                    }
                                    ret = rx.recv() => {
                                        match ret {
                                            Some(jpeg_data) => {
                                                tracing::debug!("sending jpeg data to client, size: {}", jpeg_data.len());
                                                let mut stream = conn.open_outbound_stream(msquic_async::StreamType::Unidirectional, false).await?;
                                                stream.write_all(&jpeg_data).await?;
                                                poll_fn(|cx| stream.poll_finish_write(cx)).await?;
                                            }
                                            None => {
                                                tracing::debug!("jpeg data channel closed");
                                                break;
                                            }
                                        }
                                    }
                                }
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

    std::mem::drop(conn_event_group);
    tracing::debug!("ISEKAI connection task shutting down, waiting for tasks to finish");
    tasks.join_all().await;
    tracing::debug!("ISEKAI connection task exiting");
    tokio::time::sleep(std::time::Duration::from_secs(1)).await; // Give some time for tasks to finish

    anyhow::Ok(())
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    // console_subscriber::init();
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stdout)
        .init();

    let reg = Arc::new(msquic::Registration::new(&msquic::RegistrationConfig::default()).unwrap());

    let (tx, rx) = mpsc::channel();
    let is_streaming = Arc::new(AtomicBool::new(false));
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

            // ✅ UIへ送信
            if tx.send((size, data)).is_err() {
                tracing::error!("failed to send frame to UI");
                break;
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
    let reg_clone = Arc::clone(&reg);
    let res = eframe::run_native(
        "Camera Stream App",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new(reg_clone, rx, is_streaming, is_terminated, mjpeg_tx_holder)))),
    );
    tracing::debug!("eframe exited, waiting camera task stopped");
    camera_task_handle.await.unwrap().unwrap();
    tracing::debug!("camera task finished");
    let metrics = tokio::runtime::Handle::current().metrics();
    tracing::debug!("Tokio runtime alive tasks: {}", metrics.num_alive_tasks());
    tracing::debug!("reg's count: {}", Arc::strong_count(&reg));
    res
}

struct MyApp {
    // 接続設定
    target: String,
    jwt: String,
    is_open: bool,

    reg: Arc<msquic::Registration>,
    // 非同期タスクとの共有状態
    open_wait: Option<mpsc::Receiver<()>>,
    shutdown_token: Option<CancellationToken>,
    mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    public_address: Arc<Mutex<Option<String>>>,
    log_shared: Arc<Mutex<String>>,

    // カメラ表示
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: Arc<AtomicBool>,
    is_terminated: Arc<AtomicBool>,

    // ログ表示用ローカルコピー
    log: String,
}

impl MyApp {
    fn new(
        reg: Arc<msquic::Registration>,
        rx: mpsc::Receiver<([usize; 2], Bytes)>,
        is_streaming: Arc<AtomicBool>,
        is_terminated: Arc<AtomicBool>,
        mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    ) -> Self {
        Self {
            reg,
            target: "https://link2.isekai.tools:8443".to_string(),
            jwt: String::new(),
            is_open: false,
            open_wait: None,
            shutdown_token: None,
            mjpeg_tx_holder,
            public_address: Arc::new(Mutex::new(None)),
            log_shared: Arc::new(Mutex::new("Ready.".to_string())),
            rx,
            texture: None,
            is_streaming,
            is_terminated,
            log: "Ready.".to_string(),
        }
    }

    fn open(&mut self) {
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
        
        let (open_wait_tx, open_wait_rx) = mpsc::channel();
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
            let _ = open_wait_tx.send(()); // Notify that the task has finished
        });
        self.open_wait = Some(open_wait_rx);
        self.shutdown_token = Some(shutdown_token);
        self.is_open = true;
    }

    fn close(&mut self) {
        if let Some(token) = self.shutdown_token.take() {
            token.cancel();
        }
        if let Some(open_wait_rx) = self.open_wait.take() {
            tracing::debug!("Waiting for ISEKAI connection task to finish");
            let _ = open_wait_rx.recv();
            tracing::debug!("ISEKAI connection task finished");
        }
        *self.mjpeg_tx_holder.lock().unwrap() = None;
        *self.public_address.lock().unwrap() = None;
        *self.log_shared.lock().unwrap() = "Closed.".to_string();
        self.is_open = false;
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ✅ 新しいフレーム受信（最新のみ使う）
        while let Ok((size, data)) = self.rx.try_recv() {
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

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("📷 Camera Stream");

            ui.separator();

            // ✅ 接続設定
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

            // ✅ PublicAddress表示
            if let Some(addr) = self.public_address.lock().unwrap().as_ref() {
                ui.label(format!("Public Address: {}", addr));
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

    fn on_exit(&mut self) {
        tracing::debug!("on_exit begin");
        self.close();
        self.is_terminated.store(true, Ordering::Relaxed);
        tracing::debug!("on_exit end");
    }

    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
    }
}
