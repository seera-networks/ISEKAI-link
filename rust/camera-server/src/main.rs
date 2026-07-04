use bytes::Bytes;
use eframe::egui;
use http::Uri;
use isekai_link_utils::{
    create_forward_masque_connection, create_masque_channel, create_normal_channel,
    get_certificate, get_public_address, make_msquic_async_client_config,
    make_msquic_async_listener,
};
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

async fn run_isekai_connection(
    target: String,
    jwt: String,
    mut mjpeg_rx: tokio::sync::mpsc::Receiver<Bytes>,
    public_address_out: Arc<Mutex<Option<String>>>,
    log_out: Arc<Mutex<String>>,
) -> anyhow::Result<()> {
    let uri: Uri = target.parse()?;

    let (reg, config) = make_msquic_async_client_config(None, "h3")?;
    let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), "h3qx-01")?;

    let normal_channel =
        create_normal_channel(uri.clone(), reg.clone(), config.clone(), config_qmux.clone())
            .await?;
    let public_addr = get_public_address(uri.clone(), &jwt, normal_channel.clone()).await?;

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

    let channel = create_masque_channel(uri.clone(), reg.clone(), config, config_qmux.clone())
        .await
        .map_err(|e| {
            tracing::error!("Failed to create MASQUE channel: {e:?}");
            anyhow::anyhow!("Failed to create MASQUE channel: {e:?}")
        })?;

    create_forward_masque_connection(
        &jwt,
        listen_addr,
        channel.clone(),
        &mut tasks,
        Some(Arc::clone(&public_address_out)),
    )
    .await?;

    let mut txs = Vec::new();
    loop {
        tokio::select! {
            conn = listener.accept() => {
                let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(100);
                txs.push(tx);
                match conn {
                    Ok(conn) => {
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

    anyhow::Ok(())
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let (tx, rx) = mpsc::channel();
    let is_streaming = Arc::new(AtomicBool::new(false));
    let is_streaming_camera = Arc::clone(&is_streaming);

    let mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>> =
        Arc::new(Mutex::new(None));
    let mjpeg_tx_holder_camera = Arc::clone(&mjpeg_tx_holder);

    // ✅ カメラスレッド起動
    tokio::task::spawn_blocking(move || {
        let mut cam = videoio::VideoCapture::new(0, videoio::CAP_ANY).unwrap();
        cam.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0)?;
        cam.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0)?;

        loop {
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

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Camera Stream App",
        options,
        Box::new(|_cc| Box::new(MyApp::new(rx, is_streaming, mjpeg_tx_holder))),
    )
}

struct MyApp {
    // 接続設定
    target: String,
    jwt: String,
    is_open: bool,

    // 非同期タスクとの共有状態
    open_task: Option<tokio::task::AbortHandle>,
    mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    public_address: Arc<Mutex<Option<String>>>,
    log_shared: Arc<Mutex<String>>,

    // カメラ表示
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: Arc<AtomicBool>,
    resolution: usize,

    // ログ表示用ローカルコピー
    log: String,
}

impl MyApp {
    fn new(
        rx: mpsc::Receiver<([usize; 2], Bytes)>,
        is_streaming: Arc<AtomicBool>,
        mjpeg_tx_holder: Arc<Mutex<Option<tokio::sync::mpsc::Sender<Bytes>>>>,
    ) -> Self {
        Self {
            target: "https://127.0.0.1:8443".to_string(),
            jwt: String::new(),
            is_open: false,
            open_task: None,
            mjpeg_tx_holder,
            public_address: Arc::new(Mutex::new(None)),
            log_shared: Arc::new(Mutex::new("Ready.".to_string())),
            rx,
            texture: None,
            is_streaming,
            resolution: 0,
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

        let handle = tokio::spawn(async move {
            let log_for_error = Arc::clone(&log_shared);
            if let Err(e) =
                run_isekai_connection(target, jwt, mjpeg_rx, public_address, log_shared).await
            {
                tracing::error!("ISEKAI connection failed: {e:?}");
                *log_for_error.lock().unwrap() = format!("Error: {e}");
            }
        });
        self.open_task = Some(handle.abort_handle());
        self.is_open = true;
    }

    fn close(&mut self) {
        if let Some(handle) = self.open_task.take() {
            handle.abort();
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

            // ✅ 解像度選択
            ui.horizontal(|ui| {
                ui.label("Resolution:");
                egui::ComboBox::from_id_source("resolution")
                    .selected_text(match self.resolution {
                        0 => "640x480",
                        1 => "1280x720",
                        _ => "1920x1080",
                    })
                    .show_ui(ui, |ui| {
                        ui.selectable_value(&mut self.resolution, 0, "640x480");
                        ui.selectable_value(&mut self.resolution, 1, "1280x720");
                        ui.selectable_value(&mut self.resolution, 2, "1920x1080");
                    });
            });

            ui.separator();

            if let Some(texture) = &self.texture {
                ui.image(texture);
            } else {
                ui.label("Loading camera feed...");
            }

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

