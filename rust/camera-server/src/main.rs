use argh::FromArgs;
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
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};
use tokio::{io::AsyncWriteExt, task::JoinSet};

#[derive(FromArgs, Clone)]
/// server args
pub struct CmdOptions {
    /// target address of the MASQUE server
    #[argh(option, default = "String::from(\"https://127.0.0.1:8443\")")]
    target: String,
    /// JWT for authentication, if the server requires it
    #[argh(option, default = "String::from(\"\")")]
    jwt: String,
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();
    let cmd_opts: CmdOptions = argh::from_env();

    let (tx, rx) = mpsc::channel();
    let (mjpeg_tx, mut mjpeg_rx) = tokio::sync::mpsc::channel::<Bytes>(100);

    let is_streaming = Arc::new(AtomicBool::new(false));
    let is_streaming_camera = Arc::clone(&is_streaming);

    let mut tasks = JoinSet::new();

    tasks.spawn(async move {
        let uri: Uri = cmd_opts.target.parse()?;

        let (reg, config) = make_msquic_async_client_config(None, "h3")?;
        let (reg, config_qmux) = make_msquic_async_client_config(Some(reg), "h3qx-01")?;

        let normal_channel = create_normal_channel(uri.clone(), reg.clone(), config.clone(), config_qmux.clone()).await?;
        let public_addr = get_public_address(uri.clone(), &cmd_opts.jwt, normal_channel.clone()).await?;

        let cert_info = get_certificate(uri.clone(), &cmd_opts.jwt, normal_channel).await?;
        tracing::info!(
            "got certificate for hostname {}, public address: {}",
            cert_info.hostname,
            public_addr
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

        create_forward_masque_connection(&cmd_opts.jwt, listen_addr, channel.clone(), &mut tasks)
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
    });

    // ✅ カメラスレッド起動
    tasks.spawn_blocking(move || {
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
            match mjpeg_tx.try_send(jpeg_data) {
                Ok(()) => {}
                Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                    // Drop this frame under backpressure.
                }
                Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                    tracing::error!("mjpeg_tx closed");
                    break;
                }
            }

            // FPS制御
            thread::sleep(std::time::Duration::from_millis(33));
        }
        anyhow::Ok(())
    });

    tokio::spawn(async move {
        while let Some(res) = tasks.join_next().await {
            tracing::info!("task completed");
            if let Err(err) = res? {
                tracing::error!("task failed: {}", err);
            }
        }
        anyhow::Ok(())
    });

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Camera Stream App",
        options,
        Box::new(|_cc| Box::new(MyApp::new(rx, is_streaming))),
    )
}

struct MyApp {
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: Arc<AtomicBool>,
    resolution: usize,
    log: String,
}

impl MyApp {
    fn new(rx: mpsc::Receiver<([usize; 2], Bytes)>, is_streaming: Arc<AtomicBool>) -> Self {
        Self {
            rx,
            texture: None,
            is_streaming,
            resolution: 0,
            log: "Ready.".to_string(),
        }
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

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("📷 Camera Stream");

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
                    self.log = "Streaming started.".to_string();
                }
            } else {
                if ui.button("■ Stop").clicked() {
                    self.is_streaming.store(false, Ordering::Relaxed);
                    self.log = "Streaming stopped.".to_string();
                }
            }

            ui.separator();

            // ✅ ログ表示
            ui.label("Log:");
            ui.text_edit_multiline(&mut self.log);
        });
        ctx.request_repaint();
    }
}
