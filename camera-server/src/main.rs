use bytes::Bytes;
use eframe::egui;
use msquic_async::msquic;
use opencv::{
    core::{self, AlgorithmHint},
    imgcodecs, imgproc,
    prelude::*,
    videoio,
};
use std::{future::poll_fn, net::SocketAddr, sync::Arc, sync::mpsc, thread};
use tokio::{io::AsyncWriteExt, task::JoinSet};

fn make_msquic_async_listener(
    registration: Option<Arc<msquic::Registration>>,
    addr: Option<SocketAddr>,
    cert_pem: &str,
    key_pem: &str,
) -> anyhow::Result<(Arc<msquic::Registration>, msquic_async::Listener)> {
    let registration = if let Some(registration) = registration {
        registration
    } else {
        Arc::new(msquic::Registration::new(
            &msquic::RegistrationConfig::default(),
        )?)
    };
    let alpn = [msquic::BufferRef::from("sample")];
    let configuration = msquic::Configuration::open(
        &registration,
        &alpn,
        Some(
            &&&msquic::Settings::new()
                .set_IdleTimeoutMs(30_000)
                .set_MaximumMtu(1200)
                .set_KeepAliveIntervalMs(10_000)
                .set_DestCidUpdateIdleTimeoutMs(0)
                .set_PeerBidiStreamCount(100)
                .set_PeerUnidiStreamCount(100)
                .set_DatagramReceiveEnabled()
                .set_StreamMultiReceiveEnabled(),
        ),
    )?;

    #[cfg(not(windows))]
    {
        use std::io::Write;
        use tempfile::NamedTempFile;
        let mut cert_file = NamedTempFile::new()?;
        cert_file.write_all(cert_pem.as_bytes())?;
        let cert_path = cert_file.into_temp_path();
        let cert_path = cert_path.to_string_lossy().into_owned();

        let mut key_file = NamedTempFile::new()?;
        key_file.write_all(key_pem.as_bytes())?;
        let key_path = key_file.into_temp_path();
        let key_path = key_path.to_string_lossy().into_owned();

        let cred_config =
            msquic::CredentialConfig::new().set_credential(msquic::Credential::CertificateFile(
                msquic::CertificateFile::new(key_path.to_string(), cert_path.to_string()),
            ));
        configuration.load_credential(&cred_config)?;
    }

    #[cfg(windows)]
    {
        use schannel::RawPointer;
        use schannel::cert_context::{CertContext, KeySpec};
        use schannel::cert_store::{CertAdd, Memory};
        use schannel::crypt_prov::{AcquireOptions, ProviderType};

        let mut store = Memory::new().unwrap().into_store();

        let name = String::from("msquic-async-example");

        let cert_ctx = CertContext::from_pem(cert_pem).unwrap();

        let mut options = AcquireOptions::new();
        options.container(&name);

        let type_ = ProviderType::rsa_full();

        let mut container = match options.acquire(type_) {
            Ok(container) => container,
            Err(_) => options.new_keyset(true).acquire(type_).unwrap(),
        };
        container
            .import()
            .import_pkcs8_pem(key_pem.as_bytes())
            .unwrap();

        cert_ctx
            .set_key_prov_info()
            .container(&name)
            .type_(type_)
            .keep_open(true)
            .key_spec(KeySpec::key_exchange())
            .set()
            .unwrap();

        let context = store.add_cert(&cert_ctx, CertAdd::Always).unwrap();

        let cred_config = msquic::CredentialConfig::new().set_credential(
            msquic::Credential::CertificateContext(unsafe { context.as_ptr() }),
        );

        configuration.load_credential(&cred_config)?;
    };

    let listener = msquic_async::Listener::new(&registration, configuration)?;
    listener.start(&alpn, addr)?;
    Ok((registration, listener))
}

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let (tx, rx) = mpsc::channel();
    let (mjpeg_tx, mut mjpeg_rx) = tokio::sync::mpsc::channel::<Bytes>(100);

    let mut tasks = JoinSet::new();

    tasks.spawn_blocking(move || {
        let addr: SocketAddr = "127.0.0.1:4567".parse()?;
        let (_registration, listener) = make_msquic_async_listener(
            None,
            Some(addr),
            include_str!("../certs/server.crt"),
            include_str!("../certs/server.key"),
        )?;
        tracing::info!("listening on {}", listener.local_addr()?);

        tokio::spawn(async move {
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
        anyhow::Ok(())
    });

    // ✅ カメラスレッド起動
    tasks.spawn_blocking(move || {
        let mut cam = videoio::VideoCapture::new(0, videoio::CAP_ANY).unwrap();
        cam.set(videoio::CAP_PROP_FRAME_WIDTH, 640.0)?;
        cam.set(videoio::CAP_PROP_FRAME_HEIGHT, 480.0)?;

        loop {
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

    tokio::spawn(async move{
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
        Box::new(|_cc| Box::new(MyApp::new(rx))),
    )
}

struct MyApp {
    rx: mpsc::Receiver<([usize; 2], Bytes)>,
    texture: Option<egui::TextureHandle>,
    is_streaming: bool,
    resolution: usize,
    log: String,
}

impl MyApp {
    fn new(rx: mpsc::Receiver<([usize; 2], Bytes)>) -> Self {
        Self {
            rx,
            texture: None,
            is_streaming: false,
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
                if self.is_streaming {
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
            if !self.is_streaming {
                if ui.button("▶ Start").clicked() {
                    self.is_streaming = true;
                    self.log = "Streaming started.".to_string();
                }
            } else {
                if ui.button("■ Stop").clicked() {
                    self.is_streaming = false;
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
