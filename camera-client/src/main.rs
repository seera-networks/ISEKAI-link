use bytes::Bytes;
use eframe::egui;
use msquic_async::msquic;
use opencv::{core::AlgorithmHint, imgcodecs, prelude::*};
use std::sync::Arc;
use tokio::{io::AsyncReadExt, sync::mpsc};

fn make_msquic_async_client_config(
    registration: Option<Arc<msquic::Registration>>,
) -> anyhow::Result<(Arc<msquic::Registration>, Arc<msquic::Configuration>)> {
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

    let (tx, rx) = mpsc::channel::<(u64, Bytes)>(100);

    tokio::spawn(async move {
        let (registration, configuration) = make_msquic_async_client_config(None)?;
        let conn = msquic_async::Connection::new(&registration)?;
        conn.start(&configuration, "127.0.0.1", 4567).await?;
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

    let options = eframe::NativeOptions::default();
    eframe::run_native(
        "Camera Client App",
        options,
        Box::new(|_cc| Box::new(MyApp::new(rx))),
    )
}

struct MyApp {
    rx: mpsc::Receiver<(u64, Bytes)>,
    texture: Option<egui::TextureHandle>,
}

impl MyApp {
    fn new(rx: mpsc::Receiver<(u64, Bytes)>) -> Self {
        Self { rx, texture: None }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // ✅ 新しいフレーム受信（最新のみ使う）
        let mut largest_seq = 0;
        while let Ok((seq, data)) = self.rx.try_recv() {
            if seq > largest_seq || largest_seq == 0 {
                largest_seq = seq;
            } else {
                tracing::debug!("Discarding old frame with seq {seq}");
                continue;
            }
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

            let image = egui::ColorImage::from_rgb(
                [rgb.cols() as usize, rgb.rows() as usize],
                rgb.data_bytes().unwrap(),
            );

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

            if let Some(texture) = &self.texture {
                ui.image(texture);
            } else {
                ui.label("Loading camera feed...");
            }
        });
        ctx.request_repaint();
    }
}
