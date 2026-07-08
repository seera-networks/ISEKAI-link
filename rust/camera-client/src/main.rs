use bytes::Bytes;
use eframe::egui;
use egui_plot::{Line, Plot, PlotPoints};
use isekai_link_utils::make_msquic_async_client_config;
use msquic_async::msquic;
use opencv::{core::AlgorithmHint, imgcodecs, prelude::*};
use std::{
    collections::VecDeque,
    future::poll_fn,
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::{io::AsyncReadExt, sync::mpsc};

#[tokio::main]
async fn main() -> eframe::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_span_events(tracing_subscriber::fmt::format::FmtSpan::FULL)
        .with_writer(std::io::stderr)
        .init();

    let reg = Arc::new(msquic::Registration::new(&msquic::RegistrationConfig::default()).unwrap());
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default().with_inner_size([1400.0, 1000.0]),
        ..Default::default()
    };
    eframe::run_native(
        "Camera Client App",
        options,
        Box::new(|_cc| Ok(Box::new(MyApp::new(reg)))),
    )
}

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

struct MyApp {
    reg: Arc<msquic::Registration>,
    server_addr: String,
    server_port: String,
    connected: bool,
    is_isekai_link: bool,
    rx: Option<mpsc::Receiver<(u64, Bytes)>>,
    conn_task: Option<tokio::task::AbortHandle>,
    isekai_link_path: Arc<Mutex<Option<(SocketAddr, SocketAddr)>>>,
    p2p_path: Arc<Mutex<Option<(SocketAddr, SocketAddr)>>>,
    migrate_tx: Option<mpsc::Sender<(SocketAddr, SocketAddr)>>,
    rtt_rx: Option<mpsc::Receiver<f64>>,
    texture: Option<egui::TextureHandle>,
    rtt_history: VecDeque<f64>,
}

impl MyApp {
    fn new(reg: Arc<msquic::Registration>) -> Self {
        Self {
            reg,
            server_addr: "161.33.142.214".to_string(),
            server_port: "16205".to_string(),
            connected: false,
            is_isekai_link: true,
            rx: None,
            conn_task: None,
            isekai_link_path: Arc::new(Mutex::new(None)),
            p2p_path: Arc::new(Mutex::new(None)),
            texture: None,
            migrate_tx: None,
            rtt_rx: None,
            rtt_history: VecDeque::new(),
        }
    }

    fn connect(&mut self) {
        let (tx, rx) = mpsc::channel::<(u64, Bytes)>(100);
        let (migrate_tx, mut migrate_rx) = mpsc::channel::<(SocketAddr, SocketAddr)>(10);
        let (rtt_tx, rtt_rx) = mpsc::channel::<f64>(100);
        let addr = self.server_addr.clone();
        let port: u16 = self.server_port.parse().unwrap_or_else(|_| {
            tracing::warn!(
                "Invalid port '{}', falling back to default 15640",
                self.server_port
            );
            15640
        });

        let isekai_link_path = self.isekai_link_path.clone();
        let p2p_path = self.p2p_path.clone();
        let reg = self.reg.clone();
        self.rtt_rx = Some(rtt_rx);
        let handle = tokio::spawn(async move {
            let (reg, configuration) =
                make_msquic_async_client_config(Some(reg), "h3", false, false)?;
            let conn = msquic_async::Connection::new(&reg)?;
            conn.start(&configuration, "link2.isekai.tools", 8443)
                .await
                .map_err(|e| {
                    tracing::error!(
                        "Failed to start connection to link2.isekai.tools:8443: {:?}",
                        e
                    );
                    anyhow::anyhow!(
                        "Failed to start connection to link2.isekai.tools:8443: {:?}",
                        e
                    )
                })?;
            let Ok(msquic_async::ConnectionEvent::NotifyObservedAddress {
                local_address,
                observed_address,
            }) = poll_fn(|cx| conn.poll_event(cx)).await
            else {
                anyhow::bail!("Failed to get observed address");
            };
            tracing::info!("Observed address: {}", observed_address);
            std::mem::drop(conn);
            let (reg, configuration) =
                make_msquic_async_client_config(Some(reg), "sample", true, true)?;
            let conn = msquic_async::Connection::new(&reg)?;
            conn.add_candidate_addr(local_address, observed_address)?;
            tracing::info!("Starting connection to {}:{}", addr, port);
            conn.start(&configuration, &addr, port).await.map_err(|e| {
                tracing::error!("Failed to start connection to {}:{}: {:?}", addr, port, e);
                anyhow::anyhow!("Failed to start connection to {}:{}: {:?}", addr, port, e)
            })?;
            let local_addr = conn.get_local_addr().map_err(|e| {
                tracing::error!("Failed to get local address: {:?}", e);
                anyhow::anyhow!("Failed to get local address: {:?}", e)
            })?;
            let remote_addr = conn.get_remote_addr().map_err(|e| {
                tracing::error!("Failed to get remote address: {:?}", e);
                anyhow::anyhow!("Failed to get remote address: {:?}", e)
            })?;
            isekai_link_path
                .lock()
                .unwrap()
                .replace((local_addr.clone(), remote_addr.clone()));
            let orig_path = (local_addr, remote_addr);
            loop {
                let rtt = conn
                    .get_stats()
                    .map(|stats| {
                        stats.Rtt as f64 / 1000.0 // Convert microseconds to milliseconds
                    })
                    .map_err(|e| {
                        tracing::error!("Failed to get connection stats: {:?}", e);
                        anyhow::anyhow!("Failed to get connection stats: {:?}", e)
                    })?;
                rtt_tx.send(rtt).await.map_err(|e| {
                    tracing::error!("Failed to send RTT: {:?}", e);
                    anyhow::anyhow!("Failed to send RTT: {:?}", e)
                })?;
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(1)) => {
                        let rtt = conn.get_stats()
                            .map(|stats| {
                                stats.Rtt as f64 / 1000.0 // Convert microseconds to milliseconds
                            })
                            .map_err(|e| {
                                tracing::error!("Failed to get connection stats: {:?}", e);
                                anyhow::anyhow!("Failed to get connection stats: {:?}", e)
                            })?;
                        rtt_tx.send(rtt).await.map_err(|e| {
                            tracing::error!("Failed to send RTT: {:?}", e);
                            anyhow::anyhow!("Failed to send RTT: {:?}", e)
                        })?;
                    },
                    res = poll_fn(|cx| conn.poll_event(cx)) => {
                        match res {
                            Ok(event) => {
                                tracing::info!("Connection event: {:?}", event);
                                match event {
                                    msquic_async::ConnectionEvent::NotifyObservedAddress{ local_address, observed_address } => {
                                        tracing::info!("{} mapped to {}", local_address, observed_address);
                                    }
                                    msquic_async::ConnectionEvent::PathValidated{ local_address, remote_address } => {
                                        if (local_address, remote_address) != orig_path {
                                            tracing::info!("Validated P2P path: local {}, remote {}", local_address, remote_address);
                                            p2p_path.lock().unwrap().replace((local_address, remote_address));
                                        }
                                    }
                                    _ => {}
                                }

                            }
                            Err(e) => {
                                tracing::error!("Connection error: {:?}", e);
                                break;
                            }
                        }
                    }
                    ret = migrate_rx.recv() => {
                        if let Some((local_addr, remote_addr)) = ret {
                            tracing::info!("Migrating to new path: local {}, remote {}", local_addr, remote_addr);
                            conn.activate_path(local_addr, remote_addr).map_err(|e| {
                                tracing::error!("Failed to activate path: {}", e);
                                anyhow::anyhow!("Failed to activate path: {}", e)
                            })?;
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
        self.rx = Some(rx);
        self.connected = true;
    }

    fn disconnect(&mut self) {
        if let Some(handle) = self.conn_task.take() {
            handle.abort();
        }
        self.rx = None;
        self.migrate_tx = None;
        self.connected = false;
        self.is_isekai_link = true;
        self.texture = None;
    }

    fn migrate(&mut self) {
        if let Some(migrate_tx) = self.migrate_tx.as_mut() {
            if self.is_isekai_link {
                if let Some((local_addr, remote_addr)) = self.p2p_path.lock().unwrap().clone() {
                    tracing::info!(
                        "Migrating to P2P path: local {}, remote {}",
                        local_addr,
                        remote_addr
                    );
                    let _ = migrate_tx.try_send((local_addr, remote_addr));
                    self.is_isekai_link = false;
                } else {
                    tracing::warn!("No P2P path available for migration");
                }
            } else {
                if let Some((local_addr, remote_addr)) =
                    self.isekai_link_path.lock().unwrap().clone()
                {
                    tracing::info!(
                        "Migrating to Isekai Link path: local {}, remote {}",
                        local_addr,
                        remote_addr
                    );
                    let _ = migrate_tx.try_send((local_addr, remote_addr));
                    self.is_isekai_link = true;
                } else {
                    tracing::warn!("No Isekai Link path available for migration");
                }
            }
        }
    }
}

impl eframe::App for MyApp {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        // 新しいフレーム受信（最新のみ使う）
        if let Some(rx) = &mut self.rx {
            let mut largest_seq = 0u64;
            let mut new_image: Option<egui::ColorImage> = None;
            while let Ok((seq, data)) = rx.try_recv() {
                if seq > largest_seq || largest_seq == 0 {
                    largest_seq = seq;
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

                    new_image = Some(egui::ColorImage::from_rgb(
                        [rgb.cols() as usize, rgb.rows() as usize],
                        rgb.data_bytes().unwrap(),
                    ));
                } else {
                    tracing::debug!("Discarding old frame with seq {seq}");
                }
            }
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

        let mut connect_clicked = false;
        let mut disconnect_clicked = false;
        let mut migrate_clicked = false;

        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("📷 Camera Stream");

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
                if self.connected {
                    if ui.button("Disconnect").clicked() {
                        disconnect_clicked = true;
                    }
                } else if ui.button("Connect").clicked() {
                    connect_clicked = true;
                }
                if ui
                    .add_enabled(
                        self.connected
                            && self.isekai_link_path.lock().unwrap().is_some()
                            && self.p2p_path.lock().unwrap().is_some(),
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

    fn ui(&mut self, _ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        // This method is intentionally left empty as the main UI logic is handled in the `update` method.
    }
}
