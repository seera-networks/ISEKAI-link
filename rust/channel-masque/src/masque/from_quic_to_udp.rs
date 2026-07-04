use anyhow::Context;
use bytes::Buf;
use h3::quic::StreamId;
use h3_datagram::{datagram_handler::DatagramReader, quic_traits::RecvDatagram};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};

const DEFAULT_BLACKHOLE_DURATION: std::time::Duration = std::time::Duration::from_secs(60);

pub enum Message {
    RegisterStreamId(
        StreamId,
        crate::MasqueClientMode,
        mpsc::Sender<Notification>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    RegisterContextId(
        StreamId,
        u64,
        Option<SocketAddr>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    NotifySocketConnected(StreamId, SocketAddr, oneshot::Sender<anyhow::Result<()>>),
    NotifySocketDisconnected(StreamId, SocketAddr, oneshot::Sender<anyhow::Result<()>>),
    UnregisterContextId(StreamId, u64, oneshot::Sender<anyhow::Result<()>>),
}

pub enum Notification {
    NewSocket(Arc<UdpSocket>, SocketAddr, bool),
}

#[derive(Clone)]
pub struct Controller {
    stream_id: StreamId,
    tx: mpsc::Sender<Message>,
}

impl Controller {
    pub fn new(stream_id: StreamId, tx: mpsc::Sender<Message>) -> Self {
        Self { stream_id, tx }
    }

    pub async fn register_stream_id(
        &self,
        mode: crate::MasqueClientMode,
    ) -> anyhow::Result<mpsc::Receiver<Notification>> {
        let (notification_tx, notification_rx) = mpsc::channel(1024);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterStreamId(
                self.stream_id,
                mode,
                notification_tx,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterStreamId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterStreamId response"))??;
        Ok(notification_rx)
    }

    pub async fn register_context_id(
        &self,
        context_id: u64,
        addr: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterContextId(
                self.stream_id,
                context_id,
                addr,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterContextId response"))?
    }

    pub async fn notify_socket_connected(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::NotifySocketConnected(
                self.stream_id,
                addr,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send NotifySocketConnected Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive NotifySocketConnected response"))?
    }

    pub async fn notify_socket_disconnected(&self, addr: SocketAddr) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::NotifySocketDisconnected(
                self.stream_id,
                addr,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send NotifySocketDisconnected Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive NotifySocketDisconnected response"))?
    }

    pub async fn unregister_context_id(&self, context_id: u64) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::UnregisterContextId(
                self.stream_id,
                context_id,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send UnregisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive UnregisterContextId response"))?
    }
}

pub async fn thread<H>(
    mut rx: mpsc::Receiver<Message>,
    mut datagram_reader: DatagramReader<H>,
) -> anyhow::Result<()>
where
    H: RecvDatagram + 'static + Send,
    <H as RecvDatagram>::Buffer: Send,
{
    let mut notification_senders: HashMap<StreamId, mpsc::Sender<Notification>> = HashMap::new();
    let mut modes: HashMap<StreamId, crate::MasqueClientMode> = HashMap::new();
    let mut socket_info: HashMap<(StreamId, SocketAddr), (Arc<UdpSocket>, bool)> = HashMap::new();
    let mut compression_info: HashMap<(StreamId, u64), Option<SocketAddr>> = HashMap::new();
    let mut queued_datagrams: HashMap<(StreamId, SocketAddr), Vec<Vec<u8>>> = HashMap::new();
    let mut blackholes: HashMap<(StreamId, SocketAddr), tokio::time::Instant> = HashMap::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(Message::RegisterStreamId(stream_id, mode, notification_tx, resp_tx)) => {
                        tracing::debug!("received RegisterStreamId Message for stream id {}", stream_id);
                        notification_senders.insert(stream_id, notification_tx);
                        modes.insert(stream_id, mode);
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("RegisterStreamId response receiver dropped");
                        }
                    }
                    Some(Message::RegisterContextId(stream_id, context_id, addr, resp_tx)) => {
                        tracing::debug!("received RegisterContextID Message for stream id {}, context id {}, addr {:?}", stream_id, context_id, addr);
                        compression_info.insert((stream_id, context_id), addr);
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("RegisterContextId response receiver dropped");
                        }
                    }
                    Some(Message::NotifySocketConnected(stream_id, addr, resp_tx)) => {
                        tracing::debug!("received NotifySocketConnected Message for stream id {}, addr {}", stream_id, addr);
                        let socket = if let Some(entry) = socket_info.get_mut(&(stream_id, addr)) {
                            entry.1 = true;
                            tracing::info!("notified that socket for stream id {} and addr {} is connected", stream_id, addr);
                            entry.0.clone()
                        } else {
                            tracing::error!("no socket found for stream id {} and addr {}", stream_id, addr);
                            if resp_tx.send(Err(anyhow::anyhow!("no socket found for stream id {} and addr {}", stream_id, addr))).is_err() {
                                tracing::debug!("NotifySocketConnected response receiver dropped");
                            }
                            continue;                            
                        };
                        if let Some(queued_datagram) = queued_datagrams.remove(&(stream_id, addr)) {
                            for datagram in queued_datagram {
                                tracing::debug!("sending queued datagram for stream id {} and addr {}", stream_id, addr);
                                if let Err(err) = socket.send(&datagram).await {
                                    tracing::error!("failed to send queued datagram: {:?}", err);
                                }
                            }
                        }
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("NotifySocketConnected response receiver dropped");
                        }
                    }
                    Some(Message::NotifySocketDisconnected(stream_id, addr, resp_tx)) => {
                        tracing::debug!("received NotifySocketDisconnected Message for stream id {}, addr {}", stream_id, addr);
                        if let Some((_, _)) = socket_info.remove(&(stream_id, addr)) {
                            tracing::info!("notified that socket for stream id {} and addr {} is disconnected", stream_id, addr);
                            tracing::info!("blackholing datagrams for stream id {} and addr {} for {:?}", stream_id, addr, DEFAULT_BLACKHOLE_DURATION);
                            blackholes.insert((stream_id, addr), tokio::time::Instant::now() + DEFAULT_BLACKHOLE_DURATION);
                        } else {
                            tracing::error!("no socket found for stream id {} and addr {}", stream_id, addr);
                            if resp_tx.send(Err(anyhow::anyhow!("no socket found for stream id {} and addr {}", stream_id, addr))).is_err() {
                                tracing::debug!("NotifySocketDisconnected response receiver dropped");
                            }
                            continue;
                        }
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("NotifySocketDisconnected response receiver dropped");
                        }
                    }
                    Some(Message::UnregisterContextId(stream_id, context_id, resp_tx)) => {
                        tracing::debug!("received UnregisterContextID Message for stream id {}, context id {}", stream_id, context_id);
                        if let Some(_) = compression_info.remove(&(stream_id, context_id)) {
                            tracing::info!("Unregistered context id {} for stream id {}", context_id, stream_id);
                        }
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("UnregisterContextId response receiver dropped");
                        }
                    }
                    None => {
                        tracing::debug!("channel closed");
                        return Ok(());
                    }
                }
            }
            datagram = datagram_reader.read_datagram() => {
                let datagram = match datagram {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!("recv datagram error: {}", e);
                        break;
                    }
                };
                let stream_id = datagram.stream_id();
                let datagram = datagram.into_payload();
                let Some((context_id, mut payload)): Option<(u64, &[u8])> = crate::decode_var_int(datagram.chunk()) else {
                    tracing::error!("failed to decode var int from datagram");
                    continue;
                };
                let addr = match compression_info.get(&(stream_id, context_id)) {
                    Some(Some(addr)) => *addr,
                    Some(None) => {
                        if payload.is_empty() {
                            tracing::error!(
                                "missing IP version byte in datagram with context id {}",
                                context_id
                            );
                            continue;
                        }
                        let ip_version = payload.get_u8();
                        match ip_version {
                            4 => {
                                if payload.len() < 6 {
                                    tracing::error!(
                                        "missing IPv4 address and port in datagram with context id {}",
                                        context_id
                                    );
                                    continue;
                                }
                                let ip = std::net::Ipv4Addr::from_octets(<[u8; 4]>::try_from(&payload[..4]).unwrap());
                                let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[4..6]).unwrap());
                                let addr = SocketAddr::new(std::net::IpAddr::V4(ip), port);
                                tracing::debug!("context id {} target {}", context_id, addr);
                                payload.advance(6);
                                addr
                            }
                            6 => {
                                if payload.len() < 18 {
                                    tracing::error!(
                                        "missing IPv6 address and port in datagram with context id {}",
                                        context_id
                                    );
                                    continue;
                                }
                                let ip = std::net::Ipv6Addr::from(<[u8; 16]>::try_from(&payload[..16]).unwrap());
                                let port = u16::from_be_bytes(<[u8; 2]>::try_from(&payload[16..18]).unwrap());
                                let addr = SocketAddr::new(std::net::IpAddr::V6(ip), port);
                                tracing::debug!("context id {} target {}", context_id, addr);
                                payload.advance(18);
                                addr
                            }
                            _ => {
                                tracing::error!(
                                    "unknown IP version {} in datagram with context id {}",
                                    ip_version, context_id
                                );
                                continue;
                            }
                        }
                    }
                    None => {
                        tracing::debug!("unknown context id {}", context_id);
                        continue;
                    }
                };
                tracing::debug!("received datagram for stream id {}, context id {}, addr {}", stream_id, context_id, addr);
                if !blackholes.is_empty() {
                    let dropping = if let Some(blackhole_until) = blackholes.get(&(stream_id, addr)) {
                        if *blackhole_until > tokio::time::Instant::now() {
                            true
                        } else {
                            blackholes.remove(&(stream_id, addr));
                            false
                        }
                    } else {
                        false
                    };
                    if dropping {
                        tracing::debug!("drop datagram because stream id {} and addr {} is blackholed", stream_id, addr);
                        continue;
                    }
                }
                let (socket, connected) = if let Some((socket, connected)) = socket_info.get(&(stream_id, addr)) {
                    (socket.clone(), *connected)
                } else {
                    let mode = match modes.get(&stream_id) {
                        Some(mode) => mode.clone(),
                        None => {
                            tracing::error!("unknown stream id {}", stream_id);
                            continue;
                        }
                    };
                    let socket = match mode {
                        crate::MasqueClientMode::Forward(forward_addr) => {
                            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.with_context(|| "failed to bind UDP socket")?);
                            socket.connect(forward_addr).await.with_context(|| "failed to connect UDP socket")?;
                            socket_info.insert((stream_id, addr), (socket.clone(), true));
                            if let Some(notification_tx) = notification_senders.get(&stream_id) {
                                if notification_tx
                                    .send(Notification::NewSocket(socket.clone(), addr, true))
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("notification receiver dropped for stream id {}", stream_id);
                                }
                            } else {
                                tracing::error!("no notification sender for stream id {}", stream_id);
                            }
                            socket
                        }
                        crate::MasqueClientMode::WebRTC => {
                            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.with_context(|| "failed to bind UDP socket")?);
                            socket_info.insert((stream_id.clone(), addr.clone()), (socket.clone(), false));
                            if let Some(notification_tx) = notification_senders.get(&stream_id) {
                                if notification_tx
                                    .send(Notification::NewSocket(socket.clone(), addr, false))
                                    .await
                                    .is_err()
                                {
                                    tracing::debug!("notification receiver dropped for stream id {}", stream_id);
                                }
                            } else {
                                tracing::error!("no notification sender for stream id {}", stream_id);
                            }
                            queued_datagrams.insert((stream_id.clone(), addr.clone()), Vec::new());
                            queued_datagrams.get_mut(&(stream_id, addr)).expect("failed to get queued datagrams").push(payload.to_vec());
                            continue;
                        },
                    };
                    (socket, true)
                };
                if !connected {
                    tracing::debug!("socket for stream id {} and addr {} is not connected yet, queuing datagram", stream_id, addr);
                    queued_datagrams.get_mut(&(stream_id, addr)).expect("failed to get queued datagrams").push(payload.to_vec());
                    continue;
                }
                tracing::debug!("sending datagram for stream id {} and addr {}", stream_id, addr);
                if let Err(err) = socket.send(payload).await {
                    tracing::error!("failed to send datagram: {:?}", err);
                    continue;
                }

            }
        }
    }
    anyhow::Ok(())
}
