use axum::body::Bytes;
use bytes::{BufMut, BytesMut};
use futures::stream::{self, StreamExt};
use futures_concurrency::stream::StreamGroup;
use h3_datagram::{
    datagram_handler::{DatagramSender, SendDatagramError},
    quic_traits::SendDatagram,
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};

/// Object-safe wrapper for sending QUIC datagrams, enabling type erasure of the
/// concrete `DatagramSender<H, Bytes>` type so it can be carried through `ProxyState`.
pub trait ErasedSender: Send + 'static {
    fn send(&mut self, data: Bytes) -> Result<(), SendDatagramError>;
}

impl<H: SendDatagram<Bytes> + Send + 'static> ErasedSender for DatagramSender<H, Bytes> {
    fn send(&mut self, data: Bytes) -> Result<(), SendDatagramError> {
        self.send_datagram(data)
    }
}

pub enum Message {
    Start(
        mpsc::Sender<Notification>,
        oneshot::Sender<anyhow::Result<()>>,
    ),
    RegisterSocket(
        Arc<UdpSocket>,
        SocketAddr,
        bool, // whether the socket is connected (i.e. whether the remote address is fixed)
        oneshot::Sender<anyhow::Result<()>>,
    ),
    RegisterContextId(u64, Option<SocketAddr>, oneshot::Sender<anyhow::Result<()>>),
    UnregisterContextId(u64, oneshot::Sender<anyhow::Result<()>>),
    Finish(oneshot::Sender<anyhow::Result<()>>),
}

pub enum Notification {
    SocketConnected(SocketAddr),
    SocketDisconnected(SocketAddr),
    InvalidatedContextId(u64),
}

#[derive(Clone)]
pub struct Controller {
    tx: mpsc::Sender<Message>,
}

impl Controller {
    pub fn new(tx: mpsc::Sender<Message>) -> Self {
        Self { tx }
    }

    pub async fn start(&self) -> anyhow::Result<mpsc::Receiver<Notification>> {
        let (notification_tx, notification_rx) = mpsc::channel(1024);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::Start(notification_tx, resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send Start Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive Start response"))??;
        Ok(notification_rx)
    }

    pub async fn register_socket(
        &self,
        socket: Arc<UdpSocket>,
        remote_addr: SocketAddr,
        connected: bool,
    ) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterSocket(
                socket,
                remote_addr,
                connected,
                resp_tx,
            ))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterSocket Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterSocket response"))?
    }

    pub async fn register_context_id(
        &self,
        context_id: u64,
        addr: Option<SocketAddr>,
    ) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterContextId(context_id, addr, resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send RegisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive RegisterContextId response"))?
    }

    pub async fn unregister_context_id(&self, context_id: u64) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::UnregisterContextId(context_id, resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send UnregisterContextId Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive UnregisterContextId response"))?
    }

    pub async fn finish(&self) -> anyhow::Result<()> {
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::Finish(resp_tx))
            .await
            .map_err(|_| anyhow::anyhow!("Failed to send Finish Message"))?;
        resp_rx
            .await
            .map_err(|_| anyhow::anyhow!("Failed to receive Finish response"))?
    }
}

pub async fn thread(
    mut rx: mpsc::Receiver<Message>,
    mut datagram_sender: Box<dyn ErasedSender>,
) -> anyhow::Result<()> {
    let notification_tx = match rx.recv().await {
        Some(Message::Start(notification_tx, resp_tx)) => {
            tracing::debug!("received Start Message");
            if resp_tx.send(anyhow::Ok(())).is_err() {
                tracing::debug!("Start response receiver dropped");
            }
            notification_tx
        }
        Some(_) => {
            tracing::debug!("received unknown Message");
            return Ok(());
        }
        None => {
            tracing::debug!("channel closed");
            return Ok(());
        }
    };

    let mut udp_recv_keys = HashMap::new();
    let mut udp_recv_group = StreamGroup::new();
    let mut uncompressed_context_id = None;
    let mut compression_info = HashMap::new();
    loop {
        tokio::select! {
            msg = rx.recv() => {
                match msg {
                    Some(Message::Start(_, resp_tx)) => {
                        tracing::debug!("received unexpected Start Message");
                        if resp_tx
                            .send(Err(anyhow::anyhow!("unexpected Start Message")))
                            .is_err()
                        {
                            tracing::debug!("unexpected Start response receiver dropped");
                        }
                    }
                    Some(Message::RegisterSocket(socket, remote_addr, connected, resp_tx)) => {
                        let udp_recv = Box::pin(stream::unfold(
                            (socket, remote_addr.clone(), connected),
                            |(socket, remote_addr, mut connected)| async move {
                                let mut buf = [0; 65535];
                                if connected {
                                    match socket.recv(&mut buf).await {
                                        Ok(len) => Some((
                                            Ok((
                                                Bytes::copy_from_slice(&buf[..len]),
                                                remote_addr.clone(),
                                                false,
                                            )),
                                            (socket, remote_addr, connected),
                                        )),
                                        Err(err) => {
                                            tracing::error!("failed to receive udp datagram: {:?}", err);
                                            Some((
                                                Err((anyhow::anyhow!("failed to receive udp datagram: {:?}", err), remote_addr.clone())),
                                                (socket, remote_addr, connected),
                                            ))
                                        }
                                    }
                                } else {
                                    match socket.recv_from(&mut buf).await {
                                        Ok((len, addr)) => {
                                            tracing::info!("UDP socket received datagram from {}, connecting socket to this address", addr);
                                            if let Err(e) = socket.connect(addr).await {
                                                tracing::error!("failed to connect udp socket: {:?}", e);
                                                return None;
                                            }
                                            connected = true;
                                            Some((
                                                Ok((
                                                    Bytes::copy_from_slice(&buf[..len]),
                                                    remote_addr.clone(),
                                                    true,
                                                )),
                                                (socket, remote_addr, connected),
                                            ))
                                        },
                                        Err(err) => {
                                            tracing::error!("failed to receive udp datagram: {:?}", err);
                                            Some((
                                                Err((anyhow::anyhow!("failed to receive udp datagram: {:?}", err), remote_addr.clone())),
                                                (socket, remote_addr, connected),
                                            ))
                                        }
                                    }
                                }
                            },
                        ));
                        let key = udp_recv_group.insert(udp_recv);
                        udp_recv_keys.insert(remote_addr, key);
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("RegisterSocket response receiver dropped");
                        }
                    }
                    Some(Message::RegisterContextId(context_id, addr, resp_tx)) => {
                        if let Some(addr) = addr {
                            compression_info.insert(addr, context_id);
                            tracing::info!("registered compressed context id {} for addr {}", context_id, addr);
                        } else {
                            uncompressed_context_id = Some(context_id);
                            tracing::info!("registered uncompressed context id {}", context_id);
                        }
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("RegisterContextId response receiver dropped");
                        }
                    }
                    Some(Message::UnregisterContextId(context_id, resp_tx)) => {
                        if let Some(id) = &uncompressed_context_id {
                            if *id == context_id {
                                uncompressed_context_id = None;
                                tracing::info!("unregistered uncompressed context id {}", context_id);
                            }
                        }
                        let size = compression_info.len();
                        compression_info.retain(|_, &mut id| id != context_id);
                        if compression_info.len() < size {
                            tracing::info!("unregistered compressed context id {}", context_id);
                        }
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("UnregisterContextId response receiver dropped");
                        }
                    }
                    Some(Message::Finish(resp_tx)) => {
                        tracing::info!("received Finish Message, exiting");
                        if resp_tx.send(anyhow::Ok(())).is_err() {
                            tracing::debug!("Finish response receiver dropped");
                        }
                        break;
                    }
                    None => {
                        tracing::debug!("channel closed");
                        break;
                    }
                }
            }
            ret = udp_recv_group.next(), if !udp_recv_group.is_empty() => {
                let (data, addr) = match ret {
                    Some(Ok((data, addr, just_connected))) => {
                        if just_connected {
                            tracing::info!("UDP socket for {} connected", addr);
                            if let Err(e) = notification_tx.send(Notification::SocketConnected(addr)).await {
                                tracing::error!("failed to send socket connected notification: {:?}", e);
                            }
                        }
                        (data, addr)
                    }
                    Some(Err((_err, addr))) => {
                        let key = udp_recv_keys.remove(&addr);
                        if let Some(key) = key {
                            udp_recv_group.remove(key);
                        }
                        let context_id = compression_info.remove(&addr);

                        tracing::info!("UDP socket for {} disconnected", addr);
                        if let Err(e) = notification_tx.send(Notification::SocketDisconnected(addr)).await {
                            tracing::error!("failed to send socket disconnected notification: {:?}", e);
                        }
                        if let Some(context_id) = context_id {
                            tracing::info!("invalidated context id {} for addr {}", context_id, addr);
                            if let Err(e) = notification_tx.send(Notification::InvalidatedContextId(context_id)).await {
                                tracing::error!("failed to send invalidated context id notification: {:?}", e);
                            }
                        }

                        continue;
                    }
                    None => {
                        unreachable!();
                    }
                };
                tracing::debug!("received {} bytes to {}", data.len(), addr);
                let (context_id, compressed) = {
                    match compression_info.get(&addr) {
                        Some(id) => (*id, true),
                        None => match uncompressed_context_id {
                            Some(id) => (id, false),
                            None => {
                                tracing::debug!("no context id for uncompressed");
                                continue;
                            }
                        },
                    }
                };
                let mut datagram = BytesMut::new();
                datagram.extend_from_slice(&crate::encode_var_int(context_id));
                if !compressed {
                    match addr.ip() {
                        std::net::IpAddr::V4(ipv4) => {
                            datagram.put_u8(4); // IP version
                            datagram.extend_from_slice(&ipv4.octets());
                        }
                        std::net::IpAddr::V6(ipv6) => {
                            datagram.put_u8(6); // IP version
                            datagram.extend_from_slice(&ipv6.octets());
                        }
                    }
                    datagram.extend_from_slice(&addr.port().to_be_bytes());
                }
                datagram.extend_from_slice(&data);

                tracing::debug!("sending datagram {} bytes for context id {} to {}", datagram.len(), context_id, addr);
                if let Err(e) = datagram_sender.send(datagram.freeze()) {
                    tracing::warn!("send datagram error: {}", e);
                }
            }
        }
    }
    anyhow::Ok(())
}
