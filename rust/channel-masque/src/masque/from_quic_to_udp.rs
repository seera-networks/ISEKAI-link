use anyhow::Context;
use bytes::Buf;
use h3::quic::StreamId;
use h3_datagram::{datagram_handler::DatagramReader, quic_traits::RecvDatagram};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, sync::mpsc, sync::oneshot};

const DEFAULT_BLACKHOLE_DURATION: std::time::Duration = std::time::Duration::from_secs(60);

/// How often a bounded session looks for sources that have gone quiet.
///
/// **Coarse on purpose.** What it bounds is how long a dead source's socket
/// outlives it, and a socket costs little for a few seconds; waking up often to
/// reclaim it would cost more than holding it.
const IDLE_SWEEP_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);

/// A source's socket, and when that source was last heard from.
///
/// **One entry, because two tables disagree.** Recency lived in a map of its
/// own and outlived the sockets it described — entries left behind by a read
/// error, or by a datagram arriving between an eviction and its teardown —
/// which then named sockets that no longer existed as the next thing to evict.
/// An eviction that frees nothing is a cap that drifts upward.
struct Forwarding {
    socket: Arc<UdpSocket>,
    connected: bool,
    last_seen: tokio::time::Instant,
}

impl Forwarding {
    fn new(socket: Arc<UdpSocket>, connected: bool) -> Self {
        Self {
            socket,
            connected,
            last_seen: tokio::time::Instant::now(),
        }
    }
}

/// What to do about a source that has no socket yet.
#[derive(Debug, PartialEq, Eq)]
enum Admit {
    /// Under the limit; bind one.
    Room,
    /// At the limit; this one has to go first.
    Evict((StreamId, SocketAddr)),
    /// At the limit with nothing to take it from. Drop the datagram.
    Refuse,
}

/// Whether a new source can have a socket, and at whose expense.
///
/// **Least recently used, which may be somebody real.** Nothing here can tell
/// a sender that matters from one that does not — that is what makes this a
/// bound rather than a judgement, and why the limit belongs well above the
/// audience a caller expects.
///
/// **Refusing is not the same as evicting.** With every socket held by a source
/// that has never been seen to send — which the bookkeeping should make
/// impossible, but the limit is the last line and should not depend on that —
/// there is nobody to take a slot from, and the only bound left is to not
/// grant one.
fn admit(
    stream_id: StreamId,
    addr: SocketAddr,
    limit: &crate::ForwardLimits,
    sockets: &HashMap<(StreamId, SocketAddr), Forwarding>,
) -> Admit {
    // **Counted from the same table the victim comes out of.** Counting one
    // table and choosing from another is how an eviction came to free nothing.
    //
    // O(sources) per new source, and only while at the limit — which under a
    // flood is every datagram. Bounded by `max_sources`, so it is a known cost
    // rather than an open one; an ordered index would trade work on every
    // datagram for work on these.
    let mut held = 0;
    let mut victim: Option<(&(StreamId, SocketAddr), &Forwarding)> = None;
    for (key, entry) in sockets.iter().filter(|((id, _), _)| *id == stream_id) {
        held += 1;
        if key.1 != addr && victim.is_none_or(|(_, quietest)| entry.last_seen < quietest.last_seen)
        {
            victim = Some((key, entry));
        }
    }
    if held < limit.max_sources {
        return Admit::Room;
    }
    victim
        .map(|(key, _)| Admit::Evict(*key))
        .unwrap_or(Admit::Refuse)
}

/// The sources that have said nothing for longer than their session allows.
///
/// **Only bounded sessions are swept.** A session with no limit has one peer
/// and holds one socket; reclaiming it for being quiet would end a leg that is
/// merely waiting.
fn gone_quiet(
    now: tokio::time::Instant,
    limits: &HashMap<StreamId, crate::ForwardLimits>,
    sockets: &HashMap<(StreamId, SocketAddr), Forwarding>,
) -> Vec<(StreamId, SocketAddr)> {
    sockets
        .iter()
        .filter(|((stream_id, _), entry)| {
            limits
                .get(stream_id)
                .is_some_and(|l| now.duration_since(entry.last_seen) >= l.idle_after)
        })
        .map(|(key, _)| *key)
        .take(MAX_RETIRED_PER_SWEEP)
        .collect()
}

/// Ask the reader to drop a source's socket, and forget when it last sent.
///
/// **The socket itself is not dropped here.** The reader holds its own handle,
/// so dropping this one would leave it being read with nothing on the other
/// side; retiring goes through the reader, which answers `SocketDisconnected`
/// — and that is what removes this side's entry. One teardown, two doors in.
async fn retire(
    notification_senders: &HashMap<StreamId, mpsc::Sender<Notification>>,
    key: (StreamId, SocketAddr),
    sockets: &mut HashMap<(StreamId, SocketAddr), Forwarding>,
    compression_info: &mut HashMap<(StreamId, u64), Option<SocketAddr>>,
) {
    let (stream_id, addr) = key;
    // **Freed here, not when the reader answers.** The slot has to come back
    // at the moment the decision is made, or the limit is soft by however deep
    // the pipeline is — under the flood it exists for, that is the limit again
    // in flight. Nothing else reads this entry afterwards; the reader keeps its
    // own handle until it is told, which is what the notification below is.
    sockets.remove(&key);
    compression_info.retain(|(id, _), mapped| *id != stream_id || *mapped != Some(addr));
    let Some(tx) = notification_senders.get(&stream_id) else {
        return;
    };
    if tx.send(Notification::RetireSocket(addr)).await.is_err() {
        tracing::debug!("notification receiver dropped for stream id {}", stream_id);
    }
}

/// How many sources one sweep may retire.
///
/// **A tick that retired a thousand would hold this loop for a thousand sends**
/// — and this loop serves every stream on the connection, relay legs included.
/// Idle sockets are not urgent; what is left waits for the next tick.
const MAX_RETIRED_PER_SWEEP: usize = 64;

pub enum Message {
    RegisterStreamId(
        StreamId,
        crate::MasqueClientMode,
        crate::InboundActivity,
        Option<crate::ForwardLimits>,
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
    /// **Stop reading this source's socket** — it was evicted (see
    /// [`crate::ForwardLimits`]).
    ///
    /// Retiring goes out through the same door a dead socket leaves by: the
    /// reader drops it and answers `SocketDisconnected`, which is what removes
    /// it here. One teardown, reached two ways, so an evicted socket cannot
    /// leave half of itself behind.
    RetireSocket(SocketAddr),
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

    /// `activity` is bumped for every datagram this stream receives, so a
    /// caller can tell a session that is carrying something from one that has
    /// gone quiet (see [`crate::InboundActivity`]).
    pub async fn register_stream_id(
        &self,
        mode: crate::MasqueClientMode,
        activity: crate::InboundActivity,
        limits: Option<crate::ForwardLimits>,
    ) -> anyhow::Result<mpsc::Receiver<Notification>> {
        let (notification_tx, notification_rx) = mpsc::channel(1024);
        let (resp_tx, resp_rx) = oneshot::channel();
        self.tx
            .send(Message::RegisterStreamId(
                self.stream_id,
                mode,
                activity,
                limits,
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
    let mut activity: HashMap<StreamId, crate::InboundActivity> = HashMap::new();
    let mut socket_info: HashMap<(StreamId, SocketAddr), Forwarding> = HashMap::new();
    let mut compression_info: HashMap<(StreamId, u64), Option<SocketAddr>> = HashMap::new();
    let mut queued_datagrams: HashMap<(StreamId, SocketAddr), Vec<Vec<u8>>> = HashMap::new();
    let mut blackholes: HashMap<(StreamId, SocketAddr), tokio::time::Instant> = HashMap::new();
    let mut limits: HashMap<StreamId, crate::ForwardLimits> = HashMap::new();
    // Bounded sessions are swept for idle sources; unbounded ones never tick.
    let mut sweep = tokio::time::interval(IDLE_SWEEP_INTERVAL);
    sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = sweep.tick(), if !limits.is_empty() => {
                let now = tokio::time::Instant::now();
                // A stream whose receiver is gone is over; sweeping on its
                // behalf keeps the timer alive for a session that ended.
                limits.retain(|stream_id, _| {
                    notification_senders
                        .get(stream_id)
                        .is_some_and(|tx| !tx.is_closed())
                });
                for key in gone_quiet(now, &limits, &socket_info) {
                    tracing::info!(
                        "retiring the socket for stream id {} and addr {}: idle",
                        key.0,
                        key.1,
                    );
                    retire(
                        &notification_senders,
                        key,
                        &mut socket_info,
                        &mut compression_info,
                    )
                    .await;
                }
            }
            msg = rx.recv() => {
                match msg {
                    Some(Message::RegisterStreamId(stream_id, mode, inbound, forward_limits, notification_tx, resp_tx)) => {
                        tracing::debug!("received RegisterStreamId Message for stream id {}", stream_id);
                        notification_senders.insert(stream_id, notification_tx);
                        modes.insert(stream_id, mode);
                        activity.insert(stream_id, inbound);
                        if let Some(forward_limits) = forward_limits {
                            limits.insert(stream_id, forward_limits);
                        }
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
                            entry.connected = true;
                            tracing::info!("notified that socket for stream id {} and addr {} is connected", stream_id, addr);
                            entry.socket.clone()
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
                        if socket_info.remove(&(stream_id, addr)).is_some() {
                            tracing::info!("notified that socket for stream id {} and addr {} is disconnected", stream_id, addr);
                            // **This arm is only ever a socket that died** —
                            // the local service refused it — where making
                            // another immediately would fail the same way. An
                            // eviction does not arrive here: it removes its own
                            // entry where the decision is made, so nothing
                            // comes back to be told apart, and nobody is
                            // blackholed for the limit this side chose.
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
                // Counted here, before anything can decide to drop it: what a
                // reader is asking is whether the far side is still sending,
                // and a datagram that arrived answers that whether or not this
                // end had somewhere to put it.
                if let Some(inbound) = activity.get(&stream_id) {
                    inbound.record();
                }
                let datagram = datagram.into_payload();
                let Some((context_id, mut payload)): Option<(u64, &[u8])> = crate::decode_var_int(datagram.chunk()) else {
                    tracing::error!("failed to decode var int from datagram");
                    continue;
                };
                // Concrete-target CONNECT-UDP forward proxy: deliver the
                // context-stripped payload straight to the client bridge instead
                // of resolving a per-peer socket. `try_send` drops on a full
                // channel, matching stateless UDP semantics.
                if let Some(crate::MasqueClientMode::ConnectUdp(tx)) = modes.get(&stream_id) {
                    if let Err(e) = tx.try_send(bytes::Bytes::copy_from_slice(payload)) {
                        tracing::debug!("connect-udp inbound drop for stream {}: {}", stream_id, e);
                    }
                    continue;
                }
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
                let (socket, connected) = if let Some(entry) = socket_info.get_mut(&(stream_id, addr)) {
                    // **Recorded on the entry that holds the socket**, so there
                    // is one answer to "is this source still here" rather than
                    // two that can disagree — a separate table of times outlived
                    // its sockets, and then named them as things to evict.
                    entry.last_seen = tokio::time::Instant::now();
                    (entry.socket.clone(), entry.connected)
                } else {
                    // **A new source, so the count has to hold.** Checked here
                    // rather than after binding: the cap is on how many sockets
                    // exist, and one that exists for a moment has still been
                    // taken from whoever the limit was protecting.
                    if let Some(limit) = limits.get(&stream_id).copied() {
                        match admit(stream_id, addr, &limit, &socket_info) {
                            Admit::Room => {}
                            Admit::Evict(victim) => {
                                tracing::warn!(
                                    "stream id {} is at its {} source limit; retiring {} to make room for {}",
                                    stream_id,
                                    limit.max_sources,
                                    victim.1,
                                    addr,
                                );
                                retire(
                                    &notification_senders,
                                    victim,
                                    &mut socket_info,
                                    &mut compression_info,
                                )
                                .await;
                            }
                            Admit::Refuse => {
                                tracing::warn!(
                                    "stream id {} is at its {} source limit with nothing to retire; dropping the datagram from {}",
                                    stream_id,
                                    limit.max_sources,
                                    addr,
                                );
                                continue;
                            }
                        }
                    }
                    let mode = match modes.get(&stream_id) {
                        Some(mode) => mode.clone(),
                        None => {
                            tracing::error!("unknown stream id {}", stream_id);
                            continue;
                        }
                    };
                    let socket = match mode {
                        crate::MasqueClientMode::Forward(forward_addr) => {
                            // The `connect` is not only about sending. It also
                            // decides the source address, which is what makes
                            // `local_addr` — reported as `NewRemoteHost`'s
                            // second field — the address `forward_addr` will
                            // see this traffic coming from. `isekai-p2p`'s
                            // `LegDirectory` identifies a relay leg by exactly
                            // that. Bound to the wildcard and left unconnected,
                            // it would report `0.0.0.0:p`, match nothing, and
                            // take every direct path down with it silently.
                            let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.with_context(|| "failed to bind UDP socket")?);
                            socket.connect(forward_addr).await.with_context(|| "failed to connect UDP socket")?;
                            socket_info.insert((stream_id, addr), Forwarding::new(socket.clone(), true));
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
                        crate::MasqueClientMode::ConnectUdp(_) => {
                            // Payloads for this mode are delivered to the client
                            // bridge above and never reach socket creation.
                            continue;
                        }
                        crate::MasqueClientMode::WebRTC => {
                            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.with_context(|| "failed to bind UDP socket")?);
                            socket_info.insert((stream_id, addr), Forwarding::new(socket.clone(), false));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    /// A `StreamId` for the tests. **Built through `VarInt`**, which is the
    /// only conversion h3 offers; the number itself means nothing here beyond
    /// telling two sessions apart.
    fn stream(n: u64) -> StreamId {
        StreamId::from(h3::proto::varint::VarInt::from_u64(n).expect("a small id"))
    }

    fn addr(port: u16) -> SocketAddr {
        format!("203.0.113.1:{port}").parse().unwrap()
    }

    fn limits(max_sources: usize, idle_secs: u64) -> crate::ForwardLimits {
        crate::ForwardLimits {
            max_sources,
            idle_after: Duration::from_secs(idle_secs),
        }
    }

    /// A socket table holding `(stream, port)` sources last heard from
    /// `seconds_ago`.
    fn sockets(entries: &[(StreamId, u16, u64)]) -> HashMap<(StreamId, SocketAddr), Forwarding> {
        let now = tokio::time::Instant::now();
        entries
            .iter()
            .map(|(stream_id, port, seconds_ago)| {
                let socket = Arc::new(
                    std::net::UdpSocket::bind("127.0.0.1:0")
                        .and_then(|s| {
                            s.set_nonblocking(true)?;
                            UdpSocket::from_std(s)
                        })
                        .expect("a loopback socket"),
                );
                let mut entry = Forwarding::new(socket, true);
                entry.last_seen = now - Duration::from_secs(*seconds_ago);
                ((*stream_id, addr(*port)), entry)
            })
            .collect()
    }

    /// **Under the limit, nothing is disturbed.** The bound exists for an
    /// address the public can reach; it must cost nothing until it binds.
    #[tokio::test]
    async fn room_is_room() {
        let held = sockets(&[(stream(0), 1, 0), (stream(0), 2, 0), (stream(0), 3, 0)]);
        assert_eq!(
            admit(stream(0), addr(9), &limits(4, 60), &held),
            Admit::Room
        );
    }

    /// **At the limit, the quietest source pays.** Which may be somebody real:
    /// nothing here can tell a sender that matters from one that does not, so
    /// this is a bound rather than a judgement.
    #[tokio::test]
    async fn the_least_recently_used_source_makes_room() {
        let s = stream(0);
        let held = sockets(&[(s, 1, 30), (s, 2, 90), (s, 3, 5)]);
        assert_eq!(
            admit(s, addr(9), &limits(3, 600), &held),
            Admit::Evict((s, addr(2))),
        );
    }

    /// **Counted and chosen from the same table.** Counting one and choosing
    /// from another is how an eviction came to free nothing: the victim named
    /// a socket that had already gone, the newcomer bound anyway, and the cap
    /// drifted up by one for every such entry.
    #[tokio::test]
    async fn another_sessions_sources_neither_count_nor_pay() {
        let mine = stream(0);
        let other = stream(4);
        let held = sockets(&[(other, 1, 600), (other, 2, 600), (mine, 3, 1)]);
        assert_eq!(
            admit(mine, addr(9), &limits(2, 600), &held),
            Admit::Room,
            "two of those three are not this session's",
        );
        assert_eq!(
            admit(mine, addr(9), &limits(1, 600), &held),
            Admit::Evict((mine, addr(3))),
            "and the victim is never taken from another session",
        );
    }

    /// With nothing to take a slot from, refusing is the only bound left —
    /// and it must not evict the very source asking for room.
    #[tokio::test]
    async fn nothing_to_evict_refuses_rather_than_evicting_the_newcomer() {
        let s = stream(0);
        let held = sockets(&[(s, 9, 0)]);
        assert_eq!(admit(s, addr(9), &limits(1, 600), &held), Admit::Refuse);
    }

    /// **A session with no limit is never swept.** It has one peer and holds
    /// one socket; reclaiming it for being quiet would end a leg that is
    /// merely waiting to hear something.
    #[tokio::test]
    async fn an_unbounded_session_is_left_alone() {
        let held = sockets(&[(stream(0), 1, 86_400)]);
        assert!(gone_quiet(tokio::time::Instant::now(), &HashMap::new(), &held).is_empty());
    }

    #[tokio::test]
    async fn a_source_past_its_sessions_idle_window_is_swept() {
        let s = stream(0);
        let mut by_stream = HashMap::new();
        by_stream.insert(s, limits(1024, 120));
        let held = sockets(&[(s, 1, 121), (s, 2, 119)]);
        assert_eq!(
            gone_quiet(tokio::time::Instant::now(), &by_stream, &held),
            vec![(s, addr(1))],
        );
    }

    /// **One tick may not retire everything it finds.** Each retirement is an
    /// awaited send on a channel the connection's event loop drains, and this
    /// loop serves every stream on that connection — so a sweep of a thousand
    /// would hold relay legs behind it. What is left waits for the next tick.
    #[tokio::test]
    async fn a_sweep_takes_only_so_many_at_once() {
        let s = stream(0);
        let mut by_stream = HashMap::new();
        by_stream.insert(s, limits(4096, 10));
        let entries: Vec<(StreamId, u16, u64)> = (1..=(MAX_RETIRED_PER_SWEEP as u16 + 50))
            .map(|p| (s, p, 60))
            .collect();
        let held = sockets(&entries);
        assert_eq!(
            gone_quiet(tokio::time::Instant::now(), &by_stream, &held).len(),
            MAX_RETIRED_PER_SWEEP,
        );
    }
}
