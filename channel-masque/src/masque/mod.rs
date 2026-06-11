pub mod from_quic_to_udp;
pub mod from_udp_to_quic;

use std::sync::Mutex;
use tokio::sync::mpsc;

pub struct ProxyState {
    pub from_udp_to_quic: self::from_udp_to_quic::Controller,
    pub from_quic_to_udp: self::from_quic_to_udp::Controller,
    /// The `datagram_sender` for the `from_udp_to_quic` thread.
    /// Consumed once by `MasqueClient` after authentication. The outer `Arc<ProxyState>`
    /// satisfies `Clone + Send + Sync + 'static` required by `http::Extensions`.
    pub datagram_sender: Mutex<Option<Box<dyn self::from_udp_to_quic::ErasedSender>>>,
    /// The receiver end of the channel feeding the `from_udp_to_quic` thread.
    /// Same consume-once rationale as `datagram_sender`.
    pub from_udp_to_quic_rx: Mutex<Option<mpsc::Receiver<self::from_udp_to_quic::Message>>>,
}
