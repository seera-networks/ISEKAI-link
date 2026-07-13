//! Concrete-target CONNECT-UDP forward proxy — the P2P relay **initiator** leg.
//!
//! Bridges a local UDP socket to a remote target through the MASQUE proxy, per
//! the required spec:
//!
//! 1. Open a UDP socket.
//! 2. `recv_from` the socket, **record the source address** the datagram came
//!    from, and send the datagram to the remote through CONNECT-UDP.
//! 3. When a datagram arrives from the remote through CONNECT-UDP, `send_to` the
//!    socket using the recorded source address.
//!
//! Datagrams are framed as uncompressed HTTP Datagrams — context id `0` — which
//! is what the proxy's concrete-target CONNECT-UDP handler forwards to the URL
//! target. This module owns the socket bridge and the recorded-source logic;
//! the transport wiring (opening the CONNECT-UDP session, supplying `tx` and
//! `inbound`) is layered on top.

use std::net::SocketAddr;
use std::sync::Arc;

use bytes::{Bytes, BytesMut};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Sink for HTTP Datagram payloads destined for the CONNECT-UDP tunnel. The
/// bytes already include the leading context id; the implementor forwards them
/// to the QUIC datagram sender of an established CONNECT-UDP session.
pub trait DatagramTx: Send {
    fn send(&mut self, datagram: Bytes) -> anyhow::Result<()>;
}

/// Frame a UDP payload as an uncompressed (context id `0`) HTTP Datagram.
fn frame_context0(payload: &[u8]) -> Bytes {
    let mut d = BytesMut::with_capacity(payload.len() + 1);
    d.extend_from_slice(&crate::encode_var_int(0));
    d.extend_from_slice(payload);
    d.freeze()
}

/// Run the bidirectional bridge between the local `socket` and the CONNECT-UDP
/// tunnel until `shutdown` fires.
///
/// - **Uplink:** each datagram read from `socket` records its source and is
///   framed with context id `0` and sent via `tx`.
/// - **Downlink:** each payload from `inbound` (already context-stripped by the
///   transport layer) is `send_to` the most recently recorded source. A
///   downlink datagram that arrives before any uplink datagram (no source known
///   yet) is dropped, mirroring stateless UDP.
///
/// Uplink and downlink share one task, so the recorded source needs no locking.
pub async fn run_bridge(
    socket: Arc<UdpSocket>,
    mut tx: impl DatagramTx,
    mut inbound: mpsc::Receiver<Bytes>,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let mut last_src: Option<SocketAddr> = None;
    // Max UDP payload; oversized datagrams are truncated by the OS on recv.
    let mut buf = vec![0u8; 65_535];
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            r = socket.recv_from(&mut buf) => {
                let (n, src) = r?;
                last_src = Some(src);
                if let Err(e) = tx.send(frame_context0(&buf[..n])) {
                    tracing::error!("connect-udp uplink send failed: {e}");
                    break;
                }
            }
            payload = inbound.recv() => {
                let Some(payload) = payload else {
                    tracing::debug!("connect-udp inbound channel closed");
                    break;
                };
                match last_src {
                    Some(dst) => {
                        if let Err(e) = socket.send_to(&payload, dst).await {
                            tracing::warn!("connect-udp downlink send_to {dst} failed: {e}");
                        }
                    }
                    None => tracing::debug!(
                        "connect-udp downlink datagram dropped: no local source recorded yet"
                    ),
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    struct ChanTx(mpsc::UnboundedSender<Bytes>);
    impl DatagramTx for ChanTx {
        fn send(&mut self, d: Bytes) -> anyhow::Result<()> {
            self.0.send(d).map_err(|_| anyhow::anyhow!("tx closed"))
        }
    }

    #[test]
    fn frame_context0_prepends_zero_context() {
        let framed = frame_context0(b"hello");
        let (ctx, rest) = crate::decode_var_int(&framed).expect("valid varint");
        assert_eq!(ctx, 0);
        assert_eq!(rest, b"hello");
    }

    #[tokio::test]
    async fn bridge_records_source_and_replies_to_it() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_addr = sock.local_addr().unwrap();
        // A local "application" that talks to the bridge socket.
        let app = UdpSocket::bind("127.0.0.1:0").await.unwrap();

        let (up_tx, mut up_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_bridge(
            sock.clone(),
            ChanTx(up_tx),
            in_rx,
            shutdown.clone(),
        ));

        // Uplink: app -> bridge socket -> tx, framed as context 0.
        app.send_to(b"ping", sock_addr).await.unwrap();
        let framed = tokio::time::timeout(Duration::from_secs(1), up_rx.recv())
            .await
            .expect("uplink within timeout")
            .expect("uplink datagram");
        let (ctx, payload) = crate::decode_var_int(&framed).unwrap();
        assert_eq!(ctx, 0);
        assert_eq!(payload, b"ping");

        // Downlink: inbound payload -> bridge -> app at the recorded source.
        in_tx.send(Bytes::from_static(b"pong")).await.unwrap();
        let mut rbuf = [0u8; 16];
        let (n, from) = tokio::time::timeout(Duration::from_secs(1), app.recv_from(&mut rbuf))
            .await
            .expect("downlink within timeout")
            .unwrap();
        assert_eq!(&rbuf[..n], b"pong");
        assert_eq!(from, sock_addr, "reply comes from the bridge socket");

        shutdown.cancel();
        let _ = handle.await;
    }

    #[tokio::test]
    async fn downlink_before_any_uplink_is_dropped() {
        let sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (up_tx, _up_rx) = mpsc::unbounded_channel();
        let (in_tx, in_rx) = mpsc::channel(8);
        let shutdown = CancellationToken::new();
        let handle = tokio::spawn(run_bridge(sock, ChanTx(up_tx), in_rx, shutdown.clone()));

        // No uplink has recorded a source, so this payload is dropped (no panic).
        in_tx.send(Bytes::from_static(b"orphan")).await.unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;

        shutdown.cancel();
        assert!(handle.await.is_ok());
    }
}
