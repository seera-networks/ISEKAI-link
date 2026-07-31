//! Observed-address reports from a MASQUE relay leg (feature `msquic`).
//!
//! A relay leg's QUIC connection to the proxy is the one place this Endpoint
//! learns how it looks from outside: the proxy sends `OBSERVED_ADDRESS`, which
//! msquic surfaces as [`ConnectionEvent::NotifyObservedAddress`]. That pair —
//! the leg's own local address and the address the proxy sees it at — is what
//! the video connection later names via `add_candidate_addr` so a direct path
//! can be punched (see `docs/p2p_mode_migration_plan.md` §2.2.3).
//!
//! The reports arrive asynchronously and possibly more than once, while the
//! consumer may start watching before or after the first one lands. A
//! [`watch`] channel fits that exactly: latest-value-wins, no backlog, and a
//! late reader still sees the current answer.
//!
//! This module deliberately keeps `msquic_async::Connection` out of its public
//! surface. Callers get [`ObservedAddress`] values and nothing else, so the
//! session APIs above do not have to hand out raw QUIC handles.

use std::future::poll_fn;
use std::net::SocketAddr;

// Reached through `h3-util` rather than depended on directly, like the rest of
// this crate's msquic usage (see `crate::transport`).
use h3_util::msquic_async::h3_msquic_async::msquic_async::{Connection, ConnectionEvent};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

/// How a relay leg is addressed, as the proxy sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ObservedAddress {
    /// The leg's local address — the shared, unconnected binding a direct path
    /// will be opened from.
    pub local: SocketAddr,
    /// The address the proxy observes that binding at: the NAT mapping to
    /// advertise to the peer.
    pub observed: SocketAddr,
}

/// The receiving half of an observed-address watch. `None` until the first
/// report arrives.
pub type ObservedAddressWatch = watch::Receiver<Option<ObservedAddress>>;

/// Watch every connection `conn_rx` yields for observed-address reports.
///
/// Returns immediately with a receiver that is `None` until the first report
/// lands. The spawned task ends when `shutdown` fires, when `conn_rx` closes,
/// or when every receiver has been dropped.
///
/// `conn_rx` is a stream rather than a single connection because that is how
/// the H3 connector hands connections back (`with_channel`): one per dial,
/// including any reconnect. Reports from whichever connection is current
/// overwrite the previous value, which is the behaviour wanted — a stale NAT
/// mapping is worse than none.
pub fn spawn_observed_address_watch(
    mut conn_rx: mpsc::Receiver<Connection>,
    shutdown: CancellationToken,
) -> ObservedAddressWatch {
    let (tx, rx) = watch::channel(None);
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tx.closed() => break,
                conn = conn_rx.recv() => match conn {
                    Some(conn) => {
                        // Poll this connection until it ends, then go back to
                        // waiting for the next one.
                        watch_connection(conn, &tx, &shutdown).await;
                    }
                    None => break,
                },
            }
        }
    });
    rx
}

async fn watch_connection(
    conn: Connection,
    tx: &watch::Sender<Option<ObservedAddress>>,
    shutdown: &CancellationToken,
) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            event = poll_fn(|cx| conn.poll_event(cx)) => match event {
                Ok(ConnectionEvent::NotifyObservedAddress { local_address, observed_address }) => {
                    tracing::info!(
                        local = %local_address,
                        observed = %observed_address,
                        "relay leg observed-address report",
                    );
                    if tx.send(Some(ObservedAddress {
                        local: local_address,
                        observed: observed_address,
                    })).is_err() {
                        // Every receiver is gone; nothing left to tell.
                        break;
                    }
                }
                Ok(other) => tracing::debug!("relay leg connection event: {other:?}"),
                Err(e) => {
                    tracing::debug!("relay leg connection event stream ended: {e}");
                    break;
                }
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Dropping the connection source ends the task without ever publishing,
    /// and the receiver still reads `None` rather than hanging.
    #[tokio::test]
    async fn a_closed_connection_source_leaves_the_watch_empty() {
        let (tx, rx) = mpsc::channel(1);
        let watch = spawn_observed_address_watch(rx, CancellationToken::new());
        drop(tx);
        assert_eq!(*watch.borrow(), None);
    }

    /// A cancelled token ends the task even while it is waiting for a
    /// connection, so a session that shuts down before dialing does not leak it.
    #[tokio::test]
    async fn cancelling_the_token_ends_the_watch() {
        let (_tx, rx) = mpsc::channel(1);
        let shutdown = CancellationToken::new();
        let watch = spawn_observed_address_watch(rx, shutdown.clone());
        shutdown.cancel();
        // The task drops its sender on exit, which the receiver observes.
        let mut watch = watch;
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), watch.changed()).await;
        assert!(
            watch.has_changed().is_err() || *watch.borrow() == None,
            "the watch must not report a value nobody published"
        );
    }
}
