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
use h3_util::msquic_async::{Binding, Established};
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
    /// The socket mode the leg actually ended up on.
    ///
    /// **Carried because asking for an unconnected binding is not getting
    /// one.** `RelayOptions { unconnected: true }` is a request; the connector
    /// answers it with an ordinary connected socket on a CLAT/464XLAT host,
    /// when nothing resolved can be bound, or when the QMUX fallback takes
    /// over. A report from such a leg is still a true NAT mapping and worth
    /// showing — `camera-server` prints it — but there is no shared binding
    /// behind it for a direct path to be opened from, which is the one thing a
    /// consumer must not assume. See [`Binding`].
    pub binding: Binding,
}

/// Every address the leg currently has a path in, in the order they were
/// reported.
///
/// **One entry per local IP, because that is the unit msquic acts on.** A
/// direct-path candidate is found by the local address of the pair being
/// considered, compared by IP alone and taking the first match
/// (`QuicConnPunchableClientAddress`), so two entries on one IP would mean the
/// second is never read. A second report for an IP therefore replaces the
/// first, in place, keeping the order the leg reported them in.
///
/// **A set rather than the latest one, as of #371.** This held a single value,
/// and a leg with paths in two families reports one per path: whichever landed
/// last was the only candidate offered, so a dual-stack end facing an
/// IPv4-only peer offered it an IPv6 address about half the time and no direct
/// path formed. The reports arrive milliseconds apart and before anything acts
/// on them, so there was nothing to notice and nothing to retry — the
/// behaviour depended on the order they happened to arrive in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservedAddresses(Vec<ObservedAddress>);

impl ObservedAddresses {
    /// Record a report, replacing whatever this IP had.
    fn record(&mut self, address: ObservedAddress) {
        match self
            .0
            .iter_mut()
            .find(|held| held.local.ip() == address.local.ip())
        {
            Some(held) => *held = address,
            None => self.0.push(address),
        }
    }

    /// Nothing has been reported yet.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// How many addresses the leg has a path in.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Every one of them, in the order they were first reported.
    pub fn iter(&self) -> impl Iterator<Item = &ObservedAddress> {
        self.0.iter()
    }

    /// The one reported most recently, for a caller that can show or use only
    /// one.
    ///
    /// **Say "one of several" where this is displayed.** A dual-stack leg has
    /// two, and which is newest is a race; `camera-server` prints this as the
    /// mapping the proxy sees, which is true of it and not the whole answer.
    /// Anything *choosing a path* wants [`iter`](Self::iter) instead — that is
    /// what #371 was.
    pub fn newest(&self) -> Option<ObservedAddress> {
        self.0.last().copied()
    }
}

impl FromIterator<ObservedAddress> for ObservedAddresses {
    /// In the order given, one entry per local IP — the last of a repeated IP
    /// wins, as a later report does.
    fn from_iter<I: IntoIterator<Item = ObservedAddress>>(iter: I) -> Self {
        let mut addresses = Self::default();
        for address in iter {
            addresses.record(address);
        }
        addresses
    }
}

/// The receiving half of an observed-address watch. Empty until the first
/// report arrives.
pub type ObservedAddressWatch = watch::Receiver<ObservedAddresses>;

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
///
/// Each report carries the socket mode its connection ended up on, rather than
/// being filtered on it here. The two consumers want different things: a
/// direct path can only be opened from an unconnected binding and must check,
/// while a display of "this is the mapping the proxy sees" is true and useful
/// either way. Filtering here would answer one of them by lying to the other.
///
/// # One slot, and a leg can now have several paths
///
/// `crate::transport` *offers* multipath on these connections — whether it is
/// negotiated is up to the proxy, which has to send `initial_max_path_id` back
/// — and where it is, a leg on a host with two usable addresses runs a path on
/// each. The proxy then reports an observed address per path, each naming its
/// own `local`, and this channel still holds one: what a reader sees is
/// whichever arrived last.
///
/// **Kept this way on purpose, because the consumer that matters is additive.**
/// `isekai_p2p::direct_path::reoffer` watches this and offers each new pair as
/// a direct-path candidate, withdrawing only the entry a new one would be
/// shadowed by — the one on the same address. Reports for genuinely different
/// addresses therefore accumulate as candidates rather than replacing each
/// other, which is what punching wants: more places the peer may reach this
/// Endpoint at.
///
/// What it does cost is the two readers that take a single value. The candidate
/// `prepare` offers before the handshake is whichever path reported first, and
/// a display of "the mapping the proxy sees" shows one of several without
/// saying so. Holding a report per local address would answer both, and would
/// change every consumer's shape; it is worth doing when something needs the
/// set rather than when it first becomes possible.
pub fn spawn_observed_address_watch(
    mut conn_rx: mpsc::Receiver<Established>,
    shutdown: CancellationToken,
) -> ObservedAddressWatch {
    let (tx, rx) = watch::channel(ObservedAddresses::default());
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => break,
                _ = tx.closed() => break,
                conn = conn_rx.recv() => match conn {
                    Some(Established { conn, binding }) => {
                        // **The set starts again with each connection.** A leg
                        // that reconnects has new bindings, and an address the
                        // old connection had a path in is not one this one
                        // does -- offering it would be the stale candidate
                        // #358 was about, arriving by another route.
                        tx.send_replace(ObservedAddresses::default());
                        // Poll this connection until it ends, then go back to
                        // waiting for the next one.
                        watch_connection(conn, binding, &tx, &shutdown).await;
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
    binding: Binding,
    tx: &watch::Sender<ObservedAddresses>,
    shutdown: &CancellationToken,
) {
    // The video connection opens its direct path *on this leg's binding*. If
    // that ever stops the leg receiving — because msquic opened a second socket
    // on the same address rather than sharing the binding, say — the counters
    // here are where it shows: the leg would keep sending to the proxy and stop
    // hearing back, at the same moment the video connection goes quiet.
    let mut stats_interval = tokio::time::interval(std::time::Duration::from_secs(1));
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = stats_interval.tick() => {
                if let Ok(stats) = conn.get_stats() {
                    tracing::debug!(
                        local = ?conn.get_local_addr().ok(),
                        remote = ?conn.get_remote_addr().ok(),
                        rtt_us = stats.Rtt,
                        send_packets = stats.Send.TotalPackets,
                        send_lost = stats.Send.SuspectedLostPackets,
                        recv_packets = stats.Recv.TotalPackets,
                        recv_dropped = stats.Recv.DroppedPackets,
                        "relay leg stats",
                    );
                }
            }
            event = poll_fn(|cx| conn.poll_event(cx)) => match event {
                Ok(ConnectionEvent::NotifyObservedAddress { local_address, observed_address }) => {
                    tracing::info!(
                        local = %local_address,
                        observed = %observed_address,
                        "relay leg observed-address report",
                    );
                    let mut addresses = tx.borrow().clone();
                    addresses.record(ObservedAddress {
                        local: local_address,
                        observed: observed_address,
                        binding,
                    });
                    if tx.send(addresses).is_err() {
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
        assert!(watch.borrow().is_empty());
    }

    fn report(local: &str) -> ObservedAddress {
        let local: SocketAddr = local.parse().expect("an address");
        ObservedAddress {
            local,
            observed: local,
            binding: Binding::Unconnected,
        }
    }

    /// **#371's own sequence.** A dual-stack leg against a relay that
    /// advertises alternative addresses reported three times, 3 ms apart: two
    /// IPv4 paths and one IPv6. Holding the last of them is what offered an
    /// IPv4-only peer an IPv6 address and nothing else.
    ///
    /// What the set has to keep is one entry per IP — the second IPv4 report
    /// replaces the first, because msquic reads a candidate by IP and takes the
    /// first match, so two entries on one IP would mean the second is never
    /// read — and both families, in the order they arrived.
    #[test]
    fn a_dual_stack_leg_keeps_an_address_in_each_family() {
        let addresses: ObservedAddresses = [
            report("10.0.2.10:33705"),
            report("10.0.2.10:37560"),
            report("[2001:db8:2::10]:57529"),
        ]
        .into_iter()
        .collect();

        assert_eq!(addresses.len(), 2, "one per IP, both families");
        let locals: Vec<String> = addresses.iter().map(|a| a.local.to_string()).collect();
        assert_eq!(
            locals,
            ["10.0.2.10:37560", "[2001:db8:2::10]:57529"],
            "the newer IPv4 report replaced the older one, in its place",
        );
        assert_eq!(
            addresses.newest().expect("two").local.to_string(),
            "[2001:db8:2::10]:57529",
            "and `newest` is still the last reported, which is what a display shows",
        );
    }

    /// A report for an address already held replaces it **in place**, so the
    /// order the leg reported its paths in survives. A set that reordered would
    /// make which candidate a one-value reader picks depend on the last
    /// re-report rather than on the leg.
    #[test]
    fn a_repeat_does_not_reorder_the_set() {
        let mut addresses: ObservedAddresses = [report("10.0.0.1:1"), report("10.0.0.2:2")]
            .into_iter()
            .collect();
        addresses.record(report("10.0.0.1:3"));

        let locals: Vec<String> = addresses.iter().map(|a| a.local.to_string()).collect();
        assert_eq!(locals, ["10.0.0.1:3", "10.0.0.2:2"]);
        assert_eq!(addresses.len(), 2);
    }

    /// Nothing reported is an empty set, not an entry that means nothing: every
    /// reader asks `is_empty` and the ones that act on addresses iterate.
    #[test]
    fn nothing_reported_is_empty() {
        let none = ObservedAddresses::default();
        assert!(none.is_empty());
        assert_eq!(none.len(), 0);
        assert_eq!(none.newest(), None);
        assert_eq!(none.iter().count(), 0);
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
            watch.has_changed().is_err() || watch.borrow().is_empty(),
            "the watch must not report an address nobody published"
        );
    }
}
