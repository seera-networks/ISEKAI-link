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

use std::collections::BTreeMap;
use std::future::poll_fn;
use std::net::{IpAddr, SocketAddr};

// Reached through `h3-util` rather than depended on directly, like the rest of
// this crate's msquic usage (see `crate::transport`).
use h3_util::msquic_async::h3_msquic_async::msquic_async::{Connection, ConnectionEvent};
use h3_util::msquic_async::{Binding, Established};
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;

use crate::path_preference::OneActivePath;

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
/// **One entry per local address, which is one per path.** This held one entry
/// per local *IP*, and a second report on an IP replaced the first, because a
/// direct-path candidate is found by IP alone and taking the first match
/// (`QuicConnPunchableClientAddress`) -- so a second entry on an IP is one a
/// consumer could not use. That is still true of the consumers, and
/// [`one_per_ip`](Self::one_per_ip) is how they say so; it was never true of
/// the leg.
///
/// **A leg with the relay's alternative address on has two paths in one
/// family**, each from its own port on the same IP, and collapsing them cost
/// both of the only things this set is read for (#378). The server advertised
/// the second port as a bound address of its own, which the peer opened a
/// second direct path to -- one path slot out of four, held for the life of
/// the connection. The client read the same change as the leg having *moved*,
/// withdrew the candidate of the path carrying its traffic and offered the
/// backup path's instead. Neither end was wrong about its own rule; the set
/// had thrown away the fact that distinguishes a second path from a move.
///
/// So a path's report replaces only that path's entry, and
/// [`forget`](Self::forget) takes an entry away when its path does. What a
/// consumer that can use one address per IP should read is then a question with
/// an answer rather than a guess: the oldest live entry on each IP.
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
    /// Record a report, replacing whatever this local address had.
    ///
    /// The leg reports per path and a path keeps its local address, so a repeat
    /// is a new observed address for a path already known -- a NAT mapping that
    /// moved -- and belongs in that entry rather than in one of its own.
    fn record(&mut self, address: ObservedAddress) {
        match self.0.iter_mut().find(|held| held.local == address.local) {
            Some(held) => *held = address,
            None => self.0.push(address),
        }
    }

    /// Take away the entry a path that has gone reported, by its local address.
    ///
    /// **This is what makes [`one_per_ip`](Self::one_per_ip) answerable.**
    /// Preferring the oldest entry on an IP is only right while that entry is a
    /// path the leg still has; without this it would go on naming a dead one
    /// and the live path's mapping would never be offered, which is #358's
    /// silent failure. `PathRemoved` carries the path's local address, the same
    /// value its reports carried, so the entry can be found rather than aged
    /// out.
    ///
    /// This takes the address out of the *set*, which is what consumers read
    /// next; it does not reach the connections that were already told about it.
    /// `isekai_p2p::direct_path` withdraws a candidate only when a replacement
    /// on the same IP goes in front of it, and never withdraws a bound address,
    /// so an address alone on its IP goes on being offered until another on
    /// that IP takes over.
    ///
    /// `true` if an entry went, so the caller can publish only a real change.
    fn forget(&mut self, local: SocketAddr) -> bool {
        let before = self.0.len();
        self.0.retain(|held| held.local != local);
        self.0.len() != before
    }

    /// Retire an entry whose path is gone **and which is hiding another on its
    /// IP**, given the local addresses the connection still has a path on.
    ///
    /// **[`forget`](Self::forget) is not enough on its own, because
    /// `PathRemoved` is not raised for every path that goes away.** Of the
    /// eleven places seera-msquic removes a path, two indicate it: an abandon
    /// (local, the peer's, or a validation timeout) and loss detection giving
    /// up. A path taken off because its route stopped resolving, or because the
    /// reconciler found its local address gone, says nothing — and the entry it
    /// reported would then stay the oldest on its IP for the life of the leg,
    /// with `one_per_ip` handing it out while the live path's mapping on that
    /// IP is never offered. That is #358's silent failure, and the rule this
    /// replaced — a report replacing whatever its IP held — was immune to it
    /// by accident.
    ///
    /// **Only where it hides something**, which is the whole of the harm. An
    /// entry alone on its IP is the only answer there is for that IP, and
    /// whether the address is still there is not this type's to decide: a path
    /// nothing was told about is missing from `live` too, and retiring on that
    /// basis would throw away a candidate for no reason. Where two entries
    /// share an IP, one of them is being hidden, and preferring a live one is
    /// strictly better than preferring a dead one.
    ///
    /// `true` if anything went, so the caller can publish only a real change.
    fn retire_shadowed(&mut self, live: &[SocketAddr]) -> bool {
        let retiring: Vec<bool> = (0..self.0.len())
            .map(|i| {
                let held = self.0[i];
                !live.contains(&held.local)
                    && self.0[i + 1..]
                        .iter()
                        .any(|other| other.local.ip() == held.local.ip())
            })
            .collect();
        if !retiring.iter().any(|&retire| retire) {
            return false;
        }
        // `retain` visits each element once, in order, so the flags line up.
        let mut retiring = retiring.into_iter();
        self.0
            .retain(|_| !retiring.next().expect("one flag per entry"));
        true
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

    /// The oldest live entry on each IP, in the order the IPs were first
    /// reported — what a consumer that can act on one address per IP wants.
    ///
    /// **Both of this set's consumers are that consumer, for different
    /// reasons.** A direct-path candidate is read by IP alone and by the first
    /// match, so a second candidate on an IP is never consulted. A bound
    /// address advertised to the peer is read whole, so a second one on an IP
    /// *is* consulted -- and becomes another path, on a connection with four
    /// slots and a relay fallback to leave room for (#378).
    ///
    /// The oldest rather than the newest, because the oldest entry on an IP is
    /// the path the leg has been carrying its traffic on since it came up: the
    /// others are the backup paths `isekai_p2p_core::path_preference` holds in
    /// reserve, and a NAT mapping observed on a path nothing sends over is the
    /// one least worth punching to. When that path goes,
    /// [`forget`](Self::forget) takes its entry with it and the next one here
    /// is the next oldest.
    pub fn one_per_ip(&self) -> impl Iterator<Item = &ObservedAddress> {
        let mut seen: Vec<IpAddr> = Vec::new();
        self.0.iter().filter(move |address| {
            let ip = address.local.ip();
            if seen.contains(&ip) {
                return false;
            }
            seen.push(ip);
            true
        })
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
    /// In the order given, one entry per local address — the last report of a
    /// repeated address wins, as a later report does.
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
/// # One entry per path, and the leg has several
///
/// `crate::transport` *offers* multipath on these connections — whether it is
/// negotiated is up to the proxy, which has to send `initial_max_path_id` back
/// — and where it is, a leg runs a path on each usable address of the host,
/// plus one to each alternative address the relay advertises. The proxy reports
/// an observed address per path, each naming its own `local`, and the value
/// here holds all of them.
///
/// **It used to hold one entry per local IP, and before that a single value.**
/// Each collapse cost the consumer below the fact it needed. A single value
/// offered an IPv4-only peer an IPv6 address about half the time (#371); one
/// entry per IP made a leg's *second path in a family* — same IP, its own port
/// — indistinguishable from the first one moving, which had the client
/// withdraw the candidate of the path carrying its traffic and the server
/// advertise a bound address the peer spent a path slot on (#378).
///
/// So the collapsing is the consumer's to do, with
/// [`ObservedAddresses::one_per_ip`] where it is a consumer that can act on one
/// address per IP — both of `isekai_p2p::direct_path`'s are, for opposite
/// reasons — while a display that shows "the mapping the proxy sees" can say
/// "one of several" and
/// [`newest`](ObservedAddresses::newest) still answers it.
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

/// The local addresses `conn` still has a path on, as far as it will say.
///
/// Slot 0's, which is what `get_local_addr` reads and which always holds a
/// live path, plus every path this leg's loop was told about by `PathAdded`
/// that is still in the path statistics. A path nothing announced and that is
/// not in slot 0 is missing from this, which is why
/// `ObservedAddresses::retire_shadowed` only acts where an entry hides another.
fn live_addresses(conn: &Connection, announced: &BTreeMap<u32, SocketAddr>) -> Vec<SocketAddr> {
    let mut live: Vec<SocketAddr> = conn.get_local_addr().into_iter().collect();
    if let Ok(stats) = conn.get_path_statistics() {
        for path in stats {
            if let Some(local) = announced.get(&path.PathId) {
                live.push(*local);
            }
        }
    }
    live
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
    // One per connection: a leg that reconnects has new paths and new path ids.
    // Read before the first event is polled, which is what lets it recognise the
    // path the leg started on.
    let mut paths = OneActivePath::for_connection(&conn, "relay leg");
    // Which path each announced address belongs to, so a path that goes away
    // without saying so can still be noticed: its id leaves the statistics.
    let mut announced: BTreeMap<u32, SocketAddr> = BTreeMap::new();
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
                // **The backstop for a path that went away without saying so.**
                // Most of seera-msquic's path removals raise no event (see
                // `ObservedAddresses::retire_shadowed`), and an entry left
                // behind on an IP that has another path hides the live one.
                // Checked here rather than on a timer of its own: the
                // statistics are already being read, and a stale entry costs
                // nothing until something reads the set.
                let mut addresses = tx.borrow().clone();
                if addresses.retire_shadowed(&live_addresses(&conn, &announced)) {
                    tracing::info!(
                        "a relay leg path went away without an event; \
                         its address no longer hides the live one on its IP",
                    );
                    if tx.send(addresses).is_err() {
                        break;
                    }
                }
            }
            event = poll_fn(|cx| conn.poll_event(cx)) => {
                let event = match event {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::debug!("relay leg connection event stream ended: {e}");
                        break;
                    }
                };
                // **Every path event goes here first, because this loop is the
                // only thing polling them.** `poll_event` is a single-consumer
                // queue, so a leg's paths cannot be managed by a task of their
                // own alongside this one -- see [`crate::path_preference`] for
                // what it does with them and why a leg needs it.
                paths.observe(&conn, &event, "relay leg");
                match event {
                    ConnectionEvent::NotifyObservedAddress { local_address, observed_address } => {
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
                    ConnectionEvent::PathAdded { local_address, path_id, .. } => {
                        // The address this path reports is the address this
                        // path has, so the pair is what lets a removal that
                        // raises no event be noticed from the statistics.
                        announced.insert(path_id, local_address);
                        tracing::debug!(
                            local = %local_address,
                            path_id,
                            "a relay leg path was added",
                        );
                    }
                    ConnectionEvent::PathRemoved { local_address, path_id, .. } => {
                        announced.remove(&path_id);
                        // **An address this leg no longer has a path in is not
                        // an address to punch to.** The set keeps one entry per
                        // path so that a second path on an IP is not read as the
                        // first one moving (#378); the other half of that is
                        // taking an entry away when its path goes, or the oldest
                        // entry on an IP -- the one `one_per_ip` hands out --
                        // could name a path that died minutes ago while the live
                        // one is never offered.
                        let mut addresses = tx.borrow().clone();
                        if addresses.forget(local_address) {
                            // **What this does and does not do.** The entry
                            // goes, so the address stops being what `one_per_ip`
                            // hands out for its IP -- but nothing is taken off
                            // the peer connection here. `reoffer` withdraws a
                            // candidate only when it has a replacement on the
                            // same IP to put in front, and `advertise` never
                            // withdraws at all (removing a bound address would
                            // take the path over it down). So an address that
                            // was alone on its IP stays offered and advertised
                            // until something on that IP replaces it.
                            tracing::info!(
                                local = %local_address,
                                path_id,
                                "a relay leg path went away; its address is no longer \
                                 this IP's, though what was already offered stays",
                            );
                            if tx.send(addresses).is_err() {
                                break;
                            }
                        }
                    }
                    other => tracing::debug!("relay leg connection event: {other:?}"),
                }
            }
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

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("an address")
    }

    fn report(local: &str) -> ObservedAddress {
        let local: SocketAddr = addr(local);
        ObservedAddress {
            local,
            observed: local,
            binding: Binding::Unconnected,
        }
    }

    fn locals(addresses: impl Iterator<Item = ObservedAddress>) -> Vec<String> {
        addresses.map(|a| a.local.to_string()).collect()
    }

    /// **#371's own sequence.** A dual-stack leg against a relay that
    /// advertises alternative addresses reported three times, 3 ms apart: two
    /// IPv4 paths and one IPv6. Holding the last of them is what offered an
    /// IPv4-only peer an IPv6 address and nothing else.
    ///
    /// What a consumer has to be given is one address per IP — msquic reads a
    /// candidate by IP and takes the first match, so a second entry on an IP is
    /// never read — and both families, in the order they arrived. The set keeps
    /// all three, because the two IPv4 reports are two paths (#378); it is
    /// `one_per_ip` that answers #371's question.
    #[test]
    fn a_dual_stack_leg_offers_an_address_in_each_family() {
        let addresses: ObservedAddresses = [
            report("10.0.2.10:33705"),
            report("10.0.2.10:37560"),
            report("[2001:db8:2::10]:57529"),
        ]
        .into_iter()
        .collect();

        assert_eq!(addresses.len(), 3, "three paths, three entries");
        assert_eq!(
            locals(addresses.one_per_ip().copied()),
            ["10.0.2.10:33705", "[2001:db8:2::10]:57529"],
            "one per IP, both families, the IPv4 one being the path reported first",
        );
        assert_eq!(
            addresses.newest().expect("three").local.to_string(),
            "[2001:db8:2::10]:57529",
            "and `newest` is still the last reported, which is what a display shows",
        );
    }

    /// **#378's own sequence**, which is #371's with the relay's alternative
    /// address on: the leg comes up in IPv6, gains an IPv4 path to the
    /// alternative address, and a second later a *second IPv6* path to it from
    /// another local port.
    ///
    /// Read as "the leg moved", that third report withdrew the candidate of the
    /// path carrying the leg's traffic and had the server advertise a second
    /// bound address, which cost the peer connection a path slot it needed for
    /// its replacement relay path. What a consumer sees now is the IPv6 path
    /// the leg started on and the IPv4 one — the backup path's port is in the
    /// set, and offered to nobody.
    #[test]
    fn a_second_port_on_one_ip_is_a_second_path_not_a_move() {
        let mut addresses: ObservedAddresses = [
            report("[2001:db8:2::10]:41024"),
            report("10.0.2.10:35303"),
            report("[2001:db8:2::10]:56938"),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            locals(addresses.one_per_ip().copied()),
            ["[2001:db8:2::10]:41024", "10.0.2.10:35303"],
            "the path the leg started on, not the backup path's port",
        );

        // The path it started on goes away: now the backup's port is the only
        // IPv6 path the leg has, and it is what should be offered.
        assert!(addresses.forget(addr("[2001:db8:2::10]:41024")));
        assert_eq!(
            locals(addresses.one_per_ip().copied()),
            ["10.0.2.10:35303", "[2001:db8:2::10]:56938"],
            "the next oldest path on the IP takes over",
        );
    }

    /// **The removal that raises no event.** Of the eleven places seera-msquic
    /// removes a path, two indicate it; a path whose route stopped resolving,
    /// or whose local address the reconciler found gone, says nothing. The
    /// entry stays — and if its IP has since gained another path, it is the
    /// oldest on that IP and hides the live one for the life of the leg. The
    /// address going away and coming back on a fresh port is the sequence that
    /// does it, and the rule this set used to follow was immune by accident.
    #[test]
    fn an_entry_whose_path_went_quietly_stops_hiding_the_live_one() {
        let mut addresses: ObservedAddresses = [
            report("[2001:db8:2::10]:41024"),
            report("10.0.2.10:35303"),
            report("[2001:db8:2::10]:56938"),
        ]
        .into_iter()
        .collect();

        // The leg has all three: nothing is hiding anything that is gone.
        let all = [
            addr("[2001:db8:2::10]:41024"),
            addr("10.0.2.10:35303"),
            addr("[2001:db8:2::10]:56938"),
        ];
        assert!(!addresses.retire_shadowed(&all));
        assert_eq!(addresses.len(), 3);

        // The IPv6 path it started on is gone, and said nothing.
        let live = [addr("10.0.2.10:35303"), addr("[2001:db8:2::10]:56938")];
        assert!(addresses.retire_shadowed(&live));
        assert_eq!(
            locals(addresses.one_per_ip().copied()),
            ["10.0.2.10:35303", "[2001:db8:2::10]:56938"],
            "the live IPv6 path is what the IP answers with now",
        );
        assert!(
            !addresses.retire_shadowed(&live),
            "and there is nothing left to retire",
        );
    }

    /// **An entry alone on its IP is left alone, however unreachable it looks.**
    /// A path nothing announced is missing from the live list too, so retiring
    /// on that basis would throw away the only candidate an IP has for no
    /// reason. `forget` is what retires it, when the connection says so.
    #[test]
    fn an_entry_hiding_nothing_is_not_retired() {
        let mut addresses: ObservedAddresses =
            [report("10.0.2.10:35303"), report("[2001:db8:2::10]:41024")]
                .into_iter()
                .collect();

        assert!(!addresses.retire_shadowed(&[]), "neither hides the other");
        assert_eq!(addresses.len(), 2);
    }

    /// A path that was never reported takes nothing away, and says so — the
    /// caller publishes only a real change.
    #[test]
    fn forgetting_an_address_the_leg_never_reported_changes_nothing() {
        let mut addresses: ObservedAddresses = [report("10.0.2.10:35303")].into_iter().collect();

        assert!(
            !addresses.forget(addr("10.0.2.10:40000")),
            "same IP, other port"
        );
        assert!(!addresses.forget(addr("10.0.2.11:35303")), "other IP");
        assert_eq!(addresses.len(), 1);
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
        // The same path reporting again: its NAT mapping moved, which belongs
        // in its own entry and nowhere else.
        addresses.record(ObservedAddress {
            observed: addr("203.0.113.9:9"),
            ..report("10.0.0.1:1")
        });

        assert_eq!(
            locals(addresses.iter().copied()),
            ["10.0.0.1:1", "10.0.0.2:2"]
        );
        assert_eq!(addresses.len(), 2);
        assert_eq!(
            addresses.iter().next().expect("two").observed.to_string(),
            "203.0.113.9:9",
            "in place, with the new mapping",
        );
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
