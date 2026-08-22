//! Getting a peer connection off the relay: both halves of it.
//!
//! A peer connection starts on a MASQUE relay leg, which works and costs a
//! round trip through somebody else's machine. A direct path removes that, and
//! it takes both ends doing something before the first packet:
//!
//! ```text
//!   initiator                                        listener
//!   prepare()   ── candidate: its own leg's binding ──▶
//!               ◀── ADD_ADDRESS: this leg's binding ──   advertise()
//!                        …path validation…
//! ```
//!
//! **Neither half is any use alone**, which is why they are one module. The
//! initiator's candidate tells the peer where to send; the listener's
//! advertisement tells the initiator where to send. A connection with only one
//! of them stays on the relay and nothing says why — the failure is silence,
//! which is what most of the length of this file is about.
//!
//! `docs/p2p_mode_migration_plan.md` §2.2.3 is the design and §2.4 is the
//! registration rule the whole thing rests on. What is *not* here is what to do
//! once a path validates — preferring it, holding it as backup, giving up on
//! it — which belongs to whoever is carrying traffic over the connection.
//!
//! # It came out of the camera
//!
//! All of this was `camera-core::video`, and none of it was about video: portal
//! needs every line to get a forwarded connection off the relay, and a second
//! copy would fork exactly the parts nobody would think to check — which leg
//! belongs to which connection, and the ordering `set_unconnected_socket`
//! demands. Phase 4 of `docs/portal_plan.md`.

use std::collections::BTreeMap;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use msquic_async::Connection;
use tokio_util::sync::CancellationToken;

use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};

use crate::listener::LegDirectory;

/// How long to wait for the leg a connection arrived on to identify itself.
///
/// The leg records its forwarding socket when it creates one, which is when the
/// peer's first packet arrives — before the handshake this connection has just
/// finished. So it is normally already there and this is for the race, not for
/// the usual case.
const LEG_LOOKUP_WAIT: Duration = Duration::from_secs(3);
const LEG_LOOKUP_POLL: Duration = Duration::from_millis(50);

/// How an accepted connection is told which binding to punch to.
///
/// Two situations, and which one applies is not a detail: a listener with one
/// leg can hand its address to anybody, and a listener with several cannot.
#[derive(Clone)]
pub enum RelayLegs {
    /// One leg serves everybody, so every connection gets its address.
    ///
    /// What a single-peer harness has. Wrong for a listener serving several
    /// peers: each has a leg of its own, with a binding of its own.
    Single(ObservedAddressWatch),
    /// Legs told apart by the address a connection arrives from
    /// ([`LegDirectory`]).
    PerConnection(LegDirectory),
}

/// Put `conn` on a shared, unconnected socket and offer the relay leg's address
/// as a direct-path candidate. **Must run before `start`** — this is the
/// initiator's half.
///
/// The order is fixed: `set_unconnected_socket` requires a shared binding, and
/// an unconnected socket requires a specific — non-wildcard — local address.
/// That address is deliberately **loopback**: this connection's own traffic
/// goes to the relay bridge on `127.0.0.1`, and pinning it to a real interface
/// address instead cannot work on Windows at all. The direct path does not need
/// it, because `add_candidate_addr` accepts an address that is not bound here
/// yet — msquic opens the path from the relay leg's binding once the peer's
/// ADD_ADDRESS arrives (`docs/p2p_mode_migration_plan.md` §2.2.3).
pub fn prepare(conn: &Connection, candidate: ObservedAddress) -> anyhow::Result<()> {
    // All three are required for a direct path to be validated at all — without
    // them msquic never raises `PathValidated`, whatever candidate is offered.
    conn.set_share_binding(true)
        .map_err(|e| anyhow::anyhow!("could not share the UDP binding: {e}"))?;
    conn.set_unconnected_socket(true)
        .map_err(|e| anyhow::anyhow!("could not use an unconnected socket: {e}"))?;
    conn.set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| anyhow::anyhow!("could not pin the local address: {e}"))?;
    conn.add_candidate_addr(candidate.local, candidate.observed)
        .map_err(|e| anyhow::anyhow!("could not offer a direct-path candidate: {e}"))?;
    // Also offer the host address itself. A peer on the same LAN can reach it
    // directly, while the observed one is only reachable from outside the NAT —
    // and a NAT that does not hairpin (most of them) drops a packet sent from
    // inside to its own public address, so without this two peers behind the
    // same NAT can never find each other. Across the internet this candidate
    // simply fails to validate and the observed one wins.
    if candidate.local != candidate.observed {
        if let Err(e) = conn.add_candidate_addr(candidate.local, candidate.local) {
            tracing::debug!("could not offer the host candidate: {e}");
        }
    }
    tracing::info!(
        local = %candidate.local,
        observed = %candidate.observed,
        "offered direct-path candidates to the peer",
    );
    Ok(())
}

/// Tell `conn` about the binding of the leg **it** arrived on, so the peer can
/// punch a direct path to it and migrate off the relay. The listener's half.
///
/// **Which leg matters, and used not to be answerable.** Every leg delivers
/// here, and each has its own binding, so handing a connection the wrong leg's
/// address advertises a path the peer cannot reach — it stays on the relay, and
/// nothing says why. Worse, before this the newest address replaced whatever a
/// connection had, so a second peer arriving re-pointed the first peer's
/// connection at the new leg and stopped its relay traffic.
///
/// The answer is the address the connection came *from*: a leg forwards what it
/// receives from a socket of its own, so that socket's address names the leg
/// (see [`LegDirectory`]). What replaced the bug in between — take the first
/// address offered and never change it — was right only while legs came up in
/// the order their peers connected, which `Manual`, two near-simultaneous
/// peers, and a leg that reconnects all break.
///
/// Failures are logged, not fatal: an Endpoint that cannot advertise a direct
/// path simply keeps working over the relay.
pub fn advertise(conn: Connection, legs: RelayLegs, shutdown: CancellationToken) {
    tokio::spawn(async move {
        let Some(mut observed) = leg_of(&conn, &legs, &shutdown).await else {
            return;
        };
        // Applied once, and the `break` is what says so. Not because a later
        // address might be somebody else's — this now knows whose leg it is
        // watching — but because the binding is by then attached to the
        // connection, and a second `add_bound_addr` fails with
        // `QUIC_STATUS_ADDRESS_IN_USE`. So a leg that reconnects onto a new
        // binding is not re-advertised; the peer keeps the path it validated.
        loop {
            if let Some(address) = *observed.borrow_and_update() {
                apply(&conn, address);
                break;
            }
            tokio::select! {
                _ = shutdown.cancelled() => break,
                changed = observed.changed() => {
                    if changed.is_err() {
                        break;
                    }
                }
            }
        }
    });
}

/// The watch belonging to the leg `conn` came in on.
///
/// `None` means there is no direct path to advertise to this connection, and
/// says which of the two reasons it is: a connection that did not come through
/// a leg at all, or a leg that never identified itself in time.
async fn leg_of(
    conn: &Connection,
    legs: &RelayLegs,
    shutdown: &CancellationToken,
) -> Option<ObservedAddressWatch> {
    let directory = match legs {
        RelayLegs::Single(observed) => return Some(observed.clone()),
        RelayLegs::PerConnection(directory) => directory,
    };
    let peer = match conn.get_remote_addr() {
        Ok(peer) => peer,
        Err(e) => {
            tracing::warn!("could not read a connection's peer address; staying relay-only: {e}");
            return None;
        }
    };
    let deadline = tokio::time::Instant::now() + LEG_LOOKUP_WAIT;
    loop {
        if let Some(observed) = directory.leg_for(peer) {
            return Some(observed);
        }
        if tokio::time::Instant::now() >= deadline {
            // Two different things, and only one of them is fine.
            //
            // With no leg claiming any address, this is a connection that did
            // not come through a relay — something dialled the listener
            // directly — and relay-only is the right answer.
            //
            // With legs claiming addresses and none of them this one, the way a
            // leg is identified has stopped working (see [`LegDirectory`]), and
            // *every* connection is about to quietly lose its direct path. Said
            // loudly, because the symptom on its own is only that migration
            // never happens.
            match directory.claimed() {
                0 => tracing::debug!(%peer, "no relay leg has reported; staying relay-only"),
                claimed => tracing::warn!(
                    %peer,
                    claimed,
                    "no relay leg claims this connection, though others are claimed; \
                     staying relay-only",
                ),
            }
            return None;
        }
        tokio::select! {
            _ = shutdown.cancelled() => return None,
            _ = tokio::time::sleep(LEG_LOOKUP_POLL) => {}
        }
    }
}

fn apply(conn: &Connection, address: ObservedAddress) {
    if let Err(e) = conn.add_bound_addr(address.local) {
        tracing::warn!(
            local = %address.local,
            "could not add the relay leg's binding to the peer connection; \
             staying relay-only: {e}",
        );
        return;
    }
    if let Err(e) = conn.add_observed_addr(address.local, address.observed) {
        tracing::warn!(
            local = %address.local,
            observed = %address.observed,
            "could not advertise the observed address; staying relay-only: {e}",
        );
        return;
    }
    // Advertise the host address too — see the note in [`prepare`]: a peer on
    // the same LAN can only reach us there, because a NAT that does not hairpin
    // drops packets sent from inside to its own public address.
    if address.local != address.observed {
        if let Err(e) = conn.add_observed_addr(address.local, address.local) {
            tracing::debug!("could not advertise the host address: {e}");
        }
    }
    tracing::info!(
        local = %address.local,
        observed = %address.observed,
        "advertised a direct path to the peer",
    );
}

/// The connection's first path — the relay one — as msquic numbers it.
///
/// There is no event that names it: `PathAdded` reports paths that were opened
/// after a probe validated, and the path the handshake ran on was never probed.
/// It is `Paths[0]`, whose path id is 0.
const RELAY_PATH_ID: u32 = 0;

/// What a request to move onto a path turns into.
///
/// The two arms are the two worlds this has to work in at once, and which one
/// applies is decided by the peer rather than by us: multipath is negotiated, so
/// a viewer that has been updated still talks to cameras that have not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathPreference {
    /// Multipath: say which path carries traffic, and keep the rest warm.
    ///
    /// This is the operation that replaces switching, and it does two things at
    /// once. To the peer it sends PATH_AVAILABLE / PATH_BACKUP; locally it flips
    /// `Path->IsActive`, and `QuicConnChoosePath` picks at random among the
    /// active paths — so a path left available is a path this side really does
    /// send on. Declaring exactly one available is what makes "which path are we
    /// using" answerable.
    ///
    /// A path declared backup is still bound, still validated and still pinged
    /// by the path keepalive, so it does not decay while it waits — which is the
    /// whole of risk #24. That is the difference from switching: nothing is torn
    /// down, so coming back costs nothing.
    Declare { available: u32, backup: Vec<u32> },
    /// The peer never sent a `PathAdded`, so it has no multipath and the only
    /// operation available is the old switch.
    Switch,
}

/// Turn a request to move onto `wanted` into the operation to perform.
///
/// `direct_paths` is what `PathAdded` has named so far. Empty means the peer has
/// no multipath — and it stays empty for a path that only ever validated, which
/// is exactly the pre-multipath camera.
///
/// Everything known and not preferred is declared backup, not just the path
/// being left. Two candidates are offered whenever the observed address differs
/// from the host one, and both can validate on the same LAN, so "the other path"
/// is not always one path.
pub fn preference_for(
    wanted: (SocketAddr, SocketAddr),
    relay_path: (SocketAddr, SocketAddr),
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> PathPreference {
    if direct_paths.is_empty() {
        return PathPreference::Switch;
    }
    let available = if wanted == relay_path {
        RELAY_PATH_ID
    } else {
        match direct_paths.get(&wanted) {
            Some(id) => *id,
            // Validated but never added: the peer has multipath for some other
            // path and not for this one, which should not happen — switching is
            // still better than doing nothing.
            None => return PathPreference::Switch,
        }
    };
    let backup = std::iter::once(RELAY_PATH_ID)
        .chain(direct_paths.values().copied())
        .filter(|id| *id != available)
        .collect();
    PathPreference::Declare { available, backup }
}

/// Move the connection onto `wanted`, by whichever operation the peer supports.
///
/// **`false` means nothing changed**, and failures are logged rather than
/// returned upward: a connection that cannot be moved keeps working on the path
/// it is already on, which is worse than the caller asked for and much better
/// than dropping the connection. The answer exists so that a caller does not
/// record a move that did not happen — which would leave its own idea of which
/// path it is on disagreeing with the connection's.
pub fn prefer_path(
    conn: &Connection,
    wanted: (SocketAddr, SocketAddr),
    relay_path: (SocketAddr, SocketAddr),
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> bool {
    let (local, remote) = wanted;
    match preference_for(wanted, relay_path, direct_paths) {
        PathPreference::Declare { available, backup } => {
            // Demote first. Promoting first would leave a window with two
            // active paths, and msquic picks among them at random — so traffic
            // would split across both, which is the state this whole call
            // exists to avoid. The other order leaves a window with none, and
            // `QuicConnChoosePath` falls back to `Paths[0]`, the relay: still a
            // working path, which is the safe side to be wrong on.
            for id in &backup {
                if let Err(e) = conn.set_path_status(*id, false) {
                    tracing::warn!(path_id = id, "could not declare a path backup: {e}");
                }
            }
            match conn.set_path_status(available, true) {
                Ok(()) => {
                    tracing::info!(
                        %local, %remote, path_id = available, ?backup,
                        "declared a path available; every path stays active",
                    );
                    true
                }
                Err(e) => {
                    tracing::warn!(%local, %remote, "could not declare a path available: {e}");
                    false
                }
            }
        }
        PathPreference::Switch => match conn.activate_path(local, remote) {
            Ok(()) => {
                tracing::info!(%local, %remote, "activated path (the peer has no multipath)");
                true
            }
            Err(e) => {
                tracing::warn!(%local, %remote, "could not activate path: {e}");
                false
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([192, 168, 1, 59], port)),
            SocketAddr::from(([203, 0, 113, 5], port)),
        )
    }

    /// The relay pair, standing in for the loopback bridge the video connection
    /// actually runs over.
    fn relay() -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], 5000)),
            SocketAddr::from(([127, 0, 0, 1], 5001)),
        )
    }

    /// A camera without multipath never sends `PathAdded`, so there are no path
    /// ids and the only thing that can be done is what was always done.
    ///
    /// This is the mixed pair, and it is not hypothetical: cameras and viewers
    /// are updated separately, so an updated viewer meets old cameras for as
    /// long as the rollout takes.
    #[test]
    fn a_peer_without_multipath_still_gets_the_old_switch() {
        assert_eq!(
            preference_for(pair(1000), relay(), &BTreeMap::new()),
            PathPreference::Switch,
        );
    }

    /// With multipath, moving onto the direct path declares it available and the
    /// relay backup — and the relay is *kept*, which is the whole difference.
    #[test]
    fn moving_onto_the_direct_path_declares_the_relay_backup() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(pair(1000), relay(), &direct),
            PathPreference::Declare {
                available: 1,
                backup: vec![RELAY_PATH_ID],
            },
        );
    }

    /// And going back is the same operation with the preference reversed, not a
    /// different one — there is nothing to switch back to, because nothing was
    /// left.
    #[test]
    fn going_back_to_the_relay_is_the_same_operation_reversed() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(relay(), relay(), &direct),
            PathPreference::Declare {
                available: RELAY_PATH_ID,
                backup: vec![1],
            },
        );
    }

    /// Both candidates can validate at once — the host address and the observed
    /// one, which is what happens on the LAN behind the peer's own NAT — so
    /// "the other path" is not always a single path. Everything not preferred
    /// is declared backup, or the peer is left with two available paths and a
    /// preference that says nothing.
    #[test]
    fn every_path_that_is_not_preferred_is_declared_backup() {
        let direct = BTreeMap::from([(pair(1000), 1), (pair(2000), 2)]);
        assert_eq!(
            preference_for(pair(2000), relay(), &direct),
            PathPreference::Declare {
                available: 2,
                backup: vec![RELAY_PATH_ID, 1],
            },
        );
    }

    /// A pair that validated but was never added has no id to declare anything
    /// about. Switching is worse than declaring and much better than ignoring
    /// the request.
    #[test]
    fn a_path_with_no_id_falls_back_to_switching() {
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(pair(9999), relay(), &direct),
            PathPreference::Switch,
        );
    }
}
