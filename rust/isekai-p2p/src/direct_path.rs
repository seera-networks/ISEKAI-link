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
//!   reoffer()   ── candidate: the leg's new binding ──▶
//!               ◀── ADD_ADDRESS: the new binding ─────   advertise(), again
//! ```
//!
//! **And both ends have to keep doing it.** Addresses move — a renewed DHCP
//! lease, SLAAC, a laptop changing network — and an offer naming the one the
//! leg used to have names nothing msquic can punch towards. So neither half
//! acts once: each watches its own leg for the life of the connection, which
//! is #358 and the reason the bottom two lines of the diagram exist.
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

use msquic_async::{msquic, Connection, ConnectionError};
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
/// A leg's report that really is on an unconnected binding, so a direct path
/// can be built from it.
///
/// **A connected socket's mapping is a real mapping and still useless here.**
/// `RelayOptions { unconnected: true }` is a request, and the connector
/// answers it with an ordinary connected socket on a CLAT/464XLAT host, when
/// nothing resolved could be bound, or when the QMUX fallback took over — see
/// [`Binding`]. There is no shared binding behind such a report, so a
/// candidate built from it cannot be validated however many packets the peer
/// aims at it: msquic never raises `PathValidated`, `advertise` has already
/// stopped watching, and the peer has spent its punch attempts. For
/// `Connected::QmuxFallback` it is not even a UDP mapping.
///
/// Relay-only is the right answer, and it is what this would have fallen back
/// to anyway — just without the wasted attempts, and with a line saying why.
///
/// **A type rather than an `if` at the top of each function.** The two places
/// that act on a report take this instead of an [`ObservedAddress`], so the
/// check cannot be forgotten or deleted: there is no other way to make one.
/// A test that the predicate is right does not show that it is *called*, and
/// neither of those functions can be unit-tested — they need a live msquic
/// connection — so the compiler is the only thing that can hold this.
struct UnconnectedLeg(ObservedAddress);

impl UnconnectedLeg {
    /// `None`, with a line saying why, when the leg is not on an unconnected
    /// binding. `side` names what is being given up, for the log.
    fn check(address: ObservedAddress, side: &str) -> Option<Self> {
        if address.binding.is_unconnected() {
            return Some(Self(address));
        }
        tracing::info!(
            local = %address.local,
            observed = %address.observed,
            binding = ?address.binding,
            "the relay leg is not on an unconnected binding, so there is no direct path to \
             {side}; staying relay-only",
        );
        None
    }
}

pub fn prepare(conn: &Connection, candidate: ObservedAddress) -> anyhow::Result<()> {
    let Some(candidate) = UnconnectedLeg::check(candidate, "offer") else {
        return Ok(());
    };
    offer(conn, candidate)
}

/// [`prepare`] once the leg is known to be able to carry a direct path.
///
/// Split out so the check is the only way in: taking [`UnconnectedLeg`] means
/// deleting it from `prepare` does not compile.
fn offer(conn: &Connection, UnconnectedLeg(candidate): UnconnectedLeg) -> anyhow::Result<()> {
    // All three are required for a direct path to be validated at all — without
    // them msquic never raises `PathValidated`, whatever candidate is offered.
    conn.set_share_binding(true)
        .map_err(|e| anyhow::anyhow!("could not share the UDP binding: {e}"))?;
    conn.set_unconnected_socket(true)
        .map_err(|e| anyhow::anyhow!("could not use an unconnected socket: {e}"))?;
    conn.set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .map_err(|e| anyhow::anyhow!("could not pin the local address: {e}"))?;
    add_candidates(conn, candidate)?;
    tracing::info!(
        local = %candidate.local,
        observed = %candidate.observed,
        "offered direct-path candidates to the peer",
    );
    Ok(())
}

/// The QUIC status behind a failure, where there is one. `None` for the
/// variants that report a connection going away rather than a parameter being
/// refused.
fn status_of(e: &ConnectionError) -> Option<msquic::StatusCode> {
    let ConnectionError::OtherError(status) = e else {
        return None;
    };
    status.try_as_status_code().ok()
}

/// `ADDRESS_IN_USE`, which from every add-address parameter in this module
/// means "msquic already has this".
///
/// That is success here, not failure: what the caller wanted the connection to
/// know, it knows. It is also not a corner case — it is the ordinary answer
/// when a leg returns to an address it held before on an IP of its own, which
/// [`withdraw`] leaves in place. Treated as an error it produces a warning
/// saying the session is stuck on the relay, about a candidate that is sitting
/// on the connection.
fn already_there(e: &ConnectionError) -> bool {
    status_of(e) == Some(msquic::StatusCode::QUIC_STATUS_ADDRESS_IN_USE)
}

/// `NOT_FOUND` from `remove_candidate_addr`: the pair is not on the
/// connection, which is the state the removal was asking for.
fn not_there(e: &ConnectionError) -> bool {
    status_of(e) == Some(msquic::StatusCode::QUIC_STATUS_NOT_FOUND)
}

/// The candidate pair on its own, without any of [`offer`]'s pre-`start`
/// setup.
///
/// Split out because this is the whole of what a *later* offer may do: the
/// three setters above are configuration a connection only accepts before it
/// starts, and a candidate is the one part of the offer a running connection
/// can still be told about — which is what [`reoffer`] rests on.
fn add_candidates(conn: &Connection, candidate: ObservedAddress) -> anyhow::Result<()> {
    if let Err(e) = conn.add_candidate_addr(candidate.local, candidate.observed) {
        if !already_there(&e) {
            anyhow::bail!("could not offer a direct-path candidate: {e}");
        }
    }
    // Also offer the host address itself. A peer on the same LAN can reach it
    // directly, while the observed one is only reachable from outside the NAT —
    // and a NAT that does not hairpin (most of them) drops a packet sent from
    // inside to its own public address, so without this two peers behind the
    // same NAT can never find each other. Across the internet this candidate
    // simply fails to validate and the observed one wins.
    //
    // **Both entries survive here, unlike in [`apply`] — and the second one is
    // still never used.** `QUIC_PARAM_CONN_ADD_CANDIDATE_ADDRESS` allocates a
    // list entry per `(host, observed)` pair, refusing only an exact duplicate
    // with `ADDRESS_IN_USE`, so adding a second does not destroy the first the
    // way the observed-address parameter does (see the note in `apply`). But
    // both entries carry the *same* `Address` — `candidate.local` — and in
    // `QUIC_ADD_ADDRESS_NAT_TRAVERSAL`, which is the mode this stack sets
    // (`peer.rs`), msquic only ever looks at one of them:
    // `QuicConnProcessAddAddress` takes `CandidateAddresses.Flink` for the new
    // path's local address under its own `TODO - Use the correct local address
    // based on the observed address`, and the PUNCH_ME_NOW builder scans the
    // list and breaks at the first entry matching the path's local address
    // (`send.c`). The first entry is the `(local, observed)` one, so that is
    // what is always sent.
    //
    // Kept rather than deleted: it costs nothing, it is what the parameter is
    // for, and it starts working the day that TODO is addressed. It is not
    // load-bearing today, and the comment above says so rather than letting
    // the next reader assume the LAN case is covered from this side.
    if candidate.local != candidate.observed {
        if let Err(e) = conn.add_candidate_addr(candidate.local, candidate.local) {
            if !already_there(&e) {
                tracing::debug!("could not offer the host candidate: {e}");
            }
        }
    }
    Ok(())
}

/// Take a superseded candidate off the connection — **only ever the one a new
/// pair would be shadowed by.**
///
/// msquic reads the *first* candidate whose host address matches the pair it
/// is considering, compared **by IP alone**: `QuicConnPunchableClientAddress`
/// uses `QuicAddrCompareIp`, and a table pair's local address carries no port
/// at all. A stale entry on the same IP is therefore not inert — it goes on
/// answering for that IP, and the pair appended behind it is never read. That
/// is what would otherwise make a leg rebinding onto a new port, or a NAT
/// mapping moving while the host address stays, a change no amount of offering
/// could fix: the punch request would keep naming the old observed address and
/// the probe would keep leaving from the old port.
///
/// **An entry on a different IP is left alone, and that is the whole of the
/// rule.** It answers for an IP of its own, so it shadows nothing; and on a
/// host that gained an address while keeping the old one, it is the candidate
/// a live path is running on. Withdrawing it would be deciding that an address
/// is gone, which this has no business deciding — what it does know is that
/// the leg reported a different binding on the *same* IP, and a leg has one
/// binding at a time.
fn withdraw(conn: &Connection, superseded: ObservedAddress, keeping: ObservedAddress) {
    // What the offer being kept consists of. A leg that moved only its
    // observed address — the NAT mapping changing under a binding that stayed
    // put — leaves `local` identical, so the host entry `(local, local)` is
    // one and the same entry in both offers. Removing it would take back half
    // of the offer this withdrawal exists to make effective. (A moved port
    // makes them different entries, and the old one does go.)
    let keep = [
        (keeping.local, keeping.observed),
        (keeping.local, keeping.local),
    ];
    // Both of what [`add_candidates`] may have added. The host entry is only
    // added when it differs, and the pair may have been withdrawn already, so
    // `not_there` is the ordinary answer rather than a problem.
    for (host, observed) in [
        (superseded.local, superseded.observed),
        (superseded.local, superseded.local),
    ] {
        if keep.contains(&(host, observed)) {
            continue;
        }
        if let Err(e) = conn.remove_candidate_addr(host, observed) {
            if !not_there(&e) {
                tracing::debug!(
                    %host,
                    %observed,
                    "could not withdraw the superseded direct-path candidate: {e}",
                );
            }
        }
    }
}

/// Keep the offer current as the leg's address changes, for the life of
/// `conn`. The initiator's other half, and the one [`prepare`] cannot be.
///
/// [`prepare`] offers the address the leg had just before the handshake, and
/// for a host whose addresses never move that is the whole story. They move: a
/// DHCP lease is renewed onto a different address, SLAAC renumbers, a laptop
/// leaves one network for another. The relay leg follows — it rebinds and
/// reports the new `(local, observed)` pair on the very watch [`prepare`]'s
/// candidate was read from — and until this, nothing on the initiator side
/// read that pair. #358 is what that cost: at the first change the direct path
/// dies, and the session carries every byte over the relay for the rest of its
/// life with nothing in either log to say why.
///
/// `candidate` is the one [`prepare`] was given, and is checked again here for
/// the reason the check inside says: a leg that cannot carry a direct path did
/// not get [`offer`]'s three pre-`start` settings either, and a candidate
/// added to a connection without those is probe packets that cannot validate.
///
/// # Why a candidate is nearly the whole of the fix
///
/// msquic does not punch towards a candidate; it punches towards the candidate
/// belonging to the pair it is considering, found by that pair's **local**
/// address (`QuicConnPunchableClientAddress`). The pair table is rebuilt from
/// the addresses the host currently has, so after renumbering every pair in it
/// names the new local address while the only candidate on the connection
/// names the old one. Nothing matches, NAT traversal refuses the pair, and no
/// punch is requested — a silence rather than an error. Adding the new pair
/// restores the match, and `QuicConnAddCandidateAddress` both accepts the call
/// on a started connection and ends in `QuicConnQueueReconcile`, so the pair
/// it unblocks is reconsidered at once instead of at the next unrelated event.
///
/// # And why it is only nearly
///
/// That lookup takes the *first* matching candidate and matches **by IP**, so
/// an offer is not enough on its own when the host address did not change —
/// a leg rebinding onto a new port, or a NAT mapping moving underneath it. The
/// stale entry keeps answering for that IP and the new pair is never read.
/// [`withdraw`] is that half, and its rule is narrow by design: the entry for
/// this same IP goes, and nothing else does.
pub fn reoffer(
    conn: Connection,
    mut observed: ObservedAddressWatch,
    candidate: ObservedAddress,
    shutdown: CancellationToken,
) {
    // The same question [`prepare`] asked, of the same value, so the two agree
    // by construction — which is what the gate at the call sites could not do
    // for itself: a report existing is not the connection having been set up
    // for a direct path.
    let Some(UnconnectedLeg(mut last)) = UnconnectedLeg::check(candidate, "offer again later")
    else {
        return;
    };
    tokio::spawn(async move {
        loop {
            // Read before waiting, because the watch may already have moved
            // on: the handshake rides across the peer's relay-bind gap and can
            // take minutes, and the address can change inside it.
            if let Some(address) = *observed.borrow_and_update() {
                // Only the pair matters. A report that carries the same pair
                // with a different binding kind has nothing for msquic, and
                // acting on it would re-send what it already knows.
                let moved = (address.local, address.observed) != (last.local, last.observed);
                // Kept watching where [`prepare`] gives up: the leg's binding
                // can change into one no direct path can run over, and back
                // again.
                if moved {
                    if let Some(UnconnectedLeg(address)) =
                        UnconnectedLeg::check(address, "offer again")
                    {
                        match add_candidates(&conn, address) {
                            Ok(()) => {
                                // Added first, withdrawn second: a removal
                                // queues a reconciliation pass of its own, so
                                // the order costs at most one pass that reads
                                // the stale entry, where the other order has a
                                // window with no candidate for this IP at all.
                                if address.local.ip() == last.local.ip() {
                                    withdraw(&conn, last, address);
                                }
                                last = address;
                                tracing::info!(
                                    local = %address.local,
                                    observed = %address.observed,
                                    "the relay leg moved; offered its new address as a \
                                     direct-path candidate",
                                );
                            }
                            Err(e) => tracing::warn!(
                                local = %address.local,
                                observed = %address.observed,
                                "could not offer the relay leg's new address, so this session \
                                 stays on the relay: {e:#}",
                            ),
                        }
                    }
                }
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
        // Re-applied as the leg's binding moves, where this used to `break`
        // out after the first one. The reason given was that "a second
        // `add_bound_addr` fails with `QUIC_STATUS_ADDRESS_IN_USE`" — which is
        // true of the *same* address and of nothing else:
        // `QuicConnAddBoundAddress` compares the full address against the ones
        // the connection already has and refuses only a duplicate. A leg that
        // rebinds onto a different address is therefore added as a second
        // bound address, given its observed address, and advertised in an
        // ADD_ADDRESS frame of its own. What the `break` cost is the listener
        // half of #358 — the peer renumbers and re-offers while this end
        // renumbers and says nothing, so there is nowhere left to punch to.
        //
        // The pair is tracked so an unchanged report does no work: the
        // advertisement is a frame, and `add_observed_addr` would send another
        // one saying what the peer was told last time.
        //
        // Nothing is withdrawn, and unlike on the initiator's side nothing
        // needs to be: a bound address is advertised to the peer, which looks
        // an advertised address up by matching it whole rather than by taking
        // the first entry on an IP, so a stale one shadows nothing — see
        // [`withdraw`] for the asymmetry. It costs the peer a pair it will
        // probe once and fail. What a withdrawal would cost is worse: a bound
        // address is a UDP binding this connection holds and may have a
        // validated path running over. The list is capped at
        // `QUIC_MAX_LOCAL_ADDRESS_COUNT` (128), so the growth is bounded
        // rather than merely slow.
        let mut applied: Option<(SocketAddr, SocketAddr)> = None;
        loop {
            if let Some(address) = *observed.borrow_and_update() {
                if applied != Some((address.local, address.observed)) {
                    // Kept watching where this used to `return`, for
                    // [`reoffer`]'s reason: a leg that comes back on a
                    // connected socket can come back again on an unconnected
                    // one.
                    if let Some(leg) = UnconnectedLeg::check(address, "advertise") {
                        if apply(&conn, leg) {
                            applied = Some((address.local, address.observed));
                        }
                    }
                }
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

/// Advertise one `(local, observed)` pair on `conn`. `false` means it was not
/// advertised, and the caller has nothing to record.
fn apply(conn: &Connection, UnconnectedLeg(address): UnconnectedLeg) -> bool {
    // An `already_there` here is the leg reporting a *new observed address*
    // for a local address this connection is already bound to. That is
    // something to advertise, and `add_observed_addr` below is what advertises
    // it — one bound address holds one observed address, and the second call
    // replaces what the first one said. Any other status is a refusal.
    if let Err(e) = conn.add_bound_addr(address.local) {
        if !already_there(&e) {
            tracing::warn!(
                local = %address.local,
                "could not add the relay leg's binding to the peer connection; \
                 staying relay-only: {e}",
            );
            return false;
        }
    }
    if let Err(e) = conn.add_observed_addr(address.local, address.observed) {
        tracing::warn!(
            local = %address.local,
            observed = %address.observed,
            "could not advertise the observed address; staying relay-only: {e}",
        );
        return false;
    }
    // **The host address is deliberately not advertised here, unlike in
    // [`prepare`].** The two msquic parameters these use look alike and are
    // not: `QUIC_PARAM_CONN_ADD_CANDIDATE_ADDRESS` allocates a list entry per
    // `(host, observed)` pair, so calling it twice offers two candidates,
    // while `QUIC_PARAM_CONN_ADD_OBSERVED_ADDRESS` finds the *bound* address
    // and copies over its one `ObservedAddress` field
    // (`QUIC_BOUND_ADDRESS_LIST_ENTRY` has exactly one, plus a flag). A second
    // call for the same local address does not add anything; it replaces what
    // the first one said.
    //
    // This used to do it anyway, with the same wording `prepare` carries. The
    // effect was that the host address overwrote the observed one, so the only
    // ADD_ADDRESS a peer ever received named a private address -- and across
    // the internet no direct path could form at all. Traced with LTTng against
    // a server on AWS: one `FrameLogAddAddress` carrying `172.31.12.127`, five
    // PATH_CHALLENGEs to it, zero PATH_RESPONSEs, `ConnPathValidationTimeout`,
    // path removed, session back on the relay. The public address the server
    // had advertised appeared nowhere in the trace.
    //
    // What that costs, stated fully: **two peers behind one NAT that does not
    // hairpin can no longer find each other at all.** It is tempting to say
    // "from this side, and the initiator's host candidate still covers it" —
    // it does not. Both of `prepare`'s candidate entries share one host
    // address, and in this stack's `NatTraversal` mode msquic reads only the
    // first of them, so the host candidate it adds is inert (the note there
    // has the detail). The same-LAN capability came from the overwriting call
    // removed here and nowhere else.
    //
    // Taken anyway, because the case it was breaking is the ordinary one: no
    // direct path at all for any peer not on the same LAN. One bound address
    // holds one observed address, so serving both wants something other than
    // calling this twice.
    tracing::info!(
        local = %address.local,
        observed = %address.observed,
        "advertised a direct path to the peer",
    );
    true
}

/// The connection's first path — the relay one — as msquic numbers it.
///
/// There is no event that names it: `PathAdded` reports paths that were opened
/// after a probe validated, and the path the handshake ran on was never probed.
/// It is `Paths[0]`, whose path id is 0.
///
/// **Only the first one.** A relay that restarts can be re-attached as a path
/// of its own (`docs/relay_repath_plan.md` P4), and that one was probed and
/// does carry an id — see [`RelayPath`].
pub const RELAY_PATH_ID: u32 = 0;

/// Which path the relay is on: the addresses it runs over and the id msquic
/// gave it.
///
/// **This was a constant until the relay could move.** Every connection had
/// exactly one relay path, the one the handshake ran on, so
/// [`RELAY_PATH_ID`] answered for all of them. Since P4 of
/// `docs/relay_repath_plan.md` a restarted relay is attached as a new path
/// with an id of its own, and a caller that still assumed 0 would declare the
/// *dead* path available and take the live one down with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelayPath {
    /// The local and remote addresses, which is how a path is named before it
    /// has an id and how one without multipath is named for ever.
    pub pair: (SocketAddr, SocketAddr),
    /// What msquic calls it. [`RELAY_PATH_ID`] for the path the handshake ran
    /// on; whatever `PathAdded` carried for one attached since.
    pub path_id: u32,
}

impl RelayPath {
    /// The path the handshake ran on, which is every connection's relay path
    /// until one is re-attached.
    pub fn first(pair: (SocketAddr, SocketAddr)) -> Self {
        Self {
            pair,
            path_id: RELAY_PATH_ID,
        }
    }
}

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
/// **"Empty" is the caller's claim, not an observation, and it is only true once
/// `PathAdded` has had its chance.** msquic raises `PathValidated` first and
/// `PathAdded` for the same path a fraction of a millisecond later, so a caller
/// that asks here the moment a path validates is told `Switch` about a peer that
/// does have multipath — and then performs the pre-multipath switch onto a path
/// that is about to be declared backup. `camera-core` never met this because a
/// person presses its button long afterwards; `portal-core::path` met it on the
/// first hardware run and waits for the id rather than asking early.
///
/// Everything known and not preferred is declared backup, not just the path
/// being left. Two candidates are offered whenever the observed address differs
/// from the host one, and both can validate on the same LAN, so "the other path"
/// is not always one path.
pub fn preference_for(
    wanted: (SocketAddr, SocketAddr),
    relay: RelayPath,
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> PathPreference {
    if direct_paths.is_empty() {
        return PathPreference::Switch;
    }
    let available = if wanted == relay.pair {
        relay.path_id
    } else {
        match direct_paths.get(&wanted) {
            Some(id) => *id,
            // Validated but never added: the peer has multipath for some other
            // path and not for this one, which should not happen — switching is
            // still better than doing nothing.
            None => return PathPreference::Switch,
        }
    };
    // **The relay's own id, not the constant.** A re-attached relay is on a
    // path msquic numbered itself, and the path numbered 0 is the dead one it
    // replaced — declaring *that* available is how a connection is moved onto
    // a leg that carries nothing.
    let backup = std::iter::once(relay.path_id)
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
    relay: RelayPath,
    direct_paths: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> bool {
    let (local, remote) = wanted;
    match preference_for(wanted, relay, direct_paths) {
        PathPreference::Declare { available, backup } => {
            // Demote first. Promoting first would leave a window with two
            // active paths, and msquic picks among them at random — so traffic
            // would split across both, which is the state this whole call
            // exists to avoid. The other order leaves a window with none, and
            // `QuicConnChoosePath` falls back to `Paths[0]` — which is a
            // working path on every connection that has only ever had one
            // relay.
            //
            // **Not on one whose relay has been re-attached.** `Paths[0]` is
            // then the *old* leg: abandoning it under multipath sets
            // `LocalClose` and leaves it where it is (`connection.c:8380`), so
            // the window falls back to a path that carries nothing. It is
            // still the safer side to be wrong on — a window of one round trip
            // against a split that persists — but it is no longer free, which
            // is why `portal_core::path` demotes the old relay path itself
            // rather than leaving it to this.
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
    use isekai_p2p_core::transport::{Binding, Connected};

    fn leg(binding: Binding) -> ObservedAddress {
        ObservedAddress {
            local: SocketAddr::from(([192, 168, 1, 59], 51000)),
            observed: SocketAddr::from(([203, 0, 113, 5], 51000)),
            binding,
        }
    }

    #[test]
    fn an_unconnected_leg_can_carry_a_direct_path() {
        assert!(UnconnectedLeg::check(leg(Binding::Unconnected), "advertise").is_some());
    }

    #[test]
    fn a_connected_leg_cannot_whatever_the_reason() {
        // Every reason the connector gives is the same answer here: there is
        // no shared binding behind the report, so a candidate built from it
        // can never be validated. `QmuxFallback` is not even a UDP mapping.
        for why in [
            Connected::AsAsked,
            Connected::ClatStub,
            Connected::NoRoutableAddress,
            Connected::QmuxFallback,
        ] {
            assert!(
                UnconnectedLeg::check(leg(Binding::Connected(why)), "advertise").is_none(),
                "{why:?} has no binding a direct path could use"
            );
        }
    }

    fn pair(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([192, 168, 1, 59], port)),
            SocketAddr::from(([203, 0, 113, 5], port)),
        )
    }

    /// The relay pair, standing in for the loopback bridge the video connection
    /// actually runs over.
    fn relay_pair() -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], 5000)),
            SocketAddr::from(([127, 0, 0, 1], 5001)),
        )
    }

    /// The relay as it is on every connection that has never re-attached one:
    /// the handshake's path, numbered 0.
    fn relay() -> RelayPath {
        RelayPath::first(relay_pair())
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
            preference_for(relay_pair(), relay(), &direct),
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

    /// **A re-attached relay is on its own path, and 0 is the dead one.** The
    /// pair moved and so did the id; reading either from where it used to be
    /// declares the path that stopped answering available and demotes the one
    /// that works.
    #[test]
    fn a_relay_that_moved_is_declared_by_the_id_it_moved_to() {
        let moved = RelayPath {
            pair: pair(7000),
            path_id: 7,
        };
        let direct = BTreeMap::from([(pair(1000), 1)]);
        assert_eq!(
            preference_for(pair(7000), moved, &direct),
            PathPreference::Declare {
                available: 7,
                backup: vec![1],
            },
            "going back to the relay means its new id",
        );
        assert_eq!(
            preference_for(pair(1000), moved, &direct),
            PathPreference::Declare {
                available: 1,
                backup: vec![7],
            },
            "and the relay it holds as backup is the new one too, not path 0",
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

    fn refused(code: msquic::StatusCode) -> ConnectionError {
        ConnectionError::OtherError(msquic::Status::new(code))
    }

    /// The two pieces of judgement in renewing an offer, and the only part of
    /// it that can be tested at all — everything else here needs a live msquic
    /// connection. Both directions matter: a status these fail to recognise
    /// becomes a warning about a session stuck on the relay, and one they
    /// recognise too widely swallows a real refusal and claims an offer that
    /// was never made.
    #[test]
    fn an_address_already_on_the_connection_is_not_a_failure() {
        use msquic::StatusCode::*;

        assert!(already_there(&refused(QUIC_STATUS_ADDRESS_IN_USE)));
        assert!(not_there(&refused(QUIC_STATUS_NOT_FOUND)));
        // Each predicate answers for its own status and no other — including
        // the other's, which is what keeps a refused *addition* from being
        // read as an already-absent removal.
        assert!(!already_there(&refused(QUIC_STATUS_NOT_FOUND)));
        assert!(!not_there(&refused(QUIC_STATUS_ADDRESS_IN_USE)));
        for other in [
            QUIC_STATUS_INVALID_STATE,
            QUIC_STATUS_INVALID_PARAMETER,
            QUIC_STATUS_OUT_OF_MEMORY,
        ] {
            assert!(
                !already_there(&refused(other.clone())) && !not_there(&refused(other.clone())),
                "{other:?} is a refusal and has to stay one",
            );
        }
        // Not every `ConnectionError` carries a status, and the ones that do
        // not are connections going away rather than addresses already held.
        for gone in [
            ConnectionError::ConnectionClosed,
            ConnectionError::ShutdownByLocal,
        ] {
            assert!(!already_there(&gone) && !not_there(&gone), "{gone:?}");
        }
    }
}
