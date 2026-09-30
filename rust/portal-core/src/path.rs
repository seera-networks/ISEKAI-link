//! Moving a forward off the relay once a direct path exists.
//!
//! **Phase 4 of `docs/portal_plan.md`.** [`isekai_p2p::direct_path`] is how the
//! two ends find a direct path; this is what portal does with one when it turns
//! up. The initiator's side, because the initiator is the end that decides which
//! path carries traffic.
//!
//! ```text
//!   PathValidated  ─▶ wait a moment for a path id
//!   PathAdded      ─▶ preferred, by path id      (the peer has multipath)
//!   …no PathAdded  ─▶ preferred, by address pair (it does not)
//!   PathRemoved    ─▶ back to the relay          (if it was the preferred one)
//!
//!   the leg goes   ─▶ there is nowhere to fall back to
//!   a leg replaces ─▶ add_path to it, and wait for its PathAdded
//!   its PathAdded  ─▶ the relay is *here* now; abandon the path it replaced
//! ```
//!
//! # The relay is not one path for ever
//!
//! The bottom three lines are P4 of `docs/relay_repath_plan.md`, and they are
//! the reason [`Paths`] keeps a [`RelayPath`] rather than a pair. A relay that
//! restarts takes its MASQUE tunnel with it; the session stands a new leg up at
//! a new loopback address, and this loop attaches it as a path of the
//! connection that was already running.
//!
//! **The same `PathAdded` announces both kinds of path**, which is the whole
//! hazard. Read as a direct path, a replacement relay leg would be *preferred*
//! — taking forwarding off a working direct path and putting it on a relay,
//! with the per-second statistics labelled `direct` while it happened. So
//! every address a relay leg has ever answered on is remembered, and a
//! `PathAdded` naming one is the relay coming back rather than somewhere to
//! move onto.
//!
//! **And opening a path is not the same as having one.** `add_path` returns
//! before a single probe has been answered, and there is a narrow window in
//! which no probe is ever sent — msquic queues a `PATH_CHALLENGE` only for a
//! path that already has a destination connection id, and ids arrive nowhere
//! but the receive path (`docs/relay_repath_plan.md` §0.1.1). So the relay
//! becomes usable when msquic announces the path, not when this loop asks for
//! it, and a path that is never announced is given up on out loud rather than
//! waited for in silence.
//!
//! # Which event decides, and why it is not the obvious one
//!
//! **`PathValidated` arrives first and cannot be acted on.** It carries the
//! addresses and no path id, and every multipath operation needs the id — so a
//! preference made there is necessarily the *other* kind, the pre-multipath
//! `activate_path` switch. Hardware said so on the first run: `PathValidated`,
//! a switch logged as "the peer has no multipath", and then `PathAdded` for the
//! same path 140µs later, which is the peer having multipath. The connection was
//! switched onto a path that was then declared backup, leaving this end
//! believing it was on the direct path while msquic sent over the relay.
//!
//! So the id is what decides. `PathAdded` is raised when a path completes
//! validation *and* multipath was negotiated, so its arrival is the answer to
//! both questions at once — which path, and which operation. A peer without
//! multipath never sends one, and that is what [`MULTIPATH_GRACE`] is waiting
//! to find out.
//!
//! **An empty path table does not mean "no multipath"; it means "not yet".**
//! `isekai_p2p::direct_path::preference_for` reads it as the former, which is
//! correct once `PathAdded` has had its chance and wrong before — the whole of
//! the bug above.
//!
//! # There is a window, and it belongs to msquic
//!
//! A path is active from the moment msquic adds it, and `QuicConnChoosePath`
//! picks at random among active paths, so between the addition and this loop
//! being polled the connection may send over a path nothing has chosen. Nothing
//! local can act sooner than the event that announces it. What this loop can do
//! is close the window immediately rather than leave the path active while
//! waiting for something else, which is why preferring happens in the same arm
//! that learns the id — and why `prefer_path` demotes before it promotes, so
//! the failure leaves every path backup and `Paths[0]`, the relay, carrying
//! traffic.
//!
//! # It prefers on its own, and the camera does not
//!
//! `camera-client` has a person and a Migrate button. A portal has an operator
//! who started a process and went away, so a direct path that waits to be asked
//! is a direct path that never gets used. Preferring as soon as there is
//! something to prefer is the whole difference between the two callers, and it
//! is why this file exists rather than `camera-core`'s loop being made to serve
//! both — and it is also why the ordering above bit here and not there.
//!
//! # What tells us a preferred path has gone bad
//!
//! Two things, and the second exists because the first leaves a gap.
//!
//! **`PathRemoved`** is msquic saying it has abandoned a path, and that is when
//! the relay is preferred again. What it does not cover is a path msquic keeps
//! and does not carry.
//!
//! **The preferred path's own statistics** cover that. `get_path_statistics`
//! reports RTT and network statistics per path — where `get_stats`, which this
//! loop used to report, only ever describes the *first* path however many the
//! connection has. That is the whole reason a connection-level byte counter
//! cannot see a dead preferred path: under multipath the relay is still active,
//! still sending its own keepalive PINGs and still receiving their
//! acknowledgements, so the connection's totals keep advancing while the path
//! carrying the traffic delivers nothing.
//!
//! `camera-core`'s watchdog asks "have any frames arrived since we moved?",
//! which works because a frame is application data and application data travels
//! on the preferred path alone. Portal has no frame counter; [`Stalled`] asks
//! the equivalent question of the path itself — see there for what it reads and
//! why those two numbers and not others.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::time::Duration;

use msquic_async::{msquic, Connection, ConnectionEvent};
use tokio_util::sync::CancellationToken;

use isekai_p2p::direct_path::{prefer_path, RelayPath, RELAY_PATH_ID};
use isekai_p2p::peer::log_connection_stats;
use isekai_p2p::RelayLegWatch;

/// How often the connection's counters are reported.
///
/// The camera's interval, and for the same reason: it is the resolution at which
/// "the path changed and then the numbers changed" is legible afterwards, which
/// is the only way a migration that went wrong can be read out of a log.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

/// How long a validated path may go without a `PathAdded` before it is treated
/// as a path on a connection whose peer has no multipath.
///
/// **Measured rather than guessed**: on hardware the two events were 140µs
/// apart, both raised by msquic out of the same completion. A second is four
/// orders of magnitude of headroom, and it is only ever *spent* by a peer that
/// has no multipath — where the cost is one more second on the relay before the
/// old switch, on a connection that is working the whole time.
const MULTIPATH_GRACE: Duration = Duration::from_secs(1);

/// How long the preferred path may hold data with nothing coming back before
/// the relay is preferred again.
///
/// Generous next to a round trip and short next to the 30-second idle timeout
/// that would otherwise take the whole connection down. `camera-core` allows
/// five seconds for the same judgement about frames; this watches a slower
/// signal — a smoothed RTT only moves when an acknowledgement arrives — so it
/// waits longer before calling a path dead.
const STALLED_GRACE: Duration = Duration::from_secs(10);

/// How long a path opened towards a replacement relay leg may go without a
/// `PathAdded` before this loop stops waiting for it.
///
/// **The failure it bounds is silent and permanent.** `add_path` queues a
/// `PATH_CHALLENGE` only if the new path already has a destination connection
/// id, and ids are assigned nowhere but the receive path — so a path opened
/// after nothing is arriving any more is never probed, and no amount of
/// waiting changes that (`docs/relay_repath_plan.md` §0.1.1). The window is
/// narrow in production, where the ids arrived milliseconds into the
/// connection and then sat unused, but narrow is not a reason to wait for ever
/// in silence.
///
/// Ten seconds against the 214µs to 1.2ms `PathAdded` took when it worked: the
/// slack is for a challenge that has to cross a real network and be
/// retransmitted, not for the case this is really bounding.
const RELAY_PATH_PATIENCE: Duration = Duration::from_secs(10);

/// The local address to open a replacement relay path *from*, given where it
/// is going.
///
/// **Port 0 asks msquic to choose**, and an address that is not a wildcard
/// makes the path share the connection's binding rather than open one of its
/// own — which is what keeps the replacement on the same local port as the
/// path it replaces (`docs/relay_repath_plan.md` §2.1).
///
/// The address itself is the remote's, which is only ever right because a
/// relay leg is a loopback bridge: the application sends to `127.0.0.1` and
/// both ends of this path are the same host. Reading it off the remote rather
/// than naming a constant is what keeps the two on the same address family.
fn add_path_local(remote: SocketAddr) -> SocketAddr {
    SocketAddr::new(remote.ip(), 0)
}

/// The local address handed to `remove_path` when this end never learned which
/// one msquic picked.
///
/// **A wildcard address with port 0 matches any local address**
/// (`QuicConnRemovePath`, `connection.c:8283`), so the remote alone selects the
/// path. That is the only handle there is on a path that was opened and never
/// announced: `add_path` was given port 0, and without a `PathAdded` nothing
/// ever said what it became.
fn any_local() -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], 0))
}

/// The largest thing this end ever hands to `send_datagram`.
///
/// **Not `MAX_PAYLOAD`**, which is the *payload* bound: `datagram::encode`
/// prepends the session id, so a full-size payload reaches the connection four
/// bytes longer. Comparing the connection's limit against the payload figure
/// would leave a connection reporting 1163..=1166 as fine while every
/// maximum-size datagram came back `TooBig` and was counted as a loss.
const LARGEST_DATAGRAM: usize = crate::datagram::HEADER + crate::datagram::MAX_PAYLOAD;

/// How many reporting ticks between reads of the connection-wide counters.
const CONNECTION_STATS_EVERY: u32 = 5;

/// Whether the path being preferred is delivering anything.
///
/// **Two numbers, and the pair is the point.** Either alone answers the wrong
/// question:
///
/// - `BytesInFlight` alone says data is outstanding, which is what a *busy*
///   path looks like at any instant.
/// - `Rtt` alone says nothing moved, which is what an *idle* path looks like —
///   a forward carrying no traffic has nothing to measure, and calling that
///   dead would drop every quiet connection back to the relay.
///
/// Together they say: this path is holding data **and** has not had a single
/// acknowledgement in all that time. A smoothed RTT moves whenever one arrives,
/// so an unchanged `Rtt` with bytes outstanding is a path that is being sent on
/// and answering nothing. That is the failure `PathRemoved` does not cover.
///
/// **Deliberately not `BytesInFlight` growing**, which was the first thing
/// tried: congestion control stops adding to a path that is not acknowledging,
/// so the number plateaus rather than climbing, and a test for growth answers
/// "recovering" to a path that has flatlined.
#[derive(Debug, Default)]
pub struct Stalled {
    /// The `Rtt` last seen, and when it last changed.
    seen: Option<(u64, tokio::time::Instant)>,
}

impl Stalled {
    /// Fold in one sample of the preferred path. `true` when it has been
    /// holding data with an unmoving RTT for [`STALLED_GRACE`].
    ///
    /// Takes the two numbers rather than the statistics struct so the decision
    /// can be tested without a connection — it is the part worth testing, and
    /// the part that is wrong if this is wrong.
    pub fn sample(&mut self, rtt: u64, bytes_in_flight: u32, now: tokio::time::Instant) -> bool {
        // Nothing outstanding: the path is idle, not dead. Forgetting what was
        // seen is what stops an idle spell from counting towards the grace.
        if bytes_in_flight == 0 {
            self.seen = None;
            return false;
        }
        match self.seen {
            Some((last, since)) if last == rtt => now.duration_since(since) >= STALLED_GRACE,
            // First sample with data outstanding, or the RTT moved — which is
            // an acknowledgement, which is the path working.
            _ => {
                self.seen = Some((rtt, now));
                false
            }
        }
    }

    /// Forget what was seen, for when the path being watched changes.
    pub fn reset(&mut self) {
        self.seen = None;
    }
}

/// A local and a remote address, which is how a path is named before it has an
/// id and how one without multipath is named for ever.
type Pair = (SocketAddr, SocketAddr);

/// Which paths this connection has, and which one is carrying traffic.
///
/// **Its own type so the decisions can be tested at all.** They were written
/// inline in [`keep_on_the_best_path`], which needs a live QUIC connection to
/// reach — so every comparison in them was exercised by nothing, and
/// cargo-mutants could invert any of them and watch the suite pass. What is
/// here answers "what does this event mean"; the loop still does the acting,
/// because that is the part that needs the connection.
#[derive(Debug)]
struct Paths {
    /// Where the relay is: the pair it runs over and the id msquic gave it.
    ///
    /// **Not a constant pair any more.** It starts as the path the handshake
    /// ran on — no event names that one, so it is read from the connection —
    /// and it moves when a restarted relay is attached as a path of its own
    /// (`docs/relay_repath_plan.md` P4). It is never a candidate for
    /// preference on its own account; it is where preference *returns* to.
    relay: RelayPath,
    /// `None` is the relay: the path QUIC falls back to, and the one that is
    /// carrying traffic whenever nothing else has been preferred.
    preferred: Option<Pair>,
    /// What `PathAdded` has named. **Empty means the peer negotiated no
    /// multipath**, which is what makes `prefer_path` fall back to the old
    /// switch — and why an empty table before `PathAdded` has had its chance
    /// is the bug the module header describes.
    direct: BTreeMap<Pair, u32>,
    /// A pair that validated with no id yet, and when to stop waiting.
    awaiting_id: Option<(Pair, tokio::time::Instant)>,
    /// A path opened towards a replacement relay leg, and when to give up on
    /// its `PathAdded`.
    ///
    /// **Named by its remote alone.** `add_path` was given a local port of 0,
    /// so which local address msquic settled on is not known until the event
    /// arrives and says.
    awaiting_relay: Option<(SocketAddr, tokio::time::Instant)>,
    /// Every remote this loop has ever opened a path to as a relay leg.
    ///
    /// **A different question from `awaiting_relay`, and the reason is the
    /// whole hazard of P4.** A `PathAdded` that turns up after the wait was
    /// given up is still not a direct path, and reading it as one would move
    /// forwarding off a healthy direct path and onto a relay leg — with the
    /// statistics labelled `direct` while it happened.
    relay_remotes: BTreeSet<SocketAddr>,
    /// Whether the relay path can still be fallen back to.
    ///
    /// **The relay is not forever.** Its leg is a MASQUE tunnel, and a relay
    /// that restarts takes it with it — after which `relay` names a pair that
    /// carries nothing. Falling back to it then is worse than doing nothing: it
    /// declares a dead path available, takes the live one down to backup, and
    /// the connection stops.
    relay_usable: bool,
}

impl Paths {
    fn new(relay: Pair) -> Self {
        Self {
            relay: RelayPath::first(relay),
            preferred: None,
            direct: BTreeMap::new(),
            awaiting_id: None,
            awaiting_relay: None,
            relay_remotes: BTreeSet::new(),
            relay_usable: true,
        }
    }

    /// Where to send traffic when there is nowhere better, or `None`.
    ///
    /// `None` is a connection with no fallback left: the relay leg has gone and
    /// nothing has replaced it. Every caller that would have reached for the
    /// relay has to ask, because the answer changed from "always" the moment
    /// the leg could die under a running session.
    fn fall_back(&self) -> Option<RelayPath> {
        self.relay_usable.then_some(self.relay)
    }

    /// The relay leg has stopped carrying traffic.
    ///
    /// **Recorded rather than acted on.** Nothing is preferred here: the
    /// connection may well be on a direct path and perfectly healthy, and the
    /// only thing that has changed is that there is no longer anywhere to fall
    /// back *to*. That matters when something tries.
    fn relay_is_gone(&mut self) {
        self.relay_usable = false;
    }

    /// A path has been opened towards a replacement leg at `remote`.
    ///
    /// The remote is remembered twice on purpose: once as what is being waited
    /// for, and once — for ever — as an address that belongs to a relay leg
    /// and can therefore never be read as a direct path.
    fn opening_to(&mut self, remote: SocketAddr, until: tokio::time::Instant) {
        self.relay_remotes.insert(remote);
        self.awaiting_relay = Some((remote, until));
    }

    /// Stop waiting for a replacement path, and say what was being waited for.
    fn stop_opening(&mut self) -> Option<SocketAddr> {
        self.awaiting_relay.take().map(|(remote, _)| remote)
    }

    /// `PathAdded`: a path validated **and** carries an id.
    ///
    /// **Three kinds of path arrive through one event**, and telling them
    /// apart is the whole of what this does. A direct path is something to
    /// move onto. A replacement relay leg is something to fall back *to*, and
    /// moving onto it would take forwarding off a working direct path. And a
    /// replacement that arrives after this loop stopped waiting is neither:
    /// it has already been asked to go away.
    fn added(&mut self, pair: Pair, path_id: u32) -> Added {
        if pair == self.relay.pair {
            return Added::Nothing;
        }
        if self.relay_remotes.contains(&pair.1) {
            // **Only the one being waited for ends the wait.** A leg that was
            // superseded can still have its `PATH_RESPONSE` arrive — msquic
            // raises `PathAdded` from the response frame without asking
            // whether the path is being abandoned — and clearing the wait on
            // that would disarm the patience for the leg that *is* current.
            // Its own event would then arrive too late to be anything, and
            // nothing would ever say the connection had lost its fallback.
            if !self.awaiting_relay.is_some_and(|(r, _)| r == pair.1) {
                return Added::RelayTooLate;
            }
            self.awaiting_relay = None;
            let old = self.relay;
            self.relay = RelayPath { pair, path_id };
            // **Here and not at `add_path`.** A path that has been opened is
            // not yet a fallback; one that msquic has announced has passed
            // validation, which is what makes it somewhere traffic could go.
            self.relay_usable = true;
            return Added::TheRelayMoved { old };
        }
        self.direct.insert(pair, path_id);
        self.stop_waiting_for(pair);
        // Already on it: the preference does not need making twice, and
        // remaking it would reset the stall watchdog's grace for nothing.
        match self.preferred != Some(pair) {
            true => Added::Direct,
            false => Added::Nothing,
        }
    }

    /// `PathValidated`: a path is usable and has no id yet.
    ///
    /// Returns whether this is news — a pair already known, already preferred,
    /// or the relay itself has nothing to wait for.
    fn validated(&self, pair: Pair) -> bool {
        pair != self.relay.pair
            // A relay leg's own address is never a direct path, whatever
            // order the events about it arrive in.
            && !self.relay_remotes.contains(&pair.1)
            && self.preferred != Some(pair)
            && !self.direct.contains_key(&pair)
    }

    /// Start the grace window that decides "the peer has no multipath".
    ///
    /// **`now` is passed in** so the deadline is a fact a test can check rather
    /// than whatever the clock said while it ran.
    fn wait_for_id(&mut self, pair: Pair, now: tokio::time::Instant) {
        self.awaiting_id = Some((pair, now + MULTIPATH_GRACE));
    }

    /// `PathRemoved`: a path is gone.
    ///
    /// **Including the relay's, since P4.** A re-attached relay is an ordinary
    /// added path, so the peer can abandon it and msquic raises the same event
    /// it raises for any other — where the original handshake path could only
    /// ever be lost with the connection. Read as "a path we were not using"
    /// that would leave `relay_usable` true for a path that no longer exists,
    /// and the next thing to fall back would demote every direct path and then
    /// fail to promote an id msquic has forgotten: no active path at all.
    fn removed(&mut self, pair: Pair) -> Removed {
        if pair == self.relay.pair {
            self.relay_usable = false;
            return Removed::TheRelay;
        }
        self.direct.remove(&pair);
        // Validated, then abandoned before it was ever preferred: waiting out
        // the grace would end in switching onto a path that no longer exists.
        self.stop_waiting_for(pair);
        let was_carrying = self.preferred == Some(pair);
        if was_carrying {
            self.preferred = None;
        }
        match was_carrying {
            true => Removed::WeWereOnIt,
            false => Removed::OneWeWereNotUsing,
        }
    }

    /// `PathStatusChanged`: the peer declared a path active or backup.
    ///
    /// Returns whether it just demoted the one this end was using. **The
    /// peer's declaration moves this end too** — a PATH_BACKUP clears our own
    /// `IsActive` — so this is bookkeeping rather than a fight. What must not
    /// happen is `preferred` staying behind, because it labels the per-second
    /// statistics: the operator would read `direct` off a connection running
    /// on the relay, which is the failure this module was written for.
    ///
    /// **The relay's own path is not treated as demotable here**, and that is
    /// deliberate rather than an oversight of P4. A path declared backup is
    /// still bound, still validated and still pinged, so a backup relay is a
    /// fallback that has not gone anywhere — unlike [`removed`](Self::removed),
    /// where it has. Nothing in this system sends such a declaration in any
    /// case: the initiator is the end that decides which path carries traffic,
    /// and the listener only ever echoes.
    fn status_changed(&mut self, pair: Pair, is_active: bool) -> bool {
        let demoted = !is_active && self.preferred == Some(pair);
        if demoted {
            self.preferred = None;
        }
        demoted
    }

    /// Record that a path is now carrying traffic.
    fn now_carrying(&mut self, pair: Pair) {
        self.preferred = Some(pair);
    }

    /// Whether the grace window is running for this pair.
    fn stop_waiting_for(&mut self, pair: Pair) {
        if self.awaiting_id.is_some_and(|(waiting, _)| waiting == pair) {
            self.awaiting_id = None;
        }
    }
}

/// What a `PathRemoved` turned out to be about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Removed {
    /// The path that was carrying traffic. Something has to take it over.
    WeWereOnIt,
    /// A path nothing was using.
    OneWeWereNotUsing,
    /// **The relay's own.** Not a fallback any more, whatever else is running.
    TheRelay,
}

/// What a `PathAdded` turned out to be about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Added {
    /// Nothing to do: the relay's own path, or one already being used.
    Nothing,
    /// A direct path. Worth moving onto.
    Direct,
    /// A replacement relay leg validated. The relay is now here; `old` is the
    /// path it replaced, which is what has to be taken out.
    TheRelayMoved { old: RelayPath },
    /// A replacement relay leg validated after this loop gave up on it and
    /// asked msquic to drop it.
    RelayTooLate,
}

/// What the peer's datagram limits mean for UDP forwarding.
///
/// **Said once rather than discovered.** `send_enabled` false means the peer
/// never advertised `max_datagram_frame_size`, so every UDP forward over this
/// connection is dead before it starts — which is exactly how phase 3a's bug
/// hid, as one `Denied` per datagram with nothing said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Datagrams {
    /// The peer will not receive them at all.
    Refused,
    /// It will, but takes less than this end is prepared to send.
    ///
    /// **Checked rather than adopted**: [`crate::datagram::MAX_PAYLOAD`] is a
    /// promise `docs/portal.md` makes to callers, and raising it per connection
    /// would leave DNS working on one network and not another.
    ///
    /// **The number comes with it**, because it is the whole diagnosis: a peer
    /// at 900 against a limit of 1200 has most of its UDP forwarding broken,
    /// and one at 1199 loses only the largest DNS responses. Without it both
    /// read as the same sentence.
    TooSmall {
        max_send_length: u16,
    },
    Fine {
        max_send_length: u16,
    },
}

/// What an event asks the loop to do about the connection.
///
/// **The dispatch is a decision too.** With the arms written inline, dropping
/// one entirely — ignoring every `PathRemoved`, say — compiled and passed,
/// because reaching the loop needs a live QUIC connection. Naming the outcomes
/// lets a test say which event means what; the loop still does the part that
/// needs the connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// An event this loop has nothing to say about.
    Nothing,
    /// Ask for this path, and record it as carrying traffic if the ask takes.
    MoveOnto { pair: Pair, path_id: u32 },
    /// A replacement relay leg validated. The relay is at `pair`/`path_id`
    /// now, and `old` is the path it replaced.
    ///
    /// **Not [`MoveOnto`](Step::MoveOnto), and that is the point of P4.** A
    /// relay path is where forwarding *returns* to; preferring it on arrival
    /// would take a healthy direct path out of service to stand on a relay.
    RelayMoved {
        pair: Pair,
        path_id: u32,
        old: RelayPath,
    },
    /// A replacement relay path turned up after this loop stopped waiting for
    /// it and asked msquic to drop it.
    RelayTooLate { pair: Pair, path_id: u32 },
    /// A path validated with no id; the grace window is now running for it.
    WaitForAnId { pair: Pair },
    /// The path in use has gone. Ask for the relay back.
    BackToTheRelay { pair: Pair, path_id: u32 },
    /// A path went away that nothing was using.
    LostOneWeWereNotUsing { pair: Pair, path_id: u32 },
    /// **The relay's own path went away**, which since P4 is something a peer
    /// can do: a re-attached relay is an ordinary path and can be abandoned
    /// like one. There is nothing to fall back to until another leg replaces
    /// it.
    TheRelayWentAway { pair: Pair, path_id: u32 },
    /// The peer declared the path in use backup, so this end is already off it.
    Demoted { pair: Pair, path_id: u32 },
    /// The peer changed some other path's status.
    PeerChangedAPath {
        pair: Pair,
        path_id: u32,
        is_active: bool,
    },
    /// What the peer will take in a datagram.
    Datagrams(Datagrams),
}

/// Read one event against what is known, and say what it means.
///
/// **`now` is passed in** rather than read here, so the grace window's deadline
/// is a fact a test can check.
fn step(event: &ConnectionEvent, paths: &mut Paths, now: tokio::time::Instant) -> Step {
    match event {
        // **The event that decides**, because it is the one carrying the id
        // every multipath operation needs — and because its existence is what
        // says the peer has multipath at all.
        ConnectionEvent::PathAdded {
            path_id,
            local_address,
            peer_address,
        } => {
            let pair = (*local_address, *peer_address);
            match paths.added(pair, *path_id) {
                Added::Nothing => Step::Nothing,
                Added::Direct => Step::MoveOnto {
                    pair,
                    path_id: *path_id,
                },
                Added::TheRelayMoved { old } => Step::RelayMoved {
                    pair,
                    path_id: *path_id,
                    old,
                },
                Added::RelayTooLate => Step::RelayTooLate {
                    pair,
                    path_id: *path_id,
                },
            }
        }
        // **Not acted on**, however tempting: this event has no path id, so
        // preferring now can only mean the pre-multipath switch — the wrong
        // operation whenever a `PathAdded` for the same path is a fraction of
        // a millisecond behind. The module header has what that cost on
        // hardware.
        ConnectionEvent::PathValidated {
            local_address,
            remote_address,
        } => {
            let pair = (*local_address, *remote_address);
            if !paths.validated(pair) {
                return Step::Nothing;
            }
            paths.wait_for_id(pair, now);
            Step::WaitForAnId { pair }
        }
        ConnectionEvent::PathRemoved {
            path_id,
            local_address,
            peer_address,
        } => {
            let pair = (*local_address, *peer_address);
            match paths.removed(pair) {
                Removed::WeWereOnIt => Step::BackToTheRelay {
                    pair,
                    path_id: *path_id,
                },
                Removed::OneWeWereNotUsing => Step::LostOneWeWereNotUsing {
                    pair,
                    path_id: *path_id,
                },
                Removed::TheRelay => Step::TheRelayWentAway {
                    pair,
                    path_id: *path_id,
                },
            }
        }
        ConnectionEvent::DatagramStateChanged {
            send_enabled,
            max_send_length,
        } => Step::Datagrams(datagram_state(*send_enabled, *max_send_length)),
        ConnectionEvent::PathStatusChanged {
            path_id,
            local_address,
            peer_address,
            is_active,
        } => {
            let pair = (*local_address, *peer_address);
            match paths.status_changed(pair, *is_active) {
                true => Step::Demoted {
                    pair,
                    path_id: *path_id,
                },
                false => Step::PeerChangedAPath {
                    pair,
                    path_id: *path_id,
                    is_active: *is_active,
                },
            }
        }
        _ => Step::Nothing,
    }
}

fn datagram_state(send_enabled: bool, max_send_length: u16) -> Datagrams {
    if !send_enabled {
        Datagrams::Refused
    } else if usize::from(max_send_length) < LARGEST_DATAGRAM {
        Datagrams::TooSmall { max_send_length }
    } else {
        Datagrams::Fine { max_send_length }
    }
}

/// Watch `conn`'s paths and keep it on the best one, until the connection ends.
///
/// **Returns when the connection is no longer usable**, which is what makes this
/// the caller's "the peer went away" signal too. That is not a convenience: the
/// event stream is a single queue per connection, so a second task polling it
/// would take events belonging to this one — a portal client cannot both watch
/// paths and separately watch for closure.
pub async fn keep_on_the_best_path(
    conn: Connection,
    shutdown: CancellationToken,
    // **Where the relay leg is**, as it moves. `None` is the tunnel under the
    // relay path having stopped carrying traffic — what a relay restarting
    // looks like from here — and `Some` is the loopback address a replacement
    // leg answers on, which is the *remote* of the path this loop then opens
    // to it. `isekai_p2p::InitiatorSession::relay_leg` is where a portal
    // session gets it. Until this existed the fallback was assumed to be there
    // for ever.
    mut relay_leg: RelayLegWatch,
) {
    // No event names the path the handshake ran on — `PathAdded` reports paths
    // opened after a probe validated, and this one was never probed — so it is
    // read from the connection instead.
    let relay_at_start = match (conn.get_local_addr(), conn.get_remote_addr()) {
        (Ok(local), Ok(remote)) => (local, remote),
        _ => {
            tracing::warn!(
                "could not read the relay path's addresses; no path can be preferred \
                 without them, so every path that turns up is held as backup and the \
                 relay keeps the traffic",
            );
            stay_on_the_relay(&conn, &shutdown, &mut relay_leg).await;
            return;
        }
    };
    tracing::info!(
        local = %relay_at_start.0, remote = %relay_at_start.1,
        "forwarding over the relay path",
    );

    // Which paths there are and which one is carrying traffic. Every decision
    // this loop makes about an event is one of `Paths`' methods, which is what
    // makes them testable without a connection.
    let mut paths = Paths::new(relay_at_start);
    // Whether the path being preferred is delivering. Reset whenever the
    // preference moves, so a new path starts with a clean grace period.
    let mut stalled = Stalled::default();
    let mut ticks: u32 = 0;
    // Said once. See the `None` arm below: nothing there clears the stall, so
    // the answer repeats every tick and only the latch stops the log with it.
    let mut said_no_fallback = false;
    // Stops the arm below once the session that feeds it is gone: a dropped
    // sender makes `changed` return at once and for ever, which without this
    // is a loop that spins instead of waiting for events.
    let mut leg_watching = true;

    // The reporting the camera apps have, with the one thing they cannot say
    // added: which path the numbers are about. `get_stats` is sampled here
    // rather than from a task of its own because this loop already knows that,
    // and because it is served by queueing an operation to msquic's connection
    // worker and **blocking the calling thread** until it runs — one caller per
    // connection is enough, and #155 is what a second one costs.
    let mut reporting = tokio::time::interval(STATS_INTERVAL);
    reporting.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => return,
            // **Recorded, not acted on** -- see `Paths::relay_is_gone`. A
            // connection on a direct path is unaffected until something tries
            // to fall back, and one already on the relay is about to find out
            // by itself.
            //
            // **The record is kept either way; only the warning asks why.** A
            // session being wound down or refused cancels the leg too (a
            // refused re-ticket cancels both tokens together), and saying "the
            // relay leg has gone" for a close is the false warning
            // `isekai_p2p`'s own watcher re-checks to avoid. The fallback is
            // still gone, so the bookkeeping stands; there is simply nobody to
            // tell.
            moved = relay_leg.changed(), if leg_watching => {
                if moved.is_err() {
                    // The session is gone, so nothing will move the leg again.
                    // Not worth saying: whatever took the session down has
                    // already said it, and this loop ends when the connection
                    // does.
                    leg_watching = false;
                    continue;
                }
                let at = *relay_leg.borrow_and_update();
                on_the_relay_leg_moving(&conn, &mut paths, at, &shutdown);
                continue;
            }
            _ = reporting.tick() => {
                // **Not every tick.** `get_stats` and `get_path_statistics`
                // are each served by queueing an operation to msquic's
                // connection worker and *blocking the calling thread* until it
                // runs — which is what #155 cost a day to find. The per-path
                // call has to happen every tick because the watchdog reads it;
                // the connection-wide one carries loss and congestion totals
                // that nothing here decides on, so it is sampled a fifth as
                // often rather than doubling the stall this loop imposes.
                //
                // Labelled `connection` because it describes the *first* path
                // however many there are — printing it as `direct` was this
                // loop's own bug.
                ticks = ticks.wrapping_add(1);
                if ticks.is_multiple_of(CONNECTION_STATS_EVERY) {
                    match conn.get_stats() {
                        Ok(stats) => log_connection_stats(&conn, &stats, "connection"),
                        Err(e) => tracing::debug!("could not read connection stats: {e}"),
                    }
                }
                if report_paths(&conn, paths.preferred, &paths.direct, &mut stalled) {
                    let stale = paths.preferred;
                    match paths.fall_back() {
                        Some(relay) => {
                            // **Preferring the relay again, not tearing
                            // anything down.** Under multipath the relay was
                            // never left, only declared backup, so this is
                            // withdrawing a preference — nothing in flight is
                            // lost by asking.
                            //
                            // **Said here, not before the question.** It used
                            // to be logged first, so with the leg gone the log
                            // read "forwarding goes back to the relay" and then,
                            // on the next line, that it had not moved.
                            tracing::warn!(
                                local = %stale.map(|p| p.0.to_string()).unwrap_or_default(),
                                remote = %stale.map(|p| p.1.to_string()).unwrap_or_default(),
                                "the direct path has held data for {STALLED_GRACE:?} without \
                                 a single acknowledgement; forwarding goes back to the relay",
                            );
                            // **Only forget the preference if the move
                            // happened.** `prefer_path` answers `false` when
                            // nothing changed, and clearing `preferred` anyway
                            // would leave traffic on the stalled path with the
                            // watchdog switched off — it only judges a path it
                            // believes is preferred, so there would be no
                            // second attempt.
                            if prefer_path(&conn, relay.pair, relay, &paths.direct) {
                                paths.preferred = None;
                                stalled.reset();
                            }
                        }
                        // **Nowhere to go.** Declaring the dead relay available
                        // would take the stalled path down to backup with it and
                        // stop the connection outright — worse than leaving it
                        // on a path that may yet recover.
                        //
                        // **Once.** Nothing here resets the watchdog or moves
                        // the preference, deliberately, so `report_paths`
                        // answers `true` on every tick from now on: without the
                        // latch this is an `error` a second for the rest of the
                        // connection, on the level operators alert on. The
                        // `Some` arm repeats on purpose — a failed `prefer_path`
                        // is worth retrying — and here there is nothing to
                        // retry.
                        None => {
                            if !said_no_fallback {
                                said_no_fallback = true;
                                tracing::error!(
                                    local = %stale.map(|p| p.0.to_string()).unwrap_or_default(),
                                    remote = %stale.map(|p| p.1.to_string()).unwrap_or_default(),
                                    "the direct path has stalled and the relay leg is gone, \
                                     so there is nothing to fall back to; leaving the \
                                     forwards where they are",
                                );
                            }
                        }
                    }
                }
                continue;
            }
            // Nothing to wait for unless a path was opened to a replacement
            // relay leg. See `RELAY_PATH_PATIENCE` for the silence this bounds.
            _ = sleep_until(paths.awaiting_relay.map(|(_, at)| at)) => {
                let remote = paths.stop_opening().expect("only armed with a remote");
                tracing::error!(
                    %remote,
                    "the path opened to the replacement relay leg was never validated \
                     within {RELAY_PATH_PATIENCE:?}; this connection has no fallback. The \
                     probe is never sent when the new path has no destination connection \
                     id, and nothing can supply one once the old leg has stopped \
                     delivering (`docs/relay_repath_plan.md` §0.1.1)",
                );
                // **Taken out rather than left**, because the cap is four
                // paths and a session that outlives several relay restarts
                // would otherwise reach it one unprobed path at a time.
                drop_the_path(&conn, (any_local(), remote));
                continue;
            }
            // Nothing to wait for unless a pair has validated without an id.
            _ = sleep_until(paths.awaiting_id.map(|(_, at)| at)) => {
                let (pair, _) = paths.awaiting_id.take().expect("only armed with a pair");
                // No `PathAdded` in all that time, so the peer negotiated no
                // multipath and the old switch is the only operation there is.
                // `direct` is empty, which is what makes `prefer_path` choose it.
                tracing::info!(
                    local = %pair.0, remote = %pair.1,
                    "no path id after {MULTIPATH_GRACE:?}; the peer has no multipath",
                );
                if prefer_path(&conn, pair, paths.relay, &paths.direct) {
                    paths.now_carrying(pair);
                    stalled.reset();
                }
                continue;
            }
            event = std::future::poll_fn(|cx| conn.poll_event(cx)) => event,
        };
        let Ok(event) = event else {
            // The stream erroring is the connection ending, which is this
            // function's other job to report.
            return;
        };
        // **Decide, then act.** What each event means is `step`'s, which a
        // test can reach; what to do about it needs the connection, which is
        // why it is still here.
        match step(&event, &mut paths, tokio::time::Instant::now()) {
            Step::Nothing => {}
            Step::RelayMoved { pair, path_id, old } => {
                // **"No fallback" is a recoverable state now**, so the latch
                // that made the stall watchdog say so once has to be released
                // — or a second genuine episode, after this relay goes too, is
                // silent on the level operators alert on.
                said_no_fallback = false;
                match paths.preferred {
                    // Nothing else is carrying traffic, which means the
                    // connection has been sending over a relay path that
                    // stopped answering. This is the one it should be on.
                    None => {
                        tracing::info!(
                            path_id, local = %pair.0, remote = %pair.1,
                            "the relay is back on a path of its own; forwarding goes there",
                        );
                        prefer_path(&conn, pair, paths.relay, &paths.direct);
                    }
                    // A direct path is carrying traffic and keeps it. **A path
                    // is active the moment msquic adds it**, so leaving this
                    // one alone would put the connection back to choosing at
                    // random between the two — the split this module exists to
                    // prevent, and here it would be a split onto the relay.
                    Some(_) => {
                        tracing::info!(
                            path_id, local = %pair.0, remote = %pair.1,
                            "the relay is back on a path of its own, held as backup; \
                             the direct path keeps the traffic",
                        );
                        if let Err(e) = conn.set_path_status(path_id, false) {
                            tracing::warn!(
                                path_id,
                                "could not hold the replacement relay path as backup; \
                                 traffic may split across it and the direct path: {e}",
                            );
                        }
                    }
                }
                // **Demoted before it is abandoned, and that is not belt and
                // braces.** Abandoning is asynchronous and can fail, and a
                // path left active is one `QuicConnChoosePath` picks at random
                // — while the old relay's id has just dropped out of every
                // future `preference_for` backup list, since the relay's id is
                // the new one and `direct` never held the old. Nothing else
                // would ever demote it, so traffic would split onto a leg that
                // carries nothing.
                if let Err(e) = conn.set_path_status(old.path_id, false) {
                    tracing::debug!(
                        path_id = old.path_id,
                        "could not hold the old relay path as backup; msquic may have \
                         forgotten it already: {e}",
                    );
                }
                // **Then abandoned**, and only after the new one is in hand:
                // under multipath this is a `PATH_ABANDON` rather than a
                // removal, so the slot comes back when the peer answers and
                // not here (`docs/relay_repath_plan.md` §0.3).
                drop_the_path(&conn, old.pair);
            }
            Step::RelayTooLate { pair, path_id } => tracing::debug!(
                path_id, local = %pair.0, remote = %pair.1,
                "a replacement relay path validated after this connection stopped \
                 waiting for it; it has already been asked to go away",
            ),
            Step::MoveOnto { pair, path_id } => {
                if prefer_path(&conn, pair, paths.relay, &paths.direct) {
                    paths.now_carrying(pair);
                    // A new path starts with a clean grace: carrying the last
                    // one's `(rtt, since)` over would let this one inherit a
                    // window that is already most of the way run.
                    stalled.reset();
                    tracing::info!(
                        path_id, local = %pair.0, remote = %pair.1,
                        "forwarding moved onto the direct path; the relay stays as backup",
                    );
                }
            }
            Step::WaitForAnId { pair } => tracing::info!(
                local = %pair.0, remote = %pair.1,
                "a direct path validated; waiting up to {MULTIPATH_GRACE:?} for its id",
            ),
            Step::BackToTheRelay { pair, path_id } => {
                // The one we were on. Going back is a preference, not a
                // reconnection — the relay path was never torn down, only
                // declared backup — so nothing in flight is lost by asking.
                match paths.fall_back() {
                    Some(relay) => {
                        tracing::warn!(
                            path_id, local = %pair.0, remote = %pair.1,
                            "the direct path was removed; forwarding goes back to the relay",
                        );
                        prefer_path(&conn, relay.pair, relay, &paths.direct);
                    }
                    None => tracing::error!(
                        path_id, local = %pair.0, remote = %pair.1,
                        "the direct path was removed and the relay leg is gone, so this \
                         connection has no path left",
                    ),
                }
            }
            Step::LostOneWeWereNotUsing { pair, path_id } => tracing::debug!(
                path_id, local = %pair.0, remote = %pair.1,
                "a path this connection was not using was removed",
            ),
            Step::TheRelayWentAway { pair, path_id } => tracing::warn!(
                path_id, local = %pair.0, remote = %pair.1,
                "the relay path was abandoned; this connection has no fallback until \
                 another leg replaces it",
            ),
            Step::Demoted { pair, path_id } => {
                // **Nothing to do either way** — the peer's PATH_BACKUP has
                // already moved this end off the path — but what to *say*
                // depends on whether there is a relay left underneath.
                // `preferred` is now `None`, which switches the watchdog off,
                // so if this line were wrong nothing else would speak up and
                // the connection would die at its idle timeout in silence.
                match paths.fall_back() {
                    Some(_) => tracing::warn!(
                        path_id, local = %pair.0, remote = %pair.1,
                        "the peer declared the path we were using backup; \
                         forwarding is on the relay again",
                    ),
                    None => tracing::error!(
                        path_id, local = %pair.0, remote = %pair.1,
                        "the peer declared the path we were using backup and the relay \
                         leg is gone, so this connection has no path left",
                    ),
                }
                stalled.reset();
            }
            Step::PeerChangedAPath {
                pair,
                path_id,
                is_active,
            } => tracing::debug!(
                path_id, local = %pair.0, remote = %pair.1, is_active,
                "the peer changed a path's status",
            ),
            Step::Datagrams(Datagrams::Refused) => tracing::warn!(
                "the peer will not receive QUIC datagrams, so UDP forwarding over \
                 this connection cannot work; TCP forwards are unaffected",
            ),
            // The one direction the constant cannot absorb: under the limit
            // means payloads this end accepts are refused by the connection,
            // and counted as `unsent` rather than carried.
            Step::Datagrams(Datagrams::TooSmall { max_send_length }) => tracing::warn!(
                max_send_length,
                largest = LARGEST_DATAGRAM,
                "the connection takes smaller datagrams than portal will send; \
                 payloads near the limit will be refused and counted as unsent",
            ),
            Step::Datagrams(Datagrams::Fine { max_send_length }) => tracing::debug!(
                max_send_length,
                largest = LARGEST_DATAGRAM,
                "the peer receives datagrams",
            ),
        }
    }
}

/// Log what each path is doing, and say whether the preferred one has stalled.
///
/// **`get_path_statistics` and not `get_stats`**, which only ever describes the
/// first path: on a connection that has moved onto a direct one, the numbers
/// this loop used to print were the relay's, labelled `direct`. That was worse
/// than saying nothing — it is the log an operator reads to decide whether
/// migration helped.
///
/// `None` for `preferred` means the relay is carrying traffic, and then there is
/// nothing to call stalled: the relay path is the one QUIC falls back to, and
/// declaring *it* dead has nowhere to go.
///
/// **What is left here needs a connection**, which is why it is the shape it
/// is: read the statistics, say what they are, hand the judging to [`judge`].
/// Mutation testing cannot reach past `get_path_statistics`, and that is the
/// honest boundary rather than a gap — every decision below it is tested.
fn report_paths(
    conn: &Connection,
    preferred: Option<(SocketAddr, SocketAddr)>,
    direct: &BTreeMap<(SocketAddr, SocketAddr), u32>,
    stalled: &mut Stalled,
) -> bool {
    let paths = match conn.get_path_statistics() {
        Ok(paths) => paths,
        Err(e) => {
            tracing::debug!("could not read per-path statistics: {e}");
            return false;
        }
    };
    for path in &paths {
        tracing::debug!(
            path_id = path.PathId,
            rtt_us = path.Rtt,
            min_rtt_us = path.MinRtt,
            mtu = path.Mtu,
            in_flight = path.NetworkStatistics.BytesInFlight,
            cwnd = path.NetworkStatistics.CongestionWindow,
            bandwidth = path.NetworkStatistics.Bandwidth,
            "path",
        );
    }
    judge(
        &paths,
        preferred,
        direct,
        stalled,
        tokio::time::Instant::now(),
    )
}

/// Whether the path being preferred has stopped delivering.
///
/// **Three answers, and two of them reset the watchdog.**
///
/// * Nothing is preferred, so the relay is carrying traffic — and there is
///   nothing to call stalled, because the relay is where declaring a path dead
///   would send it.
/// * The entry cannot be identified this tick. Saying nothing is right: the
///   alternative is judging the wrong path, and the wrong path here is a
///   healthy one.
/// * Otherwise, the watchdog sees it.
///
/// **Resetting rather than merely answering `false`** is the part worth
/// pinning: a spell with no preference must not count towards the grace, or a
/// path preferred a moment later inherits a window already most of the way run.
///
/// Split from [`report_paths`] because everything above it needs a live
/// connection to read the statistics from, and none of this does.
fn judge(
    paths: &[msquic::ffi::QUIC_PATH_STATISTICS],
    preferred: Option<Pair>,
    direct: &BTreeMap<Pair, u32>,
    stalled: &mut Stalled,
    now: tokio::time::Instant,
) -> bool {
    let Some(pair) = preferred else {
        stalled.reset();
        return false;
    };
    let Some(path) = preferred_entry(paths, pair, direct) else {
        tracing::debug!("cannot tell which entry is the preferred path; not judging it");
        stalled.reset();
        return false;
    };
    stalled.sample(path.Rtt, path.NetworkStatistics.BytesInFlight, now)
}

/// Which statistics entry belongs to the path being preferred.
///
/// **The entries carry no addresses**, only a `PathId` that msquic says does not
/// identify one — so this is positional, and the position depends on which of
/// the two operations `prefer_path` performed.
///
/// **Without multipath the preferred path is the first entry.**
/// `QuicPathSetActive` *swaps* it into `Paths[0]` (`seera-msquic`'s
/// `src/core/path.c`): the activated path is copied to index 0 and the one it
/// replaced takes its old slot. So after the `activate_path` fallback the last
/// entry is the **demoted relay** — which reports a frozen `Rtt`, because no
/// acknowledgement lands there any more, beside the *shared* `BytesInFlight`
/// that every path carries when they share a `PathId`. Reading that pair as a
/// stall would declare a perfectly healthy direct path dead within ten seconds
/// of ordinary traffic, and this function existed to get that exactly backwards
/// until review read the core.
///
/// **With multipath the id is known and is used.** `PathAdded` carried it, so
/// `direct` has it; entries with any other id are certainly not this path. If
/// more than one shares it — which happens when a rebinding path inherits the
/// id of the one it replaces — there is no way to choose, and `None` says so.
fn preferred_entry<'a>(
    paths: &'a [msquic::ffi::QUIC_PATH_STATISTICS],
    preferred: (SocketAddr, SocketAddr),
    direct: &BTreeMap<(SocketAddr, SocketAddr), u32>,
) -> Option<&'a msquic::ffi::QUIC_PATH_STATISTICS> {
    let Some(&path_id) = direct.get(&preferred) else {
        // No id for it means `prefer_path` took the `Switch` branch, which is
        // the swap described above.
        return paths.first();
    };
    let mut matching = paths.iter().filter(|p| p.PathId == path_id);
    let first = matching.next()?;
    match matching.next() {
        None => Some(first),
        Some(_) => None,
    }
}

/// Wait until `deadline`, or forever if there is none.
///
/// `select!` needs a future in every arm whether or not anything is armed, and
/// "forever" is the honest spelling of nothing to wait for — a zero-length sleep
/// would make the arm ready on every poll and spin the loop.
async fn sleep_until(deadline: Option<tokio::time::Instant>) {
    match deadline {
        Some(at) => tokio::time::sleep_until(at).await,
        None => std::future::pending().await,
    }
}

/// Ask msquic to abandon a path, and say so if it will not.
///
/// **Not a removal, under multipath.** `QuicConnRemovePath` sets `LocalClose`,
/// queues a `PATH_ABANDON` frame and returns; the slot comes back when the
/// peer answers, not here (`connection.c:8380`,
/// `docs/relay_repath_plan.md` §0.3). That is also why this cannot take the
/// connection down the way `remove_bound_addr` can — the branch that aborts
/// belongs to connections without multipath, and a portal connection that has
/// a path to abandon has it.
fn drop_the_path(conn: &Connection, pair: Pair) {
    match conn.remove_path(pair.0, pair.1) {
        Ok(()) => tracing::debug!(
            local = %pair.0, remote = %pair.1,
            "asked msquic to abandon a path",
        ),
        Err(e) => tracing::warn!(
            local = %pair.0, remote = %pair.1,
            "could not abandon a path, so it goes on occupying one of the four slots \
             this connection has: {e}",
        ),
    }
}

/// The relay leg has moved, or has gone. Record it, and open a path to the
/// replacement when there is one.
///
/// **This is P4's action, and all of it.** Everything else about a moving
/// relay is bookkeeping in [`Paths`]; this is the one place that asks the
/// connection for anything — and it asks for an `add_path` and nothing more.
/// Whether the new path may be *used* is decided when msquic announces it,
/// because a path that has been opened has not yet been validated and a
/// fallback that has not validated is not a fallback.
fn on_the_relay_leg_moving(
    conn: &Connection,
    paths: &mut Paths,
    at: Option<SocketAddr>,
    shutdown: &CancellationToken,
) {
    let Some(at) = at else {
        // **Recorded, not acted on** — see [`Paths::relay_is_gone`]. A
        // connection on a direct path is unaffected until something tries to
        // fall back, and one already on the relay is about to find out by
        // itself.
        //
        // **The record is kept either way; only the warning asks why.** A
        // session being wound down or refused takes its leg with it, and
        // saying "the relay leg has gone" on an ordinary close is the false
        // warning `isekai_p2p`'s own watcher re-checks to avoid.
        if !shutdown.is_cancelled() {
            tracing::warn!(
                local = %paths.relay.pair.0, remote = %paths.relay.pair.1,
                "the relay leg has gone; this connection has no fallback until one \
                 replaces it",
            );
        }
        // A path opened towards the leg *before* this one is waiting for a
        // validation that can no longer arrive: the leg it points at has gone
        // too. Sitting out its patience would only delay saying so.
        if let Some(stale) = paths.stop_opening() {
            drop_the_path(conn, (any_local(), stale));
        }
        paths.relay_is_gone();
        return;
    };
    // **A new leg means the old one died, whether or not that was seen.** A
    // `watch` keeps only its latest value, so the `None` that said so can be
    // coalesced away by the `Some` that follows it — and a handler that
    // depended on having seen it would go on offering a dead pair as somewhere
    // to fall back to.
    paths.relay_is_gone();
    // **The far end, not a local address.** What the session reports is the
    // loopback socket the application sends to, which is where the relay
    // bridge listens — so from the peer connection's side it is the remote of
    // the relay path.
    if paths.awaiting_relay.is_some_and(|(remote, _)| remote == at) {
        // Already opened, and the patience for it is already running.
        return;
    }
    // A path still being waited for points at a leg that has been replaced,
    // for the same coalescing reason. Left alone it would sit out its patience
    // and then occupy one of the four slots until the connection ended.
    if let Some(stale) = paths.stop_opening() {
        drop_the_path(conn, (any_local(), stale));
    }
    match conn.add_path(add_path_local(at), at) {
        Ok(()) => {
            tracing::info!(
                remote = %at,
                "a replacement relay leg is up; opening a path to it and waiting up to \
                 {RELAY_PATH_PATIENCE:?} for it to validate",
            );
            paths.opening_to(at, tokio::time::Instant::now() + RELAY_PATH_PATIENCE);
        }
        // Nothing to retry against: the session stands up one leg per relay
        // death, and the next attempt comes with the next one.
        Err(e) => tracing::error!(
            remote = %at,
            "a replacement relay leg is up, but a path to it could not be opened, so \
             this connection still has no fallback: {e}",
        ),
    }
}

/// Whether a path msquic has just added should be held as backup.
///
/// **Every path except the relay's own.** `path_id` 0 is the path the handshake
/// ran on — the one carrying traffic in this fallback, and the one that must
/// stay available. Read the other way round it demotes the relay and leaves
/// every new path active, which is the opposite of what this function exists
/// for and would put traffic on a path nothing chose.
///
/// The relay is never announced by `PathAdded` anyway, since it was never
/// probed; this holds even so, because a comparison that is only correct
/// because of what does not happen is one nobody can check.
fn hold_as_backup(path_id: u32) -> bool {
    path_id != RELAY_PATH_ID
}

/// Stay on the relay, and hold every path that turns up as backup.
///
/// The fallback for a connection whose own addresses could not be read. Without
/// them there is nothing to compare a path against, so none can be preferred —
/// but **doing nothing is not the same as staying on the relay**, and that
/// distinction is this function's whole reason for existing rather than being a
/// `while` loop over events.
///
/// A path is active the moment msquic adds it. Left alone it sits alongside the
/// relay, `QuicConnChoosePath` picks between them at random, and the warning
/// above says "staying on the relay" while half the traffic goes over a path
/// nothing chose — the one case in this module that really does split. Demoting
/// needs only the path id, which the event carries, so it costs nothing to be
/// right here.
///
/// The events have to be drained regardless: this is also how the caller learns
/// the connection closed.
///
/// **Not reachable from a test**, for the same reason as [`report_paths`]: it
/// polls a live connection's event stream. The one decision it makes is
/// [`hold_as_backup`], which is.
async fn stay_on_the_relay(
    conn: &Connection,
    shutdown: &CancellationToken,
    relay_leg: &mut RelayLegWatch,
) {
    let mut watching = true;
    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => return,
            // **Said here too, and only said.** This branch holds every path
            // it sees as backup because it cannot tell one from another
            // without the addresses, so the relay is carrying everything --
            // and when its leg goes, that is the whole connection rather than
            // a fallback. Opening a path to a replacement needs a local
            // address to open it from, which is the thing this branch exists
            // because it could not read; promoting one of the held paths needs
            // only the id the event carried, but choosing *which* is the same
            // judgement it cannot make.
            moved = relay_leg.changed(), if watching => {
                if moved.is_err() {
                    watching = false;
                    continue;
                }
                match *relay_leg.borrow_and_update() {
                    None if !shutdown.is_cancelled() => tracing::error!(
                        "the relay leg has gone, and this connection could not read its \
                         own addresses -- so every path that turned up is held as backup \
                         and there is nothing left carrying traffic",
                    ),
                    Some(remote) => tracing::warn!(
                        %remote,
                        "a replacement relay leg is up, but this connection could not \
                         read its own addresses, so no path can be opened to it",
                    ),
                    None => {}
                }
                continue;
            }
            event = std::future::poll_fn(|cx| conn.poll_event(cx)) => event,
        };
        let Ok(event) = event else { return };
        if let ConnectionEvent::PathAdded { path_id, .. } = event {
            if hold_as_backup(path_id) {
                if let Err(e) = conn.set_path_status(path_id, false) {
                    tracing::warn!(
                        path_id,
                        "could not hold a new path as backup; it will carry traffic \
                         that nothing chose to put on it: {e}",
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(base: tokio::time::Instant, secs: u64) -> tokio::time::Instant {
        base + Duration::from_secs(secs)
    }

    fn entry(path_id: u32, rtt: u64) -> msquic::ffi::QUIC_PATH_STATISTICS {
        let mut stats: msquic::ffi::QUIC_PATH_STATISTICS = unsafe { std::mem::zeroed() };
        stats.PathId = path_id;
        stats.Rtt = rtt;
        stats
    }

    fn pair(port: u16) -> (SocketAddr, SocketAddr) {
        (
            format!("127.0.0.1:{port}").parse().unwrap(),
            format!("127.0.0.1:{}", port + 1).parse().unwrap(),
        )
    }

    /// **Without multipath the preferred path is the first entry, not the
    /// last.** `QuicPathSetActive` swaps the activated path into `Paths[0]` and
    /// puts the one it replaced in its old slot, so the last entry is the
    /// *demoted* relay — which reports a frozen RTT beside the shared bytes in
    /// flight, and would be read as a stall on a healthy connection.
    ///
    /// This is the one the first version had backwards.
    #[test]
    fn without_multipath_the_active_path_is_the_first_entry() {
        let paths = [entry(0, 1111), entry(0, 9999)];
        let empty = BTreeMap::new();
        let chosen = preferred_entry(&paths, pair(4000), &empty).expect("the active path");
        assert_eq!(
            chosen.Rtt, 1111,
            "the swap puts the activated path at index 0",
        );
    }

    /// With multipath the id came from `PathAdded`, so it is used.
    #[test]
    fn with_multipath_the_path_id_selects_the_entry() {
        let paths = [entry(0, 1111), entry(7, 2222)];
        let direct = BTreeMap::from([(pair(4000), 7)]);
        let chosen = preferred_entry(&paths, pair(4000), &direct).expect("the preferred path");
        assert_eq!(chosen.Rtt, 2222);
    }

    /// **And an id two entries share is not a choice.** A rebinding path
    /// inherits the id of the one it replaces, so guessing between them risks
    /// judging a path that is not the one carrying traffic — and the cost of
    /// being wrong is sending a working forward back to the relay.
    #[test]
    fn a_shared_path_id_is_refused_rather_than_guessed() {
        let paths = [entry(7, 1111), entry(7, 2222)];
        let direct = BTreeMap::from([(pair(4000), 7)]);
        assert!(preferred_entry(&paths, pair(4000), &direct).is_none());
    }

    /// The event that carries the limit describes the whole datagram, and what
    /// portal hands over is the payload plus the session id.
    #[test]
    fn the_limit_is_compared_against_what_is_actually_sent() {
        assert_eq!(
            LARGEST_DATAGRAM,
            crate::datagram::MAX_PAYLOAD + crate::datagram::HEADER,
        );
        assert!(
            crate::datagram::encode(1, &vec![0; crate::datagram::MAX_PAYLOAD])
                .expect("a payload at the limit")
                .len()
                == LARGEST_DATAGRAM,
            "and that is the length that reaches send_datagram",
        );
    }

    /// **A busy path is not a stalled one.** Data outstanding is what sending
    /// looks like; what makes it a stall is the acknowledgements never coming,
    /// and a moving RTT is an acknowledgement arriving.
    #[tokio::test]
    async fn a_path_that_is_answering_never_stalls() {
        let t0 = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        for i in 0..60 {
            // In flight the whole time, and the RTT moves — a working path
            // under load.
            assert!(
                !stalled.sample(1000 + i, 4096, at(t0, i)),
                "an acknowledged path must never be called stalled (at {i}s)",
            );
        }
    }

    /// **An idle path is not a stalled one either**, which is the other way to
    /// get this wrong: a forward carrying nothing has no RTT sample to move,
    /// and calling that dead would drop every quiet connection to the relay.
    #[tokio::test]
    async fn an_idle_path_never_stalls() {
        let t0 = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        for i in 0..60 {
            assert!(
                !stalled.sample(1000, 0, at(t0, i)),
                "nothing outstanding is idle, not dead (at {i}s)",
            );
        }
    }

    /// The case this exists for: data held, and not one acknowledgement.
    #[tokio::test]
    async fn data_held_with_no_acknowledgement_stalls_after_the_grace() {
        let t0 = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        assert!(
            !stalled.sample(1000, 4096, t0),
            "the first sample only arms it"
        );
        assert!(
            !stalled.sample(1000, 4096, at(t0, STALLED_GRACE.as_secs() - 1)),
            "a second short of the grace is not yet a verdict",
        );
        assert!(
            stalled.sample(1000, 4096, at(t0, STALLED_GRACE.as_secs())),
            "held for the whole grace with an unmoving RTT is the failure",
        );
    }

    /// **One acknowledgement resets the clock**, so a path that recovers is not
    /// punished for the seconds before it did.
    #[tokio::test]
    async fn a_single_acknowledgement_starts_the_grace_again() {
        let t0 = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        stalled.sample(1000, 4096, t0);
        // Nine seconds of silence, then the RTT moves.
        assert!(!stalled.sample(1000, 4096, at(t0, 9)));
        assert!(!stalled.sample(1100, 4096, at(t0, 9)), "the RTT moved");
        assert!(
            !stalled.sample(1100, 4096, at(t0, 18)),
            "and the grace runs from there, not from the first sample",
        );
        assert!(stalled.sample(1100, 4096, at(t0, 19)));
    }

    /// And going quiet in the middle does the same, because an idle spell is
    /// not evidence either way.
    #[tokio::test]
    async fn going_idle_clears_what_was_seen() {
        let t0 = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        stalled.sample(1000, 4096, t0);
        assert!(!stalled.sample(1000, 0, at(t0, 5)), "nothing outstanding");
        assert!(
            !stalled.sample(1000, 4096, at(t0, 20)),
            "the grace starts from here, not from before the quiet spell",
        );
    }
    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().expect("a literal")
    }

    /// A connection on the relay, with nothing else known yet.
    fn watching() -> Paths {
        Paths::new((addr(1), addr(2)))
    }

    /// **The fallback is a question now, and it used to be an assumption.**
    /// Everything that falls back reached for `relay` unconditionally, which
    /// was right while a relay leg outlived every session riding on it.
    #[test]
    fn the_relay_is_where_to_fall_back_until_its_leg_goes() {
        let mut paths = watching();
        assert_eq!(paths.fall_back(), Some(paths.relay));

        paths.relay_is_gone();
        assert_eq!(
            paths.fall_back(),
            None,
            "a dead leg is not somewhere to fall back to",
        );
    }

    /// **Losing the leg changes nothing else.** A connection on a direct path is
    /// unaffected until something tries to fall back, so marking the relay gone
    /// must not move the preference, forget a path, or touch the grace -- any of
    /// which would disturb a healthy session over an event that did not reach
    /// it.
    #[test]
    fn losing_the_leg_does_not_disturb_a_healthy_direct_path() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        paths.added(direct, 7);
        paths.now_carrying(direct);
        let relay = paths.relay;

        paths.relay_is_gone();

        assert_eq!(paths.preferred, Some(direct), "still on the direct path");
        assert_eq!(paths.direct.get(&direct), Some(&7), "still known");
        assert_eq!(paths.relay, relay, "the path is still named");
    }

    /// And a relay whose leg has gone is still not a path to move onto: `added`
    /// answers on the address, which has not changed.
    #[test]
    fn a_gone_relay_is_still_not_a_direct_path() {
        let mut paths = watching();
        let relay = paths.relay.pair;
        paths.relay_is_gone();
        assert_eq!(paths.added(relay, 9), Added::Nothing);
        assert!(paths.direct.is_empty());
    }

    /// **The failure P4 exists to not introduce.** `PathAdded` for a
    /// replacement relay leg looks exactly like `PathAdded` for a direct path
    /// — same event, same shape — and read as one it takes forwarding off a
    /// working direct path and puts it on a relay, with the per-second
    /// statistics labelled `direct` while it happens. This is why the plan
    /// put P2 before P4.
    #[test]
    fn a_replacement_relay_path_is_not_a_direct_path() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        paths.added(direct, 7);
        paths.now_carrying(direct);
        paths.relay_is_gone();

        // The leg came back somewhere else, and a path was opened to it.
        let new_leg = addr(9);
        paths.opening_to(new_leg, tokio::time::Instant::now() + RELAY_PATH_PATIENCE);
        let arrived = (addr(1), new_leg);

        assert_eq!(
            paths.added(arrived, 3),
            Added::TheRelayMoved {
                old: RelayPath::first((addr(1), addr(2))),
            },
            "the relay came back, and the path it replaces is named",
        );
        assert!(
            !paths.direct.contains_key(&arrived),
            "a relay leg is never recorded as somewhere to move onto",
        );
        assert_eq!(
            paths.preferred,
            Some(direct),
            "and the direct path keeps the traffic",
        );
    }

    /// The relay moved, so **both** halves of it moved: the pair `prefer_path`
    /// asks for and the id it asks with. Keeping the old id would declare the
    /// dead path available and demote the live one.
    #[test]
    fn the_relay_moves_pair_and_id_together() {
        let mut paths = watching();
        paths.relay_is_gone();
        let new_leg = addr(9);
        paths.opening_to(new_leg, tokio::time::Instant::now() + RELAY_PATH_PATIENCE);
        let arrived = (addr(1), new_leg);

        paths.added(arrived, 3);

        assert_eq!(
            paths.relay,
            RelayPath {
                pair: arrived,
                path_id: 3,
            },
        );
        assert_eq!(
            paths.fall_back(),
            Some(paths.relay),
            "and it is somewhere to fall back to again",
        );
    }

    /// **Opening the path is not what makes it a fallback; validating is.**
    /// `add_path` returns before a single probe has been answered, and a
    /// connection that retreated onto an unvalidated path would be retreating
    /// onto nothing.
    #[test]
    fn a_path_that_was_only_opened_is_not_yet_a_fallback() {
        let mut paths = watching();
        paths.relay_is_gone();

        paths.opening_to(addr(9), tokio::time::Instant::now() + RELAY_PATH_PATIENCE);

        assert_eq!(paths.fall_back(), None, "nothing has validated yet");
    }

    /// **A `watch` keeps only its latest value**, so a leg that dies and is
    /// replaced faster than this loop is polled arrives as one `Some` with the
    /// `None` coalesced away. Depending on having seen the `None` would leave
    /// the connection offering a dead pair as somewhere to fall back to.
    #[test]
    fn a_leg_that_moves_says_the_old_one_is_gone_even_unseen() {
        let mut paths = watching();
        assert_eq!(
            paths.fall_back(),
            Some(paths.relay),
            "healthy to start with"
        );

        // What `on_the_relay_leg_moving` does for a `Some` before it opens
        // anything: the old pair is dead whether or not its `None` was seen.
        paths.relay_is_gone();
        paths.opening_to(addr(9), tokio::time::Instant::now() + RELAY_PATH_PATIENCE);

        assert_eq!(
            paths.fall_back(),
            None,
            "the pair it holds is the dead one until a replacement validates",
        );
    }

    /// **A superseded leg can still answer, and it must not speak for the
    /// current one.** msquic raises `PathAdded` from a `PATH_RESPONSE` without
    /// asking whether the path is being abandoned, so the probe sent to a leg
    /// that has since been replaced can validate after the replacement was
    /// opened. Letting it end the wait disarms the patience for the leg that
    /// matters: the real one then arrives too late to be anything, the relay
    /// never moves, and nothing is left to report that the fallback is gone.
    #[test]
    fn a_superseded_leg_answering_late_does_not_end_the_wait_for_the_current_one() {
        let mut paths = watching();
        let now = tokio::time::Instant::now();
        paths.relay_is_gone();
        let (old_leg, new_leg) = (addr(9), addr(11));
        paths.opening_to(old_leg, now + RELAY_PATH_PATIENCE);
        // That leg went too, and a path was opened to its replacement.
        paths.stop_opening();
        paths.opening_to(new_leg, now + RELAY_PATH_PATIENCE);

        assert_eq!(
            paths.added((addr(1), old_leg), 3),
            Added::RelayTooLate,
            "the superseded leg is not the relay coming back",
        );
        assert_eq!(
            paths.awaiting_relay.map(|(remote, _)| remote),
            Some(new_leg),
            "and the current leg is still being waited for",
        );

        assert!(matches!(
            paths.added((addr(1), new_leg), 4),
            Added::TheRelayMoved { .. }
        ));
    }

    /// **The relay is an ordinary path now, and the peer can abandon it.** The
    /// handshake's path could only be lost with the connection; a re-attached
    /// one raises the same `PathRemoved` as any other. Read as "a path we were
    /// not using", it would leave a dead path on offer as somewhere to fall
    /// back to — and falling back to it demotes every direct path and then
    /// fails to promote an id msquic has forgotten, leaving none active at all.
    #[test]
    fn the_relay_path_being_abandoned_is_the_fallback_going_away() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        paths.added(direct, 7);
        paths.now_carrying(direct);

        assert_eq!(paths.removed(paths.relay.pair), Removed::TheRelay);

        assert_eq!(paths.fall_back(), None, "there is nothing to fall back to");
        assert_eq!(
            paths.preferred,
            Some(direct),
            "and the direct path is untouched by it",
        );
    }

    /// A replacement that validates after the patience ran out is still not a
    /// direct path. It has already been asked to go away, and reading it as
    /// somewhere to move onto would be the same failure arriving late.
    #[test]
    fn a_replacement_that_came_too_late_is_still_not_a_direct_path() {
        let mut paths = watching();
        paths.relay_is_gone();
        let new_leg = addr(9);
        paths.opening_to(new_leg, tokio::time::Instant::now() + RELAY_PATH_PATIENCE);
        // The patience ran out and the loop stopped waiting.
        assert_eq!(paths.stop_opening(), Some(new_leg));

        assert_eq!(paths.added((addr(1), new_leg), 3), Added::RelayTooLate);
        assert!(paths.direct.is_empty());
        assert_eq!(paths.fall_back(), None, "and it is still not a fallback");
    }

    /// `PathValidated` arrives before `PathAdded` and carries no id, so it is
    /// the first chance to mistake a relay leg for a direct path — and the
    /// grace window it would start ends in the pre-multipath switch, onto the
    /// relay.
    #[test]
    fn a_relay_leg_never_starts_the_wait_for_a_path_id() {
        let mut paths = watching();
        let new_leg = addr(9);
        paths.opening_to(new_leg, tokio::time::Instant::now() + RELAY_PATH_PATIENCE);

        assert!(!paths.validated((addr(1), new_leg)));
        assert!(
            paths.validated((addr(3), addr(4))),
            "and an ordinary direct path still does",
        );
    }

    /// **The relay is never a candidate.** `PathAdded` does not name it — the
    /// path the handshake ran on was never probed — but if one ever arrived,
    /// recording it as direct would make `prefer_path` treat the relay as the
    /// thing to move onto, and the loop would announce a migration to where it
    /// already was.
    #[test]
    fn the_relay_is_not_a_path_to_move_onto() {
        let mut paths = watching();
        let relay = paths.relay.pair;
        assert_eq!(
            paths.added(relay, 7),
            Added::Nothing,
            "the relay is not a direct path"
        );
        assert!(paths.direct.is_empty(), "and it is not recorded as one");
        assert!(!paths.validated(relay));
    }

    /// The ordinary case, and the one that must not repeat: a second
    /// `PathAdded` for the path already carrying traffic asks for nothing.
    /// Preferring again would reset the stall watchdog's grace for nothing.
    #[test]
    fn a_new_path_is_worth_moving_onto_and_the_current_one_is_not() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));

        assert_eq!(
            paths.added(direct, 9),
            Added::Direct,
            "a path we are not on is worth taking"
        );
        // **Recorded either way**, because `prefer_path` looks the path up in
        // here -- so the id has to be in before the call, not after it.
        assert_eq!(paths.direct.get(&direct), Some(&9));

        paths.now_carrying(direct);
        assert_eq!(paths.added(direct, 9), Added::Nothing, "already on it");
    }

    /// **A path that validated and was then added stops the grace.** Left
    /// running, the timer fires for a pair that now has an id and takes the
    /// pre-multipath switch -- the wrong operation, which is the bug the module
    /// header describes costing a connection on hardware.
    #[test]
    fn an_id_arriving_ends_the_wait_for_it() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        let other = (addr(5), addr(6));
        let now = tokio::time::Instant::now();

        paths.wait_for_id(direct, now);
        // **The deadline is the grace, exactly.** A window that was computed
        // the other way round would fire immediately, which reads as "the peer
        // has no multipath" for every peer.
        assert_eq!(paths.awaiting_id, Some((direct, now + MULTIPATH_GRACE)));

        // Another pair's id says nothing about this one's.
        paths.added(other, 1);
        assert_eq!(paths.awaiting_id, Some((direct, now + MULTIPATH_GRACE)));

        paths.added(direct, 2);
        assert_eq!(paths.awaiting_id, None, "the id arrived; stop waiting");
    }

    /// Waiting is for news. A pair already known, already carrying traffic, or
    /// the relay has nothing to find out.
    #[test]
    fn only_an_unknown_pair_is_worth_waiting_for_an_id_for() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        assert!(paths.validated(direct));

        paths.now_carrying(direct);
        assert!(!paths.validated(direct), "already on it");

        let mut paths = watching();
        paths.added(direct, 5);
        assert!(!paths.validated(direct), "its id is already known");
    }

    /// **Only the path we were on has to ask for the relay back.** Treating
    /// every removal as ours would withdraw a preference nothing made; treating
    /// none of them as ours would leave `preferred` naming a path that is gone,
    /// and the per-second statistics saying `direct` over the relay.
    #[test]
    fn losing_the_path_in_use_is_told_from_losing_any_other() {
        let mut paths = watching();
        let ours = (addr(3), addr(4));
        let theirs = (addr(5), addr(6));
        paths.added(ours, 1);
        paths.added(theirs, 2);
        paths.now_carrying(ours);

        assert_eq!(
            paths.removed(theirs),
            Removed::OneWeWereNotUsing,
            "not the one carrying traffic"
        );
        assert_eq!(paths.preferred, Some(ours), "and it did not move us");
        assert!(!paths.direct.contains_key(&theirs), "but it is forgotten");

        assert_eq!(paths.removed(ours), Removed::WeWereOnIt, "this one is ours");
        assert_eq!(paths.preferred, None, "back to the relay");
    }

    /// Validated, then abandoned before it was ever preferred. Waiting out the
    /// grace would end in switching onto a path that no longer exists.
    #[test]
    fn a_pair_that_goes_away_while_waiting_stops_being_waited_for() {
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        paths.wait_for_id(direct, tokio::time::Instant::now());
        assert_eq!(
            paths.removed(direct),
            Removed::OneWeWereNotUsing,
            "it was never carrying traffic"
        );
        assert_eq!(paths.awaiting_id, None);
    }

    /// **Only a demotion of the path in use moves this end.** A peer marking
    /// some other path backup is bookkeeping; a peer marking *ours* backup has
    /// already stopped our traffic going over it, and `preferred` staying
    /// behind is what would label relay traffic `direct`.
    #[test]
    fn the_peer_demoting_the_path_in_use_is_told_from_any_other_change() {
        let mut paths = watching();
        let ours = (addr(3), addr(4));
        let theirs = (addr(5), addr(6));
        paths.now_carrying(ours);

        assert!(
            !paths.status_changed(theirs, false),
            "not the one we are on"
        );
        assert!(!paths.status_changed(ours, true), "made active, not backup");
        assert_eq!(paths.preferred, Some(ours));

        assert!(paths.status_changed(ours, false));
        assert_eq!(paths.preferred, None, "the peer put us back on the relay");
    }

    /// **Three answers, not two.** "Will not take datagrams at all" and "takes
    /// smaller ones than we send" need different things said: the first kills
    /// UDP forwarding outright, the second loses only the payloads near the
    /// limit -- and reporting either as the other sends the operator after the
    /// wrong thing.
    #[test]
    fn what_the_peer_will_take_has_three_answers() {
        assert_eq!(datagram_state(false, 65535), Datagrams::Refused);
        let small = (LARGEST_DATAGRAM - 1) as u16;
        assert_eq!(
            datagram_state(true, small),
            Datagrams::TooSmall {
                max_send_length: small,
            },
            "and the number the operator needs comes with it",
        );
        // **The boundary is "at least", not "more than".** `LARGEST_DATAGRAM`
        // is what this end will send, so a peer taking exactly that is fine;
        // an off-by-one here warns on every healthy connection, which is how a
        // warning stops being read.
        let exact = LARGEST_DATAGRAM as u16;
        assert_eq!(
            datagram_state(true, exact),
            Datagrams::Fine {
                max_send_length: exact,
            },
        );
        assert_eq!(
            datagram_state(true, 65535),
            Datagrams::Fine {
                max_send_length: 65535,
            },
        );
    }

    /// **The watchdog starts again whenever the preference moves.** Carrying
    /// the last path's `(rtt, since)` over would let a new path inherit a grace
    /// that is already most of the way run, and be declared stalled for the
    /// previous one's silence.
    #[test]
    fn a_new_path_starts_with_a_clean_grace() {
        let base = tokio::time::Instant::now();
        let mut stalled = Stalled::default();
        assert!(
            !stalled.sample(1000, 1, base),
            "the first sample only records"
        );
        assert!(
            stalled.sample(1000, 1, at(base, STALLED_GRACE.as_secs() + 1)),
            "same rtt, data outstanding, grace elapsed: stalled",
        );

        stalled.reset();
        assert!(
            !stalled.sample(1000, 1, at(base, STALLED_GRACE.as_secs() + 1)),
            "after a reset the same sample is the first one again",
        );
    }
    /// **Each event has to reach the thing that handles it.** With the arms
    /// written inline none of this could be reached without a live QUIC
    /// connection, so dropping one entirely -- ignoring every `PathRemoved` --
    /// compiled and passed every test.
    #[test]
    fn every_event_this_loop_acts_on_is_dispatched_to_its_own_answer() {
        let now = tokio::time::Instant::now();
        let mut paths = watching();
        let direct = (addr(3), addr(4));

        assert_eq!(
            step(
                &ConnectionEvent::PathValidated {
                    local_address: direct.0,
                    remote_address: direct.1,
                },
                &mut paths,
                now,
            ),
            Step::WaitForAnId { pair: direct },
        );
        assert_eq!(
            step(
                &ConnectionEvent::PathAdded {
                    path_id: 7,
                    local_address: direct.0,
                    peer_address: direct.1,
                },
                &mut paths,
                now,
            ),
            Step::MoveOnto {
                pair: direct,
                path_id: 7,
            },
        );
        paths.now_carrying(direct);
        // **The same event about a relay leg means the opposite thing.** One
        // `PathAdded` carries both, and telling them apart is the whole of
        // what P4 added to this dispatch.
        let was = paths.relay;
        let leg = (addr(1), addr(9));
        paths.relay_is_gone();
        paths.opening_to(leg.1, now + RELAY_PATH_PATIENCE);
        assert_eq!(
            step(
                &ConnectionEvent::PathAdded {
                    path_id: 3,
                    local_address: leg.0,
                    peer_address: leg.1,
                },
                &mut paths,
                now,
            ),
            Step::RelayMoved {
                pair: leg,
                path_id: 3,
                old: was,
            },
        );
        assert_eq!(paths.preferred, Some(direct), "and nothing moved");
        assert_eq!(
            step(
                &ConnectionEvent::PathStatusChanged {
                    path_id: 7,
                    local_address: direct.0,
                    peer_address: direct.1,
                    is_active: false,
                },
                &mut paths,
                now,
            ),
            Step::Demoted {
                pair: direct,
                path_id: 7,
            },
        );
        paths.now_carrying(direct);
        assert_eq!(
            step(
                &ConnectionEvent::PathRemoved {
                    path_id: 7,
                    local_address: direct.0,
                    peer_address: direct.1,
                },
                &mut paths,
                now,
            ),
            Step::BackToTheRelay {
                pair: direct,
                path_id: 7,
            },
        );
        assert_eq!(
            step(
                &ConnectionEvent::DatagramStateChanged {
                    send_enabled: false,
                    max_send_length: 0,
                },
                &mut paths,
                now,
            ),
            Step::Datagrams(Datagrams::Refused),
        );
        // And an event this loop has nothing to say about stays that way.
        assert_eq!(
            step(
                &ConnectionEvent::NotifyRemoteAddressRemoved { sequence_number: 1 },
                &mut paths,
                now,
            ),
            Step::Nothing,
        );
    }

    /// **The guards are the other half.** Each of these events has a "yes" and
    /// a "no", and the loop reads them as different things to do -- so an
    /// inverted test would move onto a path it is already on, or ask for the
    /// relay back over somebody else's path going away.
    #[test]
    fn the_events_that_mean_nothing_are_told_from_the_ones_that_mean_something() {
        let now = tokio::time::Instant::now();
        let mut paths = watching();
        let direct = (addr(3), addr(4));
        let theirs = (addr(5), addr(6));
        paths.added(direct, 7);
        paths.now_carrying(direct);

        // Already on it: asking again would reset the stall watchdog's grace.
        assert_eq!(
            step(
                &ConnectionEvent::PathAdded {
                    path_id: 7,
                    local_address: direct.0,
                    peer_address: direct.1,
                },
                &mut paths,
                now,
            ),
            Step::Nothing,
        );
        // Its id is known, so there is nothing to wait for.
        assert_eq!(
            step(
                &ConnectionEvent::PathValidated {
                    local_address: direct.0,
                    remote_address: direct.1,
                },
                &mut paths,
                now,
            ),
            Step::Nothing,
        );
        // Somebody else's path, both ways round.
        assert_eq!(
            step(
                &ConnectionEvent::PathRemoved {
                    path_id: 9,
                    local_address: theirs.0,
                    peer_address: theirs.1,
                },
                &mut paths,
                now,
            ),
            Step::LostOneWeWereNotUsing {
                pair: theirs,
                path_id: 9,
            },
        );
        assert_eq!(
            step(
                &ConnectionEvent::PathStatusChanged {
                    path_id: 9,
                    local_address: theirs.0,
                    peer_address: theirs.1,
                    is_active: false,
                },
                &mut paths,
                now,
            ),
            Step::PeerChangedAPath {
                pair: theirs,
                path_id: 9,
                is_active: false,
            },
        );
        assert_eq!(paths.preferred, Some(direct), "none of that moved us");
    }
    /// **The relay path must never be the one demoted.** Inverting this holds
    /// every direct path active and puts the relay on backup — traffic on a
    /// path nothing chose, which is the failure this fallback exists to stop.
    #[test]
    fn the_relay_path_is_the_one_that_stays_available() {
        assert!(!hold_as_backup(RELAY_PATH_ID));
        assert!(hold_as_backup(RELAY_PATH_ID + 1));
        assert!(hold_as_backup(7));
    }
    /// **A spell with no preference must not count towards the grace.** The
    /// watchdog judges the path in use; with traffic on the relay there is no
    /// such path, and carrying the last one's `(rtt, since)` across would let
    /// whatever is preferred next be declared dead for the gap's silence.
    #[test]
    fn nothing_preferred_is_nothing_to_judge_and_starts_the_grace_again() {
        let base = tokio::time::Instant::now();
        let direct = BTreeMap::new();
        let mut stalled = Stalled::default();
        let paths = [entry(0, 1000)];

        // Put something in the watchdog to lose.
        assert!(!stalled.sample(1000, 1, base));
        assert!(!judge(&paths, None, &direct, &mut stalled, base));
        assert!(
            !stalled.sample(1000, 1, at(base, STALLED_GRACE.as_secs() + 1)),
            "the sample after it is the first one again",
        );
    }

    /// The entry that cannot be identified is the other reset, and for a
    /// sharper reason: judging the wrong path here declares a healthy one dead.
    #[test]
    fn an_unidentifiable_entry_is_not_judged() {
        let base = tokio::time::Instant::now();
        let mut direct = BTreeMap::new();
        // Multipath, so the id selects the entry -- and no entry carries it.
        direct.insert(pair(9), 4u32);
        let mut stalled = Stalled::default();
        let paths = [entry(1, 1000), entry(2, 1000)];

        assert!(!stalled.sample(1000, 1, base));
        assert!(!judge(&paths, Some(pair(9)), &direct, &mut stalled, base));
        assert!(
            !stalled.sample(1000, 1, at(base, STALLED_GRACE.as_secs() + 1)),
            "not judging means starting again, not holding what was seen",
        );
    }

    /// And when it can be identified, the watchdog does see it: the same rtt
    /// with data outstanding for the whole grace is a stall.
    #[test]
    fn the_path_in_use_is_the_one_the_watchdog_judges() {
        let base = tokio::time::Instant::now();
        let direct = BTreeMap::new();
        let mut stalled = Stalled::default();
        // Without multipath the preferred path is the first entry.
        let mut paths = [entry(0, 1000), entry(0, 2000)];
        paths[0].NetworkStatistics.BytesInFlight = 1;

        assert!(!judge(&paths, Some(pair(9)), &direct, &mut stalled, base));
        assert!(judge(
            &paths,
            Some(pair(9)),
            &direct,
            &mut stalled,
            at(base, STALLED_GRACE.as_secs() + 1),
        ));
    }
}
