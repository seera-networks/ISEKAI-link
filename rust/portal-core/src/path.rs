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
//! ```
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

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use msquic_async::{msquic, Connection, ConnectionEvent};
use tokio_util::sync::CancellationToken;

use isekai_p2p::direct_path::{prefer_path, RELAY_PATH_ID};
use isekai_p2p::peer::log_connection_stats;

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

/// The largest thing this end ever hands to `send_datagram`.
///
/// **Not `MAX_PAYLOAD`**, which is the *payload* bound: `datagram::encode`
/// prepends the session id, so a full-size payload reaches the connection four
/// bytes longer. Comparing the connection's limit against the payload figure
/// would leave 1180..=1183 reported as fine while every maximum-size datagram
/// came back `TooBig` and was counted as a loss.
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

/// Watch `conn`'s paths and keep it on the best one, until the connection ends.
///
/// **Returns when the connection is no longer usable**, which is what makes this
/// the caller's "the peer went away" signal too. That is not a convenience: the
/// event stream is a single queue per connection, so a second task polling it
/// would take events belonging to this one — a portal client cannot both watch
/// paths and separately watch for closure.
pub async fn keep_on_the_best_path(conn: Connection, shutdown: CancellationToken) {
    // No event names the path the handshake ran on — `PathAdded` reports paths
    // opened after a probe validated, and this one was never probed — so it is
    // read from the connection instead.
    let relay = match (conn.get_local_addr(), conn.get_remote_addr()) {
        (Ok(local), Ok(remote)) => (local, remote),
        _ => {
            tracing::warn!(
                "could not read the relay path's addresses; no path can be preferred \
                 without them, so every path that turns up is held as backup and the \
                 relay keeps the traffic",
            );
            stay_on_the_relay(&conn, &shutdown).await;
            return;
        }
    };
    tracing::info!(local = %relay.0, remote = %relay.1, "forwarding over the relay path");

    // What `PathAdded` has named. Empty means the peer negotiated no multipath,
    // and then `prefer_path` falls back to the old switch.
    let mut direct: BTreeMap<(SocketAddr, SocketAddr), u32> = BTreeMap::new();
    // `None` is the relay. Held so that `PathRemoved` can tell "the path we are
    // using has gone" from "a path we were not using has gone".
    let mut preferred: Option<(SocketAddr, SocketAddr)> = None;
    // A pair that validated and has no path id yet, and when to stop waiting
    // for one. See the module header: this is the whole of how "the peer has no
    // multipath" is told from "`PathAdded` has not arrived yet".
    let mut awaiting_id: Option<((SocketAddr, SocketAddr), tokio::time::Instant)> = None;
    // Whether the path being preferred is delivering. Reset whenever the
    // preference moves, so a new path starts with a clean grace period.
    let mut stalled = Stalled::default();
    let mut ticks: u32 = 0;

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
                if report_paths(&conn, preferred, &direct, &mut stalled) {
                    // **Preferring the relay again, not tearing anything down.**
                    // Under multipath the relay was never left, only declared
                    // backup, so this is withdrawing a preference — nothing in
                    // flight is lost by asking.
                    let stale = preferred;
                    tracing::warn!(
                        local = %stale.map(|p| p.0.to_string()).unwrap_or_default(),
                        remote = %stale.map(|p| p.1.to_string()).unwrap_or_default(),
                        "the direct path has held data for {STALLED_GRACE:?} without a single \
                         acknowledgement; forwarding goes back to the relay",
                    );
                    // **Only forget the preference if the move happened.**
                    // `prefer_path` answers `false` when nothing changed, and
                    // clearing `preferred` anyway would leave traffic on the
                    // stalled path with the watchdog switched off — it only
                    // judges a path it believes is preferred, so there would be
                    // no second attempt.
                    if prefer_path(&conn, relay, relay, &direct) {
                        preferred = None;
                        stalled.reset();
                    }
                }
                continue;
            }
            // Nothing to wait for unless a pair has validated without an id.
            _ = sleep_until(awaiting_id.map(|(_, at)| at)) => {
                let (pair, _) = awaiting_id.take().expect("only armed with a pair");
                // No `PathAdded` in all that time, so the peer negotiated no
                // multipath and the old switch is the only operation there is.
                // `direct` is empty, which is what makes `prefer_path` choose it.
                tracing::info!(
                    local = %pair.0, remote = %pair.1,
                    "no path id after {MULTIPATH_GRACE:?}; the peer has no multipath",
                );
                if prefer_path(&conn, pair, relay, &direct) {
                    preferred = Some(pair);
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
        match event {
            ConnectionEvent::PathAdded {
                path_id,
                local_address,
                peer_address,
            } => {
                let pair = (local_address, peer_address);
                if pair == relay {
                    continue;
                }
                // **The event that decides**, because it is the one carrying the
                // id every multipath operation needs — and because its existence
                // is what says the peer has multipath at all. Recorded before
                // the call, since `prefer_path` looks this path up in here.
                direct.insert(pair, path_id);
                if awaiting_id.is_some_and(|(waiting, _)| waiting == pair) {
                    awaiting_id = None;
                }
                if preferred == Some(pair) {
                    continue;
                }
                if prefer_path(&conn, pair, relay, &direct) {
                    preferred = Some(pair);
                    // A new path starts with a clean grace: carrying the last
                    // one's `(rtt, since)` over would let this one inherit a
                    // window that is already most of the way run.
                    stalled.reset();
                    tracing::info!(
                        path_id, local = %local_address, remote = %peer_address,
                        "forwarding moved onto the direct path; the relay stays as backup",
                    );
                }
            }
            ConnectionEvent::PathValidated {
                local_address,
                remote_address,
            } => {
                let pair = (local_address, remote_address);
                if pair == relay || preferred == Some(pair) || direct.contains_key(&pair) {
                    continue;
                }
                // **Not acted on here**, however tempting: this event has no
                // path id, so preferring now can only mean the pre-multipath
                // switch — which is the wrong operation whenever a `PathAdded`
                // for the same path is a fraction of a millisecond behind. The
                // module header has what that cost on hardware.
                tracing::info!(
                    local = %local_address, remote = %remote_address,
                    "a direct path validated; waiting up to {MULTIPATH_GRACE:?} for its id",
                );
                awaiting_id = Some((pair, tokio::time::Instant::now() + MULTIPATH_GRACE));
            }
            ConnectionEvent::PathRemoved {
                path_id,
                local_address,
                peer_address,
            } => {
                let pair = (local_address, peer_address);
                direct.remove(&pair);
                if awaiting_id.is_some_and(|(waiting, _)| waiting == pair) {
                    // Validated, then abandoned before it was ever preferred:
                    // waiting out the grace would end in switching onto a path
                    // that no longer exists.
                    awaiting_id = None;
                }
                if preferred != Some((local_address, peer_address)) {
                    tracing::debug!(
                        path_id, local = %local_address, remote = %peer_address,
                        "a path this connection was not using was removed",
                    );
                    continue;
                }
                // The one we were on. Going back is a preference, not a
                // reconnection — the relay path was never torn down, only
                // declared backup — so nothing in flight is lost by asking.
                tracing::warn!(
                    path_id, local = %local_address, remote = %peer_address,
                    "the direct path was removed; forwarding goes back to the relay",
                );
                preferred = None;
                prefer_path(&conn, relay, relay, &direct);
            }
            // **What the peer will take, said once rather than discovered.**
            // `send_enabled` false means it never advertised
            // `max_datagram_frame_size`, so every UDP forward over this
            // connection is dead before it starts — which is exactly how phase
            // 3a's bug hid, as one `Denied` per datagram with nothing said. And
            // `max_send_length` is the real limit `datagram::MAX_PAYLOAD` is
            // deliberately under; it is checked rather than adopted, because
            // the constant is a promise `docs/portal.md` makes to callers and
            // raising it per connection would leave DNS working on one network
            // and not another.
            ConnectionEvent::DatagramStateChanged {
                send_enabled,
                max_send_length,
            } => {
                if !send_enabled {
                    tracing::warn!(
                        "the peer will not receive QUIC datagrams, so UDP forwarding over \
                         this connection cannot work; TCP forwards are unaffected",
                    );
                } else if usize::from(max_send_length) < LARGEST_DATAGRAM {
                    // The one direction the constant cannot absorb: under the
                    // limit means payloads this end accepts are refused by the
                    // connection, and counted as `unsent` rather than carried.
                    tracing::warn!(
                        max_send_length,
                        largest = LARGEST_DATAGRAM,
                        "the connection takes smaller datagrams than portal will send; \
                         payloads near the limit will be refused and counted as unsent",
                    );
                } else {
                    tracing::debug!(
                        max_send_length,
                        largest = LARGEST_DATAGRAM,
                        "the peer receives datagrams",
                    );
                }
            }
            ConnectionEvent::PathStatusChanged {
                path_id,
                local_address,
                peer_address,
                is_active,
            } => {
                // **The peer's declaration moves this end too**, which is not
                // what it looks like: a PATH_BACKUP arriving clears this side's
                // own `Path->IsActive`, so a path the peer demotes stops
                // carrying our traffic whatever we decided. Bookkeeping rather
                // than a fight — re-declaring it available would be arguing with
                // the end that has a reason.
                //
                // What must not happen is `preferred` staying behind, because
                // it is what labels the per-second stats: the operator would
                // read `direct` off a connection running on the relay, which is
                // the failure this whole file was written for.
                let pair = (local_address, peer_address);
                if !is_active && preferred == Some(pair) {
                    tracing::warn!(
                        path_id, local = %local_address, remote = %peer_address,
                        "the peer declared the path we were using backup; \
                         forwarding is on the relay again",
                    );
                    preferred = None;
                    stalled.reset();
                } else {
                    tracing::debug!(
                        path_id, local = %local_address, remote = %peer_address, is_active,
                        "the peer changed a path's status",
                    );
                }
            }
            _ => {}
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
    let Some(pair) = preferred else {
        stalled.reset();
        return false;
    };
    let Some(path) = preferred_entry(&paths, pair, direct) else {
        // Not knowable this tick. Saying nothing is right: the alternative is
        // judging the wrong path, and the wrong path here is a healthy one.
        tracing::debug!("cannot tell which entry is the preferred path; not judging it");
        stalled.reset();
        return false;
    };
    stalled.sample(
        path.Rtt,
        path.NetworkStatistics.BytesInFlight,
        tokio::time::Instant::now(),
    )
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
async fn stay_on_the_relay(conn: &Connection, shutdown: &CancellationToken) {
    loop {
        let event = tokio::select! {
            _ = shutdown.cancelled() => return,
            event = std::future::poll_fn(|cx| conn.poll_event(cx)) => event,
        };
        let Ok(event) = event else { return };
        if let ConnectionEvent::PathAdded { path_id, .. } = event {
            // `path_id` 0 is the relay path itself, which must stay available —
            // and it is never announced by this event anyway, since the path the
            // handshake ran on was never probed.
            if path_id != RELAY_PATH_ID {
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
}
