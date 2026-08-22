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
//! `PathRemoved`, and **not a byte counter** — which is worth writing down,
//! because copying `camera-core`'s watchdog was the obvious thing to do and it
//! would not have worked here.
//!
//! That watchdog asks "have any frames arrived since we moved?", and frames are
//! application data, which travels on the preferred path alone. Portal has no
//! single frame counter, and the connection-level counter that looks like a
//! substitute is not one: under multipath the relay path is still active, still
//! carrying its own keepalive PINGs and still receiving their acknowledgements,
//! so `Recv.TotalBytes` keeps advancing however dead the preferred path is. A
//! watchdog built on it would never fire, and would read in the code as though
//! the case were handled.
//!
//! So the transport's own judgement is what is used: msquic raises `PathRemoved`
//! when it abandons a path, and that is when the relay is preferred again.
//! **The gap that leaves is a path msquic keeps and does not carry**, and there
//! is no local signal for it — the honest state of this is that hardware has to
//! say whether it happens.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use msquic_async::{Connection, ConnectionEvent};
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
                match conn.get_stats() {
                    Ok(stats) => log_connection_stats(
                        &conn,
                        &stats,
                        if preferred.is_some() { "direct" } else { "relay" },
                    ),
                    Err(e) => tracing::debug!("could not read connection stats: {e}"),
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
