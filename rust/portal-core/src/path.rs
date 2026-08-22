//! Moving a forward off the relay once a direct path exists.
//!
//! **Phase 4 of `docs/portal_plan.md`.** [`isekai_p2p::direct_path`] is how the
//! two ends find a direct path; this is what portal does with one when it turns
//! up. The initiator's side, because the initiator is the end that decides which
//! path carries traffic.
//!
//! ```text
//!   PathAdded      ─▶ held as backup      (or it starts carrying traffic unasked)
//!   PathValidated  ─▶ preferred           (nobody is here to press a button)
//!   PathRemoved    ─▶ back to the relay   (if it was the one being preferred)
//! ```
//!
//! # Held as backup first, and that ordering is the whole safety of it
//!
//! msquic makes a path active the moment it is added, and `QuicConnChoosePath`
//! picks at random among the active ones. So a portal that advertised and
//! offered candidates without this would not stay on the relay until it chose —
//! it would start splitting traffic across a path nothing has decided to trust,
//! and the operator's log would still say relay. Everything else here is
//! optional; this is not.
//!
//! # It prefers on its own, and the camera does not
//!
//! `camera-client` has a person and a Migrate button. A portal has an operator
//! who started a process and went away, so a direct path that waits to be asked
//! is a direct path that never gets used. Preferring on validation is the whole
//! difference between the two callers, and it is why this file exists rather
//! than `camera-core`'s loop being made to serve both.
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

use isekai_p2p::direct_path::prefer_path;
use isekai_p2p::peer::log_connection_stats;

/// How often the connection's counters are reported.
///
/// The camera's interval, and for the same reason: it is the resolution at which
/// "the path changed and then the numbers changed" is legible afterwards, which
/// is the only way a migration that went wrong can be read out of a log.
const STATS_INTERVAL: Duration = Duration::from_secs(1);

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
                "could not read the relay path's addresses; staying on the relay and \
                 watching only for the connection to end",
            );
            drain_events(&conn, &shutdown).await;
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
                if (local_address, peer_address) == relay {
                    continue;
                }
                // **Before anything else looks at it.** See the module header:
                // msquic has already made this path active, and until it is put
                // back to backup the connection is sending on a path nothing
                // has decided to trust.
                if let Err(e) = conn.set_path_status(path_id, false) {
                    tracing::warn!(
                        path_id,
                        "could not hold the new path as backup; it will carry traffic \
                         before it is asked to: {e}",
                    );
                }
                direct.insert((local_address, peer_address), path_id);
                tracing::info!(
                    path_id, local = %local_address, remote = %peer_address,
                    "a direct path was added and is being held as backup",
                );
            }
            ConnectionEvent::PathValidated {
                local_address,
                remote_address,
            } => {
                if (local_address, remote_address) == relay {
                    continue;
                }
                if preferred == Some((local_address, remote_address)) {
                    continue;
                }
                if prefer_path(&conn, (local_address, remote_address), relay, &direct) {
                    preferred = Some((local_address, remote_address));
                    tracing::info!(
                        local = %local_address, remote = %remote_address,
                        "forwarding moved onto the direct path; the relay stays as backup",
                    );
                }
            }
            ConnectionEvent::PathRemoved {
                path_id,
                local_address,
                peer_address,
            } => {
                direct.remove(&(local_address, peer_address));
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
            ConnectionEvent::PathStatusChanged { .. } => {
                // The peer's view of a path, which this end does not act on: it
                // decides for itself which path to send on.
                tracing::debug!("the peer changed a path's status");
            }
            _ => {}
        }
    }
}

/// Consume events until the connection ends, acting on none of them.
///
/// The fallback for a connection whose own addresses could not be read: there is
/// nothing sensible to compare a path against, so the relay is kept — but the
/// events still have to be drained, because this is also how the caller learns
/// the connection closed.
async fn drain_events(conn: &Connection, shutdown: &CancellationToken) {
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => return,
            event = std::future::poll_fn(|cx| conn.poll_event(cx)) => if event.is_err() {
                return;
            },
        }
    }
}
