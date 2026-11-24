//! Keeping one path of a control-plane or relay connection carrying traffic
//! (feature `msquic`).
//!
//! Since the control-plane and relay connections negotiate multipath
//! (`crate::transport::make_client_config`), msquic opens a path per usable
//! local address of the host and every one of them is active the moment it is
//! added. `QuicConnChoosePath` then picks **uniformly at random** among the
//! active paths for each packet, so a host with three addresses sends a third
//! of its control-plane traffic down each — three different NAT mappings,
//! three different RTTs, three congestion controllers each seeing a third of
//! the feedback. What that looks like from here is an unstable connection,
//! which is what it is.
//!
//! There is one lever: `PATH_BACKUP` says "prefer not to send here", and
//! `QuicConnChoosePath` honours it while any active path remains. So this holds
//! every path msquic adds as backup and leaves the connection on the one it
//! started on, which is the only path that was ever chosen deliberately — the
//! address the connector picked, in the family the control plane asked for.
//!
//! ```text
//!   PathAdded        ─▶ held as backup, at the back of the reserve
//!   PathRemoved      ─▶ the path carrying traffic?  promote the oldest reserve
//!                       a reserve path?              drop it from the reserve
//!   PathStatusChanged ─▶ the peer called a reserve path available: say backup
//!                        once more, then leave it alone
//! ```
//!
//! # The reserve is a queue because validation order is the only order there is
//!
//! A path becomes a candidate here when msquic announces it, and msquic
//! announces a path when it completes validation under multipath — so the
//! arrival order of `PathAdded` *is* the order the paths were validated in.
//! Nothing else distinguishes them: a path that has never carried a packet has
//! no RTT worth comparing, and the local addresses were already filtered down
//! to the usable ones by [`crate::local_address`] before any of them became a
//! path. Promoting the oldest is therefore promoting the one that has been
//! known to work for longest, and it is a total order, which matters more here
//! than being clever — two ends promoting different paths is a connection that
//! sends one way and listens another.
//!
//! # The path it starts on is never announced, and does not need to be
//!
//! There is no event for the initial path: `PathAdded` covers paths that
//! complete validation after multipath is negotiated, and a client's own first
//! path counts as validated when the connection is allocated. So this never
//! learns its path id, and never has to — it is active already, which is the
//! state this module wants it in. The one thing that needs saying about it is
//! that it died, and `PathRemoved` says that with an id this module has never
//! held as backup, which is exactly how [`OneActivePath::on_event`] recognises
//! it.
//!
//! # A path failure is no longer a connection failure, which is what makes this
//! worth doing
//!
//! Before seera-networks/msquic#228, abandoning a path required another
//! *active* path to carry the `PATH_ABANDON` frame, and declaring every extra
//! path backup left exactly one — so when the path carrying traffic died, msquic
//! closed the whole connection with `QUIC_STATUS_CONNECTION_TIMEOUT` and took
//! the healthy backups with it. A backup path counts as usable now, which is
//! what leaves anything for this module to promote.
//!
//! What remains is a window that belongs here: between msquic abandoning the
//! dead path and this module promoting a backup, `QuicConnChoosePath` finds no
//! active path and falls back to `Paths[0]` — possibly the abandoned one. It is
//! closed in the same event that opens it, since promoting happens in the arm
//! that learns the path is gone.
//!
//! # One poller per connection
//!
//! `Connection::poll_event` is a single-consumer queue: whoever polls it takes
//! the event, and a second poller on the same connection silently halves what
//! each of them sees. So this module has a decision function the holder of the
//! connection feeds ([`OneActivePath::observe`]) rather than a task of its own,
//! and [`spawn`] is for a connection nothing else was polling — which is what
//! the control-plane connection is, since `h3-msquic-async` never polls events.
//! A relay leg is already polled by [`crate::observed`], and that loop calls
//! `observe` instead.

use std::collections::VecDeque;
use std::future::poll_fn;

// Reached through `h3-util` rather than depended on directly, like the rest of
// this crate's msquic usage (see `crate::transport`).
use h3_util::msquic_async::h3_msquic_async::msquic_async::{Connection, ConnectionEvent};
use h3_util::msquic_async::{Established, H3MsQuicAsyncConnector};
use tokio::sync::mpsc;

/// What to say about a path, which is the whole vocabulary: a path status is
/// declared to the peer, and declaring it is what sets it locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Declare {
    /// `PATH_BACKUP`: held in reserve, and taken out of `QuicConnChoosePath`'s
    /// random selection while an active path remains.
    Backup(u32),
    /// `PATH_AVAILABLE`: this is the path to carry the traffic now.
    Available(u32),
}

/// One path carries the traffic; every other path msquic adds is held in
/// reserve, in validation order.
///
/// Per connection: a reconnection has new paths and new ids, so the state of
/// the one before it means nothing. [`spawn`] and [`crate::observed`] both make
/// a fresh one for each connection they are handed.
#[derive(Debug, Default)]
pub struct OneActivePath {
    /// Paths declared backup, oldest first — so the front is the next to be
    /// promoted.
    reserve: VecDeque<Held>,
    /// The reserve path this end has promoted, once it has had to promote one.
    /// `None` while the connection is still on the path it started on.
    promoted: Option<u32>,
}

#[derive(Debug)]
struct Held {
    path_id: u32,
    /// Whether the peer has been told `PATH_BACKUP` for this path a second
    /// time, after declaring it available itself. Once is worth saying — a
    /// `PATH_AVAILABLE` can cross our `PATH_BACKUP` in flight, and then neither
    /// end's view is wrong, only old. Twice would be an argument, and the peer
    /// is entitled to its own preference about where it sends.
    reasserted: bool,
}

impl OneActivePath {
    /// What this event means for the connection's paths, and nothing else.
    ///
    /// Separate from applying it so that the decisions are reachable from a
    /// test without a live connection; [`observe`](Self::observe) is the two
    /// together.
    pub fn on_event(&mut self, event: &ConnectionEvent) -> Option<Declare> {
        match *event {
            ConnectionEvent::PathAdded { path_id, .. } => self.added(path_id),
            ConnectionEvent::PathRemoved { path_id, .. } => self.removed(path_id),
            ConnectionEvent::PathStatusChanged {
                path_id, is_active, ..
            } => self.status_changed(path_id, is_active),
            _ => None,
        }
    }

    /// Decide what this event means and tell `conn` about it.
    ///
    /// `kind` names the connection in the logs ("control plane", "relay leg"):
    /// an Endpoint runs several of these at once and a path id means nothing
    /// across them.
    pub fn observe(&mut self, conn: &Connection, event: &ConnectionEvent, kind: &str) {
        if let Some(declare) = self.on_event(event) {
            apply(conn, declare, kind);
        }
    }

    /// How many paths are held in reserve.
    pub fn reserved(&self) -> usize {
        self.reserve.len()
    }

    fn added(&mut self, path_id: u32) -> Option<Declare> {
        if self.knows(path_id) {
            // An id that is already placed. Nothing msquic does should produce
            // this, but `PathRemoved` was raised twice per path until
            // seera-msquic 266769c, so a repeated path event is a genre of bug
            // that has happened here before -- and pushing a second entry would
            // leave a reserve slot that can never be promoted away.
            return None;
        }
        self.reserve.push_back(Held {
            path_id,
            reasserted: false,
        });
        Some(Declare::Backup(path_id))
    }

    fn removed(&mut self, path_id: u32) -> Option<Declare> {
        if let Some(i) = self.reserve.iter().position(|h| h.path_id == path_id) {
            // A path that was carrying nothing. The connection is unaffected,
            // and the reserve is one shorter.
            self.reserve.remove(i);
            return None;
        }
        if self.promoted == Some(path_id) {
            // The path this end promoted, gone in turn: promote the next, which
            // is what "if that one dies, the next backup" means.
            self.promoted = None;
            return self.promote_next();
        }
        if self.promoted.is_none() {
            // An id never held as backup and nothing promoted yet: the path the
            // connection started on, which is the case this module exists for.
            return self.promote_next();
        }
        // An id this end never held, with a promoted path already carrying
        // traffic -- the initial path going away after it had already been
        // replaced. Nothing to do.
        None
    }

    fn status_changed(&mut self, path_id: u32, is_active: bool) -> Option<Declare> {
        // **The peer's declaration lands on our send side.** A `PATH_AVAILABLE`
        // arriving sets `Path->IsActive` here, which is the same flag
        // `set_path_status` sets and the one `QuicConnChoosePath` selects on. So
        // the peer calling a reserve path available puts it back into the random
        // selection and undoes what this module is for, however reasonable the
        // peer's own preference is about where it sends.
        if !is_active {
            return None;
        }
        let held = self.reserve.iter_mut().find(|h| h.path_id == path_id)?;
        if held.reasserted {
            return None;
        }
        held.reasserted = true;
        Some(Declare::Backup(path_id))
    }

    fn promote_next(&mut self) -> Option<Declare> {
        let next = self.reserve.pop_front()?;
        self.promoted = Some(next.path_id);
        Some(Declare::Available(next.path_id))
    }

    fn knows(&self, path_id: u32) -> bool {
        self.promoted == Some(path_id) || self.reserve.iter().any(|h| h.path_id == path_id)
    }
}

/// Tell the connection what was decided.
///
/// A failure is logged and not retried: `set_path_status` fails for a path id
/// msquic no longer has, which is a path that went away between the event and
/// this call and needs nothing, and for a connection without multipath, where
/// there are no extra paths to hold in the first place.
fn apply(conn: &Connection, declare: Declare, kind: &str) {
    match declare {
        Declare::Backup(path_id) => match conn.set_path_status(path_id, false) {
            Ok(()) => tracing::info!(
                kind,
                path_id,
                "path held as backup; the {kind} connection keeps the path it is on",
            ),
            Err(e) => tracing::warn!(
                kind,
                path_id,
                "could not hold the path as backup; {kind} traffic may split \
                 across it at random: {e}",
            ),
        },
        Declare::Available(path_id) => match conn.set_path_status(path_id, true) {
            Ok(()) => tracing::warn!(
                kind,
                path_id,
                "the {kind} connection lost the path it was on; promoted the \
                 oldest path held in reserve",
            ),
            Err(e) => tracing::error!(
                kind,
                path_id,
                "the {kind} connection lost the path it was on and the oldest \
                 path held in reserve could not be promoted; it is now sending \
                 wherever msquic falls back to: {e}",
            ),
        },
    }
}

/// Hold the paths of every connection this connector establishes, for a
/// connection nothing else polls events on.
///
/// **The channel is attached only when there is a runtime to drain it on, and
/// that is the whole reason this takes the connector.** `connect` hands each
/// established connection over with `send().await?`: a channel nobody reads
/// stalls the connect once four connections have gone by, and a channel whose
/// receiver has been dropped fails it outright. So "attach the channel" and
/// "run the loop" cannot be separate decisions — a connector built outside a
/// runtime (`MasqueH3Transport::connect` is a synchronous constructor, and its
/// callers include FFI entry points) gets no channel at all and behaves as it
/// did before this module existed.
pub fn attach(mut connector: H3MsQuicAsyncConnector, kind: &'static str) -> H3MsQuicAsyncConnector {
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        tracing::warn!(
            kind,
            "no tokio runtime to hold the {kind} connection's paths on; msquic \
             will spread it at random across every path it adds",
        );
        return connector;
    };
    // The connector has one channel, so a caller that wants the connections for
    // something else has to do this itself -- `crate::observed` does.
    let (conn_tx, conn_rx) = mpsc::channel(4);
    connector = connector.with_channel(conn_tx);
    handle.spawn(run(conn_rx, kind));
    connector
}

/// Hold the paths of each connection in turn, for as long as the connector
/// keeps handing them over.
///
/// **No cancellation, deliberately.** Dropping the receiver early would not
/// lose a path preference, it would stop the connection reconnecting at all
/// (see [`attach`]), so this ends when the connector drops its sender and not
/// before.
async fn run(mut conn_rx: mpsc::Receiver<Established>, kind: &'static str) {
    while let Some(Established { conn, .. }) = conn_rx.recv().await {
        // Paths belong to the connection that has them, so each one starts
        // from nothing.
        let mut paths = OneActivePath::default();
        loop {
            match poll_fn(|cx| conn.poll_event(cx)).await {
                Ok(event) => {
                    paths.observe(&conn, &event, kind);
                    tracing::trace!(kind, "connection event: {event:?}");
                }
                Err(e) => {
                    // The stream erroring is this connection ending. The next
                    // one arrives on the channel.
                    tracing::debug!(kind, "connection event stream ended: {e}");
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids msquic hands out carry no meaning here beyond identity, and the
    /// addresses none at all: every decision this module makes is made from the
    /// path id and the order the events arrived in.
    const INITIAL: u32 = 0;

    fn pair() -> (std::net::SocketAddr, std::net::SocketAddr) {
        (
            "10.0.2.10:443".parse().expect("an address"),
            "198.51.100.7:443".parse().expect("an address"),
        )
    }

    fn added(path_id: u32) -> ConnectionEvent {
        let (local_address, peer_address) = pair();
        ConnectionEvent::PathAdded {
            local_address,
            peer_address,
            path_id,
        }
    }

    fn removed(path_id: u32) -> ConnectionEvent {
        let (local_address, peer_address) = pair();
        ConnectionEvent::PathRemoved {
            local_address,
            peer_address,
            path_id,
        }
    }

    fn status(path_id: u32, is_active: bool) -> ConnectionEvent {
        let (local_address, peer_address) = pair();
        ConnectionEvent::PathStatusChanged {
            local_address,
            peer_address,
            path_id,
            is_active,
        }
    }

    /// The problem this module was written for: msquic opens a path per local
    /// address and every one of them is active, so the connection sends down
    /// all of them at random. Each one is held as backup as it arrives.
    #[test]
    fn every_path_msquic_adds_is_held_as_backup() {
        let mut paths = OneActivePath::default();

        for id in [1, 2, 3] {
            assert_eq!(
                paths.on_event(&added(id)),
                Some(Declare::Backup(id)),
                "path {id} should have been held as backup",
            );
        }
        assert_eq!(paths.reserved(), 3);
    }

    /// The path the connection started on is never announced, so losing it
    /// arrives as a `PathRemoved` for an id this module has never held. That is
    /// the moment a backup has to take over, and the one that takes over is the
    /// oldest — the path validated first.
    #[test]
    fn losing_the_path_it_started_on_promotes_the_oldest_in_reserve() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(7)),
            "the oldest path in reserve should have been promoted",
        );
        assert_eq!(paths.reserved(), 1, "the promoted path leaves the reserve");
    }

    /// "And if that one dies, the next backup" — until there is no next one, at
    /// which point there is nothing this module can do and msquic closes a
    /// connection that has run out of paths.
    #[test]
    fn and_the_next_one_each_time_a_promoted_path_dies() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));
        paths.on_event(&added(8));
        paths.on_event(&added(9));

        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(7))
        );
        assert_eq!(paths.on_event(&removed(7)), Some(Declare::Available(8)));
        assert_eq!(paths.on_event(&removed(8)), Some(Declare::Available(9)));
        assert_eq!(
            paths.on_event(&removed(9)),
            None,
            "nothing left to promote, and nothing to pretend otherwise",
        );
        assert_eq!(paths.reserved(), 0);
    }

    /// A reserve path dying costs the connection nothing: it was carrying no
    /// traffic, and the path in use is still the path in use. The only effect
    /// is that it stops being a candidate.
    #[test]
    fn a_path_in_reserve_dying_promotes_nothing() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(paths.on_event(&removed(7)), None);
        assert_eq!(paths.reserved(), 1);
        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(8)),
            "the path that died must not be promoted later",
        );
    }

    /// A path added after a promotion is in reserve like any other, and is what
    /// the promoted path falls back to in turn — this is how a connection that
    /// has lost its original path still has somewhere to go.
    #[test]
    fn a_path_added_after_a_promotion_joins_the_reserve() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));
        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(7))
        );

        assert_eq!(paths.on_event(&added(8)), Some(Declare::Backup(8)));
        assert_eq!(paths.on_event(&removed(7)), Some(Declare::Available(8)));
    }

    /// The initial path can be abandoned after a backup has already taken over
    /// — msquic abandons a path when its validation times out, which can land
    /// well after loss detection gave up on it. There is nothing left to decide
    /// by then.
    #[test]
    fn an_unheld_path_dying_after_a_promotion_changes_nothing() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));
        paths.on_event(&added(8));
        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(7))
        );

        assert_eq!(
            paths.on_event(&removed(4242)),
            None,
            "a path never held, with one already promoted, decides nothing",
        );
        assert_eq!(paths.reserved(), 1, "and takes nothing out of the reserve");
    }

    /// The peer's `PATH_AVAILABLE` sets the same flag `set_path_status` does,
    /// so a reserve path the peer calls available is back in the random
    /// selection. Saying backup once more is worth it: the two declarations may
    /// simply have crossed in flight.
    #[test]
    fn the_peer_calling_a_reserve_path_available_is_answered_once() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));

        assert_eq!(
            paths.on_event(&status(7, true)),
            Some(Declare::Backup(7)),
            "the path should have been declared backup again",
        );
        assert_eq!(
            paths.on_event(&status(7, true)),
            None,
            "but not argued over: the peer is entitled to its own preference",
        );
    }

    /// The peer declaring a path backup agrees with this end about the reserve,
    /// and about the path in use it is the peer's business: it governs where the
    /// peer sends, and this module does not promote a path to overrule it.
    #[test]
    fn the_peer_calling_a_path_backup_is_not_answered() {
        let mut paths = OneActivePath::default();
        paths.on_event(&added(7));

        assert_eq!(paths.on_event(&status(7, false)), None);
        assert_eq!(paths.on_event(&status(INITIAL, false)), None);
        assert_eq!(paths.reserved(), 1);
    }

    /// A path event arriving twice used to be real (`PathRemoved` was raised
    /// twice per path until seera-msquic 266769c), and a second reserve entry
    /// for one path would be a slot that can never be promoted away.
    #[test]
    fn a_repeated_path_added_does_not_take_a_second_slot() {
        let mut paths = OneActivePath::default();

        assert_eq!(paths.on_event(&added(7)), Some(Declare::Backup(7)));
        assert_eq!(paths.on_event(&added(7)), None);
        assert_eq!(paths.reserved(), 1);
        assert_eq!(
            paths.on_event(&removed(INITIAL)),
            Some(Declare::Available(7))
        );
        assert_eq!(
            paths.on_event(&added(7)),
            None,
            "nor while it is the path carrying traffic",
        );
    }

    /// Everything else on the connection is somebody else's event.
    #[test]
    fn other_events_decide_nothing() {
        let mut paths = OneActivePath::default();
        let (local_address, observed_address) = pair();

        assert_eq!(
            paths.on_event(&ConnectionEvent::NotifyObservedAddress {
                local_address,
                observed_address,
            }),
            None,
        );
    }
}
