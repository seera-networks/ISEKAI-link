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
//!   PathAdded          ─▶ held as backup, at the back of the reserve
//!                         (promoted instead, if nothing is carrying traffic)
//!   PathRemoved        ─▶ the path carrying traffic?  promote the oldest reserve
//!                         a reserve path?              drop it from the reserve
//!                         neither?                     it never carried anything
//!   PathStatusChanged  ─▶ the peer called a reserve path available: say backup
//!                         once more, then leave it alone
//!                         the peer called the carrying path backup: that is a
//!                         path this end can no longer send on, so promote
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
//! # The path it starts on is recognised by its addresses, not its id
//!
//! There is no event for the initial path: `PathAdded` is indicated on the
//! `PATH_RESPONSE` that completes a validation, and a client's own first path
//! counts as validated when the connection is allocated. So its path id never
//! reaches this module, and losing it arrives as a `PathRemoved` for an id this
//! module has never held.
//!
//! **An id never held is not enough to recognise it by, though, and reading it
//! that way was wrong.** A path whose validation *times out* is abandoned by
//! msquic, which indicates `PathRemoved` for it — and that path never completed
//! validation, so it never produced a `PathAdded` either. Its removal looks
//! exactly like the initial path's. Promoting a backup there would leave two
//! active paths with the initial one still carrying traffic: the random split
//! this module exists to prevent, arrived at by preventing it.
//!
//! So the initial path is identified by the address pair the connection
//! reports before any path event has been seen, which is `Paths[0]` — the
//! initial path — at that moment. A `PathRemoved` naming any other pair, with
//! an id that was never held, is a path that never carried anything and
//! decides nothing.
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
//! and [`attach`] is for a connection nothing else was polling — which is what
//! the control-plane connection is, since `h3-msquic-async` never polls events.
//! A relay leg is already polled by [`crate::observed`], and that loop calls
//! `observe` instead.

use std::collections::VecDeque;
use std::future::poll_fn;
use std::net::SocketAddr;

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

/// Which path the connection is believed to be sending on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Carrying {
    /// The path the connection started on, which has no id here.
    Initial,
    /// A path this end promoted out of the reserve.
    Path(u32),
    /// Nothing, as far as this module can tell — every path it knows of is
    /// either gone or declared backup, and msquic is sending wherever it falls
    /// back to. The next path to turn up is promoted rather than held.
    Nothing,
}

/// One path carries the traffic; every other path msquic adds is held in
/// reserve, in validation order.
///
/// Per connection: a reconnection has new paths and new ids, so the state of
/// the one before it means nothing. [`attach`] and [`crate::observed`] both
/// make a fresh one for each connection they are handed.
#[derive(Debug)]
pub struct OneActivePath {
    /// The address pair of the path the connection started on, read before any
    /// path event was seen. `None` if the connection would not say, which
    /// costs the failover and not the stability — see
    /// [`for_connection`](Self::for_connection).
    initial: Option<(SocketAddr, SocketAddr)>,
    /// Paths declared backup, oldest first — so the front is the next to be
    /// promoted.
    reserve: VecDeque<Held>,
    carrying: Carrying,
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
    /// Start on the path `conn` is on.
    ///
    /// **Called before the connection's events are polled**, so the addresses
    /// read here are the initial path's: `QUIC_PARAM_CONN_LOCAL_ADDRESS` is
    /// `Paths[0]`, and no path has been abandoned or shuffled out of that slot
    /// yet.
    ///
    /// A connection that will not report them is held to the same preference —
    /// every path added is still declared backup — but cannot recognise the
    /// initial path going away, so it does not fail over. That is logged once,
    /// loudly, rather than guessed at: guessing is what promotes a backup
    /// alongside a healthy path.
    pub fn for_connection(conn: &Connection, kind: &str) -> Self {
        let initial = match (conn.get_local_addr(), conn.get_remote_addr()) {
            (Ok(local), Ok(peer)) => Some((local, peer)),
            (local, peer) => {
                tracing::warn!(
                    kind,
                    "the {kind} connection would not name the path it started on \
                     (local {local:?}, peer {peer:?}); its paths will still be held \
                     as backup, but losing that path will not promote one",
                );
                None
            }
        };
        Self::new(initial)
    }

    /// For a caller that already knows the initial path's address pair, and for
    /// tests.
    pub fn new(initial: Option<(SocketAddr, SocketAddr)>) -> Self {
        Self {
            initial,
            reserve: VecDeque::new(),
            carrying: Carrying::Initial,
        }
    }

    /// What this event means for the connection's paths, and nothing else.
    ///
    /// Separate from applying it so that the decisions are reachable from a
    /// test without a live connection; [`observe`](Self::observe) is the two
    /// together.
    pub fn on_event(&mut self, event: &ConnectionEvent) -> Option<Declare> {
        match *event {
            ConnectionEvent::PathAdded { path_id, .. } => self.added(path_id),
            ConnectionEvent::PathRemoved {
                local_address,
                peer_address,
                path_id,
            } => self.removed(path_id, (local_address, peer_address)),
            ConnectionEvent::PathStatusChanged {
                local_address,
                peer_address,
                path_id,
                is_active,
            } => self.status_changed(path_id, (local_address, peer_address), is_active),
            _ => None,
        }
    }

    /// Decide what this event means and tell `conn` about it.
    ///
    /// `kind` names the connection in the logs ("control plane", "relay leg"):
    /// an Endpoint runs several of these at once and a path id means nothing
    /// across them.
    pub fn observe(&mut self, conn: &Connection, event: &ConnectionEvent, kind: &str) {
        // **A declaration that does not take is not done.** A promotion msquic
        // refuses leaves the connection with nothing carrying traffic, and the
        // reserve entry already spent -- so the refusal picks the next path
        // rather than being logged and dropped. Bounded by the reserve, which
        // every promotion shortens.
        let mut next = self.on_event(event);
        while let Some(declare) = next {
            match apply(conn, declare, kind) {
                Ok(()) => break,
                Err(()) => next = self.declaration_failed(declare),
            }
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
        if self.carrying == Carrying::Nothing {
            // Nothing to hold this in reserve behind. The path is active
            // already, since msquic announces it on validation; declaring it
            // says so to the peer and makes it the path this module will fall
            // back *from*.
            self.carrying = Carrying::Path(path_id);
            return Some(Declare::Available(path_id));
        }
        self.reserve.push_back(Held {
            path_id,
            reasserted: false,
        });
        Some(Declare::Backup(path_id))
    }

    fn removed(&mut self, path_id: u32, pair: (SocketAddr, SocketAddr)) -> Option<Declare> {
        if let Some(i) = self.reserve.iter().position(|h| h.path_id == path_id) {
            // A path that was carrying nothing. The connection is unaffected,
            // and the reserve is one shorter.
            self.reserve.remove(i);
            return None;
        }
        if self.carrying == Carrying::Path(path_id) {
            // The path this end promoted, gone in turn: promote the next, which
            // is what "if that one dies, the next backup" means.
            return self.promote_next();
        }
        if self.carrying == Carrying::Initial && self.initial == Some(pair) {
            // The path the connection started on, which is the case this module
            // exists for.
            return self.promote_next();
        }
        // A path that never carried anything: one whose validation timed out,
        // and so was abandoned without ever having been announced. Nothing in
        // the reserve, nothing carrying traffic, nothing to decide.
        None
    }

    fn status_changed(
        &mut self,
        path_id: u32,
        pair: (SocketAddr, SocketAddr),
        is_active: bool,
    ) -> Option<Declare> {
        // **The peer's declaration lands on our send side, in both
        // directions.** A `PATH_AVAILABLE` arriving sets `Path->IsActive` here
        // and a `PATH_BACKUP` clears it -- the same flag `set_path_status` sets
        // and the one `QuicConnChoosePath` selects on. So the peer has a say in
        // what this module is for, whatever the frames mean about the peer's own
        // sending.
        if is_active {
            // A reserve path the peer called available is back in the random
            // selection, which undoes the one thing asked of it.
            let held = self.reserve.iter_mut().find(|h| h.path_id == path_id)?;
            if held.reasserted {
                return None;
            }
            held.reasserted = true;
            return Some(Declare::Backup(path_id));
        }
        // The carrying path, declared backup by the peer, is a path this end can
        // no longer send on: honour it and move, rather than argue and be left
        // with no active path at all while msquic falls back to `Paths[0]`. It
        // does not join the reserve -- the peer has said where it would rather
        // not have traffic, and this module does not keep a list of those.
        let carrying = self.carrying == Carrying::Path(path_id)
            || (self.carrying == Carrying::Initial && self.initial == Some(pair));
        if !carrying {
            return None;
        }
        self.carrying = Carrying::Nothing;
        self.promote_next()
    }

    /// The declaration msquic refused. What that leaves behind, and what to try
    /// instead.
    fn declaration_failed(&mut self, declare: Declare) -> Option<Declare> {
        match declare {
            // Nothing better to try: the path stays active and traffic may
            // split across it, which `apply` has already said out loud.
            Declare::Backup(_) => None,
            // The promotion did not take, so that path is not carrying
            // anything, whatever this module was about to believe.
            Declare::Available(path_id) => {
                if self.carrying == Carrying::Path(path_id) {
                    self.carrying = Carrying::Nothing;
                }
                self.promote_next()
            }
        }
    }

    fn promote_next(&mut self) -> Option<Declare> {
        match self.reserve.pop_front() {
            Some(next) => {
                self.carrying = Carrying::Path(next.path_id);
                Some(Declare::Available(next.path_id))
            }
            None => {
                self.carrying = Carrying::Nothing;
                None
            }
        }
    }

    fn knows(&self, path_id: u32) -> bool {
        self.carrying == Carrying::Path(path_id)
            || self.reserve.iter().any(|h| h.path_id == path_id)
    }
}

/// Tell the connection what was decided, and whether it took.
///
/// `set_path_status` fails for a path id msquic no longer has — a path that
/// went away between the event and this call — and for a connection without
/// multipath, where there are no extra paths to hold in the first place.
/// Neither is worth a retry of the same call, which is why the caller is told
/// instead.
fn apply(conn: &Connection, declare: Declare, kind: &str) -> Result<(), ()> {
    match declare {
        Declare::Backup(path_id) => match conn.set_path_status(path_id, false) {
            Ok(()) => {
                tracing::info!(
                    kind,
                    path_id,
                    "path held as backup; the {kind} connection keeps the path it is on",
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    kind,
                    path_id,
                    "could not hold the path as backup; {kind} traffic may split \
                     across it at random: {e}",
                );
                Err(())
            }
        },
        Declare::Available(path_id) => match conn.set_path_status(path_id, true) {
            Ok(()) => {
                tracing::warn!(
                    kind,
                    path_id,
                    "the {kind} connection is no longer sending on the path it was \
                     on; promoted the oldest path held in reserve",
                );
                Ok(())
            }
            Err(e) => {
                tracing::warn!(
                    kind,
                    path_id,
                    "the {kind} connection is no longer sending on the path it was \
                     on and this path could not be promoted; trying the next one \
                     held in reserve: {e}",
                );
                Err(())
            }
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
/// (see [`attach`]), so this ends when the connector drops its sender and the
/// connection it last handed over has finished, and not before.
async fn run(mut conn_rx: mpsc::Receiver<Established>, kind: &'static str) {
    while let Some(Established { conn, .. }) = conn_rx.recv().await {
        let mut current = conn;
        // Each replacement in turn, until one ends with nothing waiting behind
        // it -- then back to the channel for the next connect.
        while let Some(Established { conn, .. }) = hold(&current, &mut conn_rx, kind).await {
            current = conn;
        }
    }
}

/// Hold `conn`'s paths until it ends, or until the connector hands over the
/// connection that replaces it — which is what comes back.
///
/// **A replacement takes over rather than waiting.** `poll_event` reports the
/// end of a connection only once it reaches `ShutdownComplete`, which can lag
/// the reconnect that replaced it; waiting for it would leave the new
/// connection's paths unheld for as long as it lasts, with the channel filling
/// behind it until `connect` itself blocks.
async fn hold(
    conn: &Connection,
    conn_rx: &mut mpsc::Receiver<Established>,
    kind: &'static str,
) -> Option<Established> {
    // Paths belong to the connection that has them, so each one starts from the
    // path it is on.
    let mut paths = OneActivePath::for_connection(conn, kind);
    // Whether anything can still replace this connection. Once the connector has
    // dropped its sender nothing can, and this connection is polled to its own
    // end rather than abandoned while it is still carrying requests.
    let mut replaceable = true;
    loop {
        let event = if replaceable {
            tokio::select! {
                handed = conn_rx.recv() => match handed {
                    Some(established) => return Some(established),
                    None => {
                        replaceable = false;
                        continue;
                    }
                },
                event = poll_fn(|cx| conn.poll_event(cx)) => event,
            }
        } else {
            poll_fn(|cx| conn.poll_event(cx)).await
        };
        match event {
            Ok(event) => {
                paths.observe(conn, &event, kind);
                tracing::trace!(kind, "connection event: {event:?}");
            }
            Err(e) => {
                tracing::debug!(kind, "connection event stream ended: {e}");
                return None;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The ids msquic hands out carry no meaning here beyond identity. The
    /// addresses do carry one, for the initial path alone.
    const UNANNOUNCED: u32 = 0;

    fn addr(s: &str) -> SocketAddr {
        s.parse().expect("an address")
    }

    /// The pair the connection started on: the address the connector picked,
    /// and the proxy.
    fn initial() -> (SocketAddr, SocketAddr) {
        (addr("10.0.2.10:51000"), addr("198.51.100.7:443"))
    }

    /// Any other path of the same connection: another local address of the
    /// host, the same proxy.
    fn elsewhere() -> (SocketAddr, SocketAddr) {
        (addr("[2001:db8:2::10]:51001"), addr("198.51.100.7:443"))
    }

    fn one_active_path() -> OneActivePath {
        OneActivePath::new(Some(initial()))
    }

    fn added(path_id: u32) -> ConnectionEvent {
        ConnectionEvent::PathAdded {
            local_address: elsewhere().0,
            peer_address: elsewhere().1,
            path_id,
        }
    }

    fn removed(path_id: u32, pair: (SocketAddr, SocketAddr)) -> ConnectionEvent {
        ConnectionEvent::PathRemoved {
            local_address: pair.0,
            peer_address: pair.1,
            path_id,
        }
    }

    fn status(path_id: u32, pair: (SocketAddr, SocketAddr), is_active: bool) -> ConnectionEvent {
        ConnectionEvent::PathStatusChanged {
            local_address: pair.0,
            peer_address: pair.1,
            path_id,
            is_active,
        }
    }

    /// The problem this module was written for: msquic opens a path per local
    /// address and every one of them is active, so the connection sends down
    /// all of them at random. Each one is held as backup as it arrives.
    #[test]
    fn every_path_msquic_adds_is_held_as_backup() {
        let mut paths = one_active_path();

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
    /// arrives as a `PathRemoved` for an id this module has never held, naming
    /// the pair the connection reported at the start. That is the moment a
    /// backup has to take over, and the one that takes over is the oldest — the
    /// path validated first.
    #[test]
    fn losing_the_path_it_started_on_promotes_the_oldest_in_reserve() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
            "the oldest path in reserve should have been promoted",
        );
        assert_eq!(paths.reserved(), 1, "the promoted path leaves the reserve");
    }

    /// **A path whose validation timed out looks exactly like the initial path
    /// if only the id is read.** msquic abandons it, and indicates
    /// `PathRemoved` for it, without ever having announced it — so it has no id
    /// this module has held. Promoting a backup here would leave it active
    /// *alongside* the initial path, which is still carrying traffic: the random
    /// split this module exists to prevent.
    #[test]
    fn a_path_that_never_validated_going_away_promotes_nothing() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));

        assert_eq!(
            paths.on_event(&removed(4242, elsewhere())),
            None,
            "a path that never carried anything decides nothing",
        );
        assert_eq!(paths.reserved(), 1, "and takes nothing out of the reserve");
        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
            "the reserve is still there for the path that was carrying traffic",
        );
    }

    /// A connection that would not name the path it started on keeps the
    /// preference and loses the failover, rather than guessing which removal
    /// was the one that mattered.
    #[test]
    fn without_the_initial_pair_nothing_is_guessed() {
        let mut paths = OneActivePath::new(None);

        assert_eq!(paths.on_event(&added(7)), Some(Declare::Backup(7)));
        assert_eq!(paths.on_event(&removed(UNANNOUNCED, initial())), None);
        assert_eq!(paths.reserved(), 1);
    }

    /// "And if that one dies, the next backup" — until there is no next one, at
    /// which point there is nothing this module can do and msquic closes a
    /// connection that has run out of paths.
    #[test]
    fn and_the_next_one_each_time_a_promoted_path_dies() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));
        paths.on_event(&added(9));

        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
        );
        assert_eq!(
            paths.on_event(&removed(7, elsewhere())),
            Some(Declare::Available(8)),
        );
        assert_eq!(
            paths.on_event(&removed(8, elsewhere())),
            Some(Declare::Available(9)),
        );
        assert_eq!(
            paths.on_event(&removed(9, elsewhere())),
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
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(paths.on_event(&removed(7, elsewhere())), None);
        assert_eq!(paths.reserved(), 1);
        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(8)),
            "the path that died must not be promoted later",
        );
    }

    /// A path added after a promotion is in reserve like any other, and is what
    /// the promoted path falls back to in turn — this is how a connection that
    /// has lost its original path still has somewhere to go.
    #[test]
    fn a_path_added_after_a_promotion_joins_the_reserve() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
        );

        assert_eq!(paths.on_event(&added(8)), Some(Declare::Backup(8)));
        assert_eq!(
            paths.on_event(&removed(7, elsewhere())),
            Some(Declare::Available(8)),
        );
    }

    /// **With nothing carrying traffic, the next path to turn up is promoted
    /// rather than held.** The connection is sending wherever msquic falls back
    /// to by then, so holding this one as backup would keep it there.
    #[test]
    fn a_path_added_with_nothing_carrying_traffic_is_promoted() {
        let mut paths = one_active_path();

        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            None,
            "the initial path went away with nothing in reserve",
        );
        assert_eq!(
            paths.on_event(&added(7)),
            Some(Declare::Available(7)),
            "so this path is the one to carry traffic, not a reserve",
        );
        assert_eq!(paths.reserved(), 0);
        assert_eq!(paths.on_event(&added(8)), Some(Declare::Backup(8)));
    }

    /// The initial path's removal arriving twice must not promote twice: the
    /// second one finds a promoted path carrying traffic, and an id that is
    /// neither it nor in the reserve.
    #[test]
    fn the_initial_paths_removal_arriving_twice_promotes_once() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
        );
        assert_eq!(paths.on_event(&removed(UNANNOUNCED, initial())), None);
        assert_eq!(paths.reserved(), 1);
    }

    /// The peer's `PATH_AVAILABLE` sets the same flag `set_path_status` does,
    /// so a reserve path the peer calls available is back in the random
    /// selection. Saying backup once more is worth it: the two declarations may
    /// simply have crossed in flight.
    #[test]
    fn the_peer_calling_a_reserve_path_available_is_answered_once() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));

        assert_eq!(
            paths.on_event(&status(7, elsewhere(), true)),
            Some(Declare::Backup(7)),
            "the path should have been declared backup again",
        );
        assert_eq!(
            paths.on_event(&status(7, elsewhere(), true)),
            None,
            "but not argued over: the peer is entitled to its own preference",
        );
    }

    /// **The peer's `PATH_BACKUP` clears `IsActive` on this side**, so the
    /// carrying path it names is one this end can no longer send on. Honouring
    /// it by promoting is better than being left with no active path while
    /// msquic falls back to `Paths[0]`.
    #[test]
    fn the_peer_calling_the_carrying_path_backup_promotes() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(
            paths.on_event(&status(UNANNOUNCED, initial(), false)),
            Some(Declare::Available(7)),
        );
        assert_eq!(
            paths.on_event(&status(7, elsewhere(), false)),
            Some(Declare::Available(8)),
            "and again for the path that was promoted",
        );
        assert_eq!(paths.reserved(), 0);
    }

    /// The peer declaring a reserve path backup agrees with this end, and says
    /// nothing new.
    #[test]
    fn the_peer_calling_a_reserve_path_backup_is_not_answered() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));

        assert_eq!(paths.on_event(&status(7, elsewhere(), false)), None);
        assert_eq!(paths.reserved(), 2, "and it stays in the reserve");
    }

    /// A path event arriving twice used to be real (`PathRemoved` was raised
    /// twice per path until seera-msquic 266769c), and a second reserve entry
    /// for one path would be a slot that can never be promoted away.
    #[test]
    fn a_repeated_path_added_does_not_take_a_second_slot() {
        let mut paths = one_active_path();

        assert_eq!(paths.on_event(&added(7)), Some(Declare::Backup(7)));
        assert_eq!(paths.on_event(&added(7)), None);
        assert_eq!(paths.reserved(), 1);
        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
        );
        assert_eq!(
            paths.on_event(&added(7)),
            None,
            "nor while it is the path carrying traffic",
        );
    }

    /// **A promotion msquic refuses has to pick the next path, not be recorded
    /// as done.** The path id it names may belong to a path that went away
    /// between the event and the call, and believing it carries traffic would
    /// leave the connection on whatever msquic fell back to with a reserve
    /// nothing ever reads again.
    #[test]
    fn a_promotion_that_msquic_refuses_tries_the_next_path() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));
        paths.on_event(&added(8));
        assert_eq!(
            paths.on_event(&removed(UNANNOUNCED, initial())),
            Some(Declare::Available(7)),
        );

        assert_eq!(
            paths.declaration_failed(Declare::Available(7)),
            Some(Declare::Available(8)),
        );
        assert_eq!(
            paths.declaration_failed(Declare::Available(8)),
            None,
            "and stops when the reserve is empty",
        );
        // Nothing is carrying traffic now, so the next path to arrive is
        // promoted rather than held -- which is the recovery.
        assert_eq!(paths.on_event(&added(9)), Some(Declare::Available(9)));
    }

    /// A refused `PATH_BACKUP` has nothing to try instead; the path stays
    /// active and the log says so.
    #[test]
    fn a_refused_backup_declaration_has_no_second_choice() {
        let mut paths = one_active_path();
        paths.on_event(&added(7));

        assert_eq!(paths.declaration_failed(Declare::Backup(7)), None);
    }

    /// Everything else on the connection is somebody else's event.
    #[test]
    fn other_events_decide_nothing() {
        let mut paths = one_active_path();

        assert_eq!(
            paths.on_event(&ConnectionEvent::NotifyObservedAddress {
                local_address: initial().0,
                observed_address: addr("203.0.113.9:51000"),
            }),
            None,
        );
    }
}
