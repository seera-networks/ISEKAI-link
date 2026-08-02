//! The target side of a P2P connection: a private Peer Listener plus the relay
//! **bind** leg that forwards inbound relay UDP to a local address.
//!
//! A co-located service (e.g. the camera server's video QUIC listener) binds a
//! local socket; the relay delivers the initiator's traffic there. Because the
//! relay edge is allocated when the *initiator* connects, the bind leg needs the
//! `connection_id` the initiator produced — hence the two-phase API:
//! [`ListenerSession::create`] sets up the listener and capabilities, and
//! [`ListenerSession::bind`] attaches the relay once the initiator has connected.
//!
//! Exchange order (all values conveyed out of band):
//!
//! 1. initiator reveals its `endpoint_id`;
//! 2. this side [`create`](ListenerSession::create)s and
//!    [`issue_capability`](ListenerSession::issue_capability) for it, revealing
//!    `listener_id` + the capability;
//! 3. the initiator connects and reveals its `connection_id`;
//! 4. this side [`bind`](ListenerSession::bind)s that `connection_id`.

use std::collections::HashSet;
use std::net::SocketAddr;

use isekai_p2p_core::bind::{open_bind_session, BindSession, RelayOptions};
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};
use isekai_p2p_core::proxy::{Capability, PeerConnection, ProxyClient};
use isekai_p2p_core::transport::MasqueH3Transport;
use tokio::sync::watch;

use crate::config::{issue_endpoint_token, P2pConfig};

/// A target-side P2P session. Holds the relay bind leg open until dropped or
/// [`close`](ListenerSession::close)d.
pub struct ListenerSession {
    /// The created Peer Listener's id — hand this to the initiator.
    pub listener_id: String,
    /// This Endpoint's id.
    pub endpoint_id: String,
    proxy_url: String,
    endpoint_token: String,
    key: EndpointKey,
    forward_to: SocketAddr,
    proxy: ProxyClient<MasqueH3Transport>,
    protocol: String,
    bind: Option<BindGuard>,
    opts: RelayOptions,
    /// Session-lifetime observed address, republished by each bind leg.
    ///
    /// Every [`bind`](ListenerSession::bind) opens a *new* leg with a *new*
    /// watch, but a caller that took a receiver before the first bind — which
    /// is the normal order, since binding waits on a connection id pasted by
    /// hand — must keep seeing updates across rebinds. So the leg's watch is
    /// forwarded into this one rather than handed out directly.
    observed_tx: watch::Sender<Option<ObservedAddress>>,
}

/// What a listener does when a connection is waiting for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AcceptPolicy {
    /// Bind it. The proxy already checked that a grant authorizes the peer;
    /// this says the listener is content to let that be the whole decision.
    Auto,
    /// Bind it and say so, so the operator can see who is connected and cut
    /// them off afterwards. Same authorization, more visibility.
    AutoNotify,
    /// Bind nothing automatically. The operator drives
    /// [`bind`](ListenerSession::bind) as before.
    Manual,
}

impl AcceptPolicy {
    fn binds_automatically(self) -> bool {
        matches!(self, Self::Auto | Self::AutoNotify)
    }
}

/// What a poll did, for the UI and the log.
#[derive(Debug, Clone)]
pub enum SignalingEvent {
    /// A connection was bound and traffic can now reach the video listener.
    Bound {
        connection_id: String,
        peer_endpoint: String,
        /// The connection this replaced, if it displaced one. Only one leg
        /// exists at a time, so a new peer takes over from the last.
        replaced: Option<String>,
    },
    /// A connection is waiting and the policy says not to bind it.
    Waiting {
        connection_id: String,
        peer_endpoint: String,
    },
    /// Binding failed. The connection is left unbound and will be tried again
    /// on the next poll, until it expires.
    BindFailed {
        connection_id: String,
        error: String,
    },
    /// The proxy had more connections waiting than it would list. Whoever is
    /// beyond the cut cannot be seen from here (spec §8.5.3).
    Truncated,
}

/// What [`ListenerSession::poll_signaling`] remembers between polls.
///
/// Only which connections have been bound. The control plane cannot answer
/// that — binding is a data-plane action and leaves the connection in `relay`
/// either way — so without this every poll would bind the same connection
/// again, tearing down the leg it had just built.
#[derive(Debug, Default)]
pub struct SignalingState {
    bound: HashSet<String>,
    current: Option<String>,
}

impl SignalingState {
    /// The connection currently bound, if any.
    pub fn current(&self) -> Option<&str> {
        self.current.as_deref()
    }
}

/// Keeps the spawned bind leg alive; cancels it on drop / close.
struct BindGuard {
    handle: tokio::task::JoinHandle<()>,
}

impl ListenerSession {
    /// Obtain an Endpoint Token and create a private Peer Listener.
    ///
    /// `forward_to` is where the relay will deliver inbound traffic once
    /// [`bind`](ListenerSession::bind) runs — bind the local video listener
    /// there first. `ttl` is the listener TTL in seconds (`None` = default).
    pub async fn create(
        cfg: &P2pConfig,
        forward_to: SocketAddr,
        ttl: Option<u64>,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::create_with_token(cfg, &endpoint_token, forward_to, ttl).await
    }

    /// Like [`create`](Self::create) but choosing how the relay bind leg is
    /// opened.
    ///
    /// Pass `RelayOptions { unconnected: true, registration: Some(..) }` to make
    /// the leg usable for path migration: the direct path is opened from its
    /// binding, and [`observed_address`](Self::observed_address) then reports
    /// the address to advertise.
    pub async fn create_with_options(
        cfg: &P2pConfig,
        forward_to: SocketAddr,
        ttl: Option<u64>,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::create_with_token_and_options(cfg, &endpoint_token, forward_to, ttl, opts).await
    }

    /// Like [`create`](Self::create) but with an Endpoint Token the caller
    /// already holds, skipping the Identity API round-trip.
    ///
    /// Lets a caller that also downloads the relay certificate (which needs the
    /// same token) issue the token once. Only `proxy_url`, `protocol`, `key` and
    /// the Endpoint ID are read from `cfg`.
    pub async fn create_with_token(
        cfg: &P2pConfig,
        endpoint_token: &str,
        forward_to: SocketAddr,
        ttl: Option<u64>,
    ) -> anyhow::Result<Self> {
        Self::create_with_token_and_options(
            cfg,
            endpoint_token,
            forward_to,
            ttl,
            RelayOptions::default(),
        )
        .await
    }

    /// [`create_with_token`](Self::create_with_token) plus the relay-leg
    /// options — the form the other three delegate to.
    pub async fn create_with_token_and_options(
        cfg: &P2pConfig,
        endpoint_token: &str,
        forward_to: SocketAddr,
        ttl: Option<u64>,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let endpoint_token = endpoint_token.to_owned();
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token.clone(),
        );
        let listener = proxy.create_peer_listener(&cfg.protocol, ttl).await?;
        Ok(Self {
            listener_id: listener.listener_id,
            endpoint_id: cfg.endpoint_id(),
            proxy_url: cfg.proxy_url.clone(),
            endpoint_token,
            key: cfg.key.clone(),
            forward_to,
            proxy,
            protocol: cfg.protocol.clone(),
            bind: None,
            opts,
            observed_tx: watch::channel(None).0,
        })
    }

    /// How the proxy sees this Endpoint's relay bind leg — `None` until a leg
    /// is bound and reports.
    ///
    /// The server advertises this pair on each accepted video connection
    /// (`add_bound_addr` / `add_observed_addr`) so the initiator can punch a
    /// direct path to it. Safe to take before [`bind`](Self::bind): the
    /// receiver survives rebinds.
    ///
    /// Only meaningful when the session was created with
    /// `RelayOptions { unconnected: true, .. }`; a leg on a plain connected
    /// socket has no binding a direct path could use.
    pub fn observed_address(&self) -> ObservedAddressWatch {
        self.observed_tx.subscribe()
    }

    /// Mint a capability authorizing `allowed_endpoint` (the initiator's
    /// Endpoint ID) to connect to this listener. Returns the opaque token to
    /// hand to the initiator out of band.
    pub async fn issue_capability(
        &self,
        allowed_endpoint: &str,
        ttl: Option<u64>,
    ) -> anyhow::Result<Capability> {
        let cap = self
            .proxy
            .issue_capability(&self.listener_id, allowed_endpoint, &self.protocol, ttl)
            .await?;
        Ok(cap)
    }

    /// Attach the relay bind leg for `connection_id` (the id the initiator's
    /// `peer_connect` produced). Inbound relay UDP is forwarded to the
    /// `forward_to` given at [`create`](ListenerSession::create).
    ///
    /// Replaces any previous bind leg.
    pub async fn bind(&mut self, connection_id: &str) -> anyhow::Result<()> {
        let session = open_bind_session(
            &self.proxy_url,
            &self.endpoint_token,
            &self.key,
            connection_id,
            self.forward_to,
            self.opts.clone(),
        )
        .await?;
        // Own the session in a task that drains its notifications, so an unread
        // events channel can never stall the underlying MASQUE loop. Dropping
        // the task (on close) drops the session, whose Drop cancels the relay.
        let handle = tokio::spawn(drive_bind_session(session, self.observed_tx.clone()));
        if let Some(prev) = self.bind.replace(BindGuard { handle }) {
            prev.handle.abort();
        }
        Ok(())
    }

    /// Look for connections waiting on this listener and bind one, once.
    ///
    /// This is a single pass rather than a loop because binding needs `&mut
    /// self`, and the caller already owns this session to serve its other
    /// commands — a loop in here would take that ownership away. Call it on a
    /// timer.
    ///
    /// **The newest unbound connection wins.** A listener holds one bind leg
    /// (see [`bind`](Self::bind)), so a second peer connecting takes over from
    /// the first, and the returned [`SignalingEvent::Bound`] names what it
    /// displaced. Serving two peers at once needs a leg each, which this does
    /// not do yet.
    ///
    /// Errors from the proxy are returned; a failure to bind one connection is
    /// reported as an event and does not stop the pass.
    pub async fn poll_signaling(
        &mut self,
        state: &mut SignalingState,
        policy: AcceptPolicy,
    ) -> anyhow::Result<Vec<SignalingEvent>> {
        let listing = self
            .proxy
            .list_listener_connections(&self.listener_id, Some("relay"))
            .await?;
        let mut events = Vec::new();
        if listing.truncated {
            events.push(SignalingEvent::Truncated);
        }
        forget_gone(state, &listing.connections);
        let Some(next) = next_to_bind(&listing.connections, state) else {
            return Ok(events);
        };
        let next = next.clone();
        let peer_endpoint = next
            .peer_endpoint
            .clone()
            .unwrap_or_else(|| "unknown".to_owned());
        if !policy.binds_automatically() {
            events.push(SignalingEvent::Waiting {
                connection_id: next.connection_id.clone(),
                peer_endpoint,
            });
            return Ok(events);
        }
        match self.bind(&next.connection_id).await {
            Ok(()) => {
                let replaced = state.current.replace(next.connection_id.clone());
                state.bound.insert(next.connection_id.clone());
                events.push(SignalingEvent::Bound {
                    connection_id: next.connection_id.clone(),
                    peer_endpoint,
                    replaced,
                });
            }
            Err(e) => {
                // Deliberately not remembered as bound: the next pass tries
                // again, which is what a transient proxy failure wants.
                events.push(SignalingEvent::BindFailed {
                    connection_id: next.connection_id.clone(),
                    error: format!("{e:#}"),
                });
            }
        }
        Ok(events)
    }

    /// Stop the relay bind leg (if any). The Peer Listener stays until its TTL
    /// expires or the process ends.
    pub async fn close(mut self) {
        if let Some(guard) = self.bind.take() {
            guard.handle.abort();
            let _ = guard.handle.await;
        }
    }
}

/// Drain the leg's notifications and republish its observed address into the
/// session-lifetime watch.
///
/// Both have to run for as long as the leg does: an unread events channel
/// stalls the MASQUE loop, and an unforwarded report leaves the server with no
/// address to advertise.
async fn drive_bind_session(
    mut session: BindSession,
    observed_tx: watch::Sender<Option<ObservedAddress>>,
) {
    let mut leg = session.observed();
    // The leg's watch ends when its connection does; keep draining events after
    // that rather than spinning on a closed channel.
    let mut leg_open = true;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(event) => tracing::debug!("bind session event: {event:?}"),
                None => break,
            },
            changed = leg.changed(), if leg_open => {
                leg_open = republish_observed(&mut leg, &observed_tx, changed.is_ok());
            }
        }
    }
}

/// Republish one change from a leg's watch into the session-lifetime watch.
///
/// Returns whether the leg's watch is still worth polling: once it has ended
/// (`changed_ok == false`) there is nothing more to forward.
///
/// Only a `Some` is forwarded. A leg that ends without ever reporting leaves
/// the session's last known address in place rather than blanking it — the
/// server would otherwise stop advertising a direct path across a rebind that
/// has not reported yet.
fn republish_observed(
    leg: &mut ObservedAddressWatch,
    out: &watch::Sender<Option<ObservedAddress>>,
    changed_ok: bool,
) -> bool {
    if !changed_ok {
        return false;
    }
    if let Some(observed) = *leg.borrow_and_update() {
        out.send_replace(Some(observed));
    }
    true
}

/// Drop what the proxy no longer lists.
///
/// Without this the remembered set would grow for as long as the process runs.
/// The proxy's listing is already capped, so bounding this by it bounds it.
fn forget_gone(state: &mut SignalingState, connections: &[PeerConnection]) {
    let live: HashSet<&str> = connections
        .iter()
        .map(|c| c.connection_id.as_str())
        .collect();
    state.bound.retain(|id| live.contains(id.as_str()));
    if state.current.as_deref().is_some_and(|id| !live.contains(id)) {
        state.current = None;
    }
}

/// The connection to bind next, if any.
///
/// The proxy returns newest first, so the first one not already bound is the
/// newest waiting. Only one leg exists at a time, so this is also the one that
/// takes over from whatever is bound now.
fn next_to_bind<'a>(
    connections: &'a [PeerConnection],
    state: &SignalingState,
) -> Option<&'a PeerConnection> {
    connections
        .iter()
        .find(|c| !state.bound.contains(&c.connection_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn conn(id: &str) -> PeerConnection {
        PeerConnection {
            connection_id: id.to_owned(),
            state: "relay".to_owned(),
            listener_id: "pl_1".to_owned(),
            protocol: "mjpeg".to_owned(),
            peer_endpoint: Some("ep:A".to_owned()),
            relay: None,
            relay_session_id: None,
            video_host: None,
            candidates: Vec::new(),
            peer_candidates: Vec::new(),
            established_at: None,
            created_at: None,
            expires_at: None,
            updated_at: None,
        }
    }

    /// Binding is a data-plane action, so a bound connection keeps showing up
    /// in the listing exactly as it did before. Without remembering, every poll
    /// would rebind it — and rebinding tears down the leg it just built.
    #[test]
    fn a_bound_connection_is_not_picked_again() {
        let listing = vec![conn("conn_1")];
        let mut state = SignalingState::default();
        assert_eq!(
            next_to_bind(&listing, &state).map(|c| c.connection_id.as_str()),
            Some("conn_1")
        );
        state.bound.insert("conn_1".to_owned());
        assert!(next_to_bind(&listing, &state).is_none());
    }

    /// The proxy lists newest first, and only one leg exists at a time, so a
    /// peer that connects later takes over.
    #[test]
    fn the_newest_unbound_connection_is_the_one_picked() {
        let listing = vec![conn("conn_new"), conn("conn_old")];
        let mut state = SignalingState::default();
        state.bound.insert("conn_old".to_owned());
        assert_eq!(
            next_to_bind(&listing, &state).map(|c| c.connection_id.as_str()),
            Some("conn_new")
        );
    }

    #[test]
    fn what_the_proxy_stops_listing_is_forgotten() {
        let mut state = SignalingState::default();
        state.bound.insert("conn_gone".to_owned());
        state.bound.insert("conn_here".to_owned());
        state.current = Some("conn_gone".to_owned());

        forget_gone(&mut state, &[conn("conn_here")]);

        assert_eq!(state.bound.len(), 1);
        assert!(state.bound.contains("conn_here"));
        // The one being served expired, so nothing is being served.
        assert_eq!(state.current(), None);
    }

    /// Forgetting an expired connection lets its id be picked again if the
    /// proxy ever lists it once more — but it must not disturb the one in use.
    #[test]
    fn forgetting_leaves_the_connection_in_use_alone() {
        let mut state = SignalingState::default();
        state.bound.insert("conn_live".to_owned());
        state.current = Some("conn_live".to_owned());

        forget_gone(&mut state, &[conn("conn_live"), conn("conn_other")]);

        assert_eq!(state.current(), Some("conn_live"));
        assert!(next_to_bind(&[conn("conn_live")], &state).is_none());
    }

    #[test]
    fn manual_is_the_only_policy_that_binds_nothing() {
        assert!(AcceptPolicy::Auto.binds_automatically());
        assert!(AcceptPolicy::AutoNotify.binds_automatically());
        assert!(!AcceptPolicy::Manual.binds_automatically());
    }

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([192, 168, 1, 59], port))
    }

    fn observed(port: u16) -> ObservedAddress {
        ObservedAddress {
            local: addr(port),
            observed: addr(port + 1),
        }
    }

    /// The point of the session-lifetime watch: a receiver taken *before* any
    /// leg exists still sees what a later leg reports. That is the normal
    /// order — binding waits on a connection id pasted by hand, long after the
    /// server started watching.
    #[test]
    fn a_receiver_taken_before_the_first_bind_sees_the_leg_report() {
        let session = watch::channel(None).0;
        let mut early = session.subscribe();
        assert_eq!(*early.borrow_and_update(), None);

        let (leg_tx, mut leg_rx) = watch::channel(None);
        leg_tx.send_replace(Some(observed(1000)));
        assert!(republish_observed(&mut leg_rx, &session, true));

        assert_eq!(*early.borrow_and_update(), Some(observed(1000)));
    }

    /// And it survives the leg being replaced: `bind` can be called again, and
    /// the same receiver picks up the new leg's address.
    #[test]
    fn the_watch_survives_a_rebind() {
        let session = watch::channel(None).0;
        let mut held = session.subscribe();

        let (first_tx, mut first_rx) = watch::channel(None);
        first_tx.send_replace(Some(observed(1000)));
        republish_observed(&mut first_rx, &session, true);
        assert_eq!(*held.borrow_and_update(), Some(observed(1000)));

        // The first leg ends; the session keeps its last known address.
        assert!(!republish_observed(&mut first_rx, &session, false));
        assert_eq!(*held.borrow(), Some(observed(1000)));

        // A second leg reports, and the *same* receiver sees it.
        let (second_tx, mut second_rx) = watch::channel(None);
        second_tx.send_replace(Some(observed(2000)));
        republish_observed(&mut second_rx, &session, true);
        assert_eq!(*held.borrow_and_update(), Some(observed(2000)));
    }

    /// A leg that changes to `None` must not blank an address the server is
    /// still advertising.
    #[test]
    fn an_empty_leg_report_does_not_clear_the_session_address() {
        let session = watch::channel(None).0;
        let held = session.subscribe();

        let (leg_tx, mut leg_rx) = watch::channel(None);
        leg_tx.send_replace(Some(observed(1000)));
        republish_observed(&mut leg_rx, &session, true);

        leg_tx.send_replace(None);
        republish_observed(&mut leg_rx, &session, true);
        assert_eq!(*held.borrow(), Some(observed(1000)));
    }
}
