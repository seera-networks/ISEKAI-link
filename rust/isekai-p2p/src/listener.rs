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

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use isekai_p2p_core::bind::{
    open_bind_session, BindSession, InboundActivity, MasqueClientEvent, RelayOptions,
};
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::observed::{ObservedAddress, ObservedAddressWatch};
use isekai_p2p_core::proxy::{
    Capability, ConnectionStateFilter, Grant, ListenerEvent, PairingCode, PeerConnection,
    ProxyClient,
};
use isekai_p2p_core::transport::MasqueH3Transport;
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::config::{issue_endpoint_token, spawn_token_renewal, P2pConfig, TokenRenewal};
use crate::relay_lease::RelayLegLease;

/// How long [`ListenerSession::close`] waits for the proxy to take the listener
/// down before giving up and letting the lease do it.
///
/// Short on purpose: this runs while an application is trying to exit, and the
/// only thing lost by giving up is that a listener nobody can connect to stays
/// in its owner's peers' lists until its lease ends.
const WITHDRAW_TIMEOUT: Duration = Duration::from_secs(3);

/// A target-side P2P session. Holds the relay bind leg open until dropped or
/// [`close`](ListenerSession::close)d.
pub struct ListenerSession {
    /// The created Peer Listener's id — hand this to the initiator.
    pub listener_id: String,
    /// This Endpoint's id.
    pub endpoint_id: String,
    proxy_url: String,
    key: EndpointKey,
    forward_to: SocketAddr,
    proxy: ProxyClient<MasqueH3Transport>,
    protocol: String,
    /// One relay leg per peer being served, keyed by connection id.
    binds: std::collections::HashMap<String, BindGuard>,
    opts: RelayOptions,
    /// Session-lifetime observed address, republished by each bind leg.
    ///
    /// Every [`bind`](ListenerSession::bind) opens a *new* leg with a *new*
    /// watch, but a caller that took a receiver before the first bind — which
    /// is the normal order, since binding waits on a connection id pasted by
    /// hand — must keep seeing updates across rebinds. So the leg's watch is
    /// forwarded into this one rather than handed out directly.
    observed_tx: watch::Sender<Option<ObservedAddress>>,
    /// Which leg each accepted local connection came in on, for a caller that
    /// serves more than one peer at a time. See [`LegDirectory`].
    legs: LegDirectory,
    /// Replaces the Endpoint Token before it expires, for as long as this
    /// session lives. Held, not read.
    _renewal: TokenRenewal,
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
    },
    /// A bound connection's leg has ended, so that peer is gone.
    Unbound { connection_id: String },
    /// A connection is waiting because the listener is already serving
    /// [`MAX_CONCURRENT_PEERS`] of them.
    AtCapacity {
        connection_id: String,
        peer_endpoint: String,
    },
    /// A connection is waiting and the policy says not to bind it.
    ///
    /// Only reachable by a caller that polls under
    /// [`AcceptPolicy::Manual`]. `camera-core` does not poll at all in that
    /// mode — the operator is driving [`bind`](ListenerSession::bind) — so this
    /// is for a library user that wants to see who is waiting without binding.
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
    /// A connection's lease could not be renewed. It will be tried again; if it
    /// keeps failing the connection lapses and the peer is dropped, which shows
    /// up as an [`Unbound`](Self::Unbound).
    RenewFailed {
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
    /// Connections this listener currently holds a relay leg for.
    bound: HashSet<String>,
    /// Connections whose leg has already ended here.
    ///
    /// Separate from `bound` because they mean different things. `bound` is
    /// "being served"; this is "serving it did not last, and the listing has
    /// not caught up". Without it, a peer that vanished without reporting would
    /// be bound again the moment its leg died, and again after that, for as
    /// long as the proxy kept listing it.
    spent: HashSet<String>,
}

impl SignalingState {
    /// The connections currently bound.
    pub fn bound(&self) -> impl Iterator<Item = &str> {
        self.bound.iter().map(String::as_str)
    }
}

/// Which relay leg a local connection arrived on.
///
/// **The problem this solves is that legs are indistinguishable from inside.**
/// Every leg delivers to the same local listener, and each has its own binding
/// out on the network — so a connection has to be given *its own* leg's
/// address, and until now nothing could say which that was. What was done
/// instead was to take the first address offered and keep it, which is right
/// only while legs come up in the order their peers connect.
///
/// A leg forwards what it receives from a socket of its own
/// ([`MasqueClientEvent::NewRemoteHost`] reports that socket's address), so the
/// address the local listener sees a connection coming *from* names the leg it
/// came in *on*. That is the whole mechanism: this holds the mapping, and the
/// listener asks.
///
/// One leg can appear more than once — a peer that changes address gets another
/// forwarding socket — which is why this is keyed by address rather than by leg.
///
/// **This rests on the forwarding socket being connected before its address is
/// read.** It is bound to the wildcard, so what makes `local_addr` report
/// `127.0.0.1:p` rather than `0.0.0.0:p` is the `connect` to the local listener
/// that precedes it (`channel-masque`'s `from_quic_to_udp`). Were that to go —
/// a leg fanning out to several destinations, say — nothing here would ever
/// match, and every connection would fall back to relay-only in silence. There
/// is a note at the other end saying the same thing.
#[derive(Clone, Default)]
pub struct LegDirectory {
    forwarding: Arc<Mutex<HashMap<SocketAddr, ObservedAddressWatch>>>,
}

impl LegDirectory {
    /// The observed-address watch of the leg a connection from `peer` arrived
    /// on, or `None` while nothing has come in on a leg from that address.
    ///
    /// `None` is a real answer and not only a race: it is also what a
    /// connection that did not come through a relay leg at all gets.
    pub fn leg_for(&self, peer: SocketAddr) -> Option<ObservedAddressWatch> {
        self.forwarding.lock().unwrap().get(&peer).cloned()
    }

    fn attach(&self, forwarding: SocketAddr, leg: ObservedAddressWatch) {
        self.forwarding.lock().unwrap().insert(forwarding, leg);
    }

    /// Forget a leg's addresses. Called from [`AttachedLeg`]'s `Drop`, which is
    /// what makes the map bounded by the legs that exist.
    fn detach(&self, forwarding: &[SocketAddr]) {
        let mut map = self.forwarding.lock().unwrap();
        for addr in forwarding {
            map.remove(addr);
        }
    }

    /// How many addresses are claimed. Zero and non-zero mean different things
    /// to a connection nothing claims — see `camera-core`'s `leg_of`.
    pub fn claimed(&self) -> usize {
        self.forwarding.lock().unwrap().len()
    }
}

/// One leg's entries in a [`LegDirectory`], removed when the leg's task ends.
///
/// **`Drop` and not a line after the loop**, because legs are normally taken
/// down by aborting that task — [`ListenerSession::unbind`] when a peer goes,
/// and `close` on the way out — and an aborted task does not run what follows
/// its last await. Left in the map, a dead leg's entry keeps its watch alive
/// and, once the operating system hands that ephemeral port to a new leg's
/// forwarding socket, answers for it: a connection advertised somebody else's
/// binding, which is the fault this whole mechanism exists to remove.
struct AttachedLeg {
    legs: LegDirectory,
    forwarding: Vec<SocketAddr>,
}

impl AttachedLeg {
    fn new(legs: LegDirectory) -> Self {
        Self {
            legs,
            forwarding: Vec::new(),
        }
    }

    fn attach(&mut self, forwarding: SocketAddr, leg: ObservedAddressWatch) {
        self.legs.attach(forwarding, leg);
        self.forwarding.push(forwarding);
    }
}

impl Drop for AttachedLeg {
    fn drop(&mut self) {
        self.legs.detach(&self.forwarding);
    }
}

/// Keeps the spawned bind leg alive; cancels it on drop / close.
struct BindGuard {
    handle: tokio::task::JoinHandle<()>,
    /// What the leg has received, and what it had received when
    /// [`renew_connections`](ListenerSession::renew_connections) last looked.
    inbound: InboundActivity,
    seen: u64,
    /// Re-tickets this leg so the proxy does not reclaim it (spec §8.14).
    ///
    /// **Not what `renew_connections` does.** That reports state, which carries
    /// the connection *row*; since §8.14 a report no longer touches the leg.
    /// Held here rather than in the session so that dropping a leg stops
    /// claiming it — a listener that unbinds a peer should stop asserting it
    /// needs that leg in the same moment.
    ///
    /// `None` against a proxy that predates §8.14, where the leg has no lease
    /// to carry.
    _lease: Option<RelayLegLease>,
}

impl BindGuard {
    /// Whether anything arrived on this leg since the last time this was asked.
    ///
    /// Two reads of a counter that only goes up, which is why there is no clock
    /// and no window here: "since last time" is however long the caller went
    /// between asking.
    ///
    /// The first ask compares against nothing having arrived, so a leg bound
    /// moments earlier and not yet used answers no. That costs one pass, and
    /// several fit inside a lease — by which time a peer that connected has
    /// sent something, because connecting is what it did.
    fn carried_traffic(&mut self) -> bool {
        let count = self.inbound.count();
        let moved = count != self.seen;
        self.seen = count;
        moved
    }
}

/// How many peers one listener will serve at once.
///
/// Every peer costs a relay leg — a MASQUE session on the proxy and a task
/// here — and the listing this is driven from is attacker-influenced in the
/// sense that anyone the owner has granted access can add to it. A camera with
/// a handful of viewers is the case being served; a bound is what keeps a
/// mistake or a misbehaving client from turning into an unbounded number of
/// sessions. Whoever is beyond it is reported as waiting rather than dropped,
/// and is picked up as soon as a leg frees.
pub const MAX_CONCURRENT_PEERS: usize = 8;

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
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token,
        );
        let listener = proxy.create_peer_listener(&cfg.protocol, ttl).await?;
        // A listener outlives its Endpoint Token by hours. Without this the
        // token lapses after minutes and every proxy call fails — the signaling
        // poll first, and then the bind that would have admitted a new viewer.
        // The caller's token has no stated lifetime here, hence `None`.
        let renewal = spawn_token_renewal(cfg.clone(), proxy.clone(), None);
        Ok(Self {
            listener_id: listener.listener_id,
            endpoint_id: cfg.endpoint_id(),
            proxy_url: cfg.proxy_url.clone(),
            key: cfg.key.clone(),
            forward_to,
            proxy,
            protocol: cfg.protocol.clone(),
            binds: std::collections::HashMap::new(),
            opts,
            observed_tx: watch::channel(None).0,
            legs: LegDirectory::default(),
            _renewal: renewal,
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

    /// Which leg each local connection arrived on (see [`LegDirectory`]).
    ///
    /// This is what [`observed_address`](Self::observed_address) cannot answer:
    /// that watch carries whichever leg reported last, which is one peer's
    /// binding handed to whoever asks. A listener serving more than one viewer
    /// needs each connection told about the leg it actually came in on.
    pub fn legs(&self) -> LegDirectory {
        self.legs.clone()
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

    /// Attach a relay bind leg for `connection_id` (the id the initiator's
    /// `peer_connect` produced). Inbound relay UDP is forwarded to the
    /// `forward_to` given at [`create`](ListenerSession::create).
    ///
    /// Legs accumulate rather than replace: each peer has its own connection
    /// and its own leg, and they all deliver to the same local video listener,
    /// which is a QUIC listener and accepts as many connections as arrive.
    /// Binding a connection that already has a leg does nothing — tearing down
    /// a working leg to rebuild it would interrupt the peer being served.
    ///
    /// **Each leg gets a binding of its own**, so they report different
    /// observed addresses — the connector binds a fresh ephemeral socket per
    /// leg. They all feed the session's one watch, which therefore holds
    /// whichever reported last and is only good for showing an operator;
    /// [`legs`](Self::legs) is what says which address belongs to whom.
    ///
    /// This used to say the opposite, and believing it is what let a second
    /// viewer's leg be advertised to the first viewer's connection.
    /// `relay_base_url` is where this connection's relay answers, from the
    /// connection view. `None` — no registered relay — keeps the old
    /// behaviour of binding against the control plane's own data path.
    pub async fn bind(
        &mut self,
        connection_id: &str,
        relay_base_url: Option<&str>,
    ) -> anyhow::Result<()> {
        if self.binds.contains_key(connection_id) {
            return Ok(());
        }
        // **The target's only way to get a ticket** (proxy spec §8.14.2). The
        // `connect` response that carries the initiator's goes to the initiator,
        // and the event that told this listener about the connection carries
        // none on purpose — an event is a fast path, not a record.
        //
        // **Which refusals may be opened through, and which may not.** A proxy
        // that predates §8.14 has no such route and asks for no ticket, so its
        // bare 404 is not a reason to refuse the leg: it is opened without one,
        // exactly as it always was. A transient failure is the same case for
        // now — during the migration window the proxy still binds a ticketless
        // leg — but the renewal loop has to run for it, because that leg is
        // leased and nothing else will extend it.
        //
        // A *refusal* is different, and swallowing it was a hole: while
        // `--relay-require-ticket` is false the proxy binds whatever arrives,
        // so opening the leg anyway would hand a twenty-minute lease to a
        // connection whose grant has just been withdrawn. The whole point of
        // asking for a ticket is that the control plane gets to say no.
        let (ticket, renewable) = match self.proxy.issue_relay_ticket(connection_id).await {
            Ok(ticket) => (Some(ticket), true),
            Err(e) => match crate::relay_lease::verdict(&e) {
                crate::relay_lease::Verdict::Refused | crate::relay_lease::Verdict::LegGone => {
                    return Err(anyhow::anyhow!(
                        "the proxy will not authorize a relay leg for {connection_id}: {e}"
                    ));
                }
                // No such route: this proxy does not lease legs at all.
                crate::relay_lease::Verdict::NotLeased => {
                    tracing::debug!(
                        connection_id = %connection_id,
                        "this proxy does not issue relay tickets; opening the leg without one",
                    );
                    (None, false)
                }
                crate::relay_lease::Verdict::Retry => {
                    tracing::warn!(
                        connection_id = %connection_id,
                        "could not get a relay ticket; opening the leg without one, \
                         and renewing it from the next: {e}",
                    );
                    (None, true)
                }
            },
        };
        // **The relay the ticket names, not the proxy we registered with.**
        // A leg opened against the control plane carries a ticket for another
        // relay, and the data path refuses it — correctly, and confusingly,
        // because the refusal names a ticket problem when the mistake was the
        // host we dialled.
        let session = open_bind_session(
            relay_base_url.unwrap_or(&self.proxy_url),
            // The current one, not the one the session started with: a leg
            // opened an hour in carries a token issued minutes ago.
            &self.proxy.endpoint_token(),
            &self.key,
            connection_id,
            self.forward_to,
            ticket.as_ref().map(|t| t.ticket.as_str()),
            self.opts.clone(),
        )
        .await?;
        let inbound = session.inbound_activity();
        // Own the session in a task that drains its notifications, so an unread
        // events channel can never stall the underlying MASQUE loop. Dropping
        // the task (on close) drops the session, whose Drop cancels the relay.
        let handle = tokio::spawn(drive_bind_session(
            session,
            self.observed_tx.clone(),
            self.legs.clone(),
        ));
        // Timed off the lease the ticket just wrote. The token it is handed goes
        // nowhere on purpose — a listener does not tear its session down
        // because one peer's leg lapsed; it stops holding that leg, and
        // `poll_and_bind` picks the peer up if it comes back.
        //
        // **Unconditional, unlike `renew_connections`.** That pass renews only
        // the rows of legs something is arriving on, because holding a leg says
        // nothing about whether a peer is still there. A leg's *lease* is a
        // different question, and asking it that way would break the case the
        // relay exists for: a session that has migrated to a direct path sends
        // nothing this way, and dropping its leg would take the fallback with
        // it — while the proxy cuts an edge at the shorter of the two parties'
        // leases, so this side going quiet would end the leg outright. What
        // ends this is the leg being unbound, which happens when the proxy
        // stops listing the connection.
        //
        // **Spawned even when the ticket did not arrive.** The proxy leases a
        // ticketless leg too — once, with no way to extend it from its own side
        // — and it accepts a `/renew` for one, so this loop is what takes such a
        // leg over. Skipping it left a leg the proxy had leased for twenty
        // minutes with nothing renewing it, and since the proxy cuts an edge at
        // the shorter of the two parties' leases, that took the initiator's leg
        // down with it.
        let lease = renewable.then(|| {
            RelayLegLease::spawn(
                self.proxy.clone(),
                connection_id.to_owned(),
                ticket.as_ref(),
                CancellationToken::new(),
                CancellationToken::new(),
            )
        });
        self.binds.insert(
            connection_id.to_owned(),
            BindGuard {
                handle,
                inbound,
                seen: 0,
                _lease: lease,
            },
        );
        Ok(())
    }

    /// Drop the leg for `connection_id`, if there is one.
    fn unbind(&mut self, connection_id: &str) {
        if let Some(guard) = self.binds.remove(connection_id) {
            guard.handle.abort();
        }
    }

    /// Mint a pairing code for the owner to display (spec §8.9.1).
    ///
    /// **This and the two grant methods below act on the Endpoint, not on this
    /// session.** Two sessions of the same Endpoint see and change the same
    /// codes and grants; only [`close`](Self::close) is about this listener.
    /// They live here because this is where an app that accepts connections
    /// already is, not because a listener scopes them.
    ///
    /// Issuing one invalidates this Endpoint's previous code for this protocol:
    /// there is only ever one, because the owner is showing it on one screen.
    /// What it hands out is access to this Endpoint, not to this listener, so
    /// it keeps working across a restart that replaces the listener.
    pub async fn show_pairing_code(&self, ttl: Option<u64>) -> anyhow::Result<PairingCode> {
        Ok(self.proxy.create_pairing_code(&self.protocol, ttl).await?)
    }

    /// Who is currently allowed to connect to this Endpoint (spec §8.8.2).
    pub async fn list_grants(&self) -> anyhow::Result<Vec<Grant>> {
        Ok(self.proxy.list_grants().await?)
    }

    /// Withdraw a grant (spec §8.8.3). Takes effect on that peer's next
    /// connect; anything already established stays up.
    pub async fn revoke_grant(&self, grant_id: &str) -> anyhow::Result<()> {
        Ok(self.proxy.revoke_grant(grant_id).await?)
    }

    /// Look for connections waiting on this listener and bind one, once.
    ///
    /// This is a single pass rather than a loop because binding needs `&mut
    /// self`, and the caller already owns this session to serve its other
    /// commands — a loop in here would take that ownership away. Call it on a
    /// timer.
    ///
    /// **Every waiting peer is bound, up to [`MAX_CONCURRENT_PEERS`].** Each
    /// has its own connection and its own leg, and they all deliver to the same
    /// local video listener. Nobody displaces anybody: a second viewer used to
    /// take the first one's leg, which killed the first one's video connection
    /// on its idle timeout and left it unrecoverable.
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
            .list_listener_connections(&self.listener_id, Some(ConnectionStateFilter::Relay))
            .await?;
        let mut events = Vec::new();
        if listing.truncated {
            events.push(SignalingEvent::Truncated);
        }
        // A leg that has ended is not serving anyone, whatever the listing still
        // says. The peer usually reports itself closed and drops out of the
        // listing, and `forget_gone` covers that; this is the peer that went
        // away without reporting — killed, crashed, or off the network — whose
        // connection the proxy will keep listing until it expires.
        let ended: Vec<String> = self
            .binds
            .iter()
            .filter(|(_, guard)| guard.handle.is_finished())
            .map(|(id, _)| id.clone())
            .collect();
        for id in ended {
            self.unbind(&id);
            state.bound.remove(&id);
            state.spent.insert(id.clone());
            events.push(SignalingEvent::Unbound { connection_id: id });
        }
        // Connections the proxy no longer lists are over; drop their legs too.
        for id in forget_gone(state, &listing.connections) {
            self.unbind(&id);
            events.push(SignalingEvent::Unbound { connection_id: id });
        }

        for connection in &listing.connections {
            if state.bound.contains(&connection.connection_id)
                || state.spent.contains(&connection.connection_id)
            {
                continue;
            }
            // The listing names both parties rather than "the peer", so this
            // has to be worked out; the listener is the target, so the other
            // end is the initiator.
            let peer_endpoint = connection
                .other_party(&self.endpoint_id)
                .unwrap_or("unknown")
                .to_owned();
            if !policy.binds_automatically() {
                events.push(SignalingEvent::Waiting {
                    connection_id: connection.connection_id.clone(),
                    peer_endpoint,
                });
                continue;
            }
            if state.bound.len() >= MAX_CONCURRENT_PEERS {
                events.push(SignalingEvent::AtCapacity {
                    connection_id: connection.connection_id.clone(),
                    peer_endpoint,
                });
                continue;
            }
            match self
                .bind(
                    &connection.connection_id,
                    connection.relay_base_url.as_deref(),
                )
                .await
            {
                Ok(()) => {
                    state.bound.insert(connection.connection_id.clone());
                    events.push(SignalingEvent::Bound {
                        connection_id: connection.connection_id.clone(),
                        peer_endpoint,
                    });
                }
                Err(e) => {
                    // Deliberately not remembered as bound: the next pass tries
                    // again, which is what a transient proxy failure wants.
                    events.push(SignalingEvent::BindFailed {
                        connection_id: connection.connection_id.clone(),
                        error: format!("{e:#}"),
                    });
                }
            }
        }
        Ok(events)
    }

    /// Subscribe to what happens to this listener (spec §8.11).
    ///
    /// The channel says **when to look**, not what is true. Every event is a
    /// reason to run [`poll_signaling`](Self::poll_signaling), which reads the
    /// listing and acts on it — so there is one place that decides what to
    /// bind, and the stream only decides how soon. A missed event costs
    /// latency until the next poll and nothing else, which is the property the
    /// proxy's design leans on and the reason it is safe to lean on it here.
    ///
    /// The channel ends when the stream does. That is not a failure to report:
    /// reconnect, and poll once on the way back, which is the same thing the
    /// listener does after any disconnection.
    pub async fn subscribe(&self) -> anyhow::Result<mpsc::Receiver<ListenerEvent>> {
        Ok(self.proxy.listener_events(&self.listener_id).await?)
    }

    /// Tell the proxy that every peer this listener is serving is still being
    /// served, so their connections are not reaped underneath them (spec
    /// §8.5.4).
    ///
    /// A connection is leased for the proxy's connect TTL and swept when it
    /// lapses. Nothing about carrying video renews it — the data path and the
    /// control plane do not talk — so a listener that says nothing loses every
    /// peer at the same age, however well the streams are going. On a device
    /// that was two streams cut at three hundred seconds to the tenth.
    ///
    /// **Only the legs that are carrying something are renewed.** Holding a leg
    /// is not evidence that anyone is on the other end of it: a leg comes down
    /// when the peer reports itself closed, and a peer that was killed reports
    /// nothing, so this side would go on claiming a viewer that left at the
    /// wall socket. Renewing on that claim is what kept the proxy's TTL from
    /// ever firing, and eight abandoned legs is a camera that will not take
    /// another viewer.
    ///
    /// Datagrams arriving on the leg are the one thing this side sees for
    /// itself, and they keep arriving for as long as the peer is there. While
    /// the video is on the relay that is the video. **After the peer has moved
    /// onto the direct path it is the path keepalive**: the relay path is kept
    /// as a backup rather than torn down, and the peer pings it every ten
    /// seconds, because the peer sets `PathKeepAliveIntervalMs` too — the timer
    /// runs off each connection's own settings, so both ends have their own
    /// (`peer::DIRECT_PATH_KEEPALIVE` on the viewer, and
    /// `isekai-link-utils`' `PATH_KEEP_ALIVE_INTERVAL_MS` for the listener this
    /// runs beside). A peer old enough not to negotiate multipath pings
    /// nothing, and needs to: it never left the relay, so the video is still
    /// coming this way.
    ///
    /// When the peer goes, they stop within a keepalive interval, this stops
    /// renewing, and the connection lapses on its own TTL — which is the same
    /// thing that happens when the peer's own renewal stops, and needs nothing
    /// to be reported.
    ///
    /// A peer that has not been updated to renew for itself is unaffected: it
    /// is watching, so its traffic is here. What this does drop is a peer that
    /// is still running and has stopped sending — suspended, or backgrounded on
    /// iOS. Its lease lapses, its leg comes down, and the slot goes back, which
    /// is the intended reading of §8.5.4: not "is anyone still there" but "is
    /// anyone still using this". A peer that returns connects again.
    ///
    /// Failures are reported per connection and not returned: one connection
    /// the proxy will not renew — because it has already been reaped, say —
    /// says nothing about the others, and the next pass tries again.
    pub async fn renew_connections(&mut self, state: &SignalingState) -> Vec<SignalingEvent> {
        // Taken in one pass so every leg's counter is read, and read before any
        // of the requests below can hold things up. A leg with no guard here is
        // not this listener's to claim.
        let renewing: Vec<String> = state
            .bound()
            .filter(|id| {
                self.binds
                    .get_mut(*id)
                    .is_some_and(BindGuard::carried_traffic)
            })
            .map(str::to_owned)
            .collect();
        let mut events = Vec::new();
        for connection_id in renewing {
            if let Err(e) = self.proxy.renew_connection(&connection_id).await {
                events.push(SignalingEvent::RenewFailed {
                    connection_id,
                    error: format!("{e}"),
                });
            }
        }
        events
    }

    /// Stop the relay bind leg (if any) and withdraw the Peer Listener.
    ///
    /// The listener is deleted rather than left to lapse, because until it does
    /// it keeps appearing in every paired peer's list of what it can reach —
    /// as something that looks connectable and is not. Deleting it costs
    /// nothing now that grants belong to the Endpoint (spec §8.8) and no longer
    /// go with it; before that, this would have thrown away every pairing.
    ///
    /// A failure is logged and not returned. This runs on the way out, the
    /// listener lapses with its lease either way (60s–24h, an hour by default),
    /// and there is nothing a caller shutting down could usefully do about it.
    ///
    /// The withdrawal is bounded by [`WITHDRAW_TIMEOUT`]. Without a bound,
    /// closing the window while the proxy is unreachable would keep the process
    /// alive until the transport gave up on a request whose only purpose is
    /// tidiness.
    ///
    /// **Awaiting this is what makes the withdrawal happen.** It is an HTTP
    /// request over the same msquic registration an exiting process is about to
    /// drain, so a caller that cancels and leaves will usually find the listener
    /// still up.
    pub async fn close(mut self) {
        for (_, guard) in self.binds.drain() {
            guard.handle.abort();
            let _ = guard.handle.await;
        }
        let withdrawn = tokio::time::timeout(
            WITHDRAW_TIMEOUT,
            self.proxy.delete_peer_listener(&self.listener_id),
        )
        .await;
        match withdrawn {
            Ok(Ok(())) => {
                tracing::debug!(listener_id = %self.listener_id, "peer listener withdrawn");
            }
            Ok(Err(e)) => tracing::warn!(
                listener_id = %self.listener_id,
                "could not withdraw the peer listener; it will lapse with its lease: {e}"
            ),
            Err(_) => tracing::warn!(
                listener_id = %self.listener_id,
                "timed out withdrawing the peer listener; it will lapse with its lease"
            ),
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
    legs: LegDirectory,
) {
    let mut leg = session.observed();
    // The addresses this leg has been reached at, so they can be forgotten with
    // it however it ends. Kept here rather than looked up in the directory,
    // which cannot say whose an entry is.
    let mut attached = AttachedLeg::new(legs);
    // The leg's watch ends when its connection does; keep draining events after
    // that rather than spinning on a closed channel.
    let mut leg_open = true;
    loop {
        tokio::select! {
            event = session.events.recv() => match event {
                Some(event) => {
                    // The one event that says something about *this* leg rather
                    // than about the session: a forwarding socket was created,
                    // and everything arriving at the local listener from its
                    // address arrived on this leg.
                    if let MasqueClientEvent::NewRemoteHost(peer, socket) = event {
                        tracing::debug!(
                            %peer, forwarding = %socket, "a peer is reaching this leg",
                        );
                        attached.attach(socket, session.observed());
                    } else {
                        tracing::debug!("bind session event: {event:?}");
                    }
                }
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

/// Drop what the proxy no longer lists, and say which bound ones went.
///
/// Without this the remembered sets would grow for as long as the process runs.
/// The proxy's listing is already capped, so bounding these by it bounds them.
/// The returned ids are peers that were being served and are not there any
/// more, so their legs have to come down with them.
fn forget_gone(state: &mut SignalingState, connections: &[PeerConnection]) -> Vec<String> {
    let live: HashSet<&str> = connections
        .iter()
        .map(|c| c.connection_id.as_str())
        .collect();
    let dropped: Vec<String> = state
        .bound
        .iter()
        .filter(|id| !live.contains(id.as_str()))
        .cloned()
        .collect();
    state.bound.retain(|id| live.contains(id.as_str()));
    state.spent.retain(|id| live.contains(id.as_str()));
    dropped
}

// -- Driving a session ------------------------------------------------------
//
// Moved from `camera-core::server` (plan 4.4, phase 1c-iii-c). A session that
// nothing runs binds nobody and renews nothing, so this is not a convenience
// on top of the type above -- it is how the type is used at all.

/// How often the listener asks the proxy whether anyone is waiting.
///
/// The wait it replaces was a person reading a connection id off one screen and
/// typing it into another, so seconds is already an enormous improvement and
/// there is nothing to gain from going lower. It also bounds how much traffic a
/// camera generates while nobody is connecting, which is most of the time.
const SIGNALING_POLL_INTERVAL: Duration = Duration::from_secs(3);

/// How often the listener tells the proxy that the peers it is serving are
/// still being served (spec §8.5.4).
///
/// Well inside the proxy's connect TTL, whose default is five minutes, because
/// this side does not know that number and losing every viewer at once is what
/// happens if the guess is wrong. A request per peer per minute is nothing next
/// to the video going the other way.
///
/// It is also the window each leg is judged over: only legs that have carried
/// something since the last tick are renewed. Anything comfortably longer than
/// the path keepalive works — a peer that is there is heard from every ten
/// seconds — and a pass that skips a leg costs nothing, since several fit
/// inside one TTL.
const CONNECTION_RENEW_INTERVAL: Duration = Duration::from_secs(60);

/// How often the listener reads its connections while an event stream is up.
///
/// The stream says when to look, so this is not how a peer is noticed any more
/// — it is the backstop for the case where the stream is healthy and wrong,
/// which is the case its own design cannot rule out (spec §8.11: nothing is
/// replayed). Far apart, because being wrong for a minute is the cost and
/// asking every three seconds was the thing worth removing.
const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How long to wait before opening the stream again after it ends.
///
/// Ending is ordinary — the proxy restarting, a connection dropping, a
/// subscriber cut off for falling behind — and the listener keeps working from
/// the poll while it is away, so this only has to be short enough not to
/// matter.
const RESUBSCRIBE_DELAY: Duration = Duration::from_secs(3);

/// The longest gap between attempts once they keep failing.
///
/// A proxy that does not serve this route refuses every time, and retrying it
/// every few seconds would double this camera's request rate forever and burn a
/// nonce on the proxy for each attempt — the store those go in is capped. So
/// the gap grows until it reaches this, and drops back the moment one succeeds.
const RESUBSCRIBE_MAX_DELAY: Duration = Duration::from_secs(300);
/// What a caller asks a running [`ListenerSession`] to do. Each carries a
/// reply channel.
///
/// Every one of these is a method on the session. The channel exists because
/// [`run`] owns it exclusively -- `bind` takes `&mut` -- so anything else that
/// wants to act on the session has to ask.
pub enum ListenerCommand {
    /// Mint a capability for the initiator's Endpoint ID; replies with the token.
    IssueCapability {
        allowed_endpoint: String,
        ttl: Option<u64>,
        reply: oneshot::Sender<anyhow::Result<String>>,
    },
    /// Attach the relay bind leg for the initiator's connection id.
    ///
    /// Only needed under [`AcceptPolicy::Manual`]; otherwise the session binds
    /// what the proxy says is waiting, without anyone carrying an id across.
    Bind {
        connection_id: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
    /// Mint a pairing code to display. Replaces whatever code this listener had.
    ShowPairingCode {
        ttl: Option<u64>,
        reply: oneshot::Sender<anyhow::Result<PairingCode>>,
    },
    /// Who is currently allowed to connect.
    ListGrants {
        reply: oneshot::Sender<anyhow::Result<Vec<Grant>>>,
    },
    /// Withdraw one. Takes effect on that peer's next connect.
    RevokeGrant {
        grant_id: String,
        reply: oneshot::Sender<anyhow::Result<()>>,
    },
}
/// Drive a [`ListenerSession`] until `shutdown`.
///
/// **Moved out of `camera-core::server` unchanged** (plan 4.4, phase
/// 1c-iii-c). Nothing in it was a camera: it is how a listener session is
/// kept alive, and a second consumer running its own copy would fork the
/// parts that are least obvious -- the two poll rates, the reconcile that
/// closes the gap a fresh event stream leaves, the backoff, and the renewal
/// that is the only thing keeping a served peer's lease from lapsing.
///
/// Takes the session by value: `bind` needs it mutably and nothing else may
/// hold it, so [`ListenerCommand`] is how anything else acts on it.
pub async fn run(
    mut session: ListenerSession,
    mut cmd_rx: mpsc::Receiver<ListenerCommand>,
    policy: AcceptPolicy,
    events: broadcast::Sender<SignalingEvent>,
    shutdown: CancellationToken,
) {
    let mut signaling = SignalingState::default();
    // Two rates for the same read. While a stream is up it is a backstop and
    // runs a minute apart; without one it is how a waiting peer is noticed at
    // all, and runs every few seconds. Which one applies is decided by whether
    // `stream` holds anything.
    let mut poll = tokio::time::interval(SIGNALING_POLL_INTERVAL);
    poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut renew = tokio::time::interval(CONNECTION_RENEW_INTERVAL);
    renew.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // Opened below rather than here, so a proxy that cannot stream costs a
    // refused request rather than a failed startup.
    let mut stream: Option<mpsc::Receiver<ListenerEvent>> = None;
    let mut resubscribe_delay = RESUBSCRIBE_DELAY;
    let mut resubscribe_at = tokio::time::Instant::now();
    // Whether the stream currently open has ever delivered anything.
    //
    // **This is what "it worked" means**, and the backoff below is wrong
    // without it. A `subscribe()` that succeeds and then ends at once — a proxy
    // crash-looping, an intermediary that closes the response immediately — is
    // not a working stream, and treating it as one retries as fast as the round
    // trip allows, forever, spending a nonce per attempt out of a capped store
    // (see `RESUBSCRIBE_MAX_DELAY`). The proxy sends keepalives, so a stream
    // that is up says so.
    let mut stream_delivered = false;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            // Open, or re-open, the event stream. Nothing else waits on this:
            // the poll keeps the listener working while there is no stream, so
            // failing here is a slower listener and not a stopped one.
            _ = tokio::time::sleep_until(resubscribe_at),
                    if stream.is_none() && policy != AcceptPolicy::Manual => {
                match session.subscribe().await {
                    Ok(events) => {
                        tracing::info!("signaling: event stream open");
                        stream = Some(events);
                        // Not reset here: opening is not working. The first
                        // event is what says the stream is real.
                        stream_delivered = false;
                        // Rebuilding the interval is what makes the next line
                        // matter: `interval` completes its first tick at once,
                        // so a reconcile runs now and picks up anything that
                        // happened before the stream was listening. Anyone
                        // changing this to `interval_at(now + period, ..)`
                        // opens a gap of one whole period right here.
                        poll = tokio::time::interval(RECONCILE_INTERVAL);
                        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    }
                    Err(e) => {
                        tracing::debug!(
                            "no event stream, polling instead (retrying in {resubscribe_delay:?}): {e:#}"
                        );
                        resubscribe_delay = (resubscribe_delay * 2).min(RESUBSCRIBE_MAX_DELAY);
                        resubscribe_at = tokio::time::Instant::now() + resubscribe_delay;
                    }
                }
            }
            // An event says something changed; the listing says what. Keeping
            // the decision in one place is what makes it safe for the stream to
            // be best effort — a missed event costs latency until the next
            // reconcile and never a wrong decision (spec §8.11).
            event = async { stream.as_mut().expect("guarded").recv().await },
                    if stream.is_some() => {
                match event {
                    Some(ListenerEvent::Keepalive) => stream_delivered = true,
                    Some(_) => {
                        stream_delivered = true;
                        poll.reset_immediately();
                    }
                    None => {
                        tracing::info!("signaling: event stream ended; polling until it returns");
                        stream = None;
                        // A stream that worked and then ended is worth trying
                        // again straight away — the usual reason is the proxy
                        // restarting. One that never delivered anything is a
                        // failure wearing a success's clothes, and backs off
                        // like one.
                        if stream_delivered {
                            resubscribe_delay = RESUBSCRIBE_DELAY;
                            resubscribe_at = tokio::time::Instant::now();
                        } else {
                            resubscribe_delay =
                                (resubscribe_delay * 2).min(RESUBSCRIBE_MAX_DELAY);
                            resubscribe_at = tokio::time::Instant::now() + resubscribe_delay;
                        }
                        // And, as above, the first tick of a fresh interval is
                        // immediate: the listener goes back to reading rather
                        // than waiting out a period it has no reason to.
                        poll = tokio::time::interval(SIGNALING_POLL_INTERVAL);
                        poll.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                    }
                }
            }
            // Not conditioned on the policy — but conditioned on traffic, by
            // `renew_connections`, which renews only the legs something is
            // arriving on.
            //
            // Under `Manual` it renews nothing at all, and always has: this
            // walks what `poll_signaling` recorded, and `Manual` is the policy
            // that never polls. A connection bound by hand is served until it
            // lapses on the proxy's TTL. Nothing here has changed that; it is
            // written down because the comment that used to be here said the
            // opposite.
            _ = renew.tick() => {
                for event in session.renew_connections(&signaling).await {
                    tracing::warn!("signaling: {event:?}");
                    let _ = events.send(event);
                }
            }
            // Nothing to poll for under `Manual`: the operator binds, as before.
            _ = poll.tick(), if policy != AcceptPolicy::Manual => {
                match session.poll_signaling(&mut signaling, policy).await {
                    Ok(found) => {
                        for event in found {
                            tracing::info!("signaling: {event:?}");
                            // No subscribers is not a failure — the application
                            // binds whether or not a UI is watching.
                            let _ = events.send(event);
                        }
                    }
                    // The proxy being briefly unreachable is not a reason to
                    // stop serving; the next tick tries again.
                    Err(e) => tracing::warn!("signaling poll failed: {e:#}"),
                }
            }
            cmd = cmd_rx.recv() => match cmd {
                Some(ListenerCommand::IssueCapability { allowed_endpoint, ttl, reply }) => {
                    let result = session
                        .issue_capability(&allowed_endpoint, ttl)
                        .await
                        .map(|cap| cap.capability);
                    let _ = reply.send(result);
                }
                Some(ListenerCommand::Bind { connection_id, reply }) => {
                    // Read the connection first: a bind asked for by id alone
                    // still has to land on the relay the ticket names, and
                    // only the connection view says which that is.
                    //
                    // **A failed read is not "no relay".** Swallowing it would
                    // bind against the control plane while the ticket names
                    // the registered relay, which the data path then refuses
                    // for naming another relay — the exact confusion this
                    // change exists to remove, reintroduced by a `.ok()`.
                    let result = match session.proxy.get_connection(&connection_id).await {
                        Ok(c) => {
                            session
                                .bind(&connection_id, c.relay_base_url.as_deref())
                                .await
                        }
                        Err(e) => Err(anyhow::anyhow!(
                            "could not read {connection_id} to find its relay: {e}"
                        )),
                    };
                    let _ = reply.send(result);
                }
                Some(ListenerCommand::ShowPairingCode { ttl, reply }) => {
                    let _ = reply.send(session.show_pairing_code(ttl).await);
                }
                Some(ListenerCommand::ListGrants { reply }) => {
                    let _ = reply.send(session.list_grants().await);
                }
                Some(ListenerCommand::RevokeGrant { grant_id, reply }) => {
                    let _ = reply.send(session.revoke_grant(&grant_id).await);
                }
                None => break,
            },
        }
    }
    session.close().await;
}
#[cfg(test)]
mod tests {
    use super::*;

    /// Built from the JSON the proxy actually sends, not from the struct.
    ///
    /// A hand-written fixture agrees with whatever the struct happens to say
    /// and so cannot notice a field the server never sends — which is exactly
    /// how `peer_endpoint` came to be read here when the listing does not carry
    /// it. This shape is `ConnectionResponse` from the server's §8.5.3.
    fn conn(id: &str) -> PeerConnection {
        serde_json::from_str(&format!(
            r#"{{
                "connection_id": "{id}",
                "state": "relay",
                "listener_id": "pl_1",
                "initiator_endpoint": "ep:A",
                "target_endpoint": "ep:B",
                "protocol": "mjpeg",
                "relay_session_id": "sess_1",
                "candidates": [],
                "peer_candidates": [],
                "created_at": "2026-08-02T09:00:00Z",
                "expires_at": "2026-08-02T09:05:00Z",
                "updated_at": "2026-08-02T09:00:00Z"
            }}"#
        ))
        .expect("the listing's connection shape")
    }

    /// The listing names both parties; the listener is the target, so the peer
    /// it reports is the initiator. Getting this wrong is invisible in the
    /// happy path — it just shows the operator the wrong name, or none.
    #[test]
    fn the_peer_is_read_from_the_shape_the_listing_actually_sends() {
        let c = conn("conn_1");
        assert_eq!(c.peer_endpoint, None, "the listing does not carry this");
        assert_eq!(c.other_party("ep:B"), Some("ep:A"));
        assert_eq!(c.other_party("ep:A"), Some("ep:B"));
    }

    /// What the proxy stops listing is over: forget it, and say so, because
    /// the leg serving it has to come down with it.
    #[test]
    fn what_the_proxy_stops_listing_is_forgotten_and_reported() {
        let mut state = SignalingState::default();
        state.bound.insert("conn_gone".to_owned());
        state.bound.insert("conn_here".to_owned());
        state.spent.insert("conn_dead".to_owned());

        let dropped = forget_gone(&mut state, &[conn("conn_here")]);

        assert_eq!(dropped, vec!["conn_gone".to_owned()]);
        assert_eq!(state.bound.len(), 1);
        assert!(state.bound.contains("conn_here"));
        assert!(
            state.spent.is_empty(),
            "spent is bounded by the listing too"
        );
    }

    /// Nothing is dropped while it is still listed, however many peers there
    /// are — the sets are pruned against the listing, not against each other.
    #[test]
    fn forgetting_leaves_everyone_still_listed_alone() {
        let mut state = SignalingState::default();
        state.bound.insert("conn_a".to_owned());
        state.bound.insert("conn_b".to_owned());

        let dropped = forget_gone(&mut state, &[conn("conn_a"), conn("conn_b")]);

        assert!(dropped.is_empty());
        assert_eq!(state.bound.len(), 2);
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

    /// A peer that vanished without reporting stays listed until the proxy
    /// expires it. Its leg has ended here, so it must not be bound again —
    /// otherwise every poll rebuilds a leg that dies immediately, for as long
    /// as the proxy keeps listing the connection.
    ///
    /// `spent` is what remembers that, and it is cleared the moment the proxy
    /// does stop listing it, so an id is never held against a connection that
    /// no longer exists.
    #[test]
    fn a_peer_whose_leg_died_is_not_bound_again() {
        let mut state = SignalingState::default();
        state.spent.insert("conn_b".to_owned());

        // `poll_signaling` skips anything in `bound` or `spent`; B is spent.
        let listing = [conn("conn_b"), conn("conn_a")];
        let would_bind: Vec<&str> = listing
            .iter()
            .filter(|c| {
                !state.bound.contains(&c.connection_id) && !state.spent.contains(&c.connection_id)
            })
            .map(|c| c.connection_id.as_str())
            .collect();
        assert_eq!(would_bind, ["conn_a"], "B's leg already died here");

        forget_gone(&mut state, &[conn("conn_a")]);
        assert!(state.spent.is_empty());
    }

    /// A leg that has already reported the binding `port` names.
    fn leg_watch(port: u16) -> ObservedAddressWatch {
        watch::channel(Some(observed(port))).0.subscribe()
    }

    /// Where a leg's forwarding socket delivers from — loopback, because that
    /// is where the video listener is.
    fn forwarding(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The whole point: two legs, two answers. Before this, a connection was
    /// handed whichever address had arrived first, and a second viewer's leg
    /// could be advertised to the first viewer's connection.
    #[test]
    fn a_connection_is_answered_with_its_own_leg() {
        let legs = LegDirectory::default();
        legs.attach(forwarding(40001), leg_watch(1));
        legs.attach(forwarding(40002), leg_watch(2));

        let first = legs.leg_for(forwarding(40001)).expect("the first leg");
        let second = legs.leg_for(forwarding(40002)).expect("the second leg");

        assert_eq!(first.borrow().expect("reported").local, addr(1));
        assert_eq!(second.borrow().expect("reported").local, addr(2));
    }

    /// An address no leg forwards from is not this listener's to answer for —
    /// something that dialled the video listener directly, or a leg that has
    /// not reported yet. Both get no direct path rather than somebody else's.
    #[test]
    fn an_unknown_address_gets_no_leg() {
        let legs = LegDirectory::default();
        legs.attach(forwarding(40001), leg_watch(1));
        assert!(legs.leg_for(forwarding(40009)).is_none());
    }

    /// One leg can be reached at more than one address — a peer that changes
    /// address gets another forwarding socket — and both name the same leg.
    #[test]
    fn one_leg_can_answer_to_several_addresses() {
        let legs = LegDirectory::default();
        legs.attach(forwarding(40001), leg_watch(7));
        legs.attach(forwarding(40002), leg_watch(7));

        for port in [40001, 40002] {
            let leg = legs.leg_for(forwarding(port)).expect("the leg");
            assert_eq!(leg.borrow().expect("reported").local, addr(7));
        }
    }

    /// A leg that ends takes its addresses with it, so the map is bounded by
    /// the legs that exist rather than by every leg this session ever had.
    ///
    /// **Through `Drop`, which is the only path that runs.** Legs are normally
    /// taken down by aborting their task, and an aborted task does not reach
    /// anything after its loop — so cleaning up there left every leg a peer had
    /// left behind still answering, its watch alive, ready to be handed to
    /// whichever new leg the operating system gave that port to next.
    #[test]
    fn a_leg_that_ends_stops_answering() {
        let legs = LegDirectory::default();
        let other = {
            let mut ending = AttachedLeg::new(legs.clone());
            ending.attach(forwarding(40001), leg_watch(1));
            let mut other = AttachedLeg::new(legs.clone());
            other.attach(forwarding(40002), leg_watch(2));
            assert_eq!(legs.claimed(), 2);
            other
        };

        assert!(legs.leg_for(forwarding(40001)).is_none(), "it ended");
        assert!(
            legs.leg_for(forwarding(40002)).is_some(),
            "the other leg is untouched",
        );
        drop(other);
        assert_eq!(legs.claimed(), 0);
    }

    /// A guard over a leg that has received `datagrams` so far.
    ///
    /// The handle is a finished task rather than a live leg: nothing here reads
    /// it, and what is under test is the counter, not the session.
    fn leg(datagrams: u64) -> BindGuard {
        let inbound = InboundActivity::default();
        for _ in 0..datagrams {
            inbound.record();
        }
        BindGuard {
            handle: tokio::spawn(std::future::ready(())),
            inbound,
            seen: 0,
            _lease: None,
        }
    }

    /// The whole point of the change: holding a leg is not evidence of a peer,
    /// so a leg that has received nothing gets no claim made on its behalf.
    /// This is the viewer that was killed — its leg is still here, and nothing
    /// is coming in on it.
    #[tokio::test]
    async fn a_leg_that_has_received_nothing_is_not_claimed() {
        let mut quiet = leg(0);
        assert!(!quiet.carried_traffic());
        assert!(!quiet.carried_traffic(), "and it stays that way");
    }

    /// A viewer that is watching sends — video acknowledgements, or the path
    /// keepalive once it has moved to the direct path — so every pass sees the
    /// counter move and the lease is pushed out.
    #[tokio::test]
    async fn a_leg_still_receiving_is_claimed_every_pass() {
        let mut busy = leg(1);
        assert!(busy.carried_traffic());

        busy.inbound.record();
        assert!(busy.carried_traffic());
        busy.inbound.record();
        assert!(busy.carried_traffic());
    }

    /// What is compared is the counter against its own previous reading, not
    /// against zero: a leg that carried plenty and then went quiet stops being
    /// claimed, which is what makes a peer that leaves mid-session lapse.
    #[tokio::test]
    async fn a_leg_that_goes_quiet_stops_being_claimed() {
        let mut leg = leg(4_000);
        assert!(leg.carried_traffic(), "still arriving");

        assert!(!leg.carried_traffic(), "nothing since");
        assert!(!leg.carried_traffic());

        leg.inbound.record();
        assert!(leg.carried_traffic(), "and it recovers if the peer returns");
    }
}
