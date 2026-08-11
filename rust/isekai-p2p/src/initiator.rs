//! The initiator side of a P2P connection: `peer_connect` plus the relay
//! **connect** leg, which exposes a local UDP address a co-located client dials.
//!
//! The client (e.g. the camera client's video QUIC connection) sends to
//! [`InitiatorSession::local_addr`] instead of a public address; the relay
//! carries it to the target's bound socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use isekai_p2p_core::bind::{open_connect_relay, ConnectRelay, RelayOptions};
use isekai_p2p_core::observed::ObservedAddressWatch;
use isekai_p2p_core::proxy::{Candidate, Grant, PeerConnection, ProxyClient, ReachableListener};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::config::{issue_endpoint_token, spawn_token_renewal, P2pConfig, TokenRenewal};

/// An initiator-side P2P session. Holds the relay connect leg open until dropped
/// or [`close`](InitiatorSession::close)d.
pub struct InitiatorSession {
    /// The local UDP address to send application traffic to.
    pub local_addr: SocketAddr,
    /// The `peer_connect` response, including `connection_id` (hand this to the
    /// target so it can bind) and the relay info.
    pub connection: PeerConnection,
    relay: ConnectRelay,
    /// Kept so [`close`](Self::close) can tell the proxy the connection is
    /// over, and so the lease below can be renewed.
    proxy: ProxyClient<MasqueH3Transport>,
    /// Keeps the Peer Connection's lease alive while this session exists.
    ///
    /// **Held here, on the side that is using the connection.** A renewal is a
    /// claim that somebody is still there (spec §8.5.4), and this is the only
    /// side that can make it honestly — the listener cannot see whether its
    /// viewer is still watching. Because the claim stops when this value is
    /// dropped, it also stops when the process is killed, which is what lets
    /// the proxy expire the connection and the camera release its relay leg.
    lease: ConnectionLease,
    /// Replaces the Endpoint Token before it expires. Shared with the
    /// [`PeerDirectory`] this was opened over, when there was one, so there is
    /// one renewal loop however many handles are holding the same client.
    _renewal: Arc<TokenRenewal>,
}

/// How often to renew the Peer Connection's lease.
///
/// Well inside the proxy's connect TTL, whose default is five minutes — this
/// side does not know that number, and being cut off mid-view is what happens
/// if the guess is wrong. One request a minute is nothing beside the video
/// coming the other way.
const LEASE_RENEW_INTERVAL: Duration = Duration::from_secs(60);

/// How long [`InitiatorSession::close`] waits to report the connection closed.
///
/// Short: this runs while an application is disconnecting or exiting, and what
/// is lost by giving up is that the listener holds its relay leg for this
/// connection until the proxy expires it.
const REPORT_CLOSED_TIMEOUT: Duration = Duration::from_secs(3);

/// Renews one Peer Connection's lease until dropped.
///
/// Dropping stops the claim, which is the point: a viewer that goes away —
/// closed, killed, crashed, off the network — stops asserting it is there, and
/// the proxy expires the connection on its own. Nothing has to notice the
/// difference between those, and nothing has to be reported for it to work.
struct ConnectionLease(tokio::task::JoinHandle<()>);

impl ConnectionLease {
    fn spawn(proxy: ProxyClient<MasqueH3Transport>, connection_id: String) -> Self {
        Self(tokio::spawn(async move {
            loop {
                tokio::time::sleep(LEASE_RENEW_INTERVAL).await;
                if let Err(e) = proxy.renew_connection(&connection_id).await {
                    // Not fatal on its own: the lease outlives several of these,
                    // so a proxy that is briefly unreachable costs nothing. It
                    // is worth saying, because the visible consequence of it
                    // continuing is the video stopping partway through.
                    tracing::warn!(
                        connection_id = %connection_id,
                        "could not renew the peer connection's lease: {e}",
                    );
                }
            }
        }))
    }

    /// Stop claiming, without waiting for the drop.
    ///
    /// Used before reporting the connection closed: `closed` is terminal, and a
    /// renewal racing behind it would be refused with `400 invalid-request` and
    /// logged as a failure that is really just bad timing.
    fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for ConnectionLease {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// What lets an initiator open a connection.
///
/// The proxy accepts either; which one a caller holds says how it was let in,
/// not what it may do afterwards (spec §8.4).
enum Authorization<'a> {
    /// A one-shot token the listener's owner minted and handed over.
    Capability(&'a str),
    /// A standing grant the proxy already holds. Nothing was carried.
    Grant,
}

/// The initiator's view of the control plane, before any relay leg exists.
///
/// Everything an app needs to answer "what can I reach, and how do I get let
/// in" — the questions that used to be answered by a person reading a listener
/// id and a capability off someone else's screen.
pub struct PeerDirectory {
    proxy: ProxyClient<MasqueH3Transport>,
    /// Handed to a session opened over this directory, so the two share one
    /// renewal rather than running one each against the same client.
    renewal: Arc<TokenRenewal>,
}

impl PeerDirectory {
    /// Obtain an Endpoint Token and open the control plane.
    pub async fn open(cfg: &P2pConfig) -> anyhow::Result<Self> {
        let token = issue_endpoint_token(cfg).await?;
        Self::open_with_token(cfg, &token.endpoint_token)
    }

    /// Open with a token already in hand.
    pub fn open_with_token(cfg: &P2pConfig, endpoint_token: &str) -> anyhow::Result<Self> {
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token,
        );
        let renewal = Arc::new(spawn_token_renewal(cfg.clone(), proxy.clone(), None));
        Ok(Self { proxy, renewal })
    }

    /// The Endpoint Token in force, to pass to a connect so the app does not
    /// issue a second one.
    ///
    /// A `String` rather than a borrow because it is replaced as it expires —
    /// what this returns is a snapshot, and a caller holding it for minutes is
    /// holding a stale token.
    pub fn endpoint_token(&self) -> String {
        self.proxy.endpoint_token()
    }

    /// Listeners this Endpoint may connect to now (spec §8.10).
    pub async fn reachable(&self) -> anyhow::Result<Vec<ReachableListener>> {
        Ok(self.proxy.list_reachable_listeners().await?)
    }

    /// Listeners of this Endpoint's own account that accept self-enrolment.
    ///
    /// Appearing here is **not** permission to connect — [`Self::enrol`] turns
    /// one into the grant that is (spec §8.9.3).
    pub async fn enrollable(&self) -> anyhow::Result<Vec<ReachableListener>> {
        Ok(self.proxy.list_enrollable_listeners().await?)
    }

    /// Redeem a pairing code the listener's owner displayed (spec §8.9.2).
    pub async fn pair(&self, code: &str, label: Option<&str>) -> anyhow::Result<Grant> {
        Ok(self.proxy.pair_with_code(code, label).await?)
    }

    /// Enrol on a listener of this Endpoint's own account (spec §8.9.3).
    pub async fn enrol(&self, listener_id: &str, label: Option<&str>) -> anyhow::Result<Grant> {
        Ok(self.proxy.pair_with_listener(listener_id, label).await?)
    }

    /// Connect to one of these listeners on a grant, over the control-plane
    /// connection this already holds.
    ///
    /// The reason for going through here rather than
    /// [`InitiatorSession::connect_with_grant`] is the same reason
    /// [`Self::endpoint_token`] exists: an app that has just listed what it can
    /// reach should not open a second QUIC connection to the proxy to act on
    /// the answer.
    pub async fn connect(
        &self,
        cfg: &P2pConfig,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<InitiatorSession> {
        InitiatorSession::connect_over(
            cfg,
            &self.proxy,
            &self.endpoint_token(),
            Some(Arc::clone(&self.renewal)),
            Authorization::Grant,
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }
}

impl InitiatorSession {
    /// Obtain an Endpoint Token, `peer_connect` with `capability` +
    /// `listener_id`, and open the relay connect leg.
    ///
    /// `candidates` may be empty for relay-only use. `local_bind` is where the
    /// leg binds locally (`127.0.0.1:0` for an ephemeral port).
    pub async fn connect(
        cfg: &P2pConfig,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::connect_with_token(
            cfg,
            &endpoint_token,
            capability,
            listener_id,
            candidates,
            local_bind,
        )
        .await
    }

    /// Like [`connect`](Self::connect) but choosing how the relay connect leg is
    /// opened.
    ///
    /// Pass `RelayOptions { unconnected: true, registration: Some(..) }` to make
    /// the leg usable for path migration: the direct path is opened from its
    /// binding, and [`observed_address`](Self::observed_address) then reports
    /// the pair to hand to `add_candidate_addr`.
    pub async fn connect_with_options(
        cfg: &P2pConfig,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let endpoint_token = issue_endpoint_token(cfg).await?.endpoint_token;
        Self::connect_with_token_and_options(
            cfg,
            &endpoint_token,
            capability,
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }

    /// Like [`connect`](Self::connect) but with an Endpoint Token the caller
    /// already holds, skipping the Identity API round-trip.
    ///
    /// Only `proxy_url`, `protocol` and `key` are read from `cfg`.
    pub async fn connect_with_token(
        cfg: &P2pConfig,
        endpoint_token: &str,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
    ) -> anyhow::Result<Self> {
        Self::connect_with_token_and_options(
            cfg,
            endpoint_token,
            capability,
            listener_id,
            candidates,
            local_bind,
            RelayOptions::default(),
        )
        .await
    }

    /// [`connect_with_token`](Self::connect_with_token) plus the relay-leg
    /// options — the form the other three delegate to.
    pub async fn connect_with_token_and_options(
        cfg: &P2pConfig,
        endpoint_token: &str,
        capability: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        Self::connect_inner(
            cfg,
            endpoint_token,
            Authorization::Capability(capability),
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }

    /// Connect on a standing grant instead of a capability (spec §8.8).
    ///
    /// The difference is what the caller had to be given: a capability is a
    /// token the listener's owner minted and handed over for this one
    /// connection, and a grant is a record the proxy already holds. With a
    /// grant there is nothing to carry, so this needs only the listener's id —
    /// which [`PeerDirectory::reachable`] supplies.
    pub async fn connect_with_grant(
        cfg: &P2pConfig,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let token = issue_endpoint_token(cfg).await?;
        Self::connect_with_grant_and_token(
            cfg,
            &token.endpoint_token,
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }

    /// [`connect_with_grant`](Self::connect_with_grant) with a token already in
    /// hand, so an app that has just listed what it can reach does not issue a
    /// second one to connect.
    pub async fn connect_with_grant_and_token(
        cfg: &P2pConfig,
        endpoint_token: &str,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        Self::connect_inner(
            cfg,
            endpoint_token,
            Authorization::Grant,
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }

    /// What the two connect paths share. Only the authorization differs; the
    /// relay leg that follows does not care which one got it here.
    async fn connect_inner(
        cfg: &P2pConfig,
        endpoint_token: &str,
        auth: Authorization<'_>,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let proxy = ProxyClient::new(
            MasqueH3Transport::connect(&cfg.proxy_url)?,
            cfg.key.clone(),
            endpoint_token,
        );
        Self::connect_over(
            cfg,
            &proxy,
            endpoint_token,
            // This opened the client, so nothing else is renewing its token.
            None,
            auth,
            listener_id,
            candidates,
            local_bind,
            opts,
        )
        .await
    }

    /// The connect itself, over a control-plane connection the caller supplies.
    ///
    /// Split out so a caller that already has one — [`PeerDirectory`], which
    /// opened one to answer what is reachable — does not open a second.
    #[allow(clippy::too_many_arguments)]
    async fn connect_over(
        cfg: &P2pConfig,
        proxy: &ProxyClient<MasqueH3Transport>,
        endpoint_token: &str,
        // The caller's renewal when it has one, so `proxy`'s token is not being
        // replaced by two loops at once. `None` starts one here.
        renewal: Option<Arc<TokenRenewal>>,
        auth: Authorization<'_>,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        let connection = match auth {
            Authorization::Capability(capability) => {
                proxy
                    .peer_connect(capability, listener_id, &cfg.protocol, candidates)
                    .await?
            }
            Authorization::Grant => {
                proxy
                    .peer_connect_with_grant(listener_id, &cfg.protocol, candidates)
                    .await?
            }
        };
        let relay = connection.relay.as_ref().context(
            "connect response has no relay info; the proxy did not allocate a relay edge",
        )?;
        let handle = open_connect_relay(
            &cfg.proxy_url,
            endpoint_token,
            &cfg.key,
            &connection.connection_id,
            &relay.masque_uri,
            local_bind,
            opts,
        )
        .await?;
        let renewal = renewal
            .unwrap_or_else(|| Arc::new(spawn_token_renewal(cfg.clone(), proxy.clone(), None)));
        let lease = ConnectionLease::spawn(proxy.clone(), connection.connection_id.clone());
        Ok(Self {
            local_addr: handle.local_addr,
            connection,
            relay: handle,
            proxy: proxy.clone(),
            lease,
            _renewal: renewal,
        })
    }

    /// The connection id, to hand to the target so it can bind its relay leg.
    pub fn connection_id(&self) -> &str {
        &self.connection.connection_id
    }

    /// How the proxy sees this session's relay connect leg — `None` until the
    /// first report arrives.
    ///
    /// This is the pair the video connection names via `add_candidate_addr` to
    /// offer a direct path. Note it is **not**
    /// [`local_addr`](InitiatorSession::local_addr): that is the loopback socket
    /// the application sends to, whereas this is the leg's own binding out on
    /// the network.
    ///
    /// Only meaningful when the session was created with
    /// `RelayOptions { unconnected: true, .. }`; a leg on a plain connected
    /// socket has no binding a direct path could use.
    pub fn observed_address(&self) -> ObservedAddressWatch {
        self.relay.observed()
    }

    /// The loopback FQDN to dial for the video QUIC so its per-endpoint
    /// certificate can be validated, or `None` when the proxy has relay
    /// certificates disabled (dial `127.0.0.1` unvalidated instead).
    pub fn video_host(&self) -> Option<&str> {
        self.connection.video_host.as_deref()
    }

    /// Tear down the relay connect leg.
    /// Report the connection closed and take the relay connect leg down.
    ///
    /// The report is the important half, and it is easy to miss why. The
    /// listener finds out who is waiting for it by listing its connections in
    /// state `relay`, and binds its single leg to one of them. A connection
    /// nobody reports stays in that listing until the proxy expires it — so a
    /// peer that disconnects goes on occupying the listener's leg for minutes,
    /// and another peer already waiting is not picked up in the meantime. What
    /// looks like "the camera stopped accepting anyone" is this.
    ///
    /// Bounded by [`REPORT_CLOSED_TIMEOUT`] and never fails the caller: this
    /// runs on the way out, the connection expires on its own either way, and
    /// there is nothing a disconnecting application could do with the error.
    pub async fn close(self) {
        // Before the report: `closed` is terminal, so a renewal arriving behind
        // it is refused and logged as a failure that is only bad timing.
        self.lease.stop();
        let reported = tokio::time::timeout(
            REPORT_CLOSED_TIMEOUT,
            self.proxy
                .report_state(&self.connection.connection_id, "closed", &[]),
        )
        .await;
        match reported {
            Ok(Ok(_)) => tracing::debug!(
                connection_id = %self.connection.connection_id,
                "reported the peer connection closed"
            ),
            Ok(Err(e)) => tracing::warn!(
                connection_id = %self.connection.connection_id,
                "could not report the peer connection closed; the listener's leg \
                 stays reserved until the proxy expires it: {e}"
            ),
            Err(_) => tracing::warn!(
                connection_id = %self.connection.connection_id,
                "timed out reporting the peer connection closed; the listener's leg \
                 stays reserved until the proxy expires it"
            ),
        }
        self.relay.close().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The interval has to stay well under the proxy's connect TTL, whose
    /// default is 300 seconds and which this side never learns. Drifting up to
    /// it does not fail a build or a test anywhere else — it shows up as video
    /// that stops partway through, on somebody's screen.
    #[test]
    fn the_lease_is_renewed_well_inside_the_default_ttl() {
        let default_connect_ttl = Duration::from_secs(300);
        assert!(
            LEASE_RENEW_INTERVAL * 3 <= default_connect_ttl,
            "renewing every {LEASE_RENEW_INTERVAL:?} leaves no room for a failure or two",
        );
    }

    /// Dropping the session stops the claim. This is what makes a viewer that
    /// was killed — Ctrl+C, a crash, a lost network — release the camera's
    /// relay leg without reporting anything.
    #[tokio::test]
    async fn dropping_the_lease_stops_renewing() {
        let lease = ConnectionLease(tokio::spawn(async {
            std::future::pending::<()>().await;
        }));
        let handle = lease.0.abort_handle();
        assert!(!handle.is_finished());
        drop(lease);
        tokio::task::yield_now().await;
        assert!(handle.is_finished(), "the renewal outlived the session");
    }
}
