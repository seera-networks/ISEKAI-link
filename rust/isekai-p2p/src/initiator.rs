//! The initiator side of a P2P connection: `peer_connect` plus the relay
//! **connect** leg, which exposes a local UDP address a co-located client dials.
//!
//! The client (e.g. the camera client's video QUIC connection) sends to
//! [`InitiatorSession::local_addr`] instead of a public address; the relay
//! carries it to the target's bound socket.

use std::net::SocketAddr;

use anyhow::Context as _;
use isekai_p2p_core::bind::{open_connect_relay, ConnectRelay, RelayOptions};
use isekai_p2p_core::observed::ObservedAddressWatch;
use isekai_p2p_core::proxy::{Candidate, Grant, PeerConnection, ProxyClient, ReachableListener};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::config::{issue_endpoint_token, P2pConfig};

/// An initiator-side P2P session. Holds the relay connect leg open until dropped
/// or [`close`](InitiatorSession::close)d.
pub struct InitiatorSession {
    /// The local UDP address to send application traffic to.
    pub local_addr: SocketAddr,
    /// The `peer_connect` response, including `connection_id` (hand this to the
    /// target so it can bind) and the relay info.
    pub connection: PeerConnection,
    relay: ConnectRelay,
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
    endpoint_token: String,
}

impl PeerDirectory {
    /// Obtain an Endpoint Token and open the control plane.
    pub async fn open(cfg: &P2pConfig) -> anyhow::Result<Self> {
        let token = issue_endpoint_token(cfg).await?;
        Self::open_with_token(cfg, &token.endpoint_token)
    }

    /// Open with a token already in hand.
    pub fn open_with_token(cfg: &P2pConfig, endpoint_token: &str) -> anyhow::Result<Self> {
        Ok(Self {
            proxy: ProxyClient::new(
                MasqueH3Transport::connect(&cfg.proxy_url)?,
                cfg.key.clone(),
                endpoint_token,
            ),
            endpoint_token: endpoint_token.to_owned(),
        })
    }

    /// The token this was opened with, to pass to a connect so the app does not
    /// issue a second one.
    pub fn endpoint_token(&self) -> &str {
        &self.endpoint_token
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
            &self.endpoint_token,
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
        Ok(Self {
            local_addr: handle.local_addr,
            connection,
            relay: handle,
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
    pub async fn close(self) {
        self.relay.close().await;
    }
}
