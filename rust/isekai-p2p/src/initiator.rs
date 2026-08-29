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
use isekai_p2p_core::proxy::{
    Candidate, Grant, PeerConnection, ProxyClient, ProxyError, ReachableListener,
    RedeemedProvisioningKey, RedeemedTicket,
};
use isekai_p2p_core::transport::MasqueH3Transport;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

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
    /// Cancelled when the proxy stops accepting this Endpoint for this
    /// connection — see [`ended`](Self::ended).
    ended: CancellationToken,
    /// Replaces the Endpoint Token before it expires. Shared with the
    /// [`PeerDirectory`] this was opened over, when there was one, so there is
    /// one renewal loop however many handles are holding the same client.
    _renewal: Arc<TokenRenewal>,
}

/// What fraction of the remaining lease to let pass before renewing.
///
/// A third, so two renewals can fail before the lease lapses.
const LEASE_RENEW_DIVISOR: u32 = 3;
/// Never renew more often than this, whatever a deadline works out to.
const LEASE_RENEW_MIN: Duration = Duration::from_secs(10);
/// Nor less often, and this is also what an unreadable or missing deadline
/// falls back to. Under the five minutes the proxy's connect TTL defaults to,
/// so a lease of unknown length is still renewed in time.
const LEASE_RENEW_MAX: Duration = Duration::from_secs(60);

/// When to renew next, from the deadline the proxy just gave.
///
/// **Measured rather than assumed.** Every connection read and every renewal
/// answers with `expires_at` (spec §8.5.1), so the interval can come from the
/// lease itself instead of from a copy of the server's default sitting in this
/// file. A constant here would be a second place that number lives, and the
/// kind that breaks silently on the day the proxy's `--p2p-connect-ttl-secs`
/// moves.
///
/// **And measured on the proxy's clock, not this one.** The same response
/// carries `updated_at`, the moment the deadline was set from, so subtracting
/// one server timestamp from the other gives the lease's length without this
/// side's clock entering into it. Reading it against a local `now` instead
/// would mean a device running fast sees every fresh lease as already lapsed
/// and renews at the floor forever — six times the requests, and an `info` line
/// nowhere to say why. The local clock is only the fallback, for a response
/// that carries no `updated_at`.
fn renew_delay(
    expires_at: Option<&str>,
    updated_at: Option<&str>,
    now: OffsetDateTime,
) -> Duration {
    let timestamp = |s: Option<&str>| s.and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok());
    let Some(deadline) = timestamp(expires_at) else {
        return LEASE_RENEW_MAX;
    };
    // The answer just arrived, so the lease's whole length is what is left of it.
    let remaining = deadline - timestamp(updated_at).unwrap_or(now);
    if !remaining.is_positive() {
        // Already lapsed as far as this side can tell. Renewing at once is the
        // only thing that might still save it, and the floor keeps that from
        // becoming a spin.
        return LEASE_RENEW_MIN;
    }
    Duration::from_secs_f64(remaining.as_seconds_f64() / f64::from(LEASE_RENEW_DIVISOR))
        .clamp(LEASE_RENEW_MIN, LEASE_RENEW_MAX)
}

/// What a failed renewal means for the loop (spec §8.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Renewal {
    /// Might work next time. The lease outlives several of these.
    Retry,
    /// No later report succeeds. Stop asking.
    Over,
    /// Stop, and end the session here as well: what is refused is the Endpoint,
    /// not the request, so nothing this process does next will be accepted
    /// either.
    Refused,
}

/// What a failed renewal means.
///
/// **A loop that cannot tell these apart keeps asking once a minute for the
/// life of the process**, which is a warning a minute about something nobody
/// can act on — and for a revoked Endpoint it is worse than noisy: the session
/// goes on looking alive while carrying nothing.
///
/// `connection-closed` is what a terminal connection answers now that
/// [`ISEKAI-link-server#226`](https://github.com/seera-networks/ISEKAI-link-server/pull/226)
/// has shipped. `invalid-request` is kept alongside it because that is what a
/// proxy from before it answers, and because there is nothing in a renewal for
/// it to be about otherwise — [`ProxyClient::renew_connection`] sends `{}`, and
/// [`InitiatorSession::close`] reports no candidates. **A renewal that ever
/// carries a candidate has to revisit this**: a reflexive address the proxy
/// refuses (CGNAT, spec §8.4.1) is refused every time, and treating that as
/// terminal would end a session over one bad candidate.
///
/// **Only `endpoint-revoked` ends the session.** `insufficient-permission` is
/// refused against the permissions on the *current Endpoint Token*, and this
/// process replaces that token every few minutes — so it can be a token minted
/// before a permission existed rather than an Endpoint that may not do this.
/// Retrying costs a warning a minute and recovers on its own; treating it as
/// terminal would tear down every live session the day the proxy starts
/// requiring a permission on this route.
fn renewal_verdict(error: &ProxyError) -> Renewal {
    let ProxyError::Problem { problem, .. } = error else {
        // A transport failure says nothing about the connection.
        return Renewal::Retry;
    };
    match problem.as_ref().map(|p| p.kind()) {
        Some("connection-closed" | "connection-not-found" | "invalid-request") => Renewal::Over,
        Some("endpoint-revoked") => Renewal::Refused,
        // `token-expired` and `insufficient-permission` included: both are
        // about the token, which is shared with the loop that replaces it, so
        // the next attempt carries a new one.
        _ => Renewal::Retry,
    }
}

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
    /// Takes the `connect` response itself, so the first renewal is timed off
    /// the real lease exactly like every one after it.
    /// Both tokens are cancelled for the answers that mean this process will
    /// not be let back in: `leg` winds the relay down, and `ended` is what the
    /// application watches — a session that has migrated to a direct path does
    /// not stop when the leg does.
    fn spawn(
        proxy: ProxyClient<MasqueH3Transport>,
        connection: &PeerConnection,
        leg: CancellationToken,
        ended: CancellationToken,
    ) -> Self {
        let connection_id = connection.connection_id.clone();
        let mut delay = renew_delay(
            connection.expires_at.as_deref(),
            connection.updated_at.as_deref(),
            OffsetDateTime::now_utc(),
        );
        Self(tokio::spawn(async move {
            loop {
                tokio::time::sleep(delay).await;
                match proxy.renew_connection(&connection_id).await {
                    Ok(connection) => {
                        delay = renew_delay(
                            connection.expires_at.as_deref(),
                            connection.updated_at.as_deref(),
                            OffsetDateTime::now_utc(),
                        );
                        tracing::trace!(
                            connection_id = %connection_id,
                            next = ?delay,
                            "renewed the peer connection's lease",
                        );
                    }
                    Err(e) => match renewal_verdict(&e) {
                        Renewal::Over => {
                            // The connection is gone or the peer closed it. Said
                            // once, and then this stops rather than asking a
                            // question that now has a permanent answer.
                            tracing::info!(
                                connection_id = %connection_id,
                                "the peer connection is over; no longer renewing it: {e}",
                            );
                            return;
                        }
                        Renewal::Refused => {
                            // The Endpoint is refused, not the request. Renewing
                            // is pointless and so is everything else this
                            // process would do with the connection — but the
                            // video is riding a relay leg that is still up, so
                            // left alone the viewer watches a session that looks
                            // alive and carries nothing. Revocation is the
                            // emergency stop; this is how it reaches whoever is
                            // watching.
                            tracing::error!(
                                connection_id = %connection_id,
                                "this endpoint has been revoked; ending the session: {e}",
                            );
                            leg.cancel();
                            ended.cancel();
                            return;
                        }
                        Renewal::Retry => {
                            // Not fatal on its own: the lease outlives several
                            // of these, so a proxy that is briefly unreachable
                            // costs nothing. Worth saying, because the visible
                            // consequence of it continuing is the video stopping
                            // partway through.
                            tracing::warn!(
                                connection_id = %connection_id,
                                retry_in = ?delay,
                                "could not renew the peer connection's lease: {e}",
                            );
                        }
                    },
                }
            }
        }))
    }

    /// Stop claiming, without waiting for the drop.
    ///
    /// Used before reporting the connection closed: `closed` is terminal, and a
    /// renewal racing behind it would be refused with `400 connection-closed`
    /// and logged as a failure that is really just bad timing.
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

    /// Redeem a Ticket, binding this Endpoint to it (spec §8.12.3).
    ///
    /// Unlike a pairing code this is a 256-bit secret that was handed over out
    /// of band, so it is not read off a screen and several can be outstanding
    /// at once. What comes back is a Grant with a finite life, and the
    /// listeners reachable through it — the latter so that redeeming does not
    /// have to be followed by a listing. An empty list is not a failure.
    pub async fn redeem_ticket(
        &self,
        ticket: &str,
        label: Option<&str>,
    ) -> anyhow::Result<RedeemedTicket> {
        Ok(self.proxy.redeem_ticket(ticket, label).await?)
    }

    /// Redeem a Provisioning Key, binding this Endpoint to it (spec §8.13.5).
    ///
    /// **Unlike a Ticket, doing this again is the point.** A second redemption
    /// answers `200` and moves `expires_at` to `max(existing, now + grant_ttl)`,
    /// never backwards — which is how a job that outlives `grant_ttl` keeps its
    /// authorization, and why that ceiling is an hour rather than a day.
    ///
    /// `assertion` is required when the key was issued with an `oidc` binding,
    /// and has to be **minted for this call** rather than reused: the proxy
    /// verifies it every time.
    pub async fn redeem_provisioning_key(
        &self,
        key: &str,
        assertion: Option<&str>,
        label: Option<&str>,
    ) -> anyhow::Result<RedeemedProvisioningKey> {
        Ok(self
            .proxy
            .redeem_provisioning_key(key, assertion, label)
            .await?)
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
        let ended = CancellationToken::new();
        let lease = ConnectionLease::spawn(
            proxy.clone(),
            &connection,
            handle.shutdown_token(),
            ended.clone(),
        );
        Ok(Self {
            local_addr: handle.local_addr,
            connection,
            relay: handle,
            proxy: proxy.clone(),
            lease,
            ended,
            _renewal: renewal,
        })
    }

    /// Cancelled if the proxy refuses this Endpoint (`endpoint-revoked`,
    /// `insufficient-permission` — spec §8.5.4).
    ///
    /// **Worth watching even though the relay leg is torn down too.** A session
    /// that has migrated to a direct path is not carried by the leg any more, so
    /// dropping the leg does not stop it; and where the leg *is* carrying the
    /// video, what the application sees is a connection that goes quiet and
    /// times out half a minute later, rather than a reason.
    ///
    /// Revocation is the emergency stop. This is how it reaches whoever is
    /// watching.
    pub fn ended(&self) -> CancellationToken {
        self.ended.clone()
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
        if self.ended.is_cancelled() {
            // Revoked. `report_state` goes through the same auth layer that
            // just refused the renewal, so it can only be refused too — and
            // waiting out `REPORT_CLOSED_TIMEOUT` to be told so would end a
            // revocation with a warning about the listener's leg staying
            // reserved, which is neither true nor the point.
            self.relay.close().await;
            return;
        }
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

    const SERVER_NOW: i64 = 1_800_000_000;

    fn stamp(unix_secs: i64) -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(unix_secs)
    }

    /// A lease of `secs` the proxy just handed out: both timestamps on its clock.
    fn lease(secs: i64) -> (Option<String>, Option<String>) {
        let format = |t: OffsetDateTime| Some(t.format(&Rfc3339).unwrap());
        (format(stamp(SERVER_NOW + secs)), format(stamp(SERVER_NOW)))
    }

    /// This side's clock, `skew` seconds off the proxy's.
    fn local_clock(skew: i64) -> OffsetDateTime {
        stamp(SERVER_NOW + skew)
    }

    /// The interval comes from the lease the proxy just handed back, so a proxy
    /// configured differently from the default is followed rather than guessed
    /// at. A third of what is left leaves room for two failures.
    #[test]
    fn the_interval_is_measured_from_the_deadline() {
        let (expires_at, updated_at) = lease(150);
        assert_eq!(
            renew_delay(expires_at.as_deref(), updated_at.as_deref(), local_clock(0)),
            Duration::from_secs(50)
        );
        let (expires_at, updated_at) = lease(90);
        assert_eq!(
            renew_delay(expires_at.as_deref(), updated_at.as_deref(), local_clock(0)),
            Duration::from_secs(30)
        );
    }

    /// Both timestamps come from the proxy, so what this device thinks the time
    /// is cannot move the interval. Without that, a clock running an hour fast
    /// reads every fresh lease as lapsed and renews at the floor for as long as
    /// the app runs — six times the requests, and nothing said about it.
    #[test]
    fn a_wrong_local_clock_does_not_change_the_interval() {
        let (expires_at, updated_at) = lease(150);
        for skew in [0, 3_600, -3_600] {
            assert_eq!(
                renew_delay(
                    expires_at.as_deref(),
                    updated_at.as_deref(),
                    local_clock(skew)
                ),
                Duration::from_secs(50),
                "a clock {skew}s off should not have mattered",
            );
        }
        // And that is what the local clock alone would have made of it.
        assert_eq!(
            renew_delay(expires_at.as_deref(), None, local_clock(3_600)),
            LEASE_RENEW_MIN
        );
    }

    /// A deadline that is missing or in a shape this cannot read must not turn
    /// into "never renew". The fallback is under the shortest lease the proxy
    /// is likely to hand out.
    #[test]
    fn an_unreadable_deadline_still_renews_in_time() {
        let now = OffsetDateTime::UNIX_EPOCH;
        assert_eq!(renew_delay(None, None, now), LEASE_RENEW_MAX);
        assert_eq!(renew_delay(Some("soon"), None, now), LEASE_RENEW_MAX);
        assert!(LEASE_RENEW_MAX < Duration::from_secs(300));
    }

    /// An unreadable `updated_at` is not fatal — it falls back to the local
    /// clock, which is what this did before the proxy's own was available.
    #[test]
    fn an_unreadable_issue_time_falls_back_to_the_local_clock() {
        let (expires_at, _) = lease(150);
        assert_eq!(
            renew_delay(expires_at.as_deref(), Some("just now"), local_clock(0)),
            Duration::from_secs(50)
        );
    }

    /// A long lease must not push the renewal past the fallback, and a lapsed
    /// or absurdly short one must not turn into a spin.
    #[test]
    fn the_interval_stays_between_its_bounds() {
        for (secs, expected) in [
            (86_400, LEASE_RENEW_MAX),
            (1, LEASE_RENEW_MIN),
            (-60, LEASE_RENEW_MIN),
        ] {
            let (expires_at, updated_at) = lease(secs);
            assert_eq!(
                renew_delay(expires_at.as_deref(), updated_at.as_deref(), local_clock(0)),
                expected,
                "a lease of {secs}s",
            );
        }
    }

    fn problem(kind: &str) -> ProxyError {
        ProxyError::Problem {
            status: 404,
            problem: Some(
                serde_json::from_value(serde_json::json!({
                    "type": format!("https://isekai.link/problems/{kind}"),
                    "title": kind,
                    "status": 404,
                }))
                .expect("problem parses"),
            ),
            retry_after: None,
        }
    }

    /// A connection that is gone, or one the peer has closed, will not come
    /// back — and a renewal task that keeps asking produces a warning a minute
    /// about something nobody can act on.
    #[test]
    fn a_permanent_answer_ends_the_renewal() {
        assert_eq!(
            renewal_verdict(&problem("connection-closed")),
            Renewal::Over
        );
        assert_eq!(
            renewal_verdict(&problem("connection-not-found")),
            Renewal::Over,
        );
    }

    /// What a proxy from before `connection-closed` answers for the same thing.
    /// Dropping it would turn a terminal connection into the forever-loop this
    /// exists to prevent, against every proxy that has not been updated yet.
    #[test]
    fn the_older_answer_for_the_same_thing_still_ends_it() {
        assert_eq!(renewal_verdict(&problem("invalid-request")), Renewal::Over);
    }

    /// A revoked Endpoint is refused on every request, so this must not be
    /// mistaken for something worth retrying — and it is not merely permanent,
    /// it has to end the session, or the viewer keeps watching a connection
    /// that carries nothing.
    #[test]
    fn a_revoked_endpoint_ends_the_session_as_well() {
        assert_eq!(
            renewal_verdict(&problem("endpoint-revoked")),
            Renewal::Refused,
        );
    }

    /// Permissions are checked against the token, not the Endpoint, and this
    /// process replaces its token every few minutes. Ending the session here
    /// would tear down every live one the day the proxy starts requiring a
    /// permission on this route, against tokens minted before it existed.
    #[test]
    fn a_permission_the_token_lacks_is_not_the_endpoint_being_refused() {
        assert_eq!(
            renewal_verdict(&problem("insufficient-permission")),
            Renewal::Retry,
        );
    }

    /// Anything that might work next time keeps the loop alive: the lease
    /// outlives several failures, so a proxy that is briefly unreachable must
    /// not end a session that is streaming fine.
    #[test]
    fn a_transient_failure_does_not() {
        assert_eq!(renewal_verdict(&problem("internal")), Renewal::Retry);
        assert_eq!(
            renewal_verdict(&ProxyError::Transport(anyhow::anyhow!("connection reset"))),
            Renewal::Retry,
        );
    }

    /// The token is shared with the loop that replaces it, so the next attempt
    /// carries the new one — retrying is the refresh.
    #[test]
    fn an_expired_token_is_worth_another_attempt() {
        assert_eq!(renewal_verdict(&problem("token-expired")), Renewal::Retry);
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
