//! The initiator side of a P2P connection: `peer_connect` plus the relay
//! **connect** leg, which exposes a local UDP address a co-located client dials.
//!
//! The client (e.g. the camera client's video QUIC connection) sends to
//! [`InitiatorSession::local_addr`] instead of a public address; the relay
//! carries it to the target's bound socket.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

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
use tokio::sync::{oneshot, watch};
use tokio_util::sync::CancellationToken;

use crate::config::{issue_endpoint_token, spawn_token_renewal, P2pConfig, TokenRenewal};
use crate::relay_lease::RelayLegLease;

/// An initiator-side P2P session. Holds a relay connect leg open until dropped
/// or [`close`](InitiatorSession::close)d.
///
/// **Not always the leg it started with.** When the relay restarts, the leg
/// stops carrying traffic and the proxy's row for the connection goes with it;
/// since `docs/relay_repath_plan.md` P3 this session answers by making a new
/// connection and a new leg to stand where the old one did. What it reports —
/// [`local_addr`](Self::local_addr), [`connection`](Self::connection) and the
/// rest — is the attachment in force now, which is why they are accessors and
/// not the fields they used to be.
///
/// **Nothing has moved onto the new leg yet.** That is P4. Until it lands, a
/// peer connection that migrated to a direct path gets its fallback back
/// without being told, and one riding the relay itself ends as it always did.
pub struct InitiatorSession {
    /// What a holder may read about the attachment in force.
    ///
    /// Kept beside the attachment rather than borrowed out of it: the swap
    /// happens on a task nobody here is waiting for, so a reader holding a
    /// borrow across one would be holding the leg that died.
    facts: watch::Receiver<Facts>,
    /// Where the relay leg is, as it moves — see [`relay_leg`](Self::relay_leg).
    leg: RelayLegWatch,
    /// Cancelled when the proxy stops accepting this Endpoint for this
    /// connection — see [`ended`](Self::ended).
    ended: CancellationToken,
    /// Asks the supervisor to take the session down. Cancelled by
    /// [`close`](Self::close) and by `Drop`, so a session nobody closed still
    /// stops claiming.
    shutdown: CancellationToken,
    /// Answered once the supervisor has reported the connection closed and the
    /// leg has wound down. Taken by [`close`](Self::close), which is the only
    /// thing that waits for it.
    closed: Option<oneshot::Receiver<()>>,
    /// Replaces the Endpoint Token before it expires. Shared with the
    /// [`PeerDirectory`] this was opened over, when there was one, so there is
    /// one renewal loop however many handles are holding the same client.
    _renewal: Arc<TokenRenewal>,
}

/// One relay attachment: a Peer Connection, the leg that carries it, and the
/// two leases that keep each alive.
///
/// **These four live and die together**, which is the reason they are a type.
/// Both leases are keyed on the connection id, and one of them on the leg's
/// origin as well, so a leg replaced without them is a pair of loops renewing
/// things that no longer exist — and the failures that produces name the
/// proxy rather than this.
struct Attachment {
    /// The `peer_connect` response, including `connection_id` (hand this to
    /// the target so it can bind) and the relay info.
    connection: PeerConnection,
    relay: ConnectRelay,
    /// Keeps the Peer Connection's lease alive while this attachment exists.
    ///
    /// **Held here, on the side that is using the connection.** A renewal is a
    /// claim that somebody is still there (spec §8.5.4), and this is the only
    /// side that can make it honestly — the listener cannot see whether its
    /// viewer is still watching. Because the claim stops when this value is
    /// dropped, it also stops when the process is killed, which is what lets
    /// the proxy expire the connection and the camera release its relay leg.
    lease: ConnectionLease,
    /// Keeps this side's **relay leg** alive (proxy spec §8.14).
    ///
    /// **A second lease, on a different thing.** `lease` above carries the
    /// connection row by reporting state; this one re-tickets the leg. Since
    /// §8.14 the proxy stopped extending the leg when a state report arrives,
    /// so a session that renewed only the row would keep a live connection with
    /// nothing flowing over it — and the visible symptom would be video that
    /// stops twenty minutes in with the control plane insisting everything is
    /// fine.
    ///
    /// Against a proxy that predates §8.14 this stops itself on the first
    /// attempt and nothing else changes.
    relay_lease: RelayLegLease,
}

/// Where a session's relay leg answers, and a notification each time it moves.
///
/// **`None` is the leg having gone with nothing in its place** — no fallback,
/// for as long as it lasts. `Some` is the loopback address the leg answers on
/// now, which is the *remote* of the relay path from the peer connection's
/// point of view.
///
/// One signal rather than two, and that is deliberate: "it has gone" and "it
/// is over here now" are the same question asked at different moments, and a
/// separate token for the first would go on answering about a leg that has
/// since been replaced.
pub type RelayLegWatch = watch::Receiver<Option<SocketAddr>>;

/// What a holder of the session can read about the attachment in force.
///
/// A copy rather than a view. The attachment belongs to the supervisor task,
/// and it is replaced whole.
#[derive(Clone)]
struct Facts {
    local_addr: SocketAddr,
    connection: PeerConnection,
    observed: ObservedAddressWatch,
}

/// The two channels the supervisor writes and the session reads.
///
/// Together rather than as two arguments, because they are written in the same
/// breath and a replacement that updated one of them alone would be a session
/// reporting two different legs depending on which question was asked.
struct Published {
    facts: watch::Sender<Facts>,
    leg: watch::Sender<Option<SocketAddr>>,
}

impl Published {
    /// A leg has taken over.
    fn now_at(&self, attachment: &Attachment) {
        self.facts.send_replace(Facts::of(attachment));
        self.leg.send_replace(Some(attachment.relay.local_addr));
    }

    /// The leg has gone, and nothing is in its place yet.
    ///
    /// **`facts` is left alone.** The connection row and the loopback address
    /// it names are still what the application is using; what has changed is
    /// only that the leg behind them stopped carrying.
    fn leg_is_gone(&self) {
        self.leg.send_replace(None);
    }
}

impl Facts {
    fn of(attachment: &Attachment) -> Self {
        Self {
            local_addr: attachment.relay.local_addr,
            connection: attachment.connection.clone(),
            observed: attachment.relay.observed(),
        }
    }
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

/// What it took to stand this session's relay leg up, kept so it can be done
/// again (`docs/relay_repath_plan.md` P3).
///
/// **The listener id is remembered rather than looked up again.** A Grant
/// outlives the listener it was made against — spec §8.8 keeps Listener out of
/// its key precisely so that restarting the server does not mean pairing again
/// — but the id itself is new after every restart of the *peer*. So this
/// replaces a leg lost to the **relay** restarting, which is what the plan set
/// out to do; a peer that restarted underneath is a reconnect, and the
/// application above is what owns that.
struct Reattach {
    cfg: P2pConfig,
    auth: OwnedAuthorization,
    listener_id: String,
    candidates: Vec<Candidate>,
    local_bind: SocketAddr,
    opts: RelayOptions,
}

/// How a session was let in, in the form that outlives the call that used it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OwnedAuthorization {
    /// **Spent.** A capability authorizes one `connect` (spec §8.4), and the
    /// string itself is not kept, because keeping it would only make it look
    /// like something this could use twice.
    SpentCapability,
    /// A standing grant. The proxy still holds it, so it can be used again.
    Grant,
}

impl Reattach {
    /// Why this session cannot stand a new leg up, when it cannot.
    ///
    /// Answered here rather than attempted and failed, because the two reasons
    /// look nothing alike from a failed `peer_connect`: a spent capability
    /// answers with a refusal that reads like a permissions problem, and a
    /// connected socket answers with success and a leg that no path can ever
    /// be moved onto.
    fn refusal(&self) -> Option<&'static str> {
        refusal(self.auth, self.opts.unconnected)
    }
}

/// [`Reattach::refusal`], over the two things it actually reads.
fn refusal(auth: OwnedAuthorization, unconnected: bool) -> Option<&'static str> {
    match auth {
        OwnedAuthorization::SpentCapability => Some(
            "it was let in by a one-shot capability, and a capability authorizes one \
             connect. Connect on a standing grant to have a leg that replaces itself",
        ),
        // **§3.5 of the plan, answered by leaving it out.** Without
        // `unconnected` the leg is on a connected socket that no other path can
        // share, so multipath was never negotiated and there is nothing a
        // replacement leg could be attached to. Such a session is exactly the
        // one that dies with its relay — worth fixing, and a different change
        // (`peer.rs`, every session's handshake) from this one.
        OwnedAuthorization::Grant if !unconnected => Some(
            "its leg is on a connected socket, so no path could be moved onto a \
             replacement (`docs/relay_repath_plan.md` §3.5)",
        ),
        OwnedAuthorization::Grant => None,
    }
}

/// How long to wait before the first attempt at replacing a lost relay leg.
///
/// **Not zero.** A relay that has stopped answering is usually a relay that is
/// restarting, and a `peer_connect` issued in the same breath as the leg's
/// death is the one most likely to be answered by nothing at all.
const REATTACH_FIRST_DELAY: Duration = Duration::from_secs(1);
/// The ceiling the backoff climbs to.
const REATTACH_MAX_DELAY: Duration = Duration::from_secs(30);
/// The shortest time between one leg standing up and the next attempt to
/// replace it — see [`reattach_delay`], which is where this is not backoff.
const REATTACH_MIN_INTERVAL: Duration = Duration::from_secs(5);
/// How many attempts before the session is left without a fallback for good.
///
/// With the delays above that is a little over two minutes: long enough to
/// ride out a relay restart, short enough that a session running on one path
/// is *reported* as such rather than spending the rest of its life asking.
const REATTACH_ATTEMPTS: u32 = 8;
/// How long [`InitiatorSession::close`] waits for the supervisor to report the
/// connection closed and wind the leg down.
///
/// Covers both of the bounds it is waiting on — [`REPORT_CLOSED_TIMEOUT`] and
/// the leg's own wind-down — with room to spare, so a warning here means
/// something other than those two took the time.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);

/// How long to wait before attempt `attempt` (0-based) at replacing a leg,
/// given that it stood up `since_stood_up` ago.
///
/// Exponential with a ceiling, and a **floor that is not backoff at all**
/// (`docs/relay_repath_plan.md` §0.3). Under multipath `remove_path` is
/// asynchronous — msquic sends `PATH_ABANDON` and `PathsCount` does not drop
/// until the peer answers — so legs replaced faster than paths retire walk the
/// connection into `QUIC_MAX_PATH_COUNT`, which is 4 and already holds a relay
/// path and a direct one. A relay that flaps every few hundred milliseconds
/// would otherwise cost a `peer_connect` every few hundred milliseconds.
///
/// `since_stood_up` is what keeps that floor off the ordinary case, and it is
/// counted from the leg standing up rather than from it dying — a leg that
/// carried a session for hours has long since paid the interval, and its
/// replacement starts on the backoff alone. **It includes the time the retry
/// loop has already spent**, so the floor is charged once rather than once per
/// attempt: from the second attempt on, the waiting itself has covered it.
fn reattach_delay(attempt: u32, since_stood_up: Duration) -> Duration {
    let backoff = REATTACH_FIRST_DELAY
        .saturating_mul(1u32 << attempt.min(16))
        .min(REATTACH_MAX_DELAY);
    backoff.max(REATTACH_MIN_INTERVAL.saturating_sub(since_stood_up))
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
        // The caller's renewal when it has one, so `proxy`'s token is not being
        // replaced by two loops at once. `None` starts one here.
        renewal: Option<Arc<TokenRenewal>>,
        auth: Authorization<'_>,
        listener_id: &str,
        candidates: &[Candidate],
        local_bind: SocketAddr,
        opts: RelayOptions,
    ) -> anyhow::Result<Self> {
        // Read before `auth` is spent on the first attach. What survives it is
        // only the *kind*: a capability cannot be used twice, so keeping the
        // string would make this look like something it is not.
        let owned = match &auth {
            Authorization::Capability(_) => OwnedAuthorization::SpentCapability,
            Authorization::Grant => OwnedAuthorization::Grant,
        };
        let ended = CancellationToken::new();
        let attachment = attach(
            cfg,
            proxy,
            auth,
            listener_id,
            candidates,
            local_bind,
            opts.clone(),
            &ended,
        )
        .await?;
        let renewal = renewal
            .unwrap_or_else(|| Arc::new(spawn_token_renewal(cfg.clone(), proxy.clone(), None)));
        let (facts, watching) = watch::channel(Facts::of(&attachment));
        let (leg, leg_at) = watch::channel(Some(attachment.relay.local_addr));
        let shutdown = CancellationToken::new();
        let (reported, closed) = oneshot::channel();
        // **The supervisor owns the attachment from here on.** It is the one
        // thing that both replaces a lost leg and takes the last one down, and
        // splitting those between a task and a `close` on this side is how the
        // two end up racing over the same leg.
        tokio::spawn(supervise(
            attachment,
            Reattach {
                cfg: cfg.clone(),
                auth: owned,
                listener_id: listener_id.to_owned(),
                candidates: candidates.to_vec(),
                local_bind,
                opts,
            },
            proxy.clone(),
            Published { facts, leg },
            ended.clone(),
            shutdown.clone(),
            reported,
        ));
        Ok(Self {
            facts: watching,
            leg: leg_at,
            ended,
            shutdown,
            closed: Some(closed),
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
    /// watching. It is also what stops a lost leg being replaced: a refused
    /// Endpoint will not be let back in under a new connection id either.
    pub fn ended(&self) -> CancellationToken {
        self.ended.clone()
    }

    /// Where the **relay leg** is, and a notification each time that moves.
    ///
    /// Not [`ended`](Self::ended), which is the session being refused. This is
    /// the fallback going away underneath a session that may be perfectly
    /// healthy on a direct path, and then coming back somewhere else — the
    /// reason anything that would fall back to the relay has to ask first
    /// (`portal_core::path`), and the reason it can then re-attach.
    ///
    /// **A live channel, not a snapshot**, because a replacement leg answers
    /// at a new loopback address and a holder that read the old one would be
    /// pointing a path at a closed socket. See [`RelayLegWatch`].
    pub fn relay_leg(&self) -> RelayLegWatch {
        self.leg.clone()
    }

    /// The local UDP address the application should send its traffic to.
    pub fn local_addr(&self) -> SocketAddr {
        self.facts.borrow().local_addr
    }

    /// The `peer_connect` response for the attachment in force, including
    /// `connection_id` (hand this to the target so it can bind) and the relay
    /// info.
    ///
    /// **A clone, and it used to be a field.** It is replaced whole when a lost
    /// leg is stood back up, so what a caller holds is a snapshot of the
    /// connection that was current when it asked.
    pub fn connection(&self) -> PeerConnection {
        self.facts.borrow().connection.clone()
    }

    /// The connection id, to hand to the target so it can bind its relay leg.
    pub fn connection_id(&self) -> String {
        self.facts.borrow().connection.connection_id.clone()
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
        self.facts.borrow().observed.clone()
    }

    /// The loopback FQDN to dial for the video QUIC so its per-endpoint
    /// certificate can be validated, or `None` when the proxy has relay
    /// certificates disabled (dial `127.0.0.1` unvalidated instead).
    pub fn video_host(&self) -> Option<String> {
        self.facts.borrow().connection.video_host.clone()
    }

    /// Report the connection closed and take the relay connect leg down.
    ///
    /// **The work is the supervisor's**; this asks for it and waits. That is
    /// not indirection for its own sake: the supervisor is the thing that
    /// replaces a lost leg, so it is also the only thing that knows which leg
    /// there is to take down. Doing it from here would mean two owners for one
    /// attachment and a race over which of them retires it.
    ///
    /// Bounded by [`CLOSE_TIMEOUT`] and never fails the caller: this runs on
    /// the way out, the connection expires on its own either way, and there is
    /// nothing a disconnecting application could do with the error.
    pub async fn close(mut self) {
        self.shutdown.cancel();
        let Some(closed) = self.closed.take() else {
            return;
        };
        if tokio::time::timeout(CLOSE_TIMEOUT, closed).await.is_err() {
            tracing::warn!(
                "the relay leg did not finish winding down within {CLOSE_TIMEOUT:?}; \
                 the listener's leg stays reserved until the proxy expires it",
            );
        }
    }
}

impl Drop for InitiatorSession {
    /// A session that is dropped rather than closed still has to stop claiming.
    ///
    /// **It used to do this by itself.** The leg and both leases were fields
    /// here, and each cancels or aborts when dropped. They belong to the
    /// supervisor now, so the ask has to be made out loud — and unlike
    /// [`close`](Self::close) there is nobody here to wait for the answer.
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Stand one relay attachment up: `peer_connect`, the leg, and the two leases.
///
/// **Called again for every replacement**, which is why it reads the Endpoint
/// Token off the proxy rather than taking one. `ProxyClient` holds the token
/// the renewal loop keeps replacing, so a leg stood up an hour into a session
/// is opened with the token in force then and not with the one the session
/// started with.
#[allow(clippy::too_many_arguments)]
async fn attach(
    cfg: &P2pConfig,
    proxy: &ProxyClient<MasqueH3Transport>,
    auth: Authorization<'_>,
    listener_id: &str,
    candidates: &[Candidate],
    local_bind: SocketAddr,
    opts: RelayOptions,
    ended: &CancellationToken,
) -> anyhow::Result<Attachment> {
    // **Measured here, in front of the request that decides**
    // (the relay proximity plan §4). The relay is chosen once, during
    // this `connect`, and the target is not present for it — so an
    // initiator that wants a say has to have measured by now. The target's
    // numbers were reported against its listener long before.
    //
    // Bounded tightly and never fatal: this sits in front of a connection
    // somebody is waiting on. Measuring nothing means the target's
    // measurements decide alone, which is a worse relay and not a failure.
    let relay_rtt = crate::relay_rtt::measure_for_connect(
        proxy,
        &crate::relay_rtt::ProbeOptions::initiator_defaults(),
    )
    .await;
    let connection = match auth {
        Authorization::Capability(capability) => {
            proxy
                .peer_connect_measured(
                    capability,
                    listener_id,
                    &cfg.protocol,
                    candidates,
                    &relay_rtt,
                )
                .await?
        }
        Authorization::Grant => {
            proxy
                .peer_connect_with_grant_measured(
                    listener_id,
                    &cfg.protocol,
                    candidates,
                    &relay_rtt,
                )
                .await?
        }
    };
    let relay = connection
        .relay
        .as_ref()
        .context("connect response has no relay info; the proxy did not allocate a relay edge")?;
    // **The ticket is what brings the leg into existence** (spec §8.14).
    // It rides along in the `connect` response, so no extra round trip.
    //
    // `None` means either a proxy that predates §8.14 — which asks for no
    // ticket — or one that could not sign. Opening the leg without one is
    // right in both cases: the first accepts it, and the second answers
    // `relay-ticket-required`, which names the real problem.
    let ticket = connection.ticket.clone();
    let handle = open_connect_relay(
        &cfg.proxy_url,
        &proxy.endpoint_token(),
        &cfg.key,
        &connection.connection_id,
        &relay.masque_uri,
        local_bind,
        ticket.as_ref().map(|t| t.ticket.as_str()),
        relay.dp_id.as_deref(),
        opts,
    )
    .await?;
    let lease = ConnectionLease::spawn(
        proxy.clone(),
        &connection,
        handle.shutdown_token(),
        ended.clone(),
    );
    // Timed off the lease the ticket just wrote, so the first renewal lands
    // where every one after it does. The same two tokens `ConnectionLease`
    // takes, and they part company here: a leg the proxy has simply
    // forgotten winds the relay down, while a leg it *refuses* to re-ticket
    // is this Endpoint being told it may not hold the connection at all,
    // which is what `ended` means to the application.
    let relay_lease = RelayLegLease::spawn(
        proxy.clone(),
        // **From the leg itself**, so the renewal cannot address a
        // different host than the one it is renewing on.
        handle.relay_origin(),
        connection.connection_id.clone(),
        ticket.as_ref(),
        handle.shutdown_token(),
        ended.clone(),
    );
    Ok(Attachment {
        connection,
        relay: handle,
        lease,
        relay_lease,
    })
}

/// Take an attachment down and tell the proxy its connection is over.
///
/// **The order is the whole of it, and the ask goes first.** Reporting
/// `closed` is what frees the connection's relay resources, so a prompt proxy
/// tears the CONNECT-UDP session down while that call is still in flight —
/// and with the ask unspoken the supervisor would read the leg's own end as a
/// loss and go stand another one up on the way out. Then the leases, because
/// `closed` is terminal and a renewal arriving behind it is refused and logged
/// as a failure that is really just bad timing.
///
/// **This is also what closes the loopback socket** the application was told
/// to send to. Every caller reads that port once, at setup, so it is only ever
/// right to do this when the leg is finished with: after a replacement has
/// taken over, or on the way out. It is why nothing here runs while a
/// replacement is still being looked for.
///
/// **The report is worth making even for a leg that is already dead.** The
/// listener finds out who is waiting for it by listing its connections in
/// state `relay`, and a connection nobody reports stays in that listing until
/// the proxy expires it — so the peer that just lost its leg goes on occupying
/// the listener's for minutes, including against the replacement this is
/// making room for.
async fn retire(
    attachment: Attachment,
    proxy: &ProxyClient<MasqueH3Transport>,
    ended: &CancellationToken,
) {
    let Attachment {
        connection,
        relay,
        lease,
        relay_lease,
    } = attachment;
    relay.shutdown_token().cancel();
    lease.stop();
    relay_lease.stop();
    if ended.is_cancelled() {
        // Revoked. `report_state` goes through the same auth layer that
        // just refused the renewal, so it can only be refused too — and
        // waiting out `REPORT_CLOSED_TIMEOUT` to be told so would end a
        // revocation with a warning about the listener's leg staying
        // reserved, which is neither true nor the point.
        relay.close().await;
        return;
    }
    let reported = tokio::time::timeout(
        REPORT_CLOSED_TIMEOUT,
        proxy.report_state(&connection.connection_id, "closed", &[]),
    )
    .await;
    match reported {
        Ok(Ok(_)) => tracing::debug!(
            connection_id = %connection.connection_id,
            "reported the peer connection closed"
        ),
        Ok(Err(e)) => tracing::warn!(
            connection_id = %connection.connection_id,
            "could not report the peer connection closed; the listener's leg \
             stays reserved until the proxy expires it: {e}"
        ),
        Err(_) => tracing::warn!(
            connection_id = %connection.connection_id,
            "timed out reporting the peer connection closed; the listener's leg \
             stays reserved until the proxy expires it"
        ),
    }
    relay.close().await;
}

/// Own the session's attachment: replace it when its leg goes, and retire it
/// when the session ends (`docs/relay_repath_plan.md` P3).
///
/// **The replacement is a new connection, not a revived one.** A listener puts
/// a connection whose leg died into `spent` and never binds it again, on
/// purpose — the same id coming back would mean reviving something it watched
/// die, and the listener has no way to tell that from a stale row. So this
/// asks for a new `connection_id`, which the listener picks up through the
/// path it already has (plan §0.2 A).
async fn supervise(
    first: Attachment,
    inputs: Reattach,
    proxy: ProxyClient<MasqueH3Transport>,
    published: Published,
    ended: CancellationToken,
    shutdown: CancellationToken,
    reported: oneshot::Sender<()>,
) {
    let mut current = Some(first);
    let mut stood_up = Instant::now();
    while let Some(attachment) = current.take() {
        if let LegOutcome::WoundDown = watch_leg(attachment.relay.ended(), shutdown.clone()).await {
            current = Some(attachment);
            break;
        }
        // **Said first, before any reason to stop is considered.** The leg is
        // dead by the time `watch_leg` answers `Gone`, and every branch below
        // either takes minutes or does not come back at all — so "the fallback
        // has gone" is reported here rather than on the way to somewhere.
        // `portal_core::path` reads this to stop offering the relay as
        // somewhere to retreat to.
        //
        // **This used to come after the revocation check**, which is the one
        // branch that leaves the peer connection running: it may still be on a
        // direct path, and it would have been left believing a dead relay was
        // there to fall back to.
        published.leg_is_gone();
        if ended.is_cancelled() {
            // **The Endpoint was refused, not the relay.** What cancelled the
            // leg is the lease that was told so, and it has already said it at
            // `error`; the leg stopping is the consequence, not the event.
            // Nothing this process asks for next would be let in either, so
            // there is no replacement to make and no second warning to add.
            current = Some(attachment);
            break;
        }
        let was = attachment.connection.connection_id.clone();
        let relay_origin = attachment.relay.relay_origin().to_owned();
        let age = stood_up.elapsed();
        if let Some(why) = inputs.refusal() {
            tracing::warn!(
                connection_id = %was,
                relay = %relay_origin,
                "the relay leg has gone and this session cannot replace it: {why}. A \
                 connection still on the relay will stop; one that migrated to a direct \
                 path keeps working with no fallback left, and will end if that path does",
            );
            // **Not retired.** The peer connection may be running perfectly
            // well on a direct path, and reporting it closed would say
            // otherwise to everyone who can see it.
            shutdown.cancelled().await;
            current = Some(attachment);
            break;
        }
        tracing::warn!(
            connection_id = %was,
            relay = %relay_origin,
            ?age,
            "the relay leg has gone; making a new connection to stand one in its place",
        );
        // **The old attachment is kept until a new one is up, not retired to
        // make room for it.** Its leg is dead and carries nothing, but it is
        // what holds the connection row, and two things hang off that row.
        // Its lease is the only thing in this process that can be *told* this
        // Endpoint has been revoked — `ended` is cancelled from a refused
        // renewal and from nowhere else — and the row itself is how the
        // control plane and the peer can still see a session that is running
        // on a direct path. Retiring first would buy back one connection
        // against whatever an Endpoint may hold at once, and would cost both
        // of those for as long as the relay stayed down: if it never came
        // back, for the rest of the session.
        let Some(replacement) = stand_up_again(&inputs, &proxy, &ended, &shutdown, age).await
        else {
            // Nothing replaced it, or the session is being closed. Either way
            // this is where P1 left things: running on whatever path it has,
            // still claiming its connection, until somebody closes it.
            shutdown.cancelled().await;
            current = Some(attachment);
            break;
        };
        // **Now**, with somewhere for the listener to go. Reporting `closed`
        // is what frees the old row, and the listener — which retired the dead
        // leg on its own and will not bind that connection again — finds the
        // new one in the same listing it was already polling (plan §0.2 A).
        retire(attachment, &proxy, &ended).await;
        tracing::info!(
            was = %was,
            connection_id = %replacement.connection.connection_id,
            relay = %replacement.relay.relay_origin(),
            local = %replacement.relay.local_addr,
            "a new relay leg is up. Nothing has moved onto it yet: the peer connection \
             goes on using the path it has (`docs/relay_repath_plan.md` P4)",
        );
        published.now_at(&replacement);
        stood_up = Instant::now();
        current = Some(replacement);
    }
    if let Some(attachment) = current {
        retire(attachment, &proxy, &ended).await;
    }
    // Whether there was anything left to retire or not: what `close` waits for
    // is that nothing more is going to happen to this session's attachment.
    let _ = reported.send(());
}

/// Try to put a new attachment where the old one was, backing off between
/// attempts, until one stands up or this session gives up on having a
/// fallback.
async fn stand_up_again(
    inputs: &Reattach,
    proxy: &ProxyClient<MasqueH3Transport>,
    ended: &CancellationToken,
    shutdown: &CancellationToken,
    age: Duration,
) -> Option<Attachment> {
    // **Held rather than raised at each attempt.** A relay that is restarting
    // refuses in several different ways on the way back up, and reporting each
    // one at `warn` would be a paragraph about a thing that then worked. What
    // is worth saying at `error` is the last one, once, if none of them worked.
    let mut last: Option<anyhow::Error> = None;
    let started = Instant::now();
    for attempt in 0..REATTACH_ATTEMPTS {
        tokio::select! {
            _ = shutdown.cancelled() => return None,
            _ = ended.cancelled() => {
                // The Endpoint is refused, not the relay. A new connection id
                // would be refused as well, and saying so belongs to whoever
                // cancelled this — the lease that was told so, which is still
                // running because the old attachment is still here.
                return None;
            }
            // **`age` plus what this loop has spent**, which together are the
            // time since the leg stood up. Passing `age` alone would charge
            // the `PATH_ABANDON` floor again at every attempt, and the backoff
            // would not climb past it until the fourth.
            _ = tokio::time::sleep(reattach_delay(attempt, age + started.elapsed())) => {}
        }
        // **The attempt is abandoned if the session is, and not awaited.**
        // `attach` makes two network calls to a proxy that has just been
        // failing, and `close` waits for this task; without the arm below, a
        // Ctrl+C landing here waits out whatever those calls do before the
        // process can exit.
        //
        // Dropping it mid-flight is safe as far as the leg goes:
        // `open_connect_relay` arms a drop guard on the token its spawned task
        // parks on, so a leg established while this future was being cancelled
        // is cancelled with it. What is left behind is a connection row, which
        // the proxy expires on its own — the same thing it does for a process
        // that was killed.
        let made = tokio::select! {
            _ = shutdown.cancelled() => return None,
            made = attach(
                &inputs.cfg,
                proxy,
                // A capability was spent on the first one; `Reattach::refusal`
                // has already turned such a session away, so what is left here
                // is a Grant.
                Authorization::Grant,
                &inputs.listener_id,
                &inputs.candidates,
                inputs.local_bind,
                inputs.opts.clone(),
                ended,
            ) => made,
        };
        match made {
            Ok(attachment) => return Some(attachment),
            Err(e) => {
                tracing::debug!(
                    attempt = attempt + 1,
                    of = REATTACH_ATTEMPTS,
                    "could not stand a new relay leg up: {e:#}",
                );
                last = Some(e);
            }
        }
    }
    // **At `error`, because this is the state the plan wants counted**
    // (`docs/relay_repath_plan.md` §3.3): a session that goes on working while
    // standing on one leg. Nothing retries after this — the relay had two
    // minutes to come back and did not, and a loop that asks forever is a loop
    // whose log nobody reads.
    tracing::error!(
        attempts = REATTACH_ATTEMPTS,
        listener_id = %inputs.listener_id,
        "gave up replacing the relay leg; this session has no fallback left. It keeps \
         working, and claiming its connection, for as long as its direct path does, \
         and ends with it{}",
        last.map(|e| format!(": {e:#}")).unwrap_or_default(),
    );
    None
}

/// How a relay leg stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegOutcome {
    /// Somebody asked it to. The ordinary close.
    WoundDown,
    /// It stopped on its own. **This is the one worth a word.**
    Gone,
}

/// Wait for a leg to stop, and say which kind of stopping it was.
///
/// **A teardown cancels both tokens**, often in the same breath, so `select!`
/// alone would report a failure on every ordinary close -- whichever arm the
/// scheduler happened to poll first. The re-check is what makes the answer
/// depend on what happened rather than on which branch won.
async fn watch_leg(ended: CancellationToken, shutdown: CancellationToken) -> LegOutcome {
    tokio::select! {
        _ = shutdown.cancelled() => LegOutcome::WoundDown,
        _ = ended.cancelled() => match shutdown.is_cancelled() {
            true => LegOutcome::WoundDown,
            false => LegOutcome::Gone,
        },
    }
}

#[cfg(test)]
mod reattach_tests {
    use super::*;

    /// The shape the backoff is supposed to have: doubling from the first
    /// delay, and then flat. Read off a leg old enough that the floor has
    /// nothing to say, so what is being checked is the backoff alone.
    #[test]
    fn the_backoff_doubles_and_then_stops() {
        let old = Duration::from_secs(3600);
        let delays: Vec<u64> = (0..REATTACH_ATTEMPTS)
            .map(|n| reattach_delay(n, old).as_secs())
            .collect();
        assert_eq!(delays, vec![1, 2, 4, 8, 16, 30, 30, 30]);
        // The point of the ceiling: a session that has been trying for a while
        // is not trying any harder than one that just started.
        assert_eq!(
            reattach_delay(u32::MAX, old),
            REATTACH_MAX_DELAY,
            "nothing overflows its way past the ceiling",
        );
    }

    /// **The floor is about `PATH_ABANDON`, not about politeness**
    /// (`docs/relay_repath_plan.md` §0.3). A relay that comes up and falls over
    /// again immediately must not cost a `peer_connect` each time it does --
    /// under multipath the paths it leaves behind have not retired yet, and
    /// four is all there are.
    #[test]
    fn a_leg_that_flapped_waits_out_the_floor() {
        let flapped = Duration::from_millis(200);
        assert_eq!(
            reattach_delay(0, flapped),
            REATTACH_MIN_INTERVAL - flapped,
            "the first attempt waits for what is left of the interval, not the backoff",
        );
    }

    /// **And it is charged once.** The floor keeps two *stand-ups* apart, and
    /// by the second attempt the waiting has already done that — so what the
    /// backoff asks for from there on is the backoff.
    #[test]
    fn the_floor_is_not_charged_again_at_every_attempt() {
        let mut since = Duration::from_millis(200);
        let mut delays = Vec::new();
        for attempt in 0..4 {
            let delay = reattach_delay(attempt, since);
            since += delay;
            delays.push(delay.as_secs_f64());
        }
        assert_eq!(
            delays,
            vec![4.8, 2.0, 4.0, 8.0],
            "the first waits out what is left of the interval; the rest are the backoff",
        );
    }

    /// And the floor stays off the case this feature exists for. A leg that
    /// has carried a session for an hour has long since paid the interval, so
    /// its replacement starts on the first backoff delay.
    #[test]
    fn a_leg_that_lasted_does_not_wait_for_it() {
        assert_eq!(
            reattach_delay(0, REATTACH_MIN_INTERVAL),
            REATTACH_FIRST_DELAY,
            "an interval already elapsed asks for nothing more",
        );
        assert!(
            REATTACH_FIRST_DELAY < REATTACH_MIN_INTERVAL,
            "or this proves nothing"
        );
    }

    /// A standing grant is what makes a leg replaceable: the proxy still holds
    /// it, so it can authorize the next `connect` as it did the first.
    #[test]
    fn a_grant_on_a_shareable_leg_can_be_used_again() {
        assert_eq!(refusal(OwnedAuthorization::Grant, true), None);
    }

    /// **A capability authorizes one connect** (spec §8.4). Trying anyway
    /// would spend the backoff on a refusal that reads like a permissions
    /// problem, which is the wrong thing for an operator to go and check.
    #[test]
    fn a_spent_capability_cannot_stand_another_leg_up() {
        let why = refusal(OwnedAuthorization::SpentCapability, true)
            .expect("a capability is spent by the connect it authorized");
        assert!(
            why.contains("grant"),
            "and it says what to do instead: {why}"
        );
    }

    /// **§3.5 of the plan, answered by saying no.** Without a shared
    /// unconnected binding there is no multipath, so a replacement leg is a
    /// leg nothing could ever be moved onto -- and standing one up would look
    /// like a recovery while changing nothing.
    #[test]
    fn a_connected_leg_has_nowhere_to_put_a_replacement() {
        assert!(refusal(OwnedAuthorization::Grant, false).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SERVER_NOW: i64 = 1_800_000_000;

    /// A leg that stops because nobody is using the session any more is the
    /// ordinary close, and warning about it would put a warning on every exit
    /// -- which is how a warning stops being read.
    #[tokio::test]
    async fn winding_the_session_down_is_not_a_lost_leg() {
        let ended = CancellationToken::new();
        let shutdown = CancellationToken::new();
        shutdown.cancel();
        assert_eq!(watch_leg(ended, shutdown).await, LegOutcome::WoundDown,);
    }

    /// The case this exists for: the leg stopped and nobody asked it to.
    #[tokio::test]
    async fn a_leg_that_stops_on_its_own_is_reported() {
        let ended = CancellationToken::new();
        let shutdown = CancellationToken::new();
        ended.cancel();
        assert_eq!(watch_leg(ended, shutdown).await, LegOutcome::Gone);
    }

    /// **Both at once is the teardown**, because cancelling a session cancels
    /// the leg too. Reading it as a loss would depend on which arm `select!`
    /// polled first -- a warning that appears on some ordinary closes and not
    /// others, which is worse than one that never appears.
    #[tokio::test]
    async fn a_teardown_that_cancels_both_is_still_a_teardown() {
        for _ in 0..50 {
            let ended = CancellationToken::new();
            let shutdown = CancellationToken::new();
            ended.cancel();
            shutdown.cancel();
            assert_eq!(
                watch_leg(ended, shutdown).await,
                LegOutcome::WoundDown,
                "whichever branch won",
            );
        }
    }

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
