//! Keeping a relay leg alive (proxy spec §8.14).
//!
//! A relay leg used to live as long as somebody kept reporting on the
//! connection: the proxy pushed the edge's expiry out on every state report, so
//! the leg's lifetime was, in effect, unbounded. It is not any more. A leg now
//! lives to the horizon written by the **relay ticket** that brought it into
//! existence, and extending it means going back to the control plane for a new
//! ticket — which is a fresh authorization decision, not a renewal of an old
//! one. A grant that its owner revoked stops the next ticket, and the leg goes
//! down at its lease instead of outliving the permission it was opened under.
//!
//! So both sides run this: a task that, at half the lease, asks for a ticket and
//! spends it on `/renew`. It is the same loop for the initiator and the target
//! — the only thing that differs is which leg the proxy decides the caller is
//! asking about, and it decides that from the authenticated Endpoint ID.
//!
//! # What it is not
//!
//! **Not [`ConnectionLease`](crate::initiator) and not
//! [`renew_connections`](crate::listener::ListenerSession::renew_connections).**
//! Those carry the connection *row* — the control plane's record that this
//! connection exists — by reporting state (§8.5.4). This carries the *leg*.
//! Since §8.14 the two are separate facts with separate deadlines: a row can
//! outlive its legs, and a leg can lapse while the row still says the peers are
//! talking. Renewing one does nothing for the other.
//!
//! # Talking to a proxy that predates §8.14
//!
//! Such a proxy has no `/ticket` route, so the first attempt comes back `404`
//! with no problem body — a plain "no such route" rather than the
//! `connection-not-found` a §8.14 proxy would send for a connection that is
//! gone. That is the signal to stop: there is no lease to carry, because that
//! proxy does not lease legs. Everything keeps working exactly as it did.

use std::time::Duration;

use isekai_p2p_core::proxy::{ProxyClient, ProxyError};
use isekai_p2p_core::transport::MasqueH3Transport;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

/// Renew at half of what is left of the lease.
///
/// Half, rather than nearer the end, because a failed renewal has to be
/// survivable: at 50% there is a whole second half in which to retry, and a
/// proxy that is briefly unreachable costs nothing. The proxy's own default
/// lease is twenty minutes, so this is a request every ten.
const LEASE_RENEW_FRACTION: f64 = 0.5;
/// Never renew more often than this, whatever a deadline works out to.
///
/// A lease that is already gone, or a clock that disagrees, must not turn into
/// a spin against the control plane.
const RENEW_MIN: Duration = Duration::from_secs(30);
/// Nor less often. Well under the proxy's default lease, so an unusually long
/// one is still renewed rather than trusted to the end.
const RENEW_MAX: Duration = Duration::from_secs(600);
/// What to wait when the lease's length is not known.
///
/// Only reached when the leg was opened without a ticket — an old proxy (where
/// this loop then stops on the first `404`), or a §8.14 proxy that could not
/// sign one (where the leg holds a single lease that this will take over). Short
/// enough to beat the shortest lease an operator would plausibly configure.
const RENEW_UNKNOWN: Duration = Duration::from_secs(120);

/// When to renew, given the deadline the proxy just wrote on this leg.
///
/// Measured against the local clock, unlike the connection row's lease
/// (`initiator::renew_delay`), because a ticket carries no "as of" timestamp to
/// measure from. The consequence of a skewed clock here is bounded by
/// [`RENEW_MIN`] and costs at worst a few extra renewals.
fn renew_delay(lease_expires_at: Option<&str>, now: OffsetDateTime) -> Duration {
    let Some(deadline) = lease_expires_at.and_then(|s| OffsetDateTime::parse(s, &Rfc3339).ok())
    else {
        return RENEW_UNKNOWN;
    };
    let remaining = deadline - now;
    if !remaining.is_positive() {
        return RENEW_MIN;
    }
    Duration::from_secs_f64(remaining.as_seconds_f64() * LEASE_RENEW_FRACTION)
        .clamp(RENEW_MIN, RENEW_MAX)
}

/// What a failed renewal means for the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// Might work next time. The lease outlives several of these.
    Retry,
    /// No later attempt succeeds. Stop asking, and the leg is finished — either
    /// because the connection is over or because this Endpoint is no longer
    /// allowed to hold it.
    Over,
    /// This proxy does not lease legs. Stop asking; nothing is wrong.
    NotLeased,
}

/// What a refusal means.
///
/// **The `404`s are not all the same**, and telling them apart is what keeps a
/// pre-§8.14 proxy from looking like a lost connection. A §8.14 proxy answers
/// `404 connection-not-found` — an RFC 9457 body with a type — for a connection
/// that is gone or a caller that is not a party. A proxy without the route
/// answers a bare `404` with nothing in it, because no handler ran.
fn verdict(error: &ProxyError) -> Verdict {
    let ProxyError::Problem {
        status, problem, ..
    } = error
    else {
        // A transport failure says nothing about the lease.
        return Verdict::Retry;
    };
    match problem.as_ref().map(|p| p.kind()) {
        // The connection has ended, this caller is no longer a party, or the
        // authorization it was made under is gone. §8.14.2 re-checks all three
        // on every ticket, which is the point of re-ticketing.
        Some(
            "connection-not-found" | "connection-closed" | "grant-invalid" | "endpoint-revoked",
        ) => Verdict::Over,
        // No problem body on a 404: there is no such route here.
        None if *status == 404 => Verdict::NotLeased,
        // `token-expired` and `insufficient-permission` included: both are
        // about the Endpoint Token, which the renewal task replaces every few
        // minutes, so the next attempt carries a new one.
        _ => Verdict::Retry,
    }
}

/// Holds one relay leg's lease open until dropped.
///
/// Dropping stops the claim, which is the point: a process that goes away stops
/// asserting its leg is in use, and the proxy reclaims it at the lease. Nothing
/// has to be reported for that to work, and nothing has to tell a crash from a
/// clean exit.
pub struct RelayLegLease(tokio::task::JoinHandle<()>);

impl RelayLegLease {
    /// Start renewing the leg `connection_id` names.
    ///
    /// `lease_expires_at` is what the ticket that opened the leg said, so the
    /// first renewal is timed off the real lease exactly like every one after
    /// it. `None` when the leg was opened without a ticket — see
    /// [`RENEW_UNKNOWN`].
    ///
    /// `lost` is cancelled when the leg can no longer be renewed **because
    /// permission for it is gone** — the connection ended, this Endpoint was
    /// revoked, the grant was withdrawn. It is deliberately *not* cancelled for
    /// a proxy that does not lease legs, which is not a loss of anything.
    pub fn spawn(
        proxy: ProxyClient<MasqueH3Transport>,
        connection_id: String,
        lease_expires_at: Option<String>,
        lost: CancellationToken,
    ) -> Self {
        let mut delay = renew_delay(lease_expires_at.as_deref(), OffsetDateTime::now_utc());
        Self(tokio::spawn(async move {
            loop {
                tokio::time::sleep(delay).await;

                // Two calls, and the first is the one that can refuse. Asking
                // for a ticket is asking to be authorized again; spending it is
                // only bookkeeping.
                let ticket = match proxy.issue_relay_ticket(&connection_id).await {
                    Ok(ticket) => ticket,
                    Err(e) => match verdict(&e) {
                        Verdict::Over => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "this relay leg will not be re-ticketed; letting it lapse: {e}",
                            );
                            lost.cancel();
                            return;
                        }
                        Verdict::NotLeased => {
                            tracing::debug!(
                                connection_id = %connection_id,
                                "this proxy does not lease relay legs; nothing to renew",
                            );
                            return;
                        }
                        Verdict::Retry => {
                            tracing::warn!(
                                connection_id = %connection_id,
                                retry_in = ?delay,
                                "could not get a relay ticket: {e}",
                            );
                            continue;
                        }
                    },
                };

                match proxy
                    .renew_relay_lease(&connection_id, &ticket.ticket)
                    .await
                {
                    Ok(lease) => {
                        delay =
                            renew_delay(Some(&lease.lease_expires_at), OffsetDateTime::now_utc());
                        tracing::trace!(
                            connection_id = %connection_id,
                            role = ?lease.role,
                            next = ?delay,
                            "renewed the relay leg's lease",
                        );
                    }
                    Err(e) => match verdict(&e) {
                        // The leg is gone from the proxy's side. Nothing this
                        // task does brings it back.
                        Verdict::Over => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "the relay leg is no longer there to renew: {e}",
                            );
                            lost.cancel();
                            return;
                        }
                        Verdict::NotLeased => return,
                        Verdict::Retry => {
                            // The ticket is spent either way — they are
                            // single-use — so the next pass fetches another.
                            tracing::warn!(
                                connection_id = %connection_id,
                                retry_in = ?delay,
                                "could not renew the relay leg's lease: {e}",
                            );
                        }
                    },
                }
            }
        }))
    }

    /// Stop claiming, without waiting for the drop.
    ///
    /// Used on the way out, before the connection is reported closed: a
    /// re-ticket racing behind that report would be refused with
    /// `connection-closed` and logged as a failure that is really just timing.
    pub fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for RelayLegLease {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use isekai_p2p_core::proxy::Problem;

    fn at(offset_secs: i64) -> String {
        (OffsetDateTime::now_utc() + time::Duration::seconds(offset_secs))
            .format(&Rfc3339)
            .unwrap()
    }

    #[test]
    fn renewal_lands_at_half_the_lease() {
        let now = OffsetDateTime::now_utc();
        // The proxy's default: twenty minutes, so ten.
        let deadline = (now + Duration::from_secs(1_200)).format(&Rfc3339).unwrap();
        assert_eq!(renew_delay(Some(&deadline), now), Duration::from_secs(600));
    }

    #[test]
    fn a_lapsed_or_unreadable_lease_does_not_spin() {
        let now = OffsetDateTime::now_utc();
        // Already gone: try at once, but no faster than the floor.
        assert_eq!(renew_delay(Some(&at(-60)), now), RENEW_MIN);
        // Unparseable, and no lease at all: the fallback, not the floor.
        assert_eq!(renew_delay(Some("not a timestamp"), now), RENEW_UNKNOWN);
        assert_eq!(renew_delay(None, now), RENEW_UNKNOWN);
        // A very long lease is still renewed rather than trusted to the end.
        assert_eq!(renew_delay(Some(&at(86_400)), now), RENEW_MAX);
    }

    fn problem(status: u16, kind: Option<&str>) -> ProxyError {
        ProxyError::Problem {
            status,
            problem: kind.map(|k| Problem {
                type_uri: format!("https://example.test/problems/{k}"),
                title: String::new(),
                status,
                detail: None,
            }),
            retry_after: None,
        }
    }

    /// **The distinction the whole migration rests on.** A proxy without the
    /// route answers a bare 404; one with it answers a typed
    /// `connection-not-found`. Reading them the same way would either make an
    /// old proxy look like a lost connection or make a lost connection look
    /// like an old proxy.
    #[test]
    fn a_bare_404_is_an_old_proxy_and_a_typed_one_is_a_lost_connection() {
        assert_eq!(verdict(&problem(404, None)), Verdict::NotLeased);
        assert_eq!(
            verdict(&problem(404, Some("connection-not-found"))),
            Verdict::Over,
        );
    }

    /// Re-ticketing is re-authorization, so the answers that mean "not any
    /// more" end the loop rather than being retried for the life of the
    /// process.
    #[test]
    fn losing_the_authorization_ends_the_loop() {
        for kind in ["grant-invalid", "endpoint-revoked", "connection-closed"] {
            assert_eq!(verdict(&problem(403, Some(kind))), Verdict::Over, "{kind}");
        }
    }

    /// Everything else is worth another go. A token that lapsed is replaced by
    /// the renewal task; a proxy that is briefly away comes back.
    #[test]
    fn everything_else_is_retried() {
        assert_eq!(
            verdict(&problem(401, Some("token-expired"))),
            Verdict::Retry
        );
        assert_eq!(
            verdict(&problem(403, Some("relay-ticket-invalid"))),
            Verdict::Retry,
        );
        assert_eq!(verdict(&problem(503, None)), Verdict::Retry);
        assert_eq!(
            verdict(&ProxyError::Transport(anyhow::anyhow!("no route to host"))),
            Verdict::Retry,
        );
    }
}
