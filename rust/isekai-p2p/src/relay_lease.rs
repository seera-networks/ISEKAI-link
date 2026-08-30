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

use isekai_p2p_core::proxy::{ProxyClient, ProxyError, RelayTicket};
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
/// Never renew more often than this, whatever a lease works out to.
///
/// A lease shorter than the round trip must not turn into a spin against the
/// control plane.
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
/// How long to wait after an attempt that might still work.
///
/// **Not the renewal interval.** Renewing at half the lease is only survivable
/// if the second half holds *several* attempts; re-sleeping the interval would
/// put the one retry at the exact moment the lease runs out, which is the one
/// moment it cannot help. The lease's own deadline is what stops this from
/// running on after there is nothing left to renew.
const RETRY_IN: Duration = Duration::from_secs(30);

/// How long the lease runs, measured **without consulting the local clock**.
///
/// A ticket carries two proxy timestamps minted in the same breath — when the
/// ticket stops being presentable, and when the leg it buys lapses — so their
/// difference is the lease minus the ticket's TTL. Both sides of the
/// subtraction come from the proxy, so a clock that disagrees with it cancels
/// out; what is left is a slight *under*estimate of the lease, which errs
/// towards renewing early.
///
/// The alternative — `lease_expires_at` against the local clock — fails badly
/// rather than gracefully: a clock ahead by more than the lease reads every
/// lease as already gone and settles into a request every [`RENEW_MIN`],
/// forever. `initiator::renew_delay` measures from a server `updated_at` for
/// exactly this reason; this is the same move with the pair a ticket has.
fn lease_span(ticket: &RelayTicket) -> Option<Duration> {
    let parse = |s: &str| OffsetDateTime::parse(s, &Rfc3339).ok();
    let span = parse(&ticket.lease_expires_at)? - parse(&ticket.expires_at)?;
    span.is_positive()
        .then(|| Duration::from_secs_f64(span.as_seconds_f64()))
}

/// When to renew a leg whose lease runs for `span`.
fn renew_delay(span: Option<Duration>) -> Duration {
    let Some(span) = span else {
        return RENEW_UNKNOWN;
    };
    Duration::from_secs_f64(span.as_secs_f64() * LEASE_RENEW_FRACTION).clamp(RENEW_MIN, RENEW_MAX)
}

/// What a failed renewal means for the loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Verdict {
    /// Might work next time. The lease outlives several of these.
    Retry,
    /// **Permission is gone**, not just the leg: the connection was closed, the
    /// grant withdrawn, this Endpoint revoked. Nothing this process does with
    /// the connection is allowed any more, so the session ends with the leg.
    Refused,
    /// **The leg is gone, and only the leg.** The proxy has no edge for this
    /// session — it restarted, or the other party's lease lapsed and took the
    /// edge with it (the proxy cuts an edge at the shorter of the two). The
    /// connection itself may be perfectly alive and running over a direct path,
    /// so this stops the relay and says nothing about the session.
    LegGone,
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
pub(crate) fn verdict(error: &ProxyError) -> Verdict {
    let ProxyError::Problem {
        status, problem, ..
    } = error
    else {
        // A transport failure says nothing about the lease.
        return Verdict::Retry;
    };
    match problem.as_ref().map(|p| p.kind()) {
        // The authorization is gone, and §8.14.2 re-checks it on every ticket —
        // which is the point of re-ticketing.
        Some("connection-closed" | "grant-invalid" | "endpoint-revoked") => Verdict::Refused,
        // **Not the same answer**, though it arrives on the same route. The
        // proxy sends this for a connection that is over *and* for one whose
        // relay edge it no longer holds, and it cannot tell the two apart for
        // us — `/ticket` looks the edge up in memory, so a proxy restart
        // answers this about a connection that is still listed. Ending the
        // application's session on it would let a data-plane fact take down a
        // session that had already migrated to a direct path. The connection
        // row has its own lease, renewed by its own loop; that is what is
        // entitled to decide the connection is over.
        Some("connection-not-found") => Verdict::LegGone,
        // No problem body on a 404: there is no such route here.
        None if *status == 404 => Verdict::NotLeased,
        // `token-expired` and `insufficient-permission` included: both are
        // about the Endpoint Token, which the renewal task replaces every few
        // minutes, so the next attempt carries a new one.
        _ => Verdict::Retry,
    }
}

/// Whether the lease this loop is carrying has already run out.
///
/// `None` — a leg opened without a ticket, so its length was never known — is
/// not lapsed: there is nothing to compare against, and giving up on a leg the
/// proxy may well still be holding would be worse than asking again.
fn lapsed(lapses_at: Option<tokio::time::Instant>) -> bool {
    lapses_at.is_some_and(|at| tokio::time::Instant::now() >= at)
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
    /// `first` is the ticket that opened the leg, so the first renewal is timed
    /// off the real lease exactly like every one after it. `None` when the leg
    /// was opened without one — see [`RENEW_UNKNOWN`].
    ///
    /// **Two tokens, for two different facts** — the same pair
    /// `initiator::ConnectionLease` takes, and for the same reason. `leg` says
    /// the relay is finished, whatever else is true; `ended` says this process
    /// is no longer allowed to hold the connection at all. A leg that lapsed
    /// because the proxy forgot it cancels only the first: the peers may be on
    /// a direct path, where the relay was never going to be used again anyway.
    /// A leg refused because the grant was withdrawn cancels both.
    pub fn spawn(
        proxy: ProxyClient<MasqueH3Transport>,
        connection_id: String,
        first: Option<&RelayTicket>,
        leg: CancellationToken,
        ended: CancellationToken,
    ) -> Self {
        let mut span = first.and_then(lease_span);
        let mut delay = renew_delay(span);
        Self(tokio::spawn(async move {
            // Monotonic, so this is the one deadline a disagreeing wall clock
            // cannot move. It is what keeps `RETRY_IN` from running on against
            // an unreachable proxy long after there is nothing left to renew.
            let mut lapses_at = span.map(|s| tokio::time::Instant::now() + s);
            loop {
                tokio::time::sleep(delay).await;

                // Two calls, and the first is the one that can refuse. Asking
                // for a ticket is asking to be authorized again; spending it is
                // only bookkeeping.
                let ticket = match proxy.issue_relay_ticket(&connection_id).await {
                    Ok(ticket) => ticket,
                    Err(e) => match verdict(&e) {
                        Verdict::Refused => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "this endpoint may no longer hold this connection: {e}",
                            );
                            leg.cancel();
                            ended.cancel();
                            return;
                        }
                        Verdict::LegGone => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "the proxy has no relay edge for this session; \
                                 winding the leg down: {e}",
                            );
                            leg.cancel();
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
                            if lapsed(lapses_at) {
                                tracing::warn!(
                                    connection_id = %connection_id,
                                    "gave up renewing a relay leg that has lapsed: {e}",
                                );
                                leg.cancel();
                                return;
                            }
                            tracing::warn!(
                                connection_id = %connection_id,
                                retry_in = ?RETRY_IN,
                                "could not get a relay ticket: {e}",
                            );
                            delay = RETRY_IN;
                            continue;
                        }
                    },
                };

                match proxy
                    .renew_relay_lease(&connection_id, &ticket.ticket)
                    .await
                {
                    Ok(lease) => {
                        // From the ticket just spent, not from the response:
                        // the pair is what makes this immune to a clock that
                        // disagrees with the proxy's (`lease_span`).
                        span = lease_span(&ticket).or(span);
                        lapses_at = span.map(|s| tokio::time::Instant::now() + s);
                        delay = renew_delay(span);
                        tracing::trace!(
                            connection_id = %connection_id,
                            role = ?lease.role,
                            next = ?delay,
                            "renewed the relay leg's lease",
                        );
                    }
                    Err(e) => match verdict(&e) {
                        Verdict::Refused => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "this endpoint may no longer hold this connection: {e}",
                            );
                            leg.cancel();
                            ended.cancel();
                            return;
                        }
                        // The proxy has no edge for this session. Nothing this
                        // task does brings it back — but the connection may
                        // still be running over a direct path, so this is the
                        // relay's end and not the session's.
                        Verdict::LegGone => {
                            tracing::info!(
                                connection_id = %connection_id,
                                "the relay leg is no longer there to renew: {e}",
                            );
                            leg.cancel();
                            return;
                        }
                        Verdict::NotLeased => return,
                        Verdict::Retry => {
                            if lapsed(lapses_at) {
                                tracing::warn!(
                                    connection_id = %connection_id,
                                    "gave up renewing a relay leg that has lapsed: {e}",
                                );
                                leg.cancel();
                                return;
                            }
                            // The ticket is spent either way — they are
                            // single-use — so the next pass fetches another.
                            tracing::warn!(
                                connection_id = %connection_id,
                                retry_in = ?RETRY_IN,
                                "could not renew the relay leg's lease: {e}",
                            );
                            delay = RETRY_IN;
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
    use isekai_p2p_core::proxy::{Problem, RelayRole};

    /// A ticket as the proxy mints it: `expires_at` a ticket TTL out,
    /// `lease_expires_at` a lease out, both on **its** clock. `skew` moves both
    /// together, which is what a clock that disagrees actually looks like.
    fn ticket(ttl_secs: i64, lease_secs: i64, skew: i64) -> RelayTicket {
        // One instant for both, as the proxy mints them — reading the clock
        // twice would put the microseconds between the reads into the span.
        let minted = OffsetDateTime::now_utc() + time::Duration::seconds(skew);
        let stamp = |secs: i64| {
            (minted + time::Duration::seconds(secs))
                .format(&Rfc3339)
                .unwrap()
        };
        RelayTicket {
            ticket: "eyJ.JWT.sig".to_owned(),
            role: RelayRole::Initiator,
            expires_at: stamp(ttl_secs),
            lease_expires_at: stamp(lease_secs),
        }
    }

    #[test]
    fn renewal_lands_at_half_the_lease() {
        // The proxy's defaults: a 45 s ticket on a twenty-minute lease, so ten
        // minutes less the ticket's own TTL — an underestimate, erring early.
        let span = lease_span(&ticket(45, 1_200, 0)).unwrap();
        assert_eq!(span, Duration::from_secs(1_155));
        assert_eq!(renew_delay(Some(span)), Duration::from_secs_f64(577.5));
    }

    /// **The failure this measurement exists to avoid.** Reading
    /// `lease_expires_at` against the local clock, a machine an hour fast sees
    /// every lease as already gone and renews at the floor forever. Both
    /// timestamps come from the proxy, so the skew cancels.
    #[test]
    fn a_clock_that_disagrees_does_not_change_the_lease() {
        let straight = lease_span(&ticket(45, 1_200, 0)).unwrap();
        for skew in [-3_600, -60, 60, 3_600, 86_400] {
            assert_eq!(
                lease_span(&ticket(45, 1_200, skew)).unwrap(),
                straight,
                "skew {skew}",
            );
        }
    }

    #[test]
    fn an_unreadable_or_backwards_lease_does_not_spin() {
        // No ticket at all: the fallback, not the floor.
        assert_eq!(renew_delay(None), RENEW_UNKNOWN);
        // Unparseable, or a lease that does not outlast the ticket: nothing to
        // measure, so the same fallback.
        let mut bad = ticket(45, 1_200, 0);
        bad.expires_at = "not a timestamp".to_owned();
        assert_eq!(lease_span(&bad), None);
        assert_eq!(lease_span(&ticket(1_200, 45, 0)), None);
        // A short lease is floored, a very long one still renewed rather than
        // trusted to the end.
        assert_eq!(renew_delay(Some(Duration::from_secs(10))), RENEW_MIN);
        assert_eq!(renew_delay(Some(Duration::from_secs(86_400))), RENEW_MAX);
    }

    /// A retry has to fit **inside** what is left of the lease. Re-sleeping the
    /// renewal interval put the one retry at the exact moment the lease ran
    /// out, which is the one moment it cannot help.
    #[test]
    fn a_retry_leaves_room_for_more_than_one() {
        let span = lease_span(&ticket(45, 1_200, 0)).unwrap();
        let remaining = span - renew_delay(Some(span));
        assert!(
            RETRY_IN * 4 < remaining,
            "a retry every {RETRY_IN:?} must fit several times into {remaining:?}",
        );
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
    fn a_bare_404_is_an_old_proxy_and_a_typed_one_is_a_lost_leg() {
        assert_eq!(verdict(&problem(404, None)), Verdict::NotLeased);
        assert_eq!(
            verdict(&problem(404, Some("connection-not-found"))),
            Verdict::LegGone,
        );
    }

    /// **A forgotten leg is not a finished session.** The proxy answers
    /// `connection-not-found` from `/ticket` when its in-memory edge is gone —
    /// a restart, or the other party's lease lapsing and cutting the edge — and
    /// the connection may be running over a direct path where the relay was
    /// never going to be used again. Only the answers that say *this Endpoint
    /// is not allowed* may end the session.
    #[test]
    fn only_a_refusal_ends_the_session() {
        assert_eq!(
            verdict(&problem(404, Some("connection-not-found"))),
            Verdict::LegGone,
        );
        for kind in ["grant-invalid", "endpoint-revoked", "connection-closed"] {
            assert_eq!(
                verdict(&problem(403, Some(kind))),
                Verdict::Refused,
                "{kind}"
            );
        }
    }

    /// Re-ticketing is re-authorization, so the answers that mean "not any
    /// more" end the loop rather than being retried for the life of the
    /// process.
    #[test]
    fn losing_the_authorization_ends_the_loop() {
        for kind in ["grant-invalid", "endpoint-revoked", "connection-closed"] {
            assert_eq!(
                verdict(&problem(403, Some(kind))),
                Verdict::Refused,
                "{kind}"
            );
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
