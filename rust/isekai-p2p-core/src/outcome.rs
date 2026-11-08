//! What a call did not do, in terms of what the caller can do about it.
//!
//! Designed in `docs/p2p_sdk_error_type.md`.
//!
//! [`ProxyError`] and [`IdentityError`] say what the wire said: a status, a
//! problem kind, a detail, a `Retry-After`. That is the right thing for them to
//! carry, and this does not replace them — delete either and the material an
//! [`Outcome`]'s `explain` is built from goes with it.
//!
//! What this adds is the reading. Three existing classifiers
//! (`auth0::RefreshError`, `config::is_permanent`, `relay_lease::verdict`)
//! independently cut their arms by **what the caller can do** rather than by
//! what went wrong, and that is the axis here.
//!
//! **The reading is not a function of the answer alone.** Three kinds of
//! context decide it, which is why [`Outcome::of_proxy`] takes a [`Reading`]
//! rather than being a `From` impl — see [`Reading`] for each.

use std::time::Duration;

use crate::identity::IdentityError;
use crate::proxy::ProxyError;

/// Why a call did not do what was asked, and what the caller can do.
///
/// **The arms are cut by action.** Cutting them by failure kind would have the
/// type promise distinctions the protocol deliberately refuses: §8.8.4,
/// §8.12.4 and §8.13.6 each collapse unknown, expired, revoked and malformed
/// into one answer so that holding a credential tells an attacker nothing about
/// which, and a caller that branches on those has rebuilt the oracle the
/// uniformity exists to deny. Which one it was reaches the caller as a sentence
/// in `explain`, never as a value.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Outcome {
    /// What was to be removed was already not there. **Not a failure.**
    ///
    /// Readers have to `match` rather than `?`: this arm sits in the `Err`
    /// position because that is where the answer arrives, not because anything
    /// went wrong.
    #[error("already gone: {explain}")]
    AlreadyGone { explain: String },

    /// Authorization refused it, and asking again with this credential asks the
    /// same rule.
    #[error("refused: {explain}")]
    Refused { explain: String },

    /// A new credential is needed — sign in again, or get another token.
    #[error("needs new credentials: {explain}")]
    Reauthenticate { explain: String },

    /// The request did not stand up. **The state did not move**, so it can be
    /// fixed and sent again.
    ///
    /// This is where the kind branches the spec *does* sanction land — the
    /// exceptions `ProxyError::kind`'s own documentation names, which "say the
    /// request did not stand up rather than that it was refused" and leave a
    /// Ticket unspent.
    #[error("rejected: {explain}")]
    Rejected { explain: String },

    /// Capacity, availability, or a credential about to be replaced. Come back.
    ///
    /// `after` is what the server asked for when it asked for anything; a wait
    /// the caller computes instead is worse, since §8.8.6 puts the sweep
    /// interval into that number on purpose.
    #[error("busy: {explain}")]
    Busy {
        after: Option<Duration>,
        explain: String,
    },

    /// What was named is no longer there.
    ///
    /// **What to do about it is the caller's to know.** The proxy answers
    /// `404 connection-not-found` both for a connection that is over and for
    /// one whose relay edge it no longer holds, and `relay_lease::verdict` and
    /// `initiator::renewal_verdict` read that one answer as opposite things on
    /// purpose. This arm reports the fact and stops there.
    #[error("no longer there: {explain}")]
    Vanished { explain: String },

    /// No answer came back.
    #[error(transparent)]
    Unreachable(#[from] Unreachable),

    /// The answer could not be read. A disagreement between the two sides.
    #[error("malformed answer: {explain}")]
    Malformed { explain: String },
}

/// Why no answer came back.
///
/// Kept apart from a single opaque bucket because the two call for different
/// things: a deadline says the caller's own budget ran out, where a transport
/// failure says the network did.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Unreachable {
    /// A deadline the caller imposed elapsed.
    ///
    /// **Nothing produces this yet.** The control-plane transport has no
    /// request timeout of its own, and the callers that put one on top of it
    /// — `relay_rtt::measure_for_connect`, the FFI's `APP_PAIR_DEADLINE` and
    /// `APP_CONNECT_DEADLINE` — do not build an error today: the first logs and
    /// connects unmeasured, the others make their own type. The arm is here
    /// because the failure demonstrably happens, and a type that cannot say so
    /// forces the next caller to fold it into `Transport`, where it is
    /// indistinguishable from a dead network.
    #[error("no answer within {waited:?}")]
    Deadline { waited: Duration },

    /// Anything else: the name, the route, the handshake.
    ///
    /// **A sentence, not the error.** An `Outcome` is a reading of an answer,
    /// not a replacement for it — the caller still holds the [`ProxyError`] or
    /// [`IdentityError`] it was read from, and nothing in this workspace
    /// downcasts inside a transport failure. Keeping a message rather than an
    /// `anyhow::Error` is what lets this be read from a borrow, which is the
    /// shape every existing classifier needs, and what lets the whole type
    /// derive `PartialEq` for tests to compare against.
    #[error("transport: {explain}")]
    Transport { explain: String },
}

/// How this call site reads a `404` or a `409`.
///
/// There is no general answer. `list_relays` turns its `404` into `Ok(None)`
/// before any error exists — "a fact about the deployment and not an error" —
/// a bodiless `404` means the route is absent, `already_registered` reads `409`
/// as "proceed", and `is_already_gone` and `is_listener_not_found` read two
/// different `404`s two different ways.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Missing {
    /// Whatever was asked for has already happened.
    Done,
    /// What was named is gone, and the caller decides what that means.
    Vanished,
}

/// What this call site knows that the answer does not say.
///
/// Three things, each of which the design found a live counter-example for:
///
/// 1. `missing` — a `404`/`409` means different things on different routes.
/// 2. `token_self_replacing` — whether a `403` here is settled or stale.
/// 3. `retryable_kinds` — which sanctioned kind branches apply here.
///
/// No `Default`: a call site that has not decided these has not decided what
/// its failures mean, and a default would let it skip that silently.
#[derive(Debug, Clone, Copy)]
pub struct Reading {
    /// How to read a `404` or `409` (see [`Missing`]).
    pub missing: Missing,

    /// Whether the credential this call carries is replaced on a timer.
    ///
    /// **`403` is not permanent everywhere.** `is_permanent`'s own wording is
    /// that nothing it matches "turns on anything the caller can do *from
    /// here*", and "from here" is load-bearing: on the path that *obtains* a
    /// token a `403` is settled, but on one that renews a lease it may be a
    /// token minted before a permission existed. `initiator::renewal_verdict`
    /// spells out the cost of getting this wrong — treating it as terminal
    /// "would tear down every live session the day the proxy starts requiring
    /// a permission on this route".
    pub token_self_replacing: bool,

    /// Kinds this route may retry **as sent**, after `after`.
    ///
    /// **An allowlist, not a denylist**, because the two existing defaults
    /// point opposite ways and this one is the safe direction:
    /// `endpoint_cert`'s predicate retries `certificate-unavailable` alone
    /// precisely because `certificate-rate-limited` "clears in days, not
    /// seconds". Retrying an unknown kind risks hammering a days-long wait;
    /// not retrying one costs a failure returned early.
    pub retryable_kinds: &'static [&'static str],

    /// Kinds that mean the request did not stand up, so it can be **corrected**
    /// and sent again.
    ///
    /// The other half of the exceptions `ProxyError::kind`'s documentation
    /// sanctions, and the half a refusal must not swallow: `redeem_ticket`
    /// answers `403 protocol-not-allowed` for a protocol the ceiling does not
    /// hold and **leaves the Ticket unspent**. Read as
    /// [`Refused`](Outcome::Refused) a caller gives up and throws the Ticket
    /// away; read as [`Busy`](Outcome::Busy) it resends the same wrong protocol
    /// forever. Neither is what the answer said.
    ///
    /// Separate from `retryable_kinds` because the two prescribe different
    /// things — wait and resend, versus fix and resend — and a single list
    /// could only mean one of them.
    pub fixable_kinds: &'static [&'static str],
}

impl Outcome {
    /// Read a proxy answer through what this call site knows.
    pub fn of_proxy(error: &ProxyError, reading: &Reading) -> Self {
        let explain = error.to_string();
        match error {
            // **The whole chain, not just the outermost message.** `{0}` prints
            // one line of an `anyhow::Error`, and `HttpsTransport::send` wraps
            // every failure in the same `"HTTPS request failed"` — so a name
            // that would not resolve, a refused connection and a rejected
            // certificate all read identically without this.
            ProxyError::Transport(inner) => Outcome::Unreachable(Unreachable::Transport {
                explain: format!("{inner:#}"),
            }),
            ProxyError::Decode(_) => Outcome::Malformed { explain },
            ProxyError::Problem {
                status,
                retry_after,
                ..
            } => read(*status, error.kind(), *retry_after, explain, reading),
        }
    }

    /// Read an Identity answer through what this call site knows.
    ///
    /// **Identity has no `Decode` arm**, so a body it could not parse arrives
    /// as `Api` with a *success* status and no kind. That is read as
    /// [`Malformed`](Outcome::Malformed) rather than let through as a 2xx.
    pub fn of_identity(error: &IdentityError, reading: &Reading) -> Self {
        let explain = error.to_string();
        match error {
            // The chain, for the reason [`Self::of_proxy`] gives.
            IdentityError::Transport(inner) => Outcome::Unreachable(Unreachable::Transport {
                explain: format!("{inner:#}"),
            }),
            IdentityError::Time => Outcome::Malformed { explain },
            IdentityError::Api {
                status,
                retry_after,
                ..
            } => {
                if (200..300).contains(status) {
                    return Outcome::Malformed { explain };
                }
                let kind = error.kind();
                read(*status, kind.as_deref(), *retry_after, explain, reading)
            }
        }
    }
}

/// The shared reading, once both error types have been reduced to what the wire
/// said.
fn read(
    status: u16,
    kind: Option<&str>,
    retry_after: Option<Duration>,
    explain: String,
    reading: &Reading,
) -> Outcome {
    // **Before the status**, because a sanctioned kind is the call site saying
    // this particular answer does not mean what its status usually does.
    if kind.is_some_and(|kind| reading.retryable_kinds.contains(&kind)) {
        return Outcome::Busy {
            after: retry_after,
            explain,
        };
    }
    if kind.is_some_and(|kind| reading.fixable_kinds.contains(&kind)) {
        return Outcome::Rejected { explain };
    }
    // **Two kinds are settled whatever the status says**, and both are
    // exceptions `kind()`'s own documentation sanctions — cases of "recognising
    // a message whose cause is on *this* side" rather than of telling refusals
    // apart. The existing classifiers read them the same way:
    // `config::is_permanent` treats `pop-signature-invalid` as permanent
    // without looking at the status, and `renewal_verdict` ends the session on
    // `endpoint-revoked` without looking either.
    if kind == Some("pop-signature-invalid") || kind == Some("endpoint-revoked") {
        return Outcome::Refused { explain };
    }
    match status {
        // The route decides; there is no general reading.
        404 | 409 => match reading.missing {
            Missing::Done => Outcome::AlreadyGone { explain },
            Missing::Vanished => Outcome::Vanished { explain },
        },
        // A credential somebody else replaces on a timer is a wait, not an
        // answer — see [`Reading::token_self_replacing`].
        401 | 403 if reading.token_self_replacing => Outcome::Busy {
            after: retry_after,
            explain,
        },
        401 => Outcome::Reauthenticate { explain },
        403 => Outcome::Refused { explain },
        429 => Outcome::Busy {
            after: retry_after,
            explain,
        },
        // Capacity and availability are what the spec names as branchable, and
        // a 5xx is the server saying the fault is its own.
        500..=599 => Outcome::Busy {
            after: retry_after,
            explain,
        },
        // Everything else the request itself did not stand up: the state did
        // not move, so fixing and resending is the answer.
        _ => Outcome::Rejected { explain },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A call site that obtains its own credentials: a `403` here is settled.
    const ISSUING: Reading = Reading {
        missing: Missing::Vanished,
        token_self_replacing: false,
        retryable_kinds: &[],
        fixable_kinds: &[],
    };

    /// A call site whose token is replaced on a timer by somebody else.
    const RENEWING: Reading = Reading {
        missing: Missing::Vanished,
        token_self_replacing: true,
        retryable_kinds: &[],
        fixable_kinds: &[],
    };

    fn problem(status: u16, kind: Option<&str>) -> ProxyError {
        ProxyError::Problem {
            status,
            problem: kind.map(|kind| {
                serde_json::from_str(&format!(
                    r#"{{"type":"https://proxy.test/problems/{kind}","status":{status}}}"#
                ))
                .expect("parses")
            }),
            retry_after: None,
        }
    }

    fn read_as(status: u16, kind: Option<&str>, reading: &Reading) -> Outcome {
        Outcome::of_proxy(&problem(status, kind), reading)
    }

    #[test]
    fn the_status_decides_where_the_call_site_has_nothing_to_add() {
        for status in [400, 422, 418] {
            assert!(
                matches!(read_as(status, None, &ISSUING), Outcome::Rejected { .. }),
                "{status} did not stand up, so the state did not move",
            );
        }
        assert!(matches!(
            read_as(403, None, &ISSUING),
            Outcome::Refused { .. }
        ));
        assert!(matches!(
            read_as(401, None, &ISSUING),
            Outcome::Reauthenticate { .. }
        ));
        for status in [429, 500, 503] {
            assert!(
                matches!(read_as(status, None, &ISSUING), Outcome::Busy { .. }),
                "{status} is capacity or availability",
            );
        }
    }

    /// **`403` is not permanent everywhere**, and this is the distinction
    /// `initiator::renewal_verdict` warns about: read as terminal on a renewal
    /// path it would end every live session the day a permission appears.
    #[test]
    fn a_self_replacing_token_turns_a_refusal_into_a_wait() {
        assert!(matches!(
            read_as(403, Some("insufficient-permission"), &ISSUING),
            Outcome::Refused { .. }
        ));
        assert!(matches!(
            read_as(403, Some("insufficient-permission"), &RENEWING),
            Outcome::Busy { .. }
        ));
        assert!(matches!(
            read_as(401, Some("token-expired"), &RENEWING),
            Outcome::Busy { .. }
        ));
    }

    /// Revocation is the exception: it is settled on any path.
    #[test]
    fn revocation_is_refused_even_where_the_token_is_replaced() {
        assert!(matches!(
            read_as(403, Some("endpoint-revoked"), &RENEWING),
            Outcome::Refused { .. }
        ));
    }

    /// The key that is not where the token points — answered for a bad
    /// signature and for an Endpoint that is not there, and neither becomes
    /// true by asking again.
    #[test]
    fn a_pop_signature_refusal_is_not_a_reauthentication() {
        assert!(matches!(
            read_as(401, Some("pop-signature-invalid"), &ISSUING),
            Outcome::Refused { .. }
        ));
        assert!(
            matches!(
                read_as(401, Some("pop-signature-invalid"), &RENEWING),
                Outcome::Refused { .. }
            ),
            "and a replaceable token does not make it a wait either",
        );
    }

    /// `404` and `409` have no general reading, so the call site supplies one.
    #[test]
    fn the_call_site_reads_a_missing_thing() {
        let gone = Reading {
            missing: Missing::Done,
            ..ISSUING
        };
        for status in [404, 409] {
            assert!(matches!(
                read_as(status, None, &gone),
                Outcome::AlreadyGone { .. }
            ));
            assert!(matches!(
                read_as(status, None, &ISSUING),
                Outcome::Vanished { .. }
            ));
        }
    }

    /// **A sanctioned kind outranks its status.** `certificate-unavailable`
    /// arrives as a refusal and means "an order is in flight"; the allowlist is
    /// how `endpoint_cert` says so without letting
    /// `certificate-rate-limited` — days, not seconds — in with it.
    #[test]
    fn an_allowed_kind_outranks_the_status() {
        let waiting_on_the_ca = Reading {
            retryable_kinds: &["certificate-unavailable"],
            ..ISSUING
        };
        assert!(matches!(
            read_as(403, Some("certificate-unavailable"), &waiting_on_the_ca),
            Outcome::Busy { .. }
        ));
        assert!(
            matches!(
                read_as(403, Some("certificate-rate-limited"), &waiting_on_the_ca),
                Outcome::Refused { .. }
            ),
            "an unknown kind gets its status, not the benefit of the doubt",
        );
    }

    /// **The other sanctioned half: fix it and send it again.**
    ///
    /// `redeem_ticket` answers `403 protocol-not-allowed` for a protocol the
    /// ceiling does not hold, and **leaves the Ticket unspent**. Read as a
    /// refusal the caller throws a spendable Ticket away; read as a wait it
    /// resends the same wrong protocol forever. Both lists are needed because
    /// they prescribe different things.
    #[test]
    fn a_fixable_kind_is_rejected_not_refused() {
        let redeeming = Reading {
            fixable_kinds: &["protocol-not-allowed"],
            ..ISSUING
        };
        assert!(matches!(
            read_as(403, Some("protocol-not-allowed"), &redeeming),
            Outcome::Rejected { .. }
        ));
        assert!(
            matches!(
                read_as(403, Some("ticket-invalid"), &redeeming),
                Outcome::Refused { .. }
            ),
            "and the uniform refusal on the same route stays a refusal",
        );
    }

    /// A kind in neither list gets its status, and a route that names a kind in
    /// both would be saying two things — so `retryable_kinds` is read first and
    /// the ordering is pinned rather than left to the reader.
    #[test]
    fn waiting_outranks_fixing_when_a_route_names_both() {
        let both = Reading {
            retryable_kinds: &["ambiguous"],
            fixable_kinds: &["ambiguous"],
            ..ISSUING
        };
        assert!(matches!(
            read_as(403, Some("ambiguous"), &both),
            Outcome::Busy { .. }
        ));
    }

    /// What the server asked to wait is carried, because a wait the caller
    /// computes comes back too early.
    #[test]
    fn the_servers_own_wait_reaches_the_caller() {
        let error = ProxyError::Problem {
            status: 429,
            problem: None,
            retry_after: Some(Duration::from_secs(42)),
        };
        let Outcome::Busy { after, .. } = Outcome::of_proxy(&error, &ISSUING) else {
            panic!("a 429 is a wait");
        };
        assert_eq!(after, Some(Duration::from_secs(42)));
    }

    #[test]
    fn a_transport_failure_says_nothing_about_the_request() {
        let error = ProxyError::Transport(anyhow::anyhow!("no route to host"));
        let outcome = Outcome::of_proxy(&error, &ISSUING);
        assert!(matches!(
            outcome,
            Outcome::Unreachable(Unreachable::Transport { .. })
        ));
    }

    /// **Identity folds a decode failure into a 2xx `Api`**, having no `Decode`
    /// arm of its own. Read by status alone that is a success; it is not.
    #[test]
    fn an_identity_body_that_would_not_parse_is_malformed_not_a_success() {
        let error = IdentityError::Api {
            status: 200,
            body: "invalid response JSON: expected value".to_owned(),
            retry_after: None,
        };
        assert!(matches!(
            Outcome::of_identity(&error, &ISSUING),
            Outcome::Malformed { .. }
        ));
    }

    #[test]
    fn identity_statuses_read_the_same_way() {
        let refused = IdentityError::Api {
            status: 403,
            body: String::new(),
            retry_after: None,
        };
        assert!(matches!(
            Outcome::of_identity(&refused, &ISSUING),
            Outcome::Refused { .. }
        ));
        assert!(matches!(
            Outcome::of_identity(&IdentityError::Time, &ISSUING),
            Outcome::Malformed { .. }
        ));
    }

    /// The problem's kind reaches the reader as a sentence, never as a value —
    /// which is the whole of §8.8.4's uniformity surviving the translation.
    #[test]
    fn what_it_was_is_said_but_not_offered_to_branch_on() {
        let outcome = read_as(403, Some("provisioning-key-invalid"), &ISSUING);
        assert!(
            outcome.to_string().contains("provisioning-key-invalid"),
            "the reader can be told: {outcome}"
        );
    }
}
