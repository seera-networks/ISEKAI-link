//! Why no Endpoint Token came back (`docs/p2p_sdk_design.md` D14).
//!
//! **The failures of one call, told apart.** [`crate::issue_endpoint_token`]
//! is the first call every session makes and the one the renewal loop repeats
//! for the life of the process, and until this type it answered with
//! `anyhow::Error` — so the only way to act on a failure was to walk the chain
//! and downcast, which is what D12 took out of `portal-core`.
//!
//! **And they are not all the Identity API's.** Minting the credential comes
//! first: an Auth0 token source that cannot refresh, or a workload identity
//! that will not mint. Folding those into [`IdentityError`] would put them in
//! its `Transport` arm — read as [`Unreachable`](isekai_p2p_core::outcome::Unreachable),
//! a network failure to retry — and throw away the one instruction that
//! matters, which is to get another credential.

use isekai_p2p_core::identity::IdentityError;
use isekai_p2p_core::outcome::{Missing, Outcome, Reading};

/// Why [`crate::issue_endpoint_token`] produced no token.
///
/// **Read it with [`TokenError::outcome`]** rather than by matching the arms:
/// the three say where the failure came from, and the [`Outcome`] says what to
/// do about it, which is what a caller is deciding.
///
/// **`{:#}` on this type does not walk the chain.** The alternate flag belongs
/// to `anyhow::Error` — that is what makes it print causes — and the `Display`
/// here is the one sentence this layer adds. To report a failure with its cause
/// behind it, go through `anyhow::Error::from(error)` and print *that* with
/// `{:#}`; `isekai_p2p_core::identity`'s own `display` test pins the same thing
/// one layer down.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The Identity API refused, or could not be reached.
    ///
    /// `explain` is what this crate has to add about the refusal — the advice
    /// for a membership that has ended, for an Enrollment Key the server will
    /// only call "invalid", for a keypair registered in another tenant — or,
    /// when there is nothing to add, which call was being made.
    #[error("{explain}")]
    Identity {
        explain: String,
        #[source]
        source: IdentityError,
    },

    /// The credential this config carries could not be produced.
    ///
    /// Nothing reached Identity: an [`Auth0TokenSource`](crate::Auth0TokenSource)
    /// could not hand over a current token, or an
    /// [`AssertionSource`](crate::AssertionSource) could not mint one.
    #[error("{explain}")]
    Credential {
        explain: &'static str,
        #[source]
        source: anyhow::Error,
    },

    /// This `Credential` has already spent its registration on another keypair.
    ///
    /// No request was made: one `Credential` registers one Endpoint, and the
    /// config handed in carries a different key. Nothing about the server
    /// changes this answer.
    #[error("{explain}")]
    Mismatched { explain: String },
}

impl TokenError {
    /// What this failure asks the caller to do.
    ///
    /// **`Reauthenticate` for every credential failure, including the ones that
    /// are really a network error.** [`Auth0TokenSource`](crate::Auth0TokenSource)
    /// and [`AssertionSource`](crate::AssertionSource) answer with
    /// `anyhow::Error`, so a refresh the authorization server refused and an
    /// authorization server that did not answer arrive here identically. Of the
    /// two misreadings this is the safer one: the thing holding the source is
    /// the only thing that can act either way, and the app's own source has
    /// already marked its sign-in state by the time this is read (see
    /// `auth0::RefreshingAuth0Token`). Reading it as `Unreachable` instead
    /// would tell a caller whose session is over to keep waiting.
    ///
    /// **`Mismatched` is `Rejected` and not `Refused`**: `Refused` is
    /// "authorization refused it, and asking again asks the same rule", and no
    /// rule was consulted. `Rejected` says the request did not stand up and the
    /// state did not move — true, and fixable, by giving each keypair its own
    /// `Credential`.
    pub fn outcome(&self) -> Outcome {
        match self {
            TokenError::Identity { source, .. } => Outcome::of_identity(source, &ISSUING),
            TokenError::Credential { explain, source } => Outcome::Reauthenticate {
                explain: format!("{explain}: {source:#}"),
            },
            TokenError::Mismatched { explain } => Outcome::Rejected {
                explain: explain.clone(),
            },
        }
    }

    /// The Identity API's answer, with what this crate can add about it.
    pub(crate) fn identity(explain: impl Into<String>, source: IdentityError) -> Self {
        TokenError::Identity {
            explain: explain.into(),
            source,
        }
    }

    /// A credential that could not be produced, named by what was being minted.
    pub(crate) fn credential(explain: &'static str, source: anyhow::Error) -> Self {
        TokenError::Credential { explain, source }
    }
}

/// How this path reads an answer (`docs/p2p_sdk_error_type.md` §3.4).
///
/// **`token_self_replacing` is false because this *is* the path that replaces
/// it.** A `403` here is settled: there is no other loop about to hand this
/// call a different token. On a path renewing a lease the same answer is a
/// wait, which is the distinction `initiator::renewal_verdict` warns about.
///
/// **A `409` does reach here** — `config::explain_issue_failure` says "a `409`
/// lands here too", and that one is the cross-tenant collision. `Unremarkable`
/// keeps it out of the permanent bucket, which is where it was before; reading
/// it as `Done` would call a cross-tenant collision "already gone". The `404`
/// is the same, and neither is what this reading is about.
///
/// `retryable_kinds` and `fixable_kinds` are empty: `429` and `503` are already
/// waits by status, and no kind on this route asks to be read against its own.
///
/// **The `401 pop-signature-invalid` this used to name moved into [`Outcome`]**,
/// which reads it status-independently with the reason recorded alongside:
/// Identity answers it for an Endpoint it cannot find as well as for a bad
/// signature, and neither becomes true by asking again — one needs a key
/// registered where the token points, the other a different key.
const ISSUING: Reading = Reading {
    not_found: Missing::Unremarkable,
    conflict: Missing::Unremarkable,
    token_self_replacing: false,
    retryable_kinds: &[],
    fixable_kinds: &[],
    gone_kinds: &[],
};

#[cfg(test)]
mod tests {
    use super::*;

    fn api(status: u16, kind: &str) -> IdentityError {
        IdentityError::Api {
            status,
            body: format!(r#"{{"type":"https://isekai.example/problems/{kind}"}}"#),
            retry_after: None,
        }
    }

    /// A refusal the server stated stays a refusal, which is what ends the
    /// renewal loop's fast retries.
    #[test]
    fn a_refusal_reads_as_refused() {
        let error = TokenError::identity("could not issue", api(403, "endpoint-revoked"));
        assert!(
            matches!(error.outcome(), Outcome::Refused { .. }),
            "{error}"
        );
    }

    /// And Identity not answering stays a wait.
    #[test]
    fn a_transport_failure_reads_as_unreachable() {
        let error = TokenError::identity(
            "could not connect",
            IdentityError::Transport(anyhow::anyhow!("connection refused")),
        );
        assert!(
            matches!(error.outcome(), Outcome::Unreachable(_)),
            "{error}"
        );
    }

    /// **The whole point of the arm** (D14): a credential that cannot be minted
    /// asks for a new credential, and must not read as a network failure to sit
    /// and wait for.
    #[test]
    fn a_credential_failure_asks_for_a_new_credential() {
        let error = TokenError::credential(
            "could not obtain a current Auth0 token",
            anyhow::anyhow!("refresh token expired"),
        );
        match error.outcome() {
            Outcome::Reauthenticate { explain } => {
                // Both halves: what was being minted, and why it was not.
                assert!(explain.contains("Auth0 token"), "{explain}");
                assert!(explain.contains("refresh token expired"), "{explain}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// A local contradiction is not an authorization decision.
    #[test]
    fn a_mismatched_credential_reads_as_rejected() {
        let error = TokenError::Mismatched {
            explain: "already registered ep:aaa".to_owned(),
        };
        assert!(
            matches!(error.outcome(), Outcome::Rejected { .. }),
            "{error}"
        );
    }

    /// **`{:#}` is `anyhow`'s flag, not ours** — the same trap that cost
    /// `portal-client` two diagnostics when the inventory routes became typed.
    /// A caller that wants the cause has to go through `anyhow::Error`.
    #[test]
    fn the_cause_comes_from_anyhow_not_from_the_alternate_flag() {
        let error = TokenError::identity(
            "this guest membership has ended",
            IdentityError::Api {
                status: 403,
                body: r#"{"type":"https://isekai.example/problems/membership-expired",
                          "detail":"ended 2027-01-31T23:59:59Z"}"#
                    .to_owned(),
                retry_after: None,
            },
        );
        assert_eq!(format!("{error:#}"), format!("{error}"));
        assert!(!format!("{error:#}").contains("2027-01-31"));
        let reported = format!("{:#}", anyhow::Error::from(error));
        assert!(reported.contains("has ended"), "{reported}");
        assert!(reported.contains("2027-01-31"), "{reported}");
    }
}
