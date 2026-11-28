//! Managing Enrollment Keys (§8.8.2 / §8.8.9), from the owner's side.
//!
//! **Route A, and no PoP.** The caller is a person who has signed in to Auth0,
//! not an Endpoint, so there is no Endpoint private key to bind the request to.
//! That is also why none of this needs a key of the caller's own.
//!
//! These are thin wrappers with one job beyond forwarding: choosing the
//! transport, so callers do not have to know that the Identity API serves
//! h1/h2 and h3 on the same port. [`crate::issue_endpoint_token`] does the same
//! for the same reason.

use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{
    EnrollmentKeyRecord, EnrollmentRecord, IdentityClient, IdentityError, IssuedEnrollmentKey,
    NewEnrollmentKey, RevokedEnrollmentKey,
};
use isekai_p2p_core::proxy::ControlPlaneTransport;
use isekai_p2p_core::transport::MasqueH3Transport;

/// How this module's routes are read.
///
/// **Beside the routes** (`p2p_sdk_design.md` D15), for the reason
/// [`isekai_p2p_core::proxy::reading`] gives at length, and beside the typed
/// wrappers rather than `IdentityClient`'s raw methods — the wrappers are what
/// a caller reaches and what D12 gave a type to.
///
/// **None of the four says anything about absence**, including [`REVOKE`]:
/// [`Reading::gone_kinds`] spells out why a `404` cannot be read by status, and
/// Identity has not been observed naming a slug for absence here. A guest
/// refused [`ISSUE`] by name arrives as an ordinary `insufficient-permission`
/// instead, which `crate::config::membership_advice` is what says so.
pub mod reading {
    use isekai_p2p_core::outcome::{Missing, Reading};

    /// The reading every route in this module shares today.
    const PLAIN: Reading = Reading {
        not_found: Missing::Unremarkable,
        conflict: Missing::Unremarkable,
        token_self_replacing: false,
        retryable_kinds: &[],
        fixable_kinds: &[],
        gone_kinds: &[],
    };

    /// [`super::issue`] — `POST /v1/enrollment-keys`.
    pub const ISSUE: Reading = PLAIN;

    /// [`super::list`] — `GET /v1/enrollment-keys`.
    pub const LIST: Reading = PLAIN;

    /// [`super::enrollments`] — `GET /v1/enrollment-keys/{id}/enrollments`.
    pub const ENROLLMENTS: Reading = PLAIN;

    /// [`super::revoke`] — `DELETE /v1/enrollment-keys/{id}`.
    pub const REVOKE: Reading = PLAIN;
}

/// How to reach the Identity API for these calls.
#[derive(Debug, Clone)]
pub struct Identity {
    pub url: String,
    pub http3: bool,
}

impl Identity {
    pub fn new(url: impl Into<String>, http3: bool) -> Self {
        Self {
            url: url.into(),
            http3,
        }
    }
}

/// Run `f` against whichever transport this deployment is configured for.
///
/// A macro rather than a generic function because each arm builds a different
/// concrete client, and the closure would have to be generic over the
/// transport to be written once.
macro_rules! on_transport {
    ($identity:expr, |$client:ident| $body:expr) => {{
        if $identity.http3 {
            let $client = IdentityClient::new(MasqueH3Transport::connect(&$identity.url)?);
            $body
        } else {
            let $client = IdentityClient::new(HttpsTransport::connect(&$identity.url)?);
            $body
        }
    }};
}

/// §8.8.2 — issue a key. The secret comes back once and never again.
pub async fn issue(
    identity: &Identity,
    auth0_token: &str,
    request: &NewEnrollmentKey,
) -> Result<IssuedEnrollmentKey, IdentityError> {
    Ok(on_transport!(identity, |client| {
        // **The one door a permission cannot close.** Issuing a key is
        // authenticated as the person and carries no Endpoint Token, so there
        // is nothing on it to narrow -- Identity refuses a guest here by name
        // instead (`guest_membership.md` §3 D7), and that refusal arrives as an
        // ordinary `insufficient-permission` unless somebody says what it was.
        //
        // **Which is said where it is reported, not here.** This used to attach
        // the sentence with `map_err(explain_membership_refusal)`, and once this
        // route returned `IdentityError` (D12) that silently became
        // `IdentityError::Transport` holding an `anyhow::Error` -- a `403` read
        // as a network failure. `portal-client` calls
        // [`crate::config::explain_membership_refusal`] on the way to the
        // screen, where an `anyhow::Error` is what is wanted.
        client.create_enrollment_key(auth0_token, request).await?
    }))
}

/// §8.8.9 — this caller's keys, newest first.
pub async fn list(
    identity: &Identity,
    auth0_token: &str,
) -> Result<Vec<EnrollmentKeyRecord>, IdentityError> {
    Ok(on_transport!(identity, |client| {
        client.list_enrollment_keys(auth0_token).await?
    }))
}

/// §8.8.9 — which Endpoints a key registered, and how each of them ended.
///
/// **Follows the cursor.** These records outlive the key precisely because "who
/// came in on it" matters most at the moment somebody revokes one, and a key a
/// CI has been using accumulates a row per job within the retention window. A
/// first page presented as the whole answer would be a truncated audit with
/// nothing saying so.
pub async fn enrollments(
    identity: &Identity,
    auth0_token: &str,
    key_id: &str,
) -> Result<Vec<EnrollmentRecord>, IdentityError> {
    Ok(on_transport!(identity, |client| {
        let mut all = Vec::new();
        let mut cursor: Option<String> = None;
        // A bound, because the cursor comes from the server: a page that keeps
        // pointing at itself would otherwise loop for as long as the process
        // lives. Deep enough that no real key reaches it.
        for _ in 0..100 {
            let (rows, next) = client
                .enrollment_key_enrollments(auth0_token, key_id, cursor.as_deref())
                .await?;
            all.extend(rows);
            match next {
                Some(next) => cursor = Some(next),
                None => break,
            }
        }
        all
    }))
}

/// §8.8.9 — stop a key, and say what became of what it grew.
pub async fn revoke(
    identity: &Identity,
    auth0_token: &str,
    key_id: &str,
) -> Result<RevokedEnrollmentKey, IdentityError> {
    Ok(on_transport!(identity, |client| {
        client
            .revoke_enrollment_key(auth0_token, key_id, None, None)
            .await?
    }))
}

/// Silences the unused-import warning on the h1/h2-only arm.
const _: fn() = || {
    fn assert_transport<T: ControlPlaneTransport>() {}
    assert_transport::<HttpsTransport>();
};
