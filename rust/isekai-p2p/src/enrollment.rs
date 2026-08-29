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
    EnrollmentKeyRecord, EnrollmentRecord, IdentityClient, IssuedEnrollmentKey, NewEnrollmentKey,
    RevokedEnrollmentKey,
};
use isekai_p2p_core::proxy::ControlPlaneTransport;
use isekai_p2p_core::transport::MasqueH3Transport;

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
) -> anyhow::Result<IssuedEnrollmentKey> {
    Ok(on_transport!(identity, |client| {
        client.create_enrollment_key(auth0_token, request).await?
    }))
}

/// §8.8.9 — this caller's keys, newest first.
pub async fn list(
    identity: &Identity,
    auth0_token: &str,
) -> anyhow::Result<Vec<EnrollmentKeyRecord>> {
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
) -> anyhow::Result<Vec<EnrollmentRecord>> {
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
) -> anyhow::Result<RevokedEnrollmentKey> {
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
