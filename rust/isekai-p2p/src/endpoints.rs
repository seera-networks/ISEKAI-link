//! Reading and retiring the Endpoints an account owns (§8.1.3 / §8.1.4 / §8.7).
//!
//! **Route A, no PoP.** The caller is the owner rather than the Endpoint, which
//! is the whole point: the device being retired is usually the one that cannot
//! answer. The self-revocation an unattended job performs is a different
//! request with different rules — see [`crate::config::release_enrollment`].
//!
//! Same shape as [`crate::enrollment`], and the transport choice lives here for
//! the same reason.

use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{
    EndpointDetail, EndpointList, IdentityClient, IdentityError, RevokeAuth, RevokeReason, Revoked,
};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::enrollment::Identity;

/// How this module's routes are read.
///
/// **Beside the routes** (`p2p_sdk_design.md` D15): a [`Reading`] is the call
/// site saying what a status means *on this route*, and when every caller
/// writes its own, the same answer ends up read several ways. The long form of
/// that argument is in [`isekai_p2p_core::proxy::reading`], which these are the
/// Identity-side counterpart of; they sit beside the typed wrappers rather than
/// `IdentityClient`'s raw methods, because the wrappers are what a caller
/// reaches and what D12 gave a type to.
///
/// **All three say nothing about absence.** [`Reading::gone_kinds`] spells out
/// why a `404` cannot be read by status — one with no problem+json body is also
/// what a wrong base path answers — and Identity has not been observed naming a
/// slug for absence on these routes. That includes [`REVOKE`]: `portal-core`
/// answers `Missing::Done` for its own revoke and keeps that on purpose,
/// because it is asking "did my registration land?" about an id it has just
/// registered itself, which is local knowledge this surface does not have.
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

    /// [`super::list`] — `GET /v1/endpoints`.
    pub const LIST: Reading = PLAIN;

    /// [`super::get`] — `GET /v1/endpoints/{id}`.
    pub const GET: Reading = PLAIN;

    /// [`super::revoke`] — `DELETE /v1/endpoints/{id}`.
    pub const REVOKE: Reading = PLAIN;
}

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

/// §8.1.3 — one page of this account's Endpoints.
///
/// **Paged rather than gathered.** Unlike an enrolment key's records, this can
/// be long-lived and large, and the cursor's own documentation warns that
/// reaching the end is not the same as having seen everything: rows can be
/// registered or revoked while the pages are being walked. A caller that wants
/// the whole list should say so, and know what it is getting.
pub async fn list(
    identity: &Identity,
    auth0_token: &str,
    status: Option<&str>,
    cursor: Option<&str>,
) -> Result<EndpointList, IdentityError> {
    Ok(on_transport!(identity, |client| {
        client.list_endpoints(auth0_token, status, cursor).await?
    }))
}

/// §8.1.4 — one Endpoint, and the live rows sharing its key.
pub async fn get(
    identity: &Identity,
    auth0_token: &str,
    endpoint_id: &str,
) -> Result<EndpointDetail, IdentityError> {
    Ok(on_transport!(identity, |client| {
        client.get_endpoint(auth0_token, endpoint_id).await?
    }))
}

/// §8.7 — retire an Endpoint this account owns.
///
/// **This cannot be undone**, and the keypair cannot register again: one key is
/// one Endpoint. A device that comes back needs a new key.
///
/// The reason is required and typed, because it lands in an audit log that
/// somebody reads during an incident, and because half the vocabulary belongs
/// to Identity rather than the caller (§8.8.8 / §8.8.9).
pub async fn revoke(
    identity: &Identity,
    auth0_token: &str,
    endpoint_id: &str,
    reason: RevokeReason,
    note: Option<&str>,
) -> Result<Revoked, IdentityError> {
    let auth = RevokeAuth::Auth0 {
        token: auth0_token,
        endpoint_id,
        reason,
    };
    Ok(on_transport!(identity, |client| {
        client.revoke_endpoint(auth, note).await?
    }))
}
