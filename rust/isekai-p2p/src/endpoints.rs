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
    EndpointDetail, EndpointList, IdentityClient, RevokeAuth, RevokeReason, Revoked,
};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::enrollment::Identity;

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
) -> anyhow::Result<EndpointList> {
    Ok(on_transport!(identity, |client| {
        client.list_endpoints(auth0_token, status, cursor).await?
    }))
}

/// §8.1.4 — one Endpoint, and the live rows sharing its key.
pub async fn get(
    identity: &Identity,
    auth0_token: &str,
    endpoint_id: &str,
) -> anyhow::Result<EndpointDetail> {
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
) -> anyhow::Result<Revoked> {
    let auth = RevokeAuth::Auth0 {
        token: auth0_token,
        endpoint_id,
        reason,
    };
    Ok(on_transport!(identity, |client| {
        client.revoke_endpoint(auth, note).await?
    }))
}
