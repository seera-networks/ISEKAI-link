//! The target's signed statement about its own video TLS key (spec §8.6.5).
//!
//! # What it is for
//!
//! Generating the video TLS key on the device stopped the proxy from reading
//! the relayed video. It did not stop the proxy *impersonating* the target: the
//! proxy derives the FQDN, holds the DNS for it and holds the ACME account, so
//! it can obtain a second, perfectly valid certificate for the same name. No
//! property of a certificate tells the two apart.
//!
//! **The one thing the proxy cannot do is sign as the target's Endpoint.** So
//! the target says, in its own hand, which key its certificate is for; the
//! initiator checks that and then requires the handshake to present that key.
//!
//! # Why it needs nothing else to check
//!
//! An Endpoint ID *is* derived from the public key (§4.2), so a statement
//! carries its own identity and a reader works it out from the signature. No
//! call to the Identity API and no trust in the proxy — which is the point,
//! since the proxy is the party this defends against.
//!
//! A proxy that drops a statement or serves a stale one is not attacking: the
//! initiator is then left with nothing to pin, which is where everybody starts.
//! What it cannot do is forge one.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::endpoint::{EndpointKey, endpoint_id_from_jwk, verify_b64url};

/// The first line of the signed string.
///
/// There so this signature and a PoP signature (§5.2) cannot be taken for one
/// another: same key, same algorithm, and only the bytes being signed to keep
/// them apart.
const DOMAIN: &str = "isekai-p2p-cert-attestation-v1";

/// A target's statement that its certificate for a hostname is for the key with
/// a given SPKI digest, signed with its Endpoint key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// The Endpoint's public key — the same value the token's `cnf.jwk` holds.
    pub jwk: Value,
    /// When the statement stops being good.
    ///
    /// **Chosen by the signer, and not capped by anyone.** It is one of the
    /// signed lines, so nothing downstream can shorten it without destroying
    /// the signature — the proxy checks only that it parses and is in the
    /// future.
    ///
    /// It bounds the statement rather than the certificate. What is being
    /// vouched for is a *key*, and the key outlives any one certificate issued
    /// against it, so a statement may safely outlast the certificate that was
    /// current when it was made.
    pub expires_at: String,
    /// ES256 over the canonical string, base64url.
    pub signature: String,
}

/// The five lines that get signed.
///
/// One function for both sides. A signer and a verifier that each build this
/// from the specification are a signer and a verifier that disagree the first
/// time either is edited.
fn canonical_string(
    endpoint_id: &str,
    hostname: &str,
    spki_sha256: &str,
    expires_at: &str,
) -> String {
    format!("{DOMAIN}\n{endpoint_id}\n{hostname}\n{spki_sha256}\n{expires_at}")
}

/// Sign a statement about the certificate `key`'s Endpoint is asking for.
pub fn attest(
    key: &EndpointKey,
    hostname: &str,
    spki_sha256: &str,
    expires_at: &str,
) -> Attestation {
    let message = canonical_string(&key.endpoint_id(), hostname, spki_sha256, expires_at);
    Attestation {
        jwk: key.public_jwk(),
        expires_at: expires_at.to_owned(),
        signature: key.sign_b64url(message.as_bytes()),
    }
}

/// Why a statement was not believed.
///
/// Told apart because they mean different things to a caller. None of them is a
/// reason to carry on: a statement that is present and wrong is the case this
/// exists to catch, and *absent* is a different thing entirely, which is why it
/// is not represented here.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum AttestationError {
    #[error("signed by {found}, not by the endpoint being connected to ({expected})")]
    WrongEndpoint { expected: String, found: String },
    #[error("the signature does not verify")]
    BadSignature,
    #[error("expired at {0}")]
    Expired(String),
    #[error("the expiry ({0}) cannot be read")]
    UnreadableExpiry(String),
}

/// Check a statement about `spki_sha256`, for `video_host`, from
/// `peer_endpoint`.
///
/// The order is the spec's (§8.6.5), and the order is the point: identity
/// first, so that everything after it is known to be the named Endpoint's own
/// words rather than something the proxy wrote.
///
/// The hostname and the digest are not compared separately — they are inside
/// the signed string, so a statement about a different name or a different key
/// fails to verify at step 2. Passing them in is what makes that true.
///
/// `now` is a parameter rather than read here, so expiry can be exercised at a
/// time of the test's choosing.
pub fn verify(
    attestation: &Attestation,
    peer_endpoint: &str,
    video_host: &str,
    spki_sha256: &str,
    now: OffsetDateTime,
) -> Result<(), AttestationError> {
    let signer = endpoint_id_from_jwk(&attestation.jwk);
    if signer != peer_endpoint {
        return Err(AttestationError::WrongEndpoint {
            expected: peer_endpoint.to_owned(),
            found: signer,
        });
    }

    let message = canonical_string(&signer, video_host, spki_sha256, &attestation.expires_at);
    if !verify_b64url(&attestation.jwk, message.as_bytes(), &attestation.signature) {
        return Err(AttestationError::BadSignature);
    }

    let expiry = OffsetDateTime::parse(&attestation.expires_at, &Rfc3339)
        .map_err(|_| AttestationError::UnreadableExpiry(attestation.expires_at.clone()))?;
    if expiry <= now {
        return Err(AttestationError::Expired(attestation.expires_at.clone()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: &str = "e4f9c3.p2p.isekai.tools";
    const SPKI: &str = "3q2-7w";
    const EXPIRES: &str = "2099-01-01T00:00:00Z";

    fn now() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + time::Duration::seconds(1_800_000_000)
    }

    #[test]
    fn a_statement_verifies_against_the_endpoint_that_signed_it() {
        let key = EndpointKey::generate();
        let a = attest(&key, HOST, SPKI, EXPIRES);
        assert_eq!(verify(&a, &key.endpoint_id(), HOST, SPKI, now()), Ok(()));
    }

    /// The whole point. A proxy can obtain a valid certificate for the same
    /// name, but it cannot produce this statement about *its* key, because it
    /// cannot sign as the target's Endpoint.
    #[test]
    fn a_statement_about_another_key_does_not_verify() {
        let key = EndpointKey::generate();
        let a = attest(&key, HOST, SPKI, EXPIRES);
        assert_eq!(
            verify(&a, &key.endpoint_id(), HOST, "another-key", now()),
            Err(AttestationError::BadSignature),
        );
    }

    /// Naming a different host does not let a statement be replayed onto it.
    #[test]
    fn a_statement_for_another_host_does_not_verify() {
        let key = EndpointKey::generate();
        let a = attest(&key, HOST, SPKI, EXPIRES);
        assert_eq!(
            verify(
                &a,
                &key.endpoint_id(),
                "other.p2p.isekai.tools",
                SPKI,
                now()
            ),
            Err(AttestationError::BadSignature),
        );
    }

    /// Identity is checked before anything else, so the rest of the answer is
    /// known to be the named Endpoint's own words.
    #[test]
    fn a_statement_from_another_endpoint_is_rejected_as_such() {
        let key = EndpointKey::generate();
        let other = EndpointKey::generate();
        let a = attest(&key, HOST, SPKI, EXPIRES);
        assert!(matches!(
            verify(&a, &other.endpoint_id(), HOST, SPKI, now()),
            Err(AttestationError::WrongEndpoint { .. }),
        ));
    }

    /// Swapping in another Endpoint's key changes who the statement is from,
    /// which is caught before the signature is even looked at.
    #[test]
    fn the_signer_is_taken_from_the_key_and_not_from_a_field() {
        let key = EndpointKey::generate();
        let other = EndpointKey::generate();
        let mut a = attest(&key, HOST, SPKI, EXPIRES);
        a.jwk = other.public_jwk();
        assert!(matches!(
            verify(&a, &key.endpoint_id(), HOST, SPKI, now()),
            Err(AttestationError::WrongEndpoint { .. }),
        ));
    }

    #[test]
    fn an_expired_statement_is_refused() {
        let key = EndpointKey::generate();
        let a = attest(&key, HOST, SPKI, "2020-01-01T00:00:00Z");
        assert_eq!(
            verify(&a, &key.endpoint_id(), HOST, SPKI, now()),
            Err(AttestationError::Expired("2020-01-01T00:00:00Z".to_owned())),
        );
    }

    /// The expiry is signed, so moving it invalidates the signature rather than
    /// extending the statement.
    #[test]
    fn the_expiry_cannot_be_pushed_out_afterwards() {
        let key = EndpointKey::generate();
        let mut a = attest(&key, HOST, SPKI, "2020-01-01T00:00:00Z");
        a.expires_at = EXPIRES.to_owned();
        assert_eq!(
            verify(&a, &key.endpoint_id(), HOST, SPKI, now()),
            Err(AttestationError::BadSignature),
        );
    }

    /// A PoP signature and this one use the same key and algorithm; only the
    /// first line keeps them from being the same bytes.
    #[test]
    fn the_signed_string_is_domain_separated() {
        assert!(canonical_string("ep:a", HOST, SPKI, EXPIRES).starts_with(DOMAIN));
    }
}
