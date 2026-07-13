//! Proof-of-Possession header generation (spec §8.0 / §15.2).
//!
//! Every P2P Connect request that presents an Endpoint Token must also prove
//! possession of the Endpoint private key by signing a canonical description of
//! the request. This module builds that canonical string and the four
//! `X-PoP-*` / `X-Endpoint-Id` header values.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::endpoint::EndpointKey;

/// Header names carrying the PoP proof (spec §8.0).
pub const HEADER_ENDPOINT_ID: &str = "x-endpoint-id";
pub const HEADER_POP_NONCE: &str = "x-pop-nonce";
pub const HEADER_POP_TIMESTAMP: &str = "x-pop-timestamp";
pub const HEADER_POP_SIGNATURE: &str = "x-pop-signature";

/// The PoP headers to attach to a request (alongside `Authorization: Bearer`).
#[derive(Debug, Clone)]
pub struct PopHeaders {
    pub endpoint_id: String,
    pub nonce: String,
    pub timestamp: String,
    pub signature: String,
}

impl PopHeaders {
    /// The four `(name, value)` header pairs to add to the request.
    pub fn as_pairs(&self) -> [(&'static str, &str); 4] {
        [
            (HEADER_ENDPOINT_ID, &self.endpoint_id),
            (HEADER_POP_NONCE, &self.nonce),
            (HEADER_POP_TIMESTAMP, &self.timestamp),
            (HEADER_POP_SIGNATURE, &self.signature),
        ]
    }
}

/// Build the PoP canonical request string (spec §8.0):
///
/// ```text
/// <HTTP-METHOD>\n<path-with-query>\n<endpoint_id>\n<timestamp>\n<nonce>\n
/// BASE64URL(SHA256(request-body))
/// ```
///
/// `body` is hashed even when empty; the final line has no trailing newline.
pub fn canonical_pop_string(
    method: &str,
    path_with_query: &str,
    endpoint_id: &str,
    timestamp: &str,
    nonce: &str,
    body: &[u8],
) -> String {
    let body_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(body));
    format!("{method}\n{path_with_query}\n{endpoint_id}\n{timestamp}\n{nonce}\n{body_hash}")
}

/// Produce PoP headers for a request, generating a fresh nonce and timestamp
/// and signing the canonical string with the Endpoint key.
pub fn sign_request(
    key: &EndpointKey,
    method: &str,
    path_with_query: &str,
    body: &[u8],
) -> PopHeaders {
    let endpoint_id = key.endpoint_id();
    let nonce = random_nonce();
    let timestamp = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("RFC 3339 formatting is infallible for now_utc");
    let canonical = canonical_pop_string(
        method,
        path_with_query,
        &endpoint_id,
        &timestamp,
        &nonce,
        body,
    );
    let signature = key.sign_b64url(canonical.as_bytes());
    PopHeaders {
        endpoint_id,
        nonce,
        timestamp,
        signature,
    }
}

/// A 128-bit random nonce, base64url-encoded (spec §8.0: ≥ 128 bits).
fn random_nonce() -> String {
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn canonical_string_shape() {
        let s = canonical_pop_string("POST", "/v1/peer/connect", "ep:a", "t", "n", b"{}");
        assert_eq!(s.lines().count(), 6);
        assert!(!s.ends_with('\n'));
        assert!(s.starts_with("POST\n/v1/peer/connect\nep:a\nt\nn\n"));
        // Empty body hashes to the well-known SHA-256("") base64url.
        let empty = canonical_pop_string("GET", "/", "ep:a", "t", "n", b"");
        assert_eq!(
            empty.rsplit('\n').next().unwrap(),
            "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
        );
    }

    #[test]
    fn sign_request_produces_verifiable_pop() {
        let key = EndpointKey::generate();
        let body = br#"{"protocol":"isekai-validator-v1"}"#;
        let pop = sign_request(&key, "POST", "/v1/peer-listeners", body);
        assert_eq!(pop.endpoint_id, key.endpoint_id());

        // Re-derive the canonical string the verifier would build and check the
        // signature against the Endpoint public key.
        let canonical = canonical_pop_string(
            "POST",
            "/v1/peer-listeners",
            &pop.endpoint_id,
            &pop.timestamp,
            &pop.nonce,
            body,
        );
        let sig = Signature::from_der(&URL_SAFE_NO_PAD.decode(pop.signature).unwrap()).unwrap();
        let public = p256::PublicKey::from_jwk_str(&key.public_jwk().to_string()).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(public);
        assert!(vk.verify(canonical.as_bytes(), &sig).is_ok());
    }

    #[test]
    fn as_pairs_yields_all_four_headers() {
        let key = EndpointKey::generate();
        let pop = sign_request(&key, "GET", "/v1/peer/connections/x", b"");
        let names: Vec<&str> = pop.as_pairs().iter().map(|(n, _)| *n).collect();
        assert_eq!(
            names,
            vec![
                "x-endpoint-id",
                "x-pop-nonce",
                "x-pop-timestamp",
                "x-pop-signature"
            ]
        );
    }
}
