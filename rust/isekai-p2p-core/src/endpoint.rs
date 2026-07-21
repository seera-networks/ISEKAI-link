//! The Endpoint keypair: identity, JWK (`cnf`), and signing.
//!
//! An Endpoint is identified by an ECDSA P-256 keypair. The private key signs
//! Proof-of-Possession (and registration challenges); the public key is
//! published to the Identity API and embedded in the Endpoint Token as the
//! RFC 7800 `cnf.jwk`. The [`EndpointKey::endpoint_id`] derivation matches the
//! MASQUE proxy's server-side derivation exactly (spec §4.2), so a token's
//! `cnf` and its `endpoint_id` agree.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::{DecodePrivateKey, EncodePrivateKey, LineEnding};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// Prefix that all Endpoint IDs carry (spec §8.1).
pub const ENDPOINT_ID_PREFIX: &str = "ep:";

/// Errors from key handling.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    /// A private key could not be generated, parsed or serialized.
    #[error("endpoint key error: {0}")]
    Key(String),
}

/// An Endpoint's ECDSA P-256 keypair.
#[derive(Clone)]
pub struct EndpointKey {
    signing: SigningKey,
}

impl std::fmt::Debug for EndpointKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print private key material.
        f.debug_struct("EndpointKey")
            .field("endpoint_id", &self.endpoint_id())
            .finish_non_exhaustive()
    }
}

impl EndpointKey {
    /// Generate a fresh random Endpoint key.
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::random(&mut rand::thread_rng()),
        }
    }

    /// Load an Endpoint key from a PKCS#8 PEM string.
    pub fn from_pkcs8_pem(pem: &str) -> Result<Self, EndpointError> {
        let signing =
            SigningKey::from_pkcs8_pem(pem).map_err(|e| EndpointError::Key(e.to_string()))?;
        Ok(Self { signing })
    }

    /// Serialize the private key to a PKCS#8 PEM string.
    ///
    /// The caller must persist this with owner-only (0600) permissions — it is
    /// long-lived key material that must never leave the Endpoint.
    pub fn to_pkcs8_pem(&self) -> Result<String, EndpointError> {
        self.signing
            .to_pkcs8_pem(LineEnding::LF)
            .map(|s| s.to_string())
            .map_err(|e| EndpointError::Key(e.to_string()))
    }

    /// The public key as a JWK — the value to publish as the token's `cnf.jwk`.
    pub fn public_jwk(&self) -> Value {
        let public = p256::PublicKey::from(*self.signing.verifying_key());
        serde_json::from_str(&public.to_jwk_string()).expect("p256 emits valid JWK JSON")
    }

    /// The canonical Endpoint ID (spec §4.2): `"ep:" + hex(SHA256(JWK Thumbprint))`.
    ///
    /// Note the spec applies SHA-256 to the RFC 7638 thumbprint (itself a
    /// SHA-256 digest); this is implemented literally to match the proxy.
    pub fn endpoint_id(&self) -> String {
        let thumbprint = jwk_thumbprint(&self.public_jwk());
        let digest = Sha256::digest(thumbprint);
        format!("{ENDPOINT_ID_PREFIX}{}", hex_encode(&digest))
    }

    /// Sign `message` (ECDSA P-256 / SHA-256), returning the base64url of the
    /// **ASN.1 DER** signature.
    ///
    /// DER is the encoding the Identity API requires (its verifier only accepts
    /// DER) and that the MASQUE proxy also accepts (its PoP verifier tries the
    /// fixed `r‖s` form first, then falls back to DER), so it works for every
    /// P2P Connect request.
    pub fn sign_b64url(&self, message: &[u8]) -> String {
        let signature: Signature = self.signing.sign(message);
        URL_SAFE_NO_PAD.encode(signature.to_der().as_bytes())
    }
}

/// Compute the RFC 7638 JWK thumbprint (SHA-256) of an EC P-256 public JWK.
///
/// Members `crv`, `kty`, `x`, `y` in lexicographic order, whitespace-free.
pub fn jwk_thumbprint(jwk: &Value) -> [u8; 32] {
    let field = |k: &str| jwk.get(k).and_then(Value::as_str).unwrap_or_default();
    let canonical = format!(
        "{{\"crv\":{},\"kty\":{},\"x\":{},\"y\":{}}}",
        json_string(field("crv")),
        json_string(field("kty")),
        json_string(field("x")),
        json_string(field("y")),
    );
    Sha256::digest(canonical.as_bytes()).into()
}

fn json_string(s: &str) -> String {
    serde_json::to_string(s).expect("serializing a &str is infallible")
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from_digit((b >> 4) as u32, 16).expect("nibble < 16"));
        out.push(char::from_digit((b & 0x0f) as u32, 16).expect("nibble < 16"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn endpoint_id_is_prefixed_hex_and_stable() {
        let key = EndpointKey::generate();
        let id = key.endpoint_id();
        assert!(id.starts_with("ep:"));
        assert_eq!(id.len(), ENDPOINT_ID_PREFIX.len() + 64);
        assert!(
            id[3..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(key.endpoint_id(), id); // deterministic
    }

    #[test]
    fn pkcs8_pem_round_trips() {
        let key = EndpointKey::generate();
        let pem = key.to_pkcs8_pem().unwrap();
        let loaded = EndpointKey::from_pkcs8_pem(&pem).unwrap();
        assert_eq!(loaded.endpoint_id(), key.endpoint_id());
        assert_eq!(loaded.public_jwk(), key.public_jwk());
    }

    #[test]
    fn public_jwk_is_ec_p256() {
        let jwk = EndpointKey::generate().public_jwk();
        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");
        assert!(jwk["x"].is_string() && jwk["y"].is_string());
    }

    #[test]
    fn signature_verifies_against_public_key() {
        let key = EndpointKey::generate();
        let sig_b64 = key.sign_b64url(b"hello");
        let bytes = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let signature = Signature::from_der(&bytes).unwrap();
        let public = p256::PublicKey::from_jwk_str(&key.public_jwk().to_string()).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(public);
        assert!(vk.verify(b"hello", &signature).is_ok());
        assert!(vk.verify(b"tampered", &signature).is_err());
    }
}
