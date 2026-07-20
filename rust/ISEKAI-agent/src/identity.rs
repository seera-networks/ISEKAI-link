//! Identity API client (spec §8.1 / §8.2): Endpoint registration and Endpoint
//! Token acquisition.
//!
//! The Identity API (`ISEKAI-identity`) is HTTPS-only and serves HTTP/1.1 and
//! HTTP/2 on TCP plus HTTP/3 on QUIC at the same port, so this client is generic
//! over [`ControlPlaneTransport`]: pair it with [`crate::https::HttpsTransport`]
//! for h1/h2 or [`crate::transport::MasqueH3Transport`] for h3.
//!
//! Every call carries the user's Auth0 Access Token as `Authorization: Bearer`;
//! token issuance additionally requires Proof-of-Possession over the request.
//! Signatures use base64url(DER), the encoding the Identity API requires.

use serde::Deserialize;
use serde_json::{Value, json};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::endpoint::EndpointKey;
use crate::pop;
use crate::proxy::ControlPlaneTransport;

/// Errors from Identity API calls.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("transport error: {0}")]
    Transport(#[from] anyhow::Error),
    #[error("Identity API returned {status}: {body}")]
    Api { status: u16, body: String },
    #[error("failed to format timestamp")]
    Time,
}

/// Response of `POST /v1/endpoints/register/challenge` (§8.1.1).
#[derive(Debug, Clone, Deserialize)]
pub struct Challenge {
    pub challenge_id: String,
    pub challenge: String,
    pub expires_at: String,
}

/// Response of `POST /v1/endpoints/register` (§8.1.2).
#[derive(Debug, Clone, Deserialize)]
pub struct Registration {
    pub endpoint_id: String,
    pub device_id: String,
    pub user_id: String,
    pub status: String,
    pub registered_at: String,
}

/// Response of `POST /v1/tokens/endpoint` (§8.2.1).
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointToken {
    pub endpoint_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub endpoint_id: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
}

/// A client for the ISEKAI Identity API over `T`.
///
/// The transport owns the base URL, so every request here is a path.
#[derive(Debug, Clone)]
pub struct IdentityClient<T> {
    transport: T,
}

impl<T: ControlPlaneTransport> IdentityClient<T> {
    /// Create a client that speaks to the Identity API over `transport`.
    pub fn new(transport: T) -> Self {
        Self { transport }
    }

    /// §8.1.1 — request a registration challenge for `key`.
    pub async fn register_challenge(
        &self,
        auth0_token: &str,
        key: &EndpointKey,
    ) -> Result<Challenge, IdentityError> {
        let body = json!({
            "endpoint_id": key.endpoint_id(),
            "public_key": key.public_jwk(),
        });
        self.post("/v1/endpoints/register/challenge", auth0_token, None, body)
            .await
    }

    /// §8.1.2 — register the Endpoint by signing the challenge (§4.3).
    pub async fn register(
        &self,
        auth0_token: &str,
        key: &EndpointKey,
        challenge: &Challenge,
        device_name: Option<&str>,
    ) -> Result<Registration, IdentityError> {
        let endpoint_id = key.endpoint_id();
        let timestamp = now_rfc3339()?;
        let signature = sign_challenge(key, &challenge.challenge, &endpoint_id, &timestamp);
        let mut body = json!({
            "challenge_id": challenge.challenge_id,
            "endpoint_id": endpoint_id,
            "timestamp": timestamp,
            "signature": signature,
        });
        if let Some(name) = device_name {
            body["device_name"] = json!(name);
        }
        self.post("/v1/endpoints/register", auth0_token, None, body)
            .await
    }

    /// §8.2.1 — obtain an Endpoint Token (Auth0 AT + PoP over this request).
    pub async fn issue_token(
        &self,
        auth0_token: &str,
        key: &EndpointKey,
        requested_permissions: Option<&[String]>,
        requested_protocols: Option<&[String]>,
        ttl: Option<i64>,
    ) -> Result<EndpointToken, IdentityError> {
        let mut body = json!({ "endpoint_id": key.endpoint_id() });
        if let Some(p) = requested_permissions {
            body["requested_permissions"] = json!(p);
        }
        if let Some(p) = requested_protocols {
            body["requested_protocols"] = json!(p);
        }
        if let Some(t) = ttl {
            body["ttl"] = json!(t);
        }
        // The PoP body hash must cover the exact bytes sent, so sign and send
        // the same serialization.
        let bytes = serde_json::to_vec(&body).expect("json body serializes");
        let pop = pop::sign_request(key, "POST", "/v1/tokens/endpoint", &bytes);
        self.post_bytes("/v1/tokens/endpoint", auth0_token, Some(&pop), bytes)
            .await
    }

    /// Convenience: challenge → register → issue a token in one call.
    pub async fn register_and_issue(
        &self,
        auth0_token: &str,
        key: &EndpointKey,
        device_name: Option<&str>,
        ttl: Option<i64>,
    ) -> Result<EndpointToken, IdentityError> {
        let challenge = self.register_challenge(auth0_token, key).await?;
        self.register(auth0_token, key, &challenge, device_name)
            .await?;
        self.issue_token(auth0_token, key, None, None, ttl).await
    }

    async fn post<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        auth0_token: &str,
        pop: Option<&pop::PopHeaders>,
        body: Value,
    ) -> Result<R, IdentityError> {
        let bytes = serde_json::to_vec(&body).expect("json body serializes");
        self.post_bytes(path, auth0_token, pop, bytes).await
    }

    async fn post_bytes<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        auth0_token: &str,
        pop: Option<&pop::PopHeaders>,
        body: Vec<u8>,
    ) -> Result<R, IdentityError> {
        let mut headers = vec![
            ("authorization".to_owned(), format!("Bearer {auth0_token}")),
            ("content-type".to_owned(), "application/json".to_owned()),
        ];
        if let Some(pop) = pop {
            headers.extend(
                pop.as_pairs()
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned())),
            );
        }
        let resp = self.transport.send("POST", path, &headers, body).await?;
        if !(200..300).contains(&resp.status) {
            return Err(IdentityError::Api {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
            });
        }
        serde_json::from_slice(&resp.body).map_err(|e| IdentityError::Api {
            status: resp.status,
            body: format!("invalid response JSON: {e}"),
        })
    }
}

/// Sign a registration/refresh challenge (spec §4.3): a base64url(DER)
/// signature over the concatenation `challenge ‖ endpoint_id ‖ timestamp`.
pub fn sign_challenge(
    key: &EndpointKey,
    challenge: &str,
    endpoint_id: &str,
    timestamp: &str,
) -> String {
    key.sign_b64url(&signed_message(challenge, endpoint_id, timestamp))
}

fn signed_message(challenge: &str, endpoint_id: &str, timestamp: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(challenge.len() + endpoint_id.len() + timestamp.len());
    buf.extend_from_slice(challenge.as_bytes());
    buf.extend_from_slice(endpoint_id.as_bytes());
    buf.extend_from_slice(timestamp.as_bytes());
    buf
}

fn now_rfc3339() -> Result<String, IdentityError> {
    OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .map_err(|_| IdentityError::Time)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::Signature;
    use p256::ecdsa::signature::Verifier;

    #[test]
    fn challenge_signature_is_der_and_verifies() {
        let key = EndpointKey::generate();
        let endpoint_id = key.endpoint_id();
        let sig_b64 = sign_challenge(&key, "chal-value", &endpoint_id, "2026-07-13T00:00:00Z");
        let der = URL_SAFE_NO_PAD.decode(sig_b64).unwrap();
        let sig = Signature::from_der(&der).unwrap();
        let public = p256::PublicKey::from_jwk_str(&key.public_jwk().to_string()).unwrap();
        let vk = p256::ecdsa::VerifyingKey::from(public);
        let msg = signed_message("chal-value", &endpoint_id, "2026-07-13T00:00:00Z");
        assert!(vk.verify(&msg, &sig).is_ok());
    }

    #[test]
    fn deserializes_token_response() {
        let json = r#"{"endpoint_token":"eyJ...","token_type":"Bearer","expires_in":900,
            "endpoint_id":"ep:abc","permissions":["peer-connect:initiate"],
            "protocols":["isekai-validator-v1"]}"#;
        let tok: EndpointToken = serde_json::from_str(json).unwrap();
        assert_eq!(tok.endpoint_token, "eyJ...");
        assert_eq!(tok.expires_in, 900);
        assert_eq!(tok.permissions, vec!["peer-connect:initiate"]);
    }
}
