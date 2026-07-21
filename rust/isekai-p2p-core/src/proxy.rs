//! MASQUE proxy P2P control-plane client (spec §8.3–§8.5).
//!
//! Drives the proxy's Private Peer endpoints (Peer Listeners, Capabilities,
//! Peer Connect, connection state) with the Endpoint Token (`Bearer`) plus a
//! Proof-of-Possession over each request.
//!
//! The client logic is **transport-agnostic**: it builds requests, signs PoP
//! and parses responses/errors, delegating the actual HTTP/3 exchange to a
//! [`ControlPlaneTransport`]. The proxy's P2P routes are HTTP/3-only, so the
//! production transport is msquic-based (`channel-masque`, wired by the binary);
//! keeping it behind a trait lets the logic be unit-tested without the msquic
//! stack.

use serde::{Deserialize, Serialize};

use crate::endpoint::EndpointKey;
use crate::pop;

/// A raw HTTP response from the control plane.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Performs a single HTTP request/response against the proxy control plane.
pub trait ControlPlaneTransport {
    /// Send `method path` with `headers` and `body`, returning the response.
    fn send(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> impl std::future::Future<Output = anyhow::Result<HttpResponse>> + Send;
}

/// An RFC 9457 problem-details error body (spec §8.0).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Problem {
    #[serde(rename = "type")]
    pub type_uri: String,
    #[serde(default)]
    pub title: String,
    pub status: u16,
    #[serde(default)]
    pub detail: Option<String>,
}

impl Problem {
    /// The error `type` slug (last path segment), e.g. `capability-invalid`.
    pub fn kind(&self) -> &str {
        self.type_uri.rsplit('/').next().unwrap_or(&self.type_uri)
    }
}

/// Errors from control-plane calls.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("transport error: {0}")]
    Transport(anyhow::Error),
    #[error("failed to decode response: {0}")]
    Decode(serde_json::Error),
    #[error("proxy returned status {status}{}", .problem.as_ref().map(|p| format!(" ({})", p.kind())).unwrap_or_default())]
    Problem {
        status: u16,
        problem: Option<Problem>,
    },
}

// ---- Candidates & DTOs (mirror the proxy handlers) ----------------------

/// Candidate type (spec §8.5.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidateType {
    Host,
    Srflx,
    Relay,
}

/// A connection candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub r#type: CandidateType,
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerListener {
    pub listener_id: String,
    pub owner_endpoint: String,
    pub protocol: String,
    pub visibility: String,
    pub status: String,
    pub created_at: String,
    pub expires_at: String,
    #[serde(default)]
    pub active_capabilities: Option<i64>,
    #[serde(default)]
    pub active_connections: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    pub capability_id: String,
    /// The opaque token — hand this to the initiator out of band.
    pub capability: String,
    pub listener_id: String,
    pub owner_endpoint: String,
    pub allowed_endpoint: String,
    pub protocol: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayInfo {
    pub masque_uri: String,
    pub session_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnection {
    pub connection_id: String,
    pub state: String,
    pub listener_id: String,
    pub protocol: String,
    #[serde(default)]
    pub peer_endpoint: Option<String>,
    #[serde(default)]
    pub relay: Option<RelayInfo>,
    #[serde(default)]
    pub relay_session_id: Option<String>,
    #[serde(default)]
    pub candidates: Vec<Candidate>,
    #[serde(default)]
    pub peer_candidates: Vec<Candidate>,
    #[serde(default)]
    pub established_at: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub updated_at: Option<String>,
}

/// The P2P control-plane client.
pub struct ProxyClient<T> {
    transport: T,
    key: EndpointKey,
    endpoint_token: String,
}

impl<T: ControlPlaneTransport> ProxyClient<T> {
    /// Create a client with an HTTP/3 transport, the Endpoint key (for PoP) and
    /// the Endpoint Token obtained from the Identity API.
    pub fn new(transport: T, key: EndpointKey, endpoint_token: impl Into<String>) -> Self {
        Self {
            transport,
            key,
            endpoint_token: endpoint_token.into(),
        }
    }

    /// `POST /v1/peer-listeners` (spec §8.3.1).
    pub async fn create_peer_listener(
        &self,
        protocol: &str,
        ttl: Option<u64>,
    ) -> Result<PeerListener, ProxyError> {
        let body = serde_json::json!({ "protocol": protocol, "ttl": ttl });
        self.request_json("POST", "/v1/peer-listeners", to_vec(&body))
            .await
    }

    /// `GET /v1/peer-listeners/{id}` (spec §8.3.2).
    pub async fn get_peer_listener(&self, listener_id: &str) -> Result<PeerListener, ProxyError> {
        self.request_json(
            "GET",
            &format!("/v1/peer-listeners/{listener_id}"),
            Vec::new(),
        )
        .await
    }

    /// `DELETE /v1/peer-listeners/{id}` (spec §8.3.3).
    pub async fn delete_peer_listener(&self, listener_id: &str) -> Result<(), ProxyError> {
        self.request_empty(
            "DELETE",
            &format!("/v1/peer-listeners/{listener_id}"),
            Vec::new(),
        )
        .await
    }

    /// `POST /v1/peer-listeners/{id}/capability` (spec §8.4.1).
    pub async fn issue_capability(
        &self,
        listener_id: &str,
        allowed_endpoint: &str,
        protocol: &str,
        ttl: Option<u64>,
    ) -> Result<Capability, ProxyError> {
        let body = serde_json::json!({
            "allowed_endpoint": allowed_endpoint, "protocol": protocol, "ttl": ttl,
        });
        self.request_json(
            "POST",
            &format!("/v1/peer-listeners/{listener_id}/capability"),
            to_vec(&body),
        )
        .await
    }

    /// `POST /v1/peer/connect` (spec §8.5.1).
    pub async fn peer_connect(
        &self,
        capability: &str,
        listener_id: &str,
        protocol: &str,
        candidates: &[Candidate],
    ) -> Result<PeerConnection, ProxyError> {
        let body = serde_json::json!({
            "capability": capability,
            "listener_id": listener_id,
            "protocol": protocol,
            "candidates": candidates,
        });
        self.request_json("POST", "/v1/peer/connect", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/connections/{id}` (spec §8.5.2).
    pub async fn get_connection(&self, connection_id: &str) -> Result<PeerConnection, ProxyError> {
        self.request_json(
            "GET",
            &format!("/v1/peer/connections/{connection_id}"),
            Vec::new(),
        )
        .await
    }

    /// `POST /v1/peer/connections/{id}/state` (Q-2).
    pub async fn report_state(
        &self,
        connection_id: &str,
        state: &str,
        candidates: &[Candidate],
    ) -> Result<PeerConnection, ProxyError> {
        let body = serde_json::json!({ "state": state, "candidates": candidates });
        self.request_json(
            "POST",
            &format!("/v1/peer/connections/{connection_id}/state"),
            to_vec(&body),
        )
        .await
    }

    // ---- request plumbing ----

    fn auth_headers(&self, method: &str, path: &str, body: &[u8]) -> Vec<(String, String)> {
        let pop = pop::sign_request(&self.key, method, path, body);
        let mut headers = vec![
            (
                "authorization".to_owned(),
                format!("Bearer {}", self.endpoint_token),
            ),
            ("content-type".to_owned(), "application/json".to_owned()),
        ];
        for (name, value) in pop.as_pairs() {
            headers.push((name.to_owned(), value.to_owned()));
        }
        headers
    }

    async fn send(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<HttpResponse, ProxyError> {
        let headers = self.auth_headers(method, path, &body);
        self.transport
            .send(method, path, &headers, body)
            .await
            .map_err(ProxyError::Transport)
    }

    async fn request_json<R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<R, ProxyError> {
        let resp = self.send(method, path, body).await?;
        if (200..300).contains(&resp.status) {
            serde_json::from_slice(&resp.body).map_err(ProxyError::Decode)
        } else {
            Err(problem_error(&resp))
        }
    }

    async fn request_empty(
        &self,
        method: &str,
        path: &str,
        body: Vec<u8>,
    ) -> Result<(), ProxyError> {
        let resp = self.send(method, path, body).await?;
        if (200..300).contains(&resp.status) {
            Ok(())
        } else {
            Err(problem_error(&resp))
        }
    }
}

fn to_vec(value: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(value).expect("json body serializes")
}

fn problem_error(resp: &HttpResponse) -> ProxyError {
    ProxyError::Problem {
        status: resp.status,
        problem: serde_json::from_slice(&resp.body).ok(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// A captured request: (method, path, headers, body).
    type Call = (String, String, Vec<(String, String)>, Vec<u8>);

    #[derive(Default)]
    struct MockTransport {
        calls: Mutex<Vec<Call>>,
        responses: Mutex<Vec<HttpResponse>>,
    }

    impl MockTransport {
        fn with_response(status: u16, body: &str) -> Self {
            let m = MockTransport::default();
            m.responses.lock().unwrap().push(HttpResponse {
                status,
                body: body.as_bytes().to_vec(),
            });
            m
        }
    }

    impl ControlPlaneTransport for MockTransport {
        async fn send(
            &self,
            method: &str,
            path: &str,
            headers: &[(String, String)],
            body: Vec<u8>,
        ) -> anyhow::Result<HttpResponse> {
            self.calls.lock().unwrap().push((
                method.to_owned(),
                path.to_owned(),
                headers.to_vec(),
                body,
            ));
            Ok(self
                .responses
                .lock()
                .unwrap()
                .pop()
                .unwrap_or(HttpResponse {
                    status: 500,
                    body: Vec::new(),
                }))
        }
    }

    fn client(transport: MockTransport) -> (ProxyClient<MockTransport>, EndpointKey) {
        let key = EndpointKey::generate();
        (
            ProxyClient::new(transport, key.clone(), "ENDPOINT.TOKEN"),
            key,
        )
    }

    fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(n, _)| n == name)
            .map(|(_, v)| v.as_str())
    }

    #[tokio::test]
    async fn peer_connect_signs_and_parses() {
        let resp = r#"{"connection_id":"conn_1","state":"relay","listener_id":"pl_1",
            "protocol":"isekai-validator-v1","peer_endpoint":"ep:B",
            "relay":{"masque_uri":"https://p/.well-known/masque/udp/relay/sess_1/","session_id":"sess_1"},
            "peer_candidates":[],"created_at":"t","expires_at":"t"}"#;
        let (client, key) = client(MockTransport::with_response(201, resp));

        let candidates = vec![Candidate {
            r#type: CandidateType::Srflx,
            address: "203.0.113.10".into(),
            port: 41000,
        }];
        let conn = client
            .peer_connect("cap_x", "pl_1", "isekai-validator-v1", &candidates)
            .await
            .unwrap();
        assert_eq!(conn.connection_id, "conn_1");
        assert_eq!(conn.state, "relay");
        assert_eq!(conn.relay.unwrap().session_id, "sess_1");

        // The request carried the Endpoint Token and a PoP over POST /v1/peer/connect.
        let calls = client.transport.calls.lock().unwrap();
        let (method, path, headers, body) = &calls[0];
        assert_eq!(method, "POST");
        assert_eq!(path, "/v1/peer/connect");
        assert_eq!(
            header(headers, "authorization").unwrap(),
            "Bearer ENDPOINT.TOKEN"
        );
        assert_eq!(header(headers, "x-endpoint-id").unwrap(), key.endpoint_id());
        assert!(header(headers, "x-pop-signature").is_some());
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["capability"], "cap_x");
        assert_eq!(sent["candidates"][0]["type"], "srflx");
    }

    #[tokio::test]
    async fn error_response_maps_to_problem() {
        let resp = r#"{"type":"https://proxy.isekai.link/problems/capability-invalid",
            "title":"Capability is invalid","status":403}"#;
        let (client, _key) = client(MockTransport::with_response(403, resp));
        let err = client
            .peer_connect("bad", "pl_1", "isekai-validator-v1", &[])
            .await
            .unwrap_err();
        match err {
            ProxyError::Problem { status, problem } => {
                assert_eq!(status, 403);
                assert_eq!(problem.unwrap().kind(), "capability-invalid");
            }
            other => panic!("expected Problem, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn delete_accepts_204_no_content() {
        let (client, _key) = client(MockTransport::with_response(204, ""));
        client.delete_peer_listener("pl_1").await.unwrap();
        let calls = client.transport.calls.lock().unwrap();
        assert_eq!(calls[0].0, "DELETE");
        assert_eq!(calls[0].1, "/v1/peer-listeners/pl_1");
    }
}
