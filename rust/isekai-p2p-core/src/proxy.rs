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

/// A per-endpoint relay TLS certificate downloaded from the proxy
/// (`GET /v1/peer/certificate`). The listener presents it on the video QUIC so
/// the initiator, dialing the matching [`PeerConnection::video_host`] FQDN, can
/// validate it instead of skipping certificate checks.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertBundle {
    /// The FQDN the certificate is issued for (resolves to loopback).
    pub hostname: String,
    /// PEM-encoded certificate chain.
    pub cert_pem: String,
    /// PEM-encoded private key.
    pub key_pem: String,
    /// Base64 (standard) PKCS#12 bundle, for platforms (Windows/Schannel) that
    /// load credentials from a PKCS#12 blob rather than PEM. Empty when absent.
    #[serde(default)]
    pub pkcs12: String,
}

/// A standing authorization for one Endpoint to reach one listener (spec §8.8).
///
/// Where a [`Capability`] is a one-shot token the owner has to carry to the
/// initiator, a grant is a record the owner keeps: it authorizes the same
/// Endpoint repeatedly and is revoked by deleting it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Grant {
    pub grant_id: String,
    /// The Endpoint being reached. Not a listener — see [`ProxyClient::create_grant`].
    pub owner_endpoint: String,
    pub allowed_endpoint: String,
    pub protocol: String,
    /// `manual`, `pairing` or `owner_match` — how this grant came to exist.
    pub origin: String,
    #[serde(default)]
    pub label: Option<String>,
    pub created_at: String,
    /// Absent means it stands until revoked.
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct GrantList {
    grants: Vec<Grant>,
}

/// A pairing code to display (spec §8.9.1). Returned once and not re-fetchable.
#[derive(Debug, Clone, Deserialize)]
pub struct PairingCode {
    /// Eight characters, shown as `XXXX-XXXX`.
    pub code: String,
    /// The Endpoint whoever redeems this will be let in to.
    pub owner_endpoint: String,
    pub protocol: String,
    pub expires_at: String,
}

/// The URI scheme a pairing QR carries.
///
/// A QR holding the bare code scans to eight characters and nothing happens —
/// the phone shows the text and the person still has to find the app and type
/// it. A URI is what lets the scan land somewhere. This is settled here rather
/// than at each display site so the desktop apps and the mobile ones agree on
/// it before the mobile QR capture exists to disagree.
const PAIRING_SCHEME: &str = "isekai://pair?code=";

/// What to put in a pairing QR for [`code`](PairingCode::code).
pub fn pairing_uri(code: &str) -> String {
    // The code alphabet is digits and uppercase letters plus the display dash,
    // so there is nothing here that needs escaping.
    format!("{PAIRING_SCHEME}{code}")
}

/// Recover a pairing code from whatever was scanned, pasted or typed.
///
/// Accepts both the URI and the bare code, because those are the two things
/// that end up in the field: one from a scanner, one from someone reading the
/// screen. Neither is validated beyond the shape — the proxy decides whether a
/// code is real, and this only has to stop the scheme prefix from being sent as
/// part of it.
pub fn pairing_code_from_input(input: &str) -> String {
    let trimmed = input.trim();
    match trimmed.strip_prefix(PAIRING_SCHEME) {
        // A scanner may append a fragment or further parameters; the code runs
        // to the first thing that could not be part of one.
        Some(rest) => rest
            .split(['&', '#'])
            .next()
            .unwrap_or(rest)
            .trim()
            .to_owned(),
        None => trimmed.to_owned(),
    }
}

/// A connection state to filter a listing by (spec §8.5.2).
///
/// Typed rather than a string because the proxy answers `400` to anything it
/// does not recognise — a set fixed by the spec is better spelled out than
/// spelled wrong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionStateFilter {
    Relay,
    HolePunching,
    Direct,
    Closed,
    Failed,
}

impl ConnectionStateFilter {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Relay => "relay",
            Self::HolePunching => "hole_punching",
            Self::Direct => "direct",
            Self::Closed => "closed",
            Self::Failed => "failed",
        }
    }
}

/// A listener this Endpoint can reach or enrol on (spec §8.10).
#[derive(Debug, Clone, Deserialize)]
pub struct ReachableListener {
    pub listener_id: String,
    /// The Endpoint running it. Unlike `listener_id` this survives a restart,
    /// so it is what identifies the device a grant was made against.
    pub owner_endpoint: String,
    pub protocol: String,
    /// Whatever the owner put there — typically a display name.
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    pub expires_at: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReachableListenerList {
    listeners: Vec<ReachableListener>,
}

impl PeerConnection {
    /// Who is on the other end, from `caller`'s point of view.
    ///
    /// Which field carries it depends on which call produced this: the connect
    /// response names the peer directly, while the reads name both parties and
    /// leave it to the reader to work out which one it is not. Asking here
    /// keeps callers from having to know that.
    pub fn other_party(&self, caller: &str) -> Option<&str> {
        if let Some(peer) = self.peer_endpoint.as_deref() {
            return Some(peer);
        }
        match (
            self.initiator_endpoint.as_deref(),
            self.target_endpoint.as_deref(),
        ) {
            (Some(initiator), Some(target)) if initiator == caller => Some(target),
            (Some(initiator), Some(_)) => Some(initiator),
            (Some(initiator), None) => Some(initiator),
            (None, other) => other,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
struct ConnectionList {
    connections: Vec<PeerConnection>,
    /// Set when the proxy cut the list short (spec §8.5.3).
    #[serde(default)]
    truncated: bool,
}

/// What listing a listener's connections found.
#[derive(Debug, Clone)]
pub struct ListenerConnections {
    pub connections: Vec<PeerConnection>,
    /// The proxy had more than it would return. Whoever is waiting beyond the
    /// cut is not in `connections`, so this must not be treated as "all of
    /// them" (spec §8.5.3).
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConnection {
    pub connection_id: String,
    pub state: String,
    pub listener_id: String,
    pub protocol: String,
    /// The other party, as `POST /v1/peer/connect` names it. **Only that
    /// response carries it** — the connection reads (`GET /v1/peer/connections/{id}`
    /// and the listener's listing) name both parties explicitly instead, so
    /// this is `None` there. Use [`Self::other_party`] rather than reaching for
    /// it directly.
    #[serde(default)]
    pub peer_endpoint: Option<String>,
    /// Present on the connection reads (spec §8.5.1, §8.5.3).
    #[serde(default)]
    pub initiator_endpoint: Option<String>,
    /// Present on the connection reads (spec §8.5.1, §8.5.3).
    #[serde(default)]
    pub target_endpoint: Option<String>,
    #[serde(default)]
    pub relay: Option<RelayInfo>,
    #[serde(default)]
    pub relay_session_id: Option<String>,
    /// The loopback FQDN the initiator should dial for the video QUIC over the
    /// relay, so it can validate the per-endpoint certificate the listener
    /// downloaded. `None` when the proxy has relay certificates disabled — in
    /// that case the initiator falls back to dialing `127.0.0.1` unvalidated.
    #[serde(default)]
    pub video_host: Option<String>,
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
#[derive(Clone)]
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

    /// `POST /v1/peer/connections/{id}/state` (spec §8.5.2).
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

    /// Push a connection's lease out without saying anything about it
    /// (spec §8.5.4).
    ///
    /// A connection is leased for `--p2p-connect-ttl-secs` and reaped when that
    /// runs out, which is how a connect nobody followed through on is cleaned
    /// up. A party that is still using one has to say so before then, or the
    /// TTL becomes the longest two peers may stay connected — five minutes, by
    /// default, however well it is going.
    ///
    /// Neither the state nor the candidates are sent: an empty body leaves both
    /// as they are, so this cannot walk a connection that has reached `direct`
    /// back to where this caller last knew it was.
    pub async fn renew_connection(
        &self,
        connection_id: &str,
    ) -> Result<PeerConnection, ProxyError> {
        self.request_json(
            "POST",
            &format!("/v1/peer/connections/{connection_id}/state"),
            to_vec(&serde_json::json!({})),
        )
        .await
    }

    /// `POST /v1/peer/grants` (spec §8.8.1).
    ///
    /// The caller is the owner, and no listener is named: a grant authorizes
    /// reaching **this Endpoint** over one protocol, through whichever listener
    /// it happens to be running. That is what lets an app be restarted without
    /// everyone it let in having to pair again.
    ///
    /// `ttl` omitted means the grant stands until revoked, which is the usual
    /// case — a dated grant is closer to a capability.
    pub async fn create_grant(
        &self,
        allowed_endpoint: &str,
        protocol: &str,
        ttl: Option<u64>,
        label: Option<&str>,
    ) -> Result<Grant, ProxyError> {
        let body = serde_json::json!({
            "allowed_endpoint": allowed_endpoint,
            "protocol": protocol,
            "ttl": ttl,
            "label": label,
        });
        self.request_json("POST", "/v1/peer/grants", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/grants` (spec §8.8.2) — everyone this Endpoint has let in.
    pub async fn list_grants(&self) -> Result<Vec<Grant>, ProxyError> {
        let list: GrantList = self
            .request_json("GET", "/v1/peer/grants", Vec::new())
            .await?;
        Ok(list.grants)
    }

    /// `DELETE /v1/peer/grants/{grant_id}` (spec §8.8.3).
    ///
    /// Takes effect on the peer's next connect; anything already established
    /// stays up.
    pub async fn revoke_grant(&self, grant_id: &str) -> Result<(), ProxyError> {
        self.request_empty("DELETE", &format!("/v1/peer/grants/{grant_id}"), Vec::new())
            .await
    }

    /// `POST /v1/peer/pairing-codes` (spec §8.9.1).
    ///
    /// Issuing one invalidates this Endpoint's previous code for the same
    /// protocol — there is only ever one, because the owner is showing it on
    /// one screen. No listener is needed: someone can pair with a camera that
    /// is switched off and connect when it comes back.
    pub async fn create_pairing_code(
        &self,
        protocol: &str,
        ttl: Option<u64>,
    ) -> Result<PairingCode, ProxyError> {
        let body = serde_json::json!({ "protocol": protocol, "ttl": ttl });
        self.request_json("POST", "/v1/peer/pairing-codes", to_vec(&body))
            .await
    }

    /// `GET /v1/peer-listeners/{id}/connections` (spec §8.5.3).
    ///
    /// How a listener finds out someone is waiting for it. `state` filters to
    /// one of the connection states; `Some("relay")` is what a listener that
    /// wants to bind is looking for.
    pub async fn list_listener_connections(
        &self,
        listener_id: &str,
        state: Option<ConnectionStateFilter>,
    ) -> Result<ListenerConnections, ProxyError> {
        let path = match state {
            Some(state) => format!(
                "/v1/peer-listeners/{listener_id}/connections?state={}",
                state.as_str()
            ),
            None => format!("/v1/peer-listeners/{listener_id}/connections"),
        };
        let list: ConnectionList = self.request_json("GET", &path, Vec::new()).await?;
        Ok(ListenerConnections {
            connections: list.connections,
            truncated: list.truncated,
        })
    }

    /// `POST /v1/peer/pair` with a code the owner displayed (spec §8.9.2).
    pub async fn pair_with_code(
        &self,
        code: &str,
        label: Option<&str>,
    ) -> Result<Grant, ProxyError> {
        let body = serde_json::json!({ "code": code, "label": label });
        self.request_json("POST", "/v1/peer/pair", to_vec(&body))
            .await
    }

    /// `POST /v1/peer/pair` on a listener of this Endpoint's own account
    /// (spec §8.9.3). Only listeners the owner opened to self-enrolment accept
    /// this, and they are the ones [`Self::list_enrollable_listeners`] returns.
    pub async fn pair_with_listener(
        &self,
        listener_id: &str,
        label: Option<&str>,
    ) -> Result<Grant, ProxyError> {
        let body = serde_json::json!({ "listener_id": listener_id, "label": label });
        self.request_json("POST", "/v1/peer/pair", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/listeners` — what this Endpoint may connect to now.
    pub async fn list_reachable_listeners(&self) -> Result<Vec<ReachableListener>, ProxyError> {
        let list: ReachableListenerList = self
            .request_json("GET", "/v1/peer/listeners", Vec::new())
            .await?;
        Ok(list.listeners)
    }

    /// `GET /v1/peer/listeners?scope=owned` — what it may *enrol on*.
    ///
    /// Being in this list is not permission to connect: pairing with one
    /// produces the grant that is (spec §8.10).
    pub async fn list_enrollable_listeners(&self) -> Result<Vec<ReachableListener>, ProxyError> {
        let list: ReachableListenerList = self
            .request_json("GET", "/v1/peer/listeners?scope=owned", Vec::new())
            .await?;
        Ok(list.listeners)
    }

    /// `POST /v1/peer/connect` authorized by a grant rather than a capability
    /// (spec §8.4). Nothing has to be carried to the initiator for this.
    pub async fn peer_connect_with_grant(
        &self,
        listener_id: &str,
        protocol: &str,
        candidates: &[Candidate],
    ) -> Result<PeerConnection, ProxyError> {
        let body = serde_json::json!({
            "listener_id": listener_id,
            "protocol": protocol,
            "candidates": candidates,
        });
        self.request_json("POST", "/v1/peer/connect", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/certificate` — download this Endpoint's per-endpoint relay
    /// TLS certificate. Returns `Ok(None)` when the proxy has relay certificates
    /// disabled (HTTP 404), so the caller can fall back to a dev certificate.
    pub async fn get_certificate(&self) -> Result<Option<CertBundle>, ProxyError> {
        let resp = self.send("GET", "/v1/peer/certificate", Vec::new()).await?;
        match resp.status {
            404 => Ok(None),
            s if (200..300).contains(&s) => serde_json::from_slice(&resp.body)
                .map(Some)
                .map_err(ProxyError::Decode),
            _ => Err(problem_error(&resp)),
        }
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

    /// The shape of what goes out matters more than the plumbing: the server
    /// decides what a request means from these fields, and a rename on either
    /// side is otherwise only found on a device.
    #[tokio::test]
    async fn pairing_sends_the_two_shapes_the_proxy_distinguishes() {
        let body = r#"{"grant_id":"gr_1","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"pairing",
            "created_at":"2026-08-02T09:00:00Z"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let grant = client
            .pair_with_code("K7M2-QX4P", Some("laptop"))
            .await
            .unwrap();
        assert_eq!(grant.origin, "pairing");
        assert_eq!(
            grant.owner_endpoint, "ep:B",
            "the grant names the Endpoint let in to, not a listener"
        );
        assert_eq!(
            grant.expires_at, None,
            "a paired grant stands until revoked"
        );

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!((method.as_str(), path.as_str()), ("POST", "/v1/peer/pair"));
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["code"], "K7M2-QX4P");
        assert_eq!(sent["label"], "laptop");
        assert!(sent["listener_id"].is_null(), "a code is not a listener id");
    }

    /// The other pairing shape, and that an absent label is sent as null rather
    /// than as the string "null" or omitted.
    #[tokio::test]
    async fn enrolling_names_the_listener_and_sends_a_null_label() {
        let body = r#"{"grant_id":"gr_2","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"owner_match",
            "created_at":"2026-08-02T09:00:00Z"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        client.pair_with_listener("pl_1", None).await.unwrap();

        let calls = client.transport.calls.lock().unwrap();
        let sent: serde_json::Value = serde_json::from_slice(&calls.last().unwrap().3).unwrap();
        assert_eq!(sent["listener_id"], "pl_1");
        assert!(sent["label"].is_null());
        assert!(sent["code"].is_null());
    }

    /// Grants are the owner's, not a listener's, and the route says so. A
    /// rename on either side is otherwise only found on a device, which is what
    /// this whole change was fixing.
    #[tokio::test]
    async fn granting_names_no_listener() {
        let body = r#"{"grant_id":"gr_1","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"manual",
            "created_at":"2026-08-02T09:00:00Z"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let grant = client
            .create_grant("ep:A", "mjpeg", None, Some("phone"))
            .await
            .unwrap();
        assert_eq!(grant.owner_endpoint, "ep:B");

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/peer/grants")
        );
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["allowed_endpoint"], "ep:A");
        assert_eq!(sent["protocol"], "mjpeg");
        assert!(sent["ttl"].is_null(), "no ttl means until revoked");
    }

    /// A keepalive says nothing about the connection — no state and no
    /// candidates — so the proxy leaves both alone and only moves the deadline.
    /// Sending the state this side last knew about would walk a connection that
    /// had reached `direct` backwards.
    #[tokio::test]
    async fn renewing_a_connection_sends_an_empty_body() {
        let body = r#"{"connection_id":"conn_1","state":"direct","listener_id":"pl_1",
            "initiator_endpoint":"ep:A","target_endpoint":"ep:B","protocol":"mjpeg",
            "candidates":[],"peer_candidates":[],"created_at":"t","expires_at":"t",
            "updated_at":"t"}"#;
        let (client, _key) = client(MockTransport::with_response(200, body));
        let renewed = client.renew_connection("conn_1").await.unwrap();
        assert_eq!(renewed.state, "direct");

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/peer/connections/conn_1/state")
        );
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert!(
            sent["state"].is_null(),
            "a keepalive must not set the state"
        );
        assert!(
            sent["candidates"].is_null(),
            "nor replace the candidates it does not have"
        );
    }

    /// Revocation addresses the grant by id alone; the proxy scopes it to the
    /// caller, so there is no listener to name here either.
    #[tokio::test]
    async fn revoking_addresses_the_grant_by_id_alone() {
        let (client, _key) = client(MockTransport::with_response(204, ""));
        client.revoke_grant("gr_1").await.unwrap();
        let calls = client.transport.calls.lock().unwrap();
        let (method, path, ..) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("DELETE", "/v1/peer/grants/gr_1")
        );
    }

    /// A code is minted against the Endpoint and a protocol, with no listener
    /// in the path or the body.
    #[tokio::test]
    async fn a_pairing_code_is_minted_against_the_endpoint() {
        let body = r#"{"code":"K7M2-QX4P","owner_endpoint":"ep:B","protocol":"mjpeg",
            "expires_at":"2026-08-02T09:05:00Z"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let issued = client
            .create_pairing_code("mjpeg", Some(120))
            .await
            .unwrap();
        assert_eq!(issued.code, "K7M2-QX4P");
        assert_eq!(issued.owner_endpoint, "ep:B");

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/peer/pairing-codes")
        );
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["protocol"], "mjpeg");
        assert_eq!(sent["ttl"], 120);
    }

    /// A listing has to carry the owner Endpoint: it is what stays the same
    /// when the camera restarts and the listener id does not.
    #[tokio::test]
    async fn a_reachable_listener_names_the_endpoint_running_it() {
        let body = r#"{"listeners":[{"listener_id":"pl_new","owner_endpoint":"ep:B",
            "protocol":"mjpeg","metadata":{"label":"居間のカメラ"},
            "expires_at":"2026-08-02T10:00:00Z"}]}"#;
        let (client, _key) = client(MockTransport::with_response(200, body));
        let found = client.list_reachable_listeners().await.unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].listener_id, "pl_new");
        assert_eq!(found[0].owner_endpoint, "ep:B");
    }

    /// The filter goes in the query string, and a truncated answer has to
    /// survive the round trip — a listener that misses it believes it has seen
    /// everyone waiting.
    #[tokio::test]
    async fn listing_connections_filters_by_state_and_keeps_truncated() {
        let body = r#"{"connections":[{"connection_id":"conn_1","state":"relay",
            "listener_id":"pl_1","initiator_endpoint":"ep:A","target_endpoint":"ep:B",
            "protocol":"mjpeg","candidates":[],"peer_candidates":[],
            "created_at":"2026-08-02T09:00:00Z","expires_at":"2026-08-02T09:05:00Z",
            "updated_at":"2026-08-02T09:00:00Z"}],"truncated":true}"#;
        let (client, _key) = client(MockTransport::with_response(200, body));
        let listing = client
            .list_listener_connections("pl_1", Some(ConnectionStateFilter::Relay))
            .await
            .unwrap();

        assert!(listing.truncated);
        assert_eq!(listing.connections.len(), 1);
        // The listing names both parties; the listener is the target.
        assert_eq!(listing.connections[0].other_party("ep:B"), Some("ep:A"));

        let calls = client.transport.calls.lock().unwrap();
        assert_eq!(
            calls.last().unwrap().1,
            "/v1/peer-listeners/pl_1/connections?state=relay"
        );
    }

    /// Omitting the filter must not send an empty one — the proxy answers 400
    /// to a `?state` with no value.
    #[tokio::test]
    async fn listing_connections_without_a_filter_sends_no_query() {
        let (client, _key) = client(MockTransport::with_response(200, r#"{"connections":[]}"#));
        let listing = client
            .list_listener_connections("pl_1", None)
            .await
            .unwrap();
        assert!(!listing.truncated, "absent means not truncated");

        let calls = client.transport.calls.lock().unwrap();
        assert_eq!(
            calls.last().unwrap().1,
            "/v1/peer-listeners/pl_1/connections"
        );
    }

    #[tokio::test]
    async fn connecting_on_a_grant_sends_no_capability() {
        let body = r#"{"connection_id":"conn_1","state":"relay","listener_id":"pl_1",
            "peer_endpoint":"ep:B","protocol":"mjpeg"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        client
            .peer_connect_with_grant("pl_1", "mjpeg", &[])
            .await
            .unwrap();

        let calls = client.transport.calls.lock().unwrap();
        let sent: serde_json::Value = serde_json::from_slice(&calls.last().unwrap().3).unwrap();
        assert!(
            sent.get("capability").is_none(),
            "sending a null capability would be a capability the proxy has to reject"
        );
        assert_eq!(sent["listener_id"], "pl_1");
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

    #[tokio::test]
    async fn get_certificate_parses_bundle() {
        let resp = r#"{"hostname":"e0123.relay.example","cert_pem":"-CERT-",
            "key_pem":"-KEY-","pkcs12":"AAAA"}"#;
        let (client, _key) = client(MockTransport::with_response(200, resp));
        let bundle = client
            .get_certificate()
            .await
            .unwrap()
            .expect("Some bundle");
        assert_eq!(bundle.hostname, "e0123.relay.example");
        assert_eq!(bundle.cert_pem, "-CERT-");
        assert_eq!(bundle.key_pem, "-KEY-");
        let calls = client.transport.calls.lock().unwrap();
        assert_eq!(calls[0].0, "GET");
        assert_eq!(calls[0].1, "/v1/peer/certificate");
    }

    #[tokio::test]
    async fn get_certificate_maps_404_to_none() {
        let (client, _key) = client(MockTransport::with_response(
            404,
            "relay certificates not configured",
        ));
        assert!(client.get_certificate().await.unwrap().is_none());
    }

    /// What a QR holds has to come back out of the field it is scanned into,
    /// and so does what someone reads off the screen instead.
    #[test]
    fn a_pairing_code_survives_the_uri_it_is_scanned_from() {
        let uri = pairing_uri("K7M2-QX4P");
        assert_eq!(uri, "isekai://pair?code=K7M2-QX4P");
        for input in [
            uri.as_str(),
            " isekai://pair?code=K7M2-QX4P ",
            "isekai://pair?code=K7M2-QX4P&v=1",
            "isekai://pair?code=K7M2-QX4P#x",
            "K7M2-QX4P",
            "  K7M2-QX4P  ",
        ] {
            assert_eq!(pairing_code_from_input(input), "K7M2-QX4P", "{input:?}");
        }
    }

    /// Anything else is passed through for the proxy to reject, rather than
    /// guessed at here.
    #[test]
    fn input_that_is_not_a_pairing_uri_is_left_alone() {
        assert_eq!(pairing_code_from_input("nonsense"), "nonsense");
        assert_eq!(
            pairing_code_from_input("https://example.test/pair?code=K7M2-QX4P"),
            "https://example.test/pair?code=K7M2-QX4P"
        );
    }
}
