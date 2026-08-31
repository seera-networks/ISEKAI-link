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

use base64::Engine as _;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, RwLock};
use tokio::sync::mpsc;

use crate::attestation::Attestation;
use crate::endpoint::EndpointKey;
use crate::pop;

/// A raw HTTP response from the control plane.
#[derive(Debug, Clone, Default)]
pub struct HttpResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// Response headers, lowercased names.
    ///
    /// **Carried because `Retry-After` lives here and nowhere else.** Both
    /// servers put the wait for `429 …-slots-exhausted` and `503
    /// …-unavailable` in the header and not in the problem body, and both
    /// specs ask the client to back off by what it says — §8.8.6 goes as far
    /// as adding the sweep interval to it, precisely so a client that obeys
    /// does not come back to a second `429`. Dropping the headers here meant
    /// no caller could obey.
    pub headers: Vec<(String, String)>,
}

impl HttpResponse {
    /// The first value of `name`, which is matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// `Retry-After` as a duration, when it is the delta-seconds form.
    ///
    /// The HTTP-date form is not parsed: neither server sends it, and a
    /// half-understood date is worse than no answer — the caller's own backoff
    /// is a sound fallback, a date read as zero is not.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        self.header("retry-after")?
            .trim()
            .parse::<u64>()
            .ok()
            .map(std::time::Duration::from_secs)
    }
}

/// Opens a long-lived response and hands its body back in pieces.
///
/// Separate from [`ControlPlaneTransport`] because it is a different shape, not
/// a different endpoint: everything else here is one request and one buffered
/// answer, and an event stream is one request whose answer never ends. A
/// transport that cannot do this simply does not implement it.
pub trait EventStreamTransport {
    /// Send the request and return its status with a channel of body chunks.
    ///
    /// Chunks arrive as the peer sends them and stop when the response ends.
    /// Dropping the receiver is what tells the transport to give up on the
    /// request, which is how a caller cancels one.
    fn open_stream(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> impl std::future::Future<
        Output = anyhow::Result<(u16, tokio::sync::mpsc::Receiver<anyhow::Result<Vec<u8>>>)>,
    > + Send;
}

/// The longest a single event line may be before the stream is abandoned.
///
/// Generous next to anything §8.11 defines — the largest event carries a few
/// identifiers and a label — so reaching it means the other end is not sending
/// what this expects, which is not a thing to keep buffering for.
const MAX_EVENT_LINE: usize = 64 * 1024;

/// Something that happened to a listener (spec §8.11).
///
/// Deserialized from the stream's lines. An unrecognised `type` is
/// [`Unknown`](Self::Unknown) rather than an error: the proxy may learn to say
/// more than this client knows about, and a listener that fell over on the
/// first unfamiliar line would be worse off than one that ignored it.
#[derive(Debug, Clone, Deserialize)]
#[serde(tag = "type")]
pub enum ListenerEvent {
    #[serde(rename = "peer.connect.created")]
    ConnectCreated {
        connection_id: String,
        #[serde(default)]
        initiator_endpoint: Option<String>,
    },
    #[serde(rename = "peer.connect.closed")]
    ConnectClosed { connection_id: String },
    #[serde(rename = "grant.created")]
    GrantCreated { grant_id: String },
    #[serde(rename = "grant.revoked")]
    GrantRevoked { grant_id: String },
    #[serde(rename = "keepalive")]
    Keepalive,
    #[serde(other)]
    Unknown,
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
    // The `detail` is included, not just the kind. The kind says which rule was
    // broken and the detail says how — `certificate-unavailable` alone cannot
    // tell "an order is already in flight" from "the CA refused", and a caller
    // reading only the kind has to go and ask the proxy's operator for the half
    // of the answer it was already sent.
    #[error("proxy returned status {status}{}", .problem.as_ref().map(|p| match p.detail.as_deref() {
        Some(detail) => format!(" ({}: {detail})", p.kind()),
        None => format!(" ({})", p.kind()),
    }).unwrap_or_default())]
    Problem {
        status: u16,
        problem: Option<Problem>,
        /// What `Retry-After` said, when it said anything.
        ///
        /// **The server's number beats one the caller computes.** A
        /// `429 provisioning-slots-exhausted` carries the wait until the
        /// earliest slot frees, and `503 provisioning-unavailable` the wait for
        /// an issuer's JWKS to come back — neither is derivable from anything
        /// the caller holds.
        retry_after: Option<std::time::Duration>,
    },
}

impl ProxyError {
    /// How long the proxy asked the caller to wait, if it did.
    pub fn retry_after(&self) -> Option<std::time::Duration> {
        match self {
            ProxyError::Problem { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// The problem's kind, for the few decisions that turn on it.
    ///
    /// Most do not: §8.13.6 collapses unknown, expired, revoked and malformed
    /// keys into one `provisioning-key-invalid` on purpose, and a caller that
    /// tries to tell those apart has rebuilt the oracle that uniformity denies.
    /// The ones that do are the exceptions §8.13.6 lists, which say the request
    /// did not stand up rather than that it was refused.
    pub fn kind(&self) -> Option<&str> {
        match self {
            ProxyError::Problem { problem, .. } => problem.as_ref().map(Problem::kind),
            _ => None,
        }
    }
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

/// Which leg of a relay a ticket is for (spec §8.14.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayRole {
    /// The side that ran `peer_connect`. Binds an ephemeral loopback source and
    /// forwards to the edge.
    Initiator,
    /// The listener's side. Binds the edge itself.
    Target,
}

/// **The proxy's signed statement that a relay leg may exist** (spec §8.14.1).
///
/// Presented in `Seera-Relay-Ticket` on the leg's CONNECT-UDP request. Until
/// the proxy shipped §8.14, a leg was authorized by the proxy's own record of
/// having allocated the edge — which works only while its control plane and
/// data path share a process. This is that authorization in a form that can
/// travel, and holding one is what brings the leg into existence.
///
/// # The two times are not the same quantity
///
/// [`expires_at`](Self::expires_at) is how long the *paper* may be presented —
/// tens of seconds, because it goes straight from the proxy to the leg.
/// [`lease_expires_at`](Self::lease_expires_at) is how long the *leg* it buys
/// will live — tens of minutes. **Renewal is timed off the second**; a client
/// that watched the first would re-ticket every half minute for nothing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTicket {
    /// The ES256 JWT itself.
    pub ticket: String,
    pub role: RelayRole,
    /// When this ticket stops being presentable.
    pub expires_at: String,
    /// When the leg it materializes lapses, unless renewed before then.
    pub lease_expires_at: String,
}

/// What `POST /v1/relay/sessions/{id}/renew` answers (spec §8.14.3).
#[derive(Debug, Clone, Deserialize)]
pub struct RelayLease {
    #[allow(dead_code)]
    pub session_id: String,
    pub role: RelayRole,
    /// When the leg now lapses.
    pub lease_expires_at: String,
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

/// What the proxy needs from a caller before it will issue a certificate, and
/// what it currently holds for this Endpoint (spec §8.6.1).
#[derive(Debug, Clone, Deserialize)]
pub struct CertificateParameters {
    /// The FQDN to put in the CSR's SAN.
    ///
    /// **Used verbatim.** The label comes from the Endpoint ID and the domain
    /// from the proxy's `--p2p-cert-domain`, which this side cannot know, so
    /// deriving it here would be reimplementing half an answer the proxy is
    /// already giving.
    pub hostname: String,
    /// The proxy's current certificate domain, for a caller that wants to
    /// derive a *peer's* name. Not needed to issue one's own.
    #[serde(default)]
    pub domain: String,
    /// The key types the proxy will accept (spec §8.6.2 rule 3). What it lists
    /// and what it accepts are the same set, so a key chosen from here cannot
    /// be refused afterwards.
    #[serde(default)]
    pub key_types: Vec<String>,
    /// Whether the proxy will still generate a key on request — the old route.
    /// Reported so a caller can tell "not supported" from "turned off".
    #[serde(default)]
    pub server_key_issuance: bool,
    /// How many issuances this Endpoint has left.
    #[serde(default)]
    pub issue_quota: Option<IssueQuota>,
    /// The certificate the proxy is holding, or `None` if it has never issued
    /// one. Present so a caller can notice its key no longer matches.
    #[serde(default)]
    pub certificate: Option<CachedCertificate>,
}

/// The issuance allowance for one Endpoint (spec §8.6.1).
#[derive(Debug, Clone, Deserialize)]
pub struct IssueQuota {
    pub limit: u32,
    pub window_secs: u64,
    pub remaining: u32,
    #[serde(default)]
    pub reset_at: Option<String>,
}

/// What the proxy has cached for this Endpoint.
#[derive(Debug, Clone, Deserialize)]
pub struct CachedCertificate {
    /// SHA-256 of the certificate's SubjectPublicKeyInfo, base64url.
    pub spki_sha256: String,
    pub not_after: String,
}

/// A certificate issued against a CSR (spec §8.6.2).
///
/// **No key and no PKCS#12, and their absence is the point**: the key stayed on
/// the device, so anything needing a PKCS#12 is assembled by the side holding
/// it.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedCertificate {
    pub hostname: String,
    /// The full chain, leaf first.
    pub cert_pem: String,
    /// SHA-256 of the SubjectPublicKeyInfo, base64url. **Check this against the
    /// local key before using the certificate** — it is also what §8.6.4 will
    /// pin.
    pub spki_sha256: String,
    #[serde(default)]
    pub issued_at: Option<String>,
    #[serde(default)]
    pub not_after: Option<String>,
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
    /// **Only the two fields above are required, and the rest are optional for
    /// the same reason [`TicketListener`] is lax.** A grant arrives from
    /// `POST /v1/peer/tickets/redeem` (§8.12.3), where failing to parse it
    /// means a single-use ticket already spent, a grant already created, and a
    /// caller told the call failed — deterministically, so retrying fails the
    /// same way. An id and the Endpoint it lets you reach are what any of this
    /// needs; a missing `created_at` is not worth that, and the fields below
    /// are shown rather than acted on.
    ///
    /// The spec requires all of them, and this is not a claim that it will not.
    /// It is that the cost of being wrong is paid once and cannot be undone.
    #[serde(default)]
    pub allowed_endpoint: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// `manual`, `pairing`, `owner_match`, `ticket` or `provisioning` — how
    /// this grant came to exist.
    #[serde(default)]
    pub origin: Option<String>,
    /// Which Provisioning Key opened this door. **Only when `origin` is
    /// `provisioning`.**
    ///
    /// Present because revoking a key has to find what it made (§8.13.7), and
    /// because it is how an owner reading a grant list answers "which key let
    /// this in". A Ticket-made grant carries no such id — the reasons differ,
    /// and §8.12.10 leaves that one open.
    #[serde(default)]
    pub provisioning_key_id: Option<String>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
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

/// A Ticket, as returned by issuing one (spec §8.12.2).
///
/// Where a pairing code names the owner and waits for a person to read it off a
/// screen, a Ticket is a 256-bit secret handed over out of band, and **several
/// can be live for the same protocol at once** — which is the half of §8.12
/// that pairing cannot do. Whoever redeems it binds themselves to it.
#[derive(Debug, Clone, Deserialize)]
pub struct Ticket {
    /// The secret itself, `tkt1_`-prefixed. **Returned by this call only and
    /// never re-fetchable** — the proxy keeps a SHA-256 of it and nothing more.
    ///
    /// The one required field, and everything else here is optional **because
    /// of** that sentence. A response this cannot parse is a ticket the proxy
    /// has already minted and will never show again: the operator would get an
    /// error, no secret to hand over, and no `ticket_id` to revoke the thing
    /// with. A missing `created_at` is not worth that.
    pub ticket: String,
    #[serde(default)]
    pub ticket_id: Option<String>,
    #[serde(default)]
    pub owner_endpoint: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// How long the Grant made by redeeming this will last. Never unlimited.
    #[serde(default)]
    pub grant_ttl: Option<u64>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    /// When the Ticket itself stops being redeemable. Unrelated to `grant_ttl`.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// One row of `GET /v1/peer/tickets` (spec §8.12.5) — the issue response
/// without the secret, plus who used it.
#[derive(Debug, Clone, Deserialize)]
pub struct TicketRecord {
    pub ticket_id: String,
    pub protocol: String,
    pub grant_ttl: u64,
    #[serde(default)]
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    /// **Absent until redeemed** — the key is missing rather than null.
    #[serde(default)]
    pub redemption: Option<TicketRedemption>,
}

/// Who redeemed a Ticket, and what it made (spec §8.12.5).
///
/// This is the owner's audit face. Without it, a Ticket handed out is a key cut
/// for nobody in particular.
#[derive(Debug, Clone, Deserialize)]
pub struct TicketRedemption {
    pub endpoint_id: String,
    pub grant_id: String,
    pub redeemed_at: String,
}

#[derive(Debug, Clone, Deserialize)]
struct TicketList {
    tickets: Vec<TicketRecord>,
}

/// What redeeming a Ticket returns (spec §8.12.3).
#[derive(Debug, Clone, Deserialize)]
pub struct RedeemedTicket {
    /// Indistinguishable from any other Grant except that `origin` is
    /// `ticket` — and §8.12.3 is explicit that `connect` must not tell them
    /// apart.
    pub grant: Grant,
    /// §8.10's answer, delivered with the grant so redeeming does not have to
    /// be followed by a listing. **Empty is not a failure**: the authorization
    /// exists, the far side just has nothing listening yet.
    #[serde(default)]
    pub listeners: Vec<TicketListener>,
}

/// What binds a Provisioning Key to something other than its own possession
/// (spec §8.13.4).
///
/// **`audience` is absent on purpose.** The proxy takes it from operator
/// configuration and refuses to let a caller name one: a workload mints tokens
/// for whatever audience it asks for, so a key naming another service's
/// audience would accept the tokens that service is holding. The issue response
/// echoes the configured value so CI knows what to mint for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProvisioningBinding {
    /// Possession alone. **Never for a public repository's CI.**
    None,
    /// A workload identity token from `issuer` whose `sub` matches exactly.
    /// No wildcards and no prefixes — cross a branch or a repository by
    /// issuing another key.
    Oidc { issuer: String, subject: String },
    /// The redeeming Endpoint Token's `sub` must equal the key owner's.
    Sub,
    /// Its `tenant_id` must equal the key owner's. Refused when either side
    /// has none: "unset matches unset" would let any caller without a tenant
    /// through.
    Tenant,
}

impl ProvisioningBinding {
    fn to_json(&self) -> serde_json::Value {
        match self {
            ProvisioningBinding::None => serde_json::json!({ "type": "none" }),
            ProvisioningBinding::Sub => serde_json::json!({ "type": "sub" }),
            ProvisioningBinding::Tenant => serde_json::json!({ "type": "tenant" }),
            ProvisioningBinding::Oidc { issuer, subject } => serde_json::json!({
                "type": "oidc",
                "issuer": issuer,
                "subject": subject,
            }),
        }
    }
}

/// A binding as the proxy reports it (spec §8.13.3).
///
/// **`kind` is a `String` rather than an enum**, unlike [`ProvisioningBinding`]
/// which the caller constructs. A type this does not recognise must not stop a
/// listing from parsing — the request side has to name something the server
/// knows, but the response side only has to be readable, and §8.13.9 has adding
/// types as an open question.
#[derive(Debug, Clone, Deserialize)]
pub struct BindingView {
    /// **Defaulted, because this sits inside a response that must always
    /// parse.** [`ProvisioningKey`] documents why every field but the secret
    /// is optional: an issue response this cannot read has already cost a
    /// minted key and one of four quota slots. A `binding` object arriving
    /// without a `type` would otherwise fail the whole response — which is the
    /// hole that typing this field opened, since the `serde_json::Value` it
    /// replaced parsed anything.
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub subject: Option<String>,
    /// **The value a caller cannot guess and cannot set.** The proxy takes it
    /// from its own configuration, so echoing it here is how whoever configures
    /// the far side learns what to mint for.
    #[serde(default)]
    pub audience: Option<String>,
}

/// A Provisioning Key as issued (spec §8.13.3).
///
/// **`key` is the only required field**, for the reason [`Ticket`] gives: it is
/// returned by this call and never again, so a response this cannot parse is a
/// key the proxy has minted, counted against a quota of four, and will never
/// show. The rest is shown rather than acted on.
///
/// The plaintext field is `key` here and `key_plaintext` on the Identity side.
/// The two servers genuinely differ, and Identity's §8.8.2 says why it does not
/// follow this one.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisioningKey {
    /// The secret, `pvk1_`-prefixed. **Store it now or lose it.**
    ///
    /// `key_plaintext` is accepted as well. Not because anything sends it —
    /// the proxy says `key` and §8.13.3 agrees — but because the cost of a
    /// name this cannot match is asymmetric: the key is already minted and
    /// counted against a quota of four, so the caller loses a slot rather than
    /// a round trip. The same argument put an alias on Identity's side, and it
    /// holds here whether or not the two ever drift.
    #[serde(alias = "key_plaintext")]
    pub key: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub owner_endpoint: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    /// How long a Grant made by redeeming this lasts. Never unlimited, and
    /// narrower than a Ticket's — §8.13.5's re-redemption is what that
    /// narrowness assumes.
    #[serde(default)]
    pub grant_ttl: Option<i64>,
    #[serde(default)]
    pub max_live_grants: Option<i64>,
    #[serde(default)]
    pub live_grants: Option<i64>,
    #[serde(default)]
    pub redemption_count: Option<i64>,
    /// Includes the `audience` the operator configured, which is the value CI
    /// has to mint for. **Not settable by the caller** — a key naming another
    /// service's audience would accept the tokens that service holds.
    #[serde(default)]
    pub binding: Option<BindingView>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    /// When the key stops being redeemable. Unrelated to `grant_ttl`.
    #[serde(default)]
    pub expires_at: Option<String>,
}

/// One row of `GET /v1/peer/provisioning-keys` (spec §8.13.7) — the issue
/// response without the secret, plus how full the key is.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisioningKeyRecord {
    pub key_id: String,
    #[serde(default)]
    pub owner_endpoint: Option<String>,
    #[serde(default)]
    pub protocol: Option<String>,
    #[serde(default)]
    pub grant_ttl: Option<i64>,
    #[serde(default)]
    pub max_live_grants: Option<i64>,
    /// Slots in use right now. **Not a running total** — a Grant that expires
    /// or is revoked frees its slot.
    #[serde(default)]
    pub live_grants: Option<i64>,
    /// Redemptions within the retention window, counting repeats: a long-lived
    /// runner that re-redeems all day is many here and one row in
    /// [`ProvisioningRedemption`].
    #[serde(default)]
    pub redemption_count: Option<i64>,
    #[serde(default)]
    pub binding: Option<BindingView>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProvisioningKeyList {
    /// **`keys`, which is not what Identity calls the same idea.** Not
    /// defaulted: a listing is idempotent and cheap to repeat, so a shape this
    /// cannot read should say so rather than read as "this Endpoint has no
    /// keys" — which is what somebody sees just before issuing past the quota.
    keys: Vec<ProvisioningKeyRecord>,
}

/// Who came in on a Provisioning Key, and how often (spec §8.13.7).
///
/// **This is the compensation, not a convenience.** §8.13.1 admits the key is a
/// bearer credential; being able to answer "which job came in on it" is part of
/// what makes that acceptable to run.
#[derive(Debug, Clone, Deserialize)]
pub struct ProvisioningRedemption {
    pub endpoint_id: String,
    #[serde(default)]
    pub grant_id: Option<String>,
    /// The workload's `sub`, when the binding is `oidc`. The assertion itself
    /// is verified and discarded; this is what it proved.
    #[serde(default)]
    pub binding_subject: Option<String>,
    #[serde(default)]
    pub first_redeemed_at: Option<String>,
    /// The most recent redemption.
    #[serde(default)]
    pub redeemed_at: Option<String>,
    /// **Counted rather than inferred from the row count.** The record is
    /// unique per `(key, endpoint)` and re-redemption updates it, so rows count
    /// Endpoints and this counts visits.
    #[serde(default)]
    pub redeem_count: Option<i64>,
}

#[derive(Debug, Clone, Deserialize)]
struct ProvisioningRedemptionList {
    redemptions: Vec<ProvisioningRedemption>,
}

/// What redeeming a Provisioning Key returns (spec §8.13.5).
///
/// **The same shape a Ticket redemption answers in**, deliberately, so that a
/// client which already redeems tickets needs no second parser — the proxy's
/// own handler says as much. The difference is in the grant: `origin` is
/// `provisioning` and `provisioning_key_id` names the key.
pub type RedeemedProvisioningKey = RedeemedTicket;

/// A listener named in a redemption response.
///
/// **Laxer than [`ReachableListener`], and kept that way after the question was
/// settled.** §8.12.3 used to say this array was §8.10's while printing an
/// example without `owner_endpoint` or `expires_at`; the spec now says those
/// are present and that "same content" never meant "optional". So the shorter
/// shape should not arrive.
///
/// This still does not require them, because of what requiring them costs when
/// one does go missing: a redemption that *succeeded* is reported as an error,
/// with the ticket single-use and already spent, the grant already created, and
/// nothing to retry — the spec makes the same point in that paragraph. Anything
/// absent here can be had from [`RedeemedTicket::grant`] or a later listing; a
/// spent ticket cannot.
#[derive(Debug, Clone, Deserialize)]
pub struct TicketListener {
    pub listener_id: String,
    pub protocol: String,
    #[serde(default)]
    pub owner_endpoint: Option<String>,
    #[serde(default)]
    pub metadata: Option<serde_json::Value>,
    #[serde(default)]
    pub expires_at: Option<String>,
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

/// The pairing code inside a scanned value, or `None` when it is not one of
/// ours.
///
/// A camera pointed at the world reads whatever is in front of it — a poster, a
/// wifi QR, a URL — and handing any of that to the proxy would spend a request
/// to be told it is not a code. Only the scheme this project puts in its own QR
/// counts, which is why that prefix is defined once, here.
///
/// A scanner may hand back more than was encoded, so the code runs to the first
/// character that could not be part of one.
pub fn pairing_code_in_uri(input: &str) -> Option<&str> {
    let rest = input.trim().strip_prefix(PAIRING_SCHEME)?;
    let code = rest.split(['&', '#']).next().unwrap_or(rest).trim();
    (!code.is_empty()).then_some(code)
}

/// Recover a pairing code from whatever was scanned, pasted or typed.
///
/// Accepts both the URI and the bare code, because those are the two things
/// that end up in the field: one from a scanner, one from someone reading the
/// screen. A bare value is not validated — the proxy decides whether a code is
/// real, and this only has to stop the scheme prefix from being sent as part of
/// it. A scan should go through [`pairing_code_in_uri`] instead, which says no
/// to everything that is not ours.
pub fn pairing_code_from_input(input: &str) -> String {
    match pairing_code_in_uri(input) {
        Some(code) => code.to_owned(),
        None => input.trim().to_owned(),
    }
}

/// The fixed prefix on a Ticket secret (spec §8.12.2).
///
/// **Not a secret and not decoration.** It is there so that secret scanners and
/// `grep` can both find one that has escaped into a log or a commit.
pub const TICKET_PREFIX: &str = "tkt1_";

/// The fixed prefix on the one-string form below (spec §8.12.8).
pub const TICKET_TRANSFER_PREFIX: &str = "iskt1_";

/// A Provisioning Key's prefix (spec §8.13.3).
///
/// Fixed and not secret, so that a secret scanner can find one — and
/// **different from Identity's `enr1_` on purpose**: whoever picks a leaked one
/// up can tell at a glance which server to revoke it at.
pub const PROVISIONING_KEY_PREFIX: &str = "pvk1_";

/// An Enrollment Key's prefix (Identity §8.8.2).
pub const ENROLLMENT_KEY_PREFIX: &str = "enr1_";

/// Every secret prefix worth keeping out of a log, longest first.
///
/// **Longest first matters**: `iskt1_` must not be matched as an `i` followed
/// by `tkt1_`, which would leave the `iskt1_` visible and redact from the wrong
/// offset.
const SECRET_PREFIXES: [&str; 4] = [
    TICKET_TRANSFER_PREFIX,
    TICKET_PREFIX,
    PROVISIONING_KEY_PREFIX,
    ENROLLMENT_KEY_PREFIX,
];

/// The authority a proxy base URL names — `tokyo.link.isekai.tools:8443`.
///
/// Shared so that the side writing a hand-over string and the side checking one
/// agree on what counts as "the same proxy". Falls back to the whole input
/// rather than erroring: a proxy URL that does not parse is a problem the
/// connect reports far better than this can.
pub fn proxy_authority(proxy_url: &str) -> &str {
    let rest = proxy_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(proxy_url);
    rest.split(['/', '?', '#']).next().unwrap_or(rest)
}

/// A Ticket together with where to redeem it (spec §8.12.8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketTransfer {
    /// Where to redeem it: an **authority**, not a URL —
    /// `tokyo.link.isekai.tools:8443`. The scheme is always `https`.
    ///
    /// **[`ticket_transfer`] always writes the port**, which §8.12.8 asks for:
    /// a bare host means 443, and this project's proxies are not there, so
    /// omitting it would leave the port to be told separately — the out-of-band
    /// step the one-string form exists to remove.
    ///
    /// A bare host can still *arrive*, since the spec permits one, and it is
    /// carried through as written rather than filled in. Whoever compares this
    /// against their own proxy is then comparing 443 against 443, which is what
    /// the shorter form meant.
    pub proxy: String,
    /// The `tkt1_` secret.
    pub ticket: String,
}

#[derive(Serialize, Deserialize)]
struct TicketTransferBody {
    p: String,
    t: String,
}

/// Pack a Ticket and its proxy into the one string to hand over.
///
/// **A Ticket on its own does not say where to spend it.** The redeeming side
/// needs a proxy to talk to, and asking whoever received it to also be told a
/// hostname is how half of them end up at the wrong one. §8.12.8 settles the
/// shape; this is that shape, in one place, so the two portal binaries cannot
/// disagree about it.
pub fn ticket_transfer(proxy: &str, ticket: &str) -> String {
    let body = TicketTransferBody {
        p: proxy.to_owned(),
        t: ticket.to_owned(),
    };
    // Unwrap: the value is two owned `String`s in a struct with no map keys
    // that can collide, so this cannot fail.
    let json = serde_json::to_vec(&body).expect("ticket transfer body is serialisable");
    format!(
        "{TICKET_TRANSFER_PREFIX}{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(json)
    )
}

/// Unpack what [`ticket_transfer`] made, or `None` if it is not one.
///
/// Also accepts a bare `tkt1_` secret, which arrives when someone was told the
/// proxy separately — the proxy is then empty and the caller uses its own. What
/// is *not* accepted is anything else, so a mistyped paste costs a message here
/// rather than a request and a `403`.
pub fn ticket_from_transfer(input: &str) -> Option<TicketTransfer> {
    let input = input.trim();
    // A link may carry it in the fragment, which §8.12.8 recommends over a path
    // or a query precisely so it stays out of Referer and access logs. Taking
    // the part after `#` costs nothing and means a copied link works.
    let input = input.rsplit('#').next().unwrap_or(input).trim();
    if let Some(encoded) = input.strip_prefix(TICKET_TRANSFER_PREFIX) {
        // **Both padding modes.** This encodes without, as §8.12.8's example
        // does, but `URL_SAFE_NO_PAD` *rejects* padding rather than tolerating
        // it — and padded urlsafe base64 is what the common encoders produce by
        // default (Python's `urlsafe_b64encode` among them). Two payload
        // lengths in three end up padded, so a proxy UI or a second
        // implementation emitting the same format would have every other
        // ticket refused here as "not a ticket". Strict out, liberal in.
        let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(encoded))
            .ok()?;
        let body: TicketTransferBody = serde_json::from_slice(&raw).ok()?;
        if !body.t.starts_with(TICKET_PREFIX) {
            return None;
        }
        return Some(TicketTransfer {
            proxy: body.p,
            ticket: body.t,
        });
    }
    input.starts_with(TICKET_PREFIX).then(|| TicketTransfer {
        proxy: String::new(),
        ticket: input.to_owned(),
    })
}

/// Which kind of secret this text begins with, if any.
///
/// **The companion to [`redact_secrets`], and they belong together.** Redacting
/// keeps a secret out of a log after somebody has mistyped; this is what stops
/// the mistyping from sending it anywhere. A guard that knew only about Tickets
/// while the redaction knew about four kinds would keep the quieter half of the
/// promise.
///
/// Matches the prefix only, so it says "this looks like a Provisioning Key",
/// never "this is a valid one" — the point is to refuse before anything is
/// sent, not to judge the value.
pub fn secret_prefix(input: &str) -> Option<&'static str> {
    // Longest first, so `iskt1_` is not reported as `tkt1_` after an `i`.
    SECRET_PREFIXES
        .iter()
        .copied()
        .find(|prefix| input.starts_with(prefix))
}

/// Replace the body of anything that looks like a secret with `…`.
///
/// Covers all four: Tickets and their transfer envelopes (§8.12.8),
/// Provisioning Keys (§8.13.3) and Enrollment Keys (Identity §8.8.2). Both
/// specs ask clients to keep these out of their own logs, and the reason every
/// prefix is fixed is so that this is a substring search rather than a
/// judgement. Applied to text about to be printed or logged, not to values in
/// flight.
///
/// **The two keys belong here as much as a Ticket does**, and more: a Ticket is
/// single-use, while a key is a standing arrangement that a scanner would find
/// weeks later in a CI log.
pub fn redact_secrets(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some((at, prefix)) = SECRET_PREFIXES
        .iter()
        .filter_map(|p| rest.find(p).map(|at| (at, *p)))
        .min_by_key(|(at, p)| (*at, std::cmp::Reverse(p.len())))
    {
        out.push_str(&rest[..at]);
        out.push_str(prefix);
        out.push('…');
        let after = &rest[at + prefix.len()..];
        // The secret runs to the first character base64url cannot contain.
        let end = after
            .find(|c: char| !c.is_ascii_alphanumeric() && c != '-' && c != '_')
            .unwrap_or(after.len());
        rest = &after[end..];
    }
    out.push_str(rest);
    out
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
    /// **The initiator's relay ticket**, carried in the `connect` response so
    /// it does not cost a second round trip (spec §8.14.1).
    ///
    /// `None` from a proxy that predates §8.14 — and, rarely, from one that
    /// could not sign. Either way the leg is opened without a ticket, which
    /// such a proxy accepts (`--relay-require-ticket` false) and a newer one
    /// refuses with `relay-ticket-required`. Only this response carries it; the
    /// connection reads never do.
    #[serde(default)]
    pub ticket: Option<RelayTicket>,
    #[serde(default)]
    pub relay_session_id: Option<String>,
    /// Where this connection's relay answers, when the control plane chose a
    /// registered one.
    ///
    /// **The target's only way to learn it.** The initiator is handed a
    /// `masque_uri`; a listener sees connections and nothing else, so without
    /// this it has nowhere to bind but the control plane — which is not where
    /// its ticket may be redeemed.
    #[serde(default)]
    pub relay_base_url: Option<String>,
    /// The loopback FQDN the initiator should dial for the video QUIC over the
    /// relay, so it can validate the per-endpoint certificate the listener
    /// downloaded. `None` when the proxy has relay certificates disabled — in
    /// that case the initiator falls back to dialing `127.0.0.1` unvalidated.
    #[serde(default)]
    pub video_host: Option<String>,
    /// The target's own statement about the key its certificate is for
    /// (spec §8.6.5), to be checked before dialing and then pinned in the
    /// handshake.
    ///
    /// **Absent is the ordinary case today** and means only that there is
    /// nothing to pin — a target that has not published one, or a proxy that
    /// does not carry the field. A statement that is *present and wrong* is the
    /// opposite of ordinary and must stop the connection.
    #[serde(default)]
    pub video_attestation: Option<Attestation>,
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
    /// Shared so it can be replaced under a live client.
    ///
    /// An Endpoint Token lasts minutes (spec §5.3 recommends 5–15), while the
    /// client outlives it by hours — so it has to be renewed in place. Rebuilding
    /// the client instead would rebuild `transport`, and for the MASQUE transport
    /// that means tearing down the tunnel every relay leg is running over.
    ///
    /// Every clone of this client sees a replacement, which is the point: the
    /// sessions hand clones around and there is only ever one current token.
    endpoint_token: Arc<RwLock<String>>,
}

impl<T: ControlPlaneTransport> ProxyClient<T> {
    /// Create a client with an HTTP/3 transport, the Endpoint key (for PoP) and
    /// the Endpoint Token obtained from the Identity API.
    pub fn new(transport: T, key: EndpointKey, endpoint_token: impl Into<String>) -> Self {
        Self {
            transport,
            key,
            endpoint_token: Arc::new(RwLock::new(endpoint_token.into())),
        }
    }

    /// The Endpoint Token in force right now.
    ///
    /// The one source of truth for it: a relay leg opened later has to carry the
    /// current token, not the one the session started with.
    pub fn endpoint_token(&self) -> String {
        self.endpoint_token
            .read()
            .expect("endpoint token lock poisoned")
            .clone()
    }

    /// Use `endpoint_token` from now on, on this client and every clone of it.
    ///
    /// The next request carries it; requests already in flight carry the old one
    /// and are not retried, which is why renewal happens before expiry rather
    /// than in response to a 401.
    pub fn set_endpoint_token(&self, endpoint_token: impl Into<String>) {
        *self
            .endpoint_token
            .write()
            .expect("endpoint token lock poisoned") = endpoint_token.into();
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

    /// `POST /v1/peer/connections/{id}/ticket` (spec §8.14.2) — get a relay
    /// ticket for this Endpoint's leg of `connection_id`.
    ///
    /// **The target has no other way to get one.** Only the initiator sees the
    /// `connect` response, and the §8.11 event that tells a listener about a
    /// connection deliberately carries no ticket — an event is a fast path, not
    /// a record, so a value that could not be fetched again has no business
    /// being on it.
    ///
    /// **This is also how both sides re-ticket**, and re-ticketing is not a
    /// renewal of an old decision: the proxy looks at the authorization again
    /// (is the grant still in force, is the peer still un-revoked, has the
    /// connection ended) and refuses if it has changed. That is what makes a
    /// revoked grant reach a session that is already running.
    ///
    /// A proxy that predates §8.14 answers `404`. The caller carries on without
    /// a ticket, which that same proxy does not ask for.
    pub async fn issue_relay_ticket(&self, connection_id: &str) -> Result<RelayTicket, ProxyError> {
        self.request_json(
            "POST",
            &format!("/v1/peer/connections/{connection_id}/ticket"),
            to_vec(&serde_json::json!({})),
        )
        .await
    }

    /// `POST /v1/relay/sessions/{id}/renew` (spec §8.14.3) — spend a fresh
    /// ticket to push this leg's lease out.
    ///
    /// **The leg has to already exist.** This replaces a lease; it does not
    /// create one, and a session whose leg was never opened answers `404`.
    ///
    /// The lease only ever moves forward, so a renewal that overtakes a later
    /// one cannot pull the leg back in.
    pub async fn renew_relay_lease(
        &self,
        session_id: &str,
        ticket: &str,
    ) -> Result<RelayLease, ProxyError> {
        self.request_json(
            "POST",
            &format!("/v1/relay/sessions/{session_id}/renew"),
            to_vec(&serde_json::json!({ "ticket": ticket })),
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

    /// `POST /v1/peer/tickets` (spec §8.12.2).
    ///
    /// **Several of these can be live for the same protocol**, which is what a
    /// pairing code cannot do — there is one of those per (Endpoint, protocol)
    /// because a person is reading it off a screen. A Ticket is handed over out
    /// of band instead, so three CI jobs can each have their own.
    ///
    /// No listener is named: what redeeming makes is a Grant, and a Grant's key
    /// has no listener in it (§8.8). So this works on a node that is about to
    /// be switched off, and the Ticket still does when it comes back.
    ///
    /// `ttl` is how long the paper is good for and `grant_ttl` is how long
    /// whoever presents it may stay. **They are different quantities and the
    /// second is not capped by the first** — a 15-minute Ticket making a
    /// 1-hour Grant is the intended case. Both clamp to 60..=86,400, and
    /// `grant_ttl` cannot be unlimited: a Ticket is for one-off work, and work
    /// that ends should not leave authorization behind.
    pub async fn create_ticket(
        &self,
        protocol: &str,
        ttl: Option<u64>,
        grant_ttl: Option<u64>,
        label: Option<&str>,
    ) -> Result<Ticket, ProxyError> {
        let body = serde_json::json!({
            "protocol": protocol,
            "ttl": ttl,
            "grant_ttl": grant_ttl,
            "label": label,
        });
        self.request_json("POST", "/v1/peer/tickets", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/tickets` (spec §8.12.5) — this Endpoint's Tickets, newest
    /// first, each with who redeemed it if anyone has.
    ///
    /// Redeemed Tickets stay here until the sweep removes them, which is the
    /// point: a record that vanished the moment it was used would not be one.
    pub async fn list_tickets(&self) -> Result<Vec<TicketRecord>, ProxyError> {
        let list: TicketList = self
            .request_json("GET", "/v1/peer/tickets", Vec::new())
            .await?;
        Ok(list.tickets)
    }

    /// `DELETE /v1/peer/tickets/{ticket_id}` (spec §8.12.6).
    ///
    /// **A Grant already made from it is not withdrawn.** Tearing up the paper
    /// does not remove whoever already walked in; use
    /// [`revoke_grant`](Self::revoke_grant) for that. An unknown id also
    /// answers `204`, since the state the caller wanted is the state there is.
    pub async fn revoke_ticket(&self, ticket_id: &str) -> Result<(), ProxyError> {
        self.request_empty(
            "DELETE",
            &format!("/v1/peer/tickets/{ticket_id}"),
            Vec::new(),
        )
        .await
    }

    /// `POST /v1/peer/tickets/redeem` (spec §8.12.3) — **the caller becomes the
    /// `allowed_endpoint`.**
    ///
    /// Every way this can be refused for authorization reasons answers the same
    /// `403 ticket-invalid`: unknown, expired, already spent, malformed, or an
    /// owner whose Endpoint has been revoked. Do not try to tell them apart —
    /// the uniformity is deliberate (§8.12.4), and the three exceptions
    /// (`400`, `403 protocol-not-allowed`, `429 grant-quota-exceeded`) are the
    /// cases where the request does not stand up at all, and **leave the Ticket
    /// unspent**.
    ///
    /// Redeeming twice is not a way to refresh anything: an existing live Grant
    /// comes back `200` with its dates untouched, and the Ticket is spent all
    /// the same.
    pub async fn redeem_ticket(
        &self,
        ticket: &str,
        label: Option<&str>,
    ) -> Result<RedeemedTicket, ProxyError> {
        let body = serde_json::json!({ "ticket": ticket, "label": label });
        self.request_json("POST", "/v1/peer/tickets/redeem", to_vec(&body))
            .await
    }

    /// `POST /v1/peer/provisioning-keys` (spec §8.13.3) — put a standing
    /// arrangement in place.
    ///
    /// **Needs `peer-provisioning:create`, which `peer-connect:accept` does not
    /// imply.** A Ticket is the extension of handing somebody a piece of paper;
    /// this says "let whoever holds this in, from now on", and §8.13.2 keeps
    /// the two apart so the second cannot arrive on a token by accident.
    ///
    /// No listener is named: what redeeming makes is a Grant, whose key has no
    /// listener in it, so the key outlives any particular listener.
    ///
    /// `binding` is optional here — unlike Identity's Enrollment Key, where it
    /// cannot be omitted. §8.8.2 explains the asymmetry: what this creates is
    /// authorization, bounded by a slot count and a `grant_ttl` and revocable
    /// down to its derived Grants, whereas an Enrollment Key creates *subjects*
    /// that stand on their own keys afterwards. **`none` is still the wrong
    /// choice for a public repository's CI.**
    pub async fn create_provisioning_key(
        &self,
        protocol: &str,
        ttl: Option<u64>,
        grant_ttl: Option<u64>,
        max_live_grants: Option<u64>,
        binding: Option<&ProvisioningBinding>,
        label: Option<&str>,
    ) -> Result<ProvisioningKey, ProxyError> {
        let mut body = serde_json::json!({ "protocol": protocol });
        if let Some(v) = ttl {
            body["ttl"] = serde_json::json!(v);
        }
        if let Some(v) = grant_ttl {
            body["grant_ttl"] = serde_json::json!(v);
        }
        if let Some(v) = max_live_grants {
            body["max_live_grants"] = serde_json::json!(v);
        }
        if let Some(binding) = binding {
            body["binding"] = binding.to_json();
        }
        if let Some(label) = label {
            body["label"] = serde_json::json!(label);
        }
        self.request_json("POST", "/v1/peer/provisioning-keys", to_vec(&body))
            .await
    }

    /// `GET /v1/peer/provisioning-keys` (spec §8.13.7) — this Endpoint's keys,
    /// each with how full it is.
    ///
    /// `live_grants` against `max_live_grants` is the number that says whether
    /// a key is turning jobs away; the ceiling alone does not.
    pub async fn list_provisioning_keys(&self) -> Result<Vec<ProvisioningKeyRecord>, ProxyError> {
        let list: ProvisioningKeyList = self
            .request_json("GET", "/v1/peer/provisioning-keys", Vec::new())
            .await?;
        Ok(list.keys)
    }

    /// `GET /v1/peer/provisioning-keys/{key_id}/redemptions` (spec §8.13.7).
    ///
    /// **Outlives the key.** Revoking or expiring one does not erase this:
    /// a key is stopped because of a leak, a compromise or somebody leaving,
    /// and that is the moment "who came in on it" matters most.
    pub async fn provisioning_redemptions(
        &self,
        key_id: &str,
    ) -> Result<Vec<ProvisioningRedemption>, ProxyError> {
        let list: ProvisioningRedemptionList = self
            .request_json(
                "GET",
                &format!("/v1/peer/provisioning-keys/{key_id}/redemptions"),
                Vec::new(),
            )
            .await?;
        Ok(list.redemptions)
    }

    /// `DELETE /v1/peer/provisioning-keys/{key_id}` (spec §8.13.7).
    ///
    /// **This deletes the Grants the key made, which is the opposite of what
    /// revoking a Ticket does.** Tearing up a piece of paper does not remove
    /// whoever already walked in, and §8.12.6 leaves those Grants alone
    /// deliberately. Here the owner does not know who is inside without asking,
    /// so "stop this key" has to mean the door it opened closes — otherwise the
    /// operator watches a door they cannot shut for up to `grant_ttl`.
    ///
    /// **Running jobs are cut off.** Established connections are not torn down,
    /// but nothing new is authorized.
    pub async fn revoke_provisioning_key(&self, key_id: &str) -> Result<(), ProxyError> {
        self.request_empty(
            "DELETE",
            &format!("/v1/peer/provisioning-keys/{key_id}"),
            Vec::new(),
        )
        .await
    }

    /// `POST /v1/peer/provisioning-keys/redeem` (spec §8.13.5) — **the caller
    /// becomes the `allowed_endpoint`.**
    ///
    /// **Redeeming again is how a long job keeps its authorization**, which is
    /// the reverse of a Ticket. `grant_ttl` is capped at an hour precisely
    /// because this extends it: the answer is `200` with `expires_at` moved to
    /// `max(existing, now + grant_ttl)`, never backwards, so a new job cannot
    /// shorten a running one's grant.
    ///
    /// Most refusals answer the same `403 provisioning-key-invalid` — unknown,
    /// expired, revoked, malformed, or an owner whose Endpoint has been
    /// revoked — and telling them apart is not the caller's business.
    /// **`403 provisioning-binding-invalid` is deliberately not one of them**:
    /// presenting a 256-bit secret is not guesswork, so that answer says the
    /// key is real and the CI is misconfigured (wrong branch, wrong repository,
    /// missing audience). Folding it in would leave an operator unable to tell
    /// a leak from a typo.
    pub async fn redeem_provisioning_key(
        &self,
        key: &str,
        assertion: Option<&str>,
        label: Option<&str>,
    ) -> Result<RedeemedProvisioningKey, ProxyError> {
        let body = serde_json::json!({
            "key": key,
            "assertion": assertion,
            "label": label,
        });
        self.request_json("POST", "/v1/peer/provisioning-keys/redeem", to_vec(&body))
            .await
    }

    /// `GET /v1/peer-listeners/{id}/events` (spec §8.11) — what happened, as it
    /// happens.
    ///
    /// The channel carries one event per line for as long as the stream lives,
    /// and ends when it does: the proxy closing it, the connection dropping, a
    /// subscriber that fell behind being cut off. Ending is not an error to
    /// report so much as a signal to reconnect and re-read the listing, which
    /// is what the caller does after any disconnection.
    ///
    /// **This is the fast path and not the record.** Nothing is replayed, so
    /// nothing here should be treated as the whole truth about anything — it
    /// says when to look, and §8.5.3 says what is there.
    pub async fn listener_events(
        &self,
        listener_id: &str,
    ) -> Result<mpsc::Receiver<ListenerEvent>, ProxyError>
    where
        T: EventStreamTransport,
    {
        let path = format!("/v1/peer-listeners/{listener_id}/events");
        let headers = self.auth_headers("GET", &path, &[]);
        let (status, mut chunks) = self
            .transport
            .open_stream("GET", &path, &headers)
            .await
            .map_err(ProxyError::Transport)?;
        if status != 200 {
            // Read what it said, within reason. A refusal tells the caller
            // whether this proxy has no such route at all or is refusing this
            // listener, and those want different responses — one is permanent
            // and one is not.
            let mut body = Vec::new();
            while body.len() < MAX_EVENT_LINE {
                match chunks.recv().await {
                    Some(Ok(chunk)) => body.extend_from_slice(&chunk),
                    _ => break,
                }
            }
            return Err(problem_error(&HttpResponse {
                status,
                body,
                headers: Vec::new(),
            }));
        }

        let (events, receiver) = mpsc::channel(32);
        tokio::spawn(async move {
            let mut buffer = Vec::new();
            let mut ready = Vec::new();
            while let Some(chunk) = chunks.recv().await {
                match chunk {
                    Ok(bytes) => buffer.extend_from_slice(&bytes),
                    Err(e) => {
                        tracing::debug!("listener event stream ended: {e}");
                        break;
                    }
                }
                Self::drain_lines(&mut buffer, &mut ready);
                // A line that never ends would grow this without limit. The
                // proxy sends one event per line, but nothing here should
                // depend on the other end being well behaved — and ending the
                // stream is what every other failure does, so the caller
                // already knows how to recover from it.
                if buffer.len() > MAX_EVENT_LINE {
                    tracing::warn!(
                        "listener event line exceeded {MAX_EVENT_LINE} bytes; ending the stream"
                    );
                    break;
                }
                for event in ready.drain(..) {
                    if events.send(event).await.is_err() {
                        return;
                    }
                }
            }
        });
        Ok(receiver)
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

    /// `GET /v1/peer/certificate/parameters` (spec §8.6.1).
    ///
    /// `None` when the proxy issues no certificates at all (no
    /// `--p2p-cert-domain`), and also what an older proxy answers by not
    /// knowing the route. Either way the caller falls back to a dev
    /// certificate or to [`get_certificate`](Self::get_certificate).
    ///
    /// Touches no CA, so it is cheap to call before every issuance.
    pub async fn certificate_parameters(
        &self,
    ) -> Result<Option<CertificateParameters>, ProxyError> {
        let resp = self
            .send("GET", "/v1/peer/certificate/parameters", Vec::new())
            .await?;
        match resp.status {
            404 | 405 => Ok(None),
            s if (200..300).contains(&s) => serde_json::from_slice(&resp.body)
                .map(Some)
                .map_err(ProxyError::Decode),
            _ => Err(problem_error(&resp)),
        }
    }

    /// `POST /v1/peer/certificate` (spec §8.6.2).
    ///
    /// The CSR is covered by this request's PoP signature — §5.2 puts the body
    /// hash in the signed string — so the chain from Endpoint ID to public key
    /// is one somebody other than the proxy could check.
    ///
    /// `Ok(None)` if the route is not there, which is an older proxy.
    /// `attestation` is the target's own statement about the key it is asking
    /// for (spec §8.6.5), and is optional: a proxy that does not know the field
    /// ignores it, and an initiator that receives no statement simply has
    /// nothing to pin. It is checked **before** issuance, so a mistake in it
    /// costs no quota.
    pub async fn issue_certificate(
        &self,
        csr_pem: &str,
        attestation: Option<&Attestation>,
    ) -> Result<Option<IssuedCertificate>, ProxyError> {
        let mut request = serde_json::json!({ "csr_pem": csr_pem });
        if let Some(attestation) = attestation {
            request["attestation"] = serde_json::to_value(attestation)
                .expect("an attestation is plain data and always serialises");
        }
        let body = to_vec(&request);
        let resp = self.send("POST", "/v1/peer/certificate", body).await?;
        match resp.status {
            404 | 405 => Ok(None),
            s if (200..300).contains(&s) => serde_json::from_slice(&resp.body)
                .map(Some)
                .map_err(ProxyError::Decode),
            _ => Err(problem_error(&resp)),
        }
    }

    // ---- request plumbing ----

    fn auth_headers(&self, method: &str, path: &str, body: &[u8]) -> Vec<(String, String)> {
        let pop = pop::sign_request(&self.key, method, path, body);
        let token = self
            .endpoint_token
            .read()
            .expect("endpoint token lock poisoned")
            .clone();
        let mut headers = vec![
            ("authorization".to_owned(), format!("Bearer {token}")),
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

    /// Read one NDJSON line off a chunked body, assembling across chunks.
    ///
    /// A line is not a chunk: one read can carry half an event or three of
    /// them, and treating chunk boundaries as record boundaries works right up
    /// until the network splits one somewhere else.
    fn drain_lines(buffer: &mut Vec<u8>, out: &mut Vec<ListenerEvent>) {
        while let Some(end) = buffer.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = buffer.drain(..=end).collect();
            let line = &line[..line.len() - 1];
            if line.is_empty() {
                continue;
            }
            match serde_json::from_slice::<ListenerEvent>(line) {
                Ok(event) => out.push(event),
                // One unreadable line is not a reason to abandon the stream:
                // the next one may be fine, and the listing is what this is
                // checked against anyway.
                Err(e) => tracing::debug!("ignoring an unreadable listener event: {e}"),
            }
        }
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
        retry_after: resp.retry_after(),
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
                ..HttpResponse::default()
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
                    ..HttpResponse::default()
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

    /// The `connect` response carries the initiator's relay ticket, and the
    /// two times on it mean different things (spec §8.14.1).
    #[tokio::test]
    async fn peer_connect_reads_the_relay_ticket() {
        let resp = r#"{"connection_id":"conn_1","state":"relay","listener_id":"pl_1",
            "protocol":"isekai-validator-v1","peer_endpoint":"ep:B",
            "relay":{"masque_uri":"https://p/x/","session_id":"sess_1"},
            "ticket":{"ticket":"eyJ.JWT.sig","role":"initiator",
                      "expires_at":"2026-07-13T08:40:45Z",
                      "lease_expires_at":"2026-07-13T09:00:00Z"},
            "peer_candidates":[],"created_at":"t","expires_at":"t"}"#;
        let (client, _key) = client(MockTransport::with_response(201, resp));
        let conn = client
            .peer_connect("cap_x", "pl_1", "isekai-validator-v1", &[])
            .await
            .unwrap();
        let ticket = conn.ticket.expect("a proxy with §8.14 sends one");
        assert_eq!(ticket.ticket, "eyJ.JWT.sig");
        assert_eq!(ticket.role, RelayRole::Initiator);
        // The lease outlives the paper — renewal is timed off the second.
        assert_ne!(ticket.expires_at, ticket.lease_expires_at);
    }

    /// **A proxy that predates §8.14 sends no ticket, and that is not an
    /// error.** The leg is opened without one, which that proxy accepts.
    #[tokio::test]
    async fn a_connect_response_without_a_ticket_still_parses() {
        let resp = r#"{"connection_id":"conn_1","state":"relay","listener_id":"pl_1",
            "protocol":"isekai-validator-v1","peer_endpoint":"ep:B",
            "relay":{"masque_uri":"https://p/x/","session_id":"sess_1"},
            "peer_candidates":[],"created_at":"t","expires_at":"t"}"#;
        let (client, _key) = client(MockTransport::with_response(201, resp));
        let conn = client
            .peer_connect("cap_x", "pl_1", "isekai-validator-v1", &[])
            .await
            .unwrap();
        assert!(conn.ticket.is_none());
    }

    /// Both relay-ticket calls go where §8.14 says, and carry a PoP over the
    /// body actually sent.
    #[tokio::test]
    async fn the_relay_ticket_calls_hit_the_right_paths() {
        let resp = r#"{"ticket":"eyJ.JWT.sig","role":"target",
            "expires_at":"t","lease_expires_at":"t2"}"#;
        let (client, key) = client(MockTransport::with_response(201, resp));
        let ticket = client.issue_relay_ticket("conn_1").await.unwrap();
        assert_eq!(ticket.role, RelayRole::Target);
        {
            let calls = client.transport.calls.lock().unwrap();
            let (method, path, headers, body) = calls.last().unwrap();
            assert_eq!(
                (method.as_str(), path.as_str()),
                ("POST", "/v1/peer/connections/conn_1/ticket")
            );
            assert_eq!(
                header(headers, pop::HEADER_ENDPOINT_ID),
                Some(key.endpoint_id().as_str())
            );
            assert_eq!(body, b"{}");
        }

        client
            .transport
            .responses
            .lock()
            .unwrap()
            .push(HttpResponse {
                status: 200,
                body: br#"{"session_id":"conn_1","role":"target","lease_expires_at":"t3"}"#
                    .to_vec(),
                ..HttpResponse::default()
            });
        let lease = client
            .renew_relay_lease("conn_1", "eyJ.JWT.sig")
            .await
            .unwrap();
        assert_eq!(lease.lease_expires_at, "t3");
        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        // Named for the relay session, not filed under /v1/peer: this route is
        // the data plane's, and moves with it.
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/relay/sessions/conn_1/renew"),
        );
        assert!(String::from_utf8_lossy(body).contains("eyJ.JWT.sig"));
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
        assert_eq!(grant.origin.as_deref(), Some("pairing"));
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

    /// A ticket names no listener either, and carries the two lifetimes
    /// separately — sending one where the other belongs would silently change
    /// how long access lasts.
    #[tokio::test]
    async fn issuing_a_ticket_sends_both_lifetimes_and_no_listener() {
        let body = r#"{"ticket_id":"tkt_1","ticket":"tkt1_secret","owner_endpoint":"ep:B",
            "protocol":"mjpeg","grant_ttl":3600,"label":"ci",
            "created_at":"2026-08-28T08:30:00Z","expires_at":"2026-08-28T08:45:00Z"}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let ticket = client
            .create_ticket("mjpeg", Some(900), Some(3600), Some("ci"))
            .await
            .unwrap();
        assert_eq!(ticket.ticket, "tkt1_secret");
        assert_eq!(ticket.grant_ttl, Some(3600));

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/peer/tickets")
        );
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["protocol"], "mjpeg");
        assert_eq!(sent["ttl"], 900, "the ticket's own life");
        assert_eq!(sent["grant_ttl"], 3600, "the life of what redeeming makes");
        assert!(
            sent["listener_id"].is_null(),
            "a ticket lands on a grant, which names no listener"
        );
    }

    /// Redeeming returns a grant that must be indistinguishable from any other
    /// (spec §8.12.3), and the listeners alongside it so the caller does not
    /// have to go and ask.
    #[tokio::test]
    async fn redeeming_a_ticket_returns_a_grant_and_the_listeners() {
        let body = r#"{"grant":{"grant_id":"gr_1","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"ticket",
            "created_at":"2026-08-28T08:32:00Z","expires_at":"2026-08-28T09:32:00Z"},
            "listeners":[{"listener_id":"pl_1","owner_endpoint":"ep:B",
                          "protocol":"mjpeg","expires_at":"2026-08-28T09:30:00Z"}]}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let redeemed = client.redeem_ticket("tkt1_secret", None).await.unwrap();
        assert_eq!(redeemed.grant.origin.as_deref(), Some("ticket"));
        assert_eq!(
            redeemed.grant.expires_at.as_deref(),
            Some("2026-08-28T09:32:00Z"),
            "a ticket's grant always ends"
        );
        assert_eq!(redeemed.listeners.len(), 1);

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, _, body) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("POST", "/v1/peer/tickets/redeem")
        );
        let sent: serde_json::Value = serde_json::from_slice(body).unwrap();
        assert_eq!(sent["ticket"], "tkt1_secret");
        assert!(sent["label"].is_null());
    }

    /// The listener shape §8.12.3 prints beside the response is shorter than
    /// §8.10's, which the same paragraph says it is. Whichever the proxy
    /// actually sends, a redemption that worked must not come back as an error
    /// — the ticket is spent either way.
    #[tokio::test]
    async fn redeeming_accepts_the_shorter_listener_shape() {
        let body = r#"{"grant":{"grant_id":"gr_1","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"ticket",
            "created_at":"2026-08-28T08:32:00Z","expires_at":"2026-08-28T09:32:00Z"},
            "listeners":[{"listener_id":"pl_1","protocol":"mjpeg",
                          "metadata":{"name":"validator-01"}}]}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let redeemed = client.redeem_ticket("tkt1_secret", None).await.unwrap();
        assert_eq!(redeemed.listeners[0].listener_id, "pl_1");
        assert_eq!(redeemed.listeners[0].owner_endpoint, None);
    }

    /// The grant is what the ticket was spent on, so losing the response to a
    /// field nobody acts on would be the same bad trade as with the listeners.
    #[tokio::test]
    async fn redeeming_survives_a_grant_missing_its_descriptive_fields() {
        let body = r#"{"grant":{"grant_id":"gr_1","owner_endpoint":"ep:B"}}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let redeemed = client.redeem_ticket("tkt1_secret", None).await.unwrap();
        assert_eq!(redeemed.grant.grant_id, "gr_1");
        assert_eq!(
            redeemed.grant.owner_endpoint, "ep:B",
            "the peer to connect to is the one field this cannot do without"
        );
        assert_eq!(redeemed.grant.origin, None);
    }

    /// An authorised peer whose far side has not started yet is not a failure,
    /// and the absence of `listeners` must not be read as one.
    #[tokio::test]
    async fn redeeming_with_nothing_listening_yet_is_not_an_error() {
        let body = r#"{"grant":{"grant_id":"gr_1","owner_endpoint":"ep:B",
            "allowed_endpoint":"ep:A","protocol":"mjpeg","origin":"ticket",
            "created_at":"2026-08-28T08:32:00Z","expires_at":"2026-08-28T09:32:00Z"}}"#;
        let (client, _key) = client(MockTransport::with_response(201, body));
        let redeemed = client.redeem_ticket("tkt1_secret", None).await.unwrap();
        assert!(redeemed.listeners.is_empty());
    }

    /// `redemption` is absent until somebody spends it — the key is missing,
    /// not null, so a required field here would fail to parse every unredeemed
    /// row.
    #[tokio::test]
    async fn an_unredeemed_ticket_parses_without_a_redemption() {
        let body = r#"{"tickets":[
            {"ticket_id":"tkt_1","protocol":"mjpeg","grant_ttl":3600,
             "created_at":"2026-08-28T08:30:00Z","expires_at":"2026-08-28T08:45:00Z"},
            {"ticket_id":"tkt_2","protocol":"mjpeg","grant_ttl":3600,
             "created_at":"2026-08-28T08:00:00Z","expires_at":"2026-08-28T08:15:00Z",
             "redemption":{"endpoint_id":"ep:A","grant_id":"gr_9",
                           "redeemed_at":"2026-08-28T08:02:00Z"}}]}"#;
        let (client, _key) = client(MockTransport::with_response(200, body));
        let tickets = client.list_tickets().await.unwrap();
        assert!(tickets[0].redemption.is_none());
        assert_eq!(
            tickets[1].redemption.as_ref().unwrap().endpoint_id,
            "ep:A",
            "who spent it is the whole point of the listing"
        );

        let calls = client.transport.calls.lock().unwrap();
        let (method, path, ..) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("GET", "/v1/peer/tickets")
        );
    }

    /// Revoking is by id on the ticket route, not the grant one — the two are
    /// different objects and §8.12.6 turns on that.
    #[tokio::test]
    async fn revoking_a_ticket_uses_the_ticket_route() {
        let (client, _key) = client(MockTransport::with_response(204, ""));
        client.revoke_ticket("tkt_1").await.unwrap();
        let calls = client.transport.calls.lock().unwrap();
        let (method, path, ..) = calls.last().unwrap();
        assert_eq!(
            (method.as_str(), path.as_str()),
            ("DELETE", "/v1/peer/tickets/tkt_1")
        );
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

    /// A line is not a chunk. The network splits the body wherever it likes, so
    /// an event can arrive in pieces and three can arrive together — reading a
    /// chunk as a record works until it does not, and then silently.
    #[test]
    fn events_are_assembled_across_whatever_the_chunks_are() {
        type Client = ProxyClient<MockTransport>;
        let mut buffer = Vec::new();
        let mut out = Vec::new();

        // Half an event.
        buffer.extend_from_slice(br#"{"type":"peer.connect.crea"#);
        Client::drain_lines(&mut buffer, &mut out);
        assert!(out.is_empty(), "half a line is not a line");

        // Its other half, then two whole ones in a single chunk.
        buffer.extend_from_slice(
            br#"ted","connection_id":"conn_1"}
{"type":"keepalive"}
{"type":"grant.revoked","grant_id":"gr_1"}
"#,
        );
        Client::drain_lines(&mut buffer, &mut out);
        assert!(buffer.is_empty(), "a complete line leaves nothing behind");
        assert!(matches!(
            out.as_slice(),
            [
                ListenerEvent::ConnectCreated { .. },
                ListenerEvent::Keepalive,
                ListenerEvent::GrantRevoked { .. }
            ]
        ));
    }

    /// The proxy may learn to say more than this client knows about, and a
    /// listener that fell over on the first unfamiliar line would be worse off
    /// than one that ignored it. Neither may take the stream down.
    #[test]
    fn an_unknown_or_unreadable_line_does_not_end_the_stream() {
        type Client = ProxyClient<MockTransport>;
        let mut buffer = Vec::new();
        let mut out = Vec::new();
        buffer.extend_from_slice(
            b"{\"type\":\"something.new\",\"whatever\":1}\nnot json at all\n\n{\"type\":\"keepalive\"}\n",
        );
        Client::drain_lines(&mut buffer, &mut out);
        assert!(matches!(
            out.as_slice(),
            [ListenerEvent::Unknown, ListenerEvent::Keepalive]
        ));
    }

    /// A line that never ends must not grow the buffer without limit. The
    /// proxy sends one event per line; nothing here should depend on the other
    /// end being well behaved.
    #[test]
    fn an_endless_line_is_not_buffered_without_limit() {
        type Client = ProxyClient<MockTransport>;
        let mut buffer = vec![b'x'; MAX_EVENT_LINE + 1];
        let mut out = Vec::new();
        Client::drain_lines(&mut buffer, &mut out);
        assert!(out.is_empty(), "there is no complete line in it");
        assert!(
            buffer.len() > MAX_EVENT_LINE,
            "the caller is the one that notices and ends the stream"
        );
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
            ProxyError::Problem {
                status, problem, ..
            } => {
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

    #[test]
    fn a_ticket_transfer_round_trips() {
        let packed = ticket_transfer("tokyo.link.isekai.tools:8443", "tkt1_QA81kTj0cA4Q8gL9");
        assert!(packed.starts_with(TICKET_TRANSFER_PREFIX));
        // The secret must not be readable in the packed form without decoding
        // it, or a shoulder-glance at a chat window is enough.
        assert!(!packed.contains("QA81kTj0cA4Q8gL9"));
        assert_eq!(
            ticket_from_transfer(&packed),
            Some(TicketTransfer {
                proxy: "tokyo.link.isekai.tools:8443".to_owned(),
                ticket: "tkt1_QA81kTj0cA4Q8gL9".to_owned(),
            })
        );
    }

    #[test]
    fn a_bare_ticket_is_accepted_and_names_no_proxy() {
        assert_eq!(
            ticket_from_transfer("  tkt1_QA81kTj0cA4Q8gL9  "),
            Some(TicketTransfer {
                proxy: String::new(),
                ticket: "tkt1_QA81kTj0cA4Q8gL9".to_owned(),
            })
        );
    }

    #[test]
    fn a_ticket_is_taken_from_a_link_fragment() {
        // §8.12.8 asks for the fragment rather than the path or query, so that
        // it stays out of Referer and access logs. A person copying the whole
        // link should still be able to paste it.
        let packed = ticket_transfer("proxy.test", "tkt1_abc");
        let link = format!("https://example.test/join#{packed}");
        assert_eq!(
            ticket_from_transfer(&link).map(|t| t.ticket),
            Some("tkt1_abc".to_owned())
        );
    }

    #[test]
    fn anything_that_is_not_a_ticket_is_refused_before_the_network() {
        for input in [
            "nonsense",
            "K7M2-QX4P",
            "",
            // Right prefix, but the payload is not base64url.
            "iskt1_!!!!",
            // Decodes, but the inner value is not a ticket — so redeeming it
            // would spend a request to be told nothing useful.
            &format!(
                "iskt1_{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(br#"{"p":"proxy.test","t":"not-a-ticket"}"#)
            ),
        ] {
            assert_eq!(ticket_from_transfer(input), None, "{input:?}");
        }
    }

    #[test]
    fn a_padded_transfer_is_accepted_too() {
        // Not what this encodes, but what another implementation is likely to:
        // padded urlsafe base64 is the default of most encoders, and
        // `URL_SAFE_NO_PAD` refuses rather than ignores it.
        let padded = base64::engine::general_purpose::URL_SAFE
            .encode(br#"{"p":"proxy.testx","t":"tkt1_abc"}"#);
        assert!(padded.contains('='), "this fixture is meant to be padded");
        assert_eq!(
            ticket_from_transfer(&format!("iskt1_{padded}")),
            Some(TicketTransfer {
                proxy: "proxy.testx".to_owned(),
                ticket: "tkt1_abc".to_owned(),
            })
        );
    }

    #[test]
    fn an_authority_is_what_two_sides_compare() {
        assert_eq!(
            proxy_authority("https://tokyo.link.isekai.tools:8443"),
            "tokyo.link.isekai.tools:8443"
        );
        assert_eq!(proxy_authority("https://a.test/base?x=1#y"), "a.test");
        assert_eq!(proxy_authority("a.test:8443"), "a.test:8443");
    }

    /// The whole point of loosening this: a response that lost a field must
    /// still hand back the secret, because there is no second chance at it.
    #[test]
    fn a_ticket_response_missing_everything_but_the_secret_still_parses() {
        let ticket: Ticket = serde_json::from_str(r#"{"ticket":"tkt1_secret"}"#).unwrap();
        assert_eq!(ticket.ticket, "tkt1_secret");
        assert_eq!(ticket.ticket_id, None);
        assert_eq!(ticket.grant_ttl, None);
    }

    /// Detection and redaction have to know the same four things.
    ///
    /// The guard that refuses a secret in the wrong flag is what stops it being
    /// sent; redaction only keeps it out of the log afterwards. Knowing fewer
    /// kinds here than there would keep the quieter half of the promise.
    #[test]
    fn every_redacted_prefix_is_also_detectable() {
        for prefix in SECRET_PREFIXES {
            let value = format!("{prefix}AbCd1234");
            assert_eq!(secret_prefix(&value), Some(prefix), "{prefix}");
            assert_eq!(redact_secrets(&value), format!("{prefix}…"), "{prefix}");
        }
    }

    /// Longest-first here too: an `iskt1_` transfer is not "a ticket after an
    /// `i`", and telling somebody the wrong one is telling them the wrong flag.
    #[test]
    fn a_transfer_is_detected_as_a_transfer() {
        assert_eq!(
            secret_prefix("iskt1_AAaa-_09"),
            Some(TICKET_TRANSFER_PREFIX),
        );
    }

    /// A pairing code and an identifier are not secrets, and refusing them
    /// would refuse the flag's own argument.
    #[test]
    fn what_is_not_a_secret_is_not_detected() {
        assert_eq!(secret_prefix("ABCD-1234"), None);
        assert_eq!(secret_prefix("pvk_AbC12345"), None);
        assert_eq!(secret_prefix("enk_AbC12345"), None);
    }

    /// The two keys are redacted for the same reason a Ticket is, and more:
    /// a Ticket is single-use, while a key is a standing arrangement that a
    /// scanner would find in a CI log weeks later.
    #[test]
    fn both_kinds_of_key_are_redacted_too() {
        assert_eq!(
            redact_secrets("issued pvk1_9dQ2mR7xK0 and enr1_AbCd-_09 today"),
            "issued pvk1_… and enr1_… today",
        );
    }

    /// Longest-first matching, which is the one way this can go quietly wrong:
    /// read as `i` + `tkt1_`, an `iskt1_` transfer keeps its `is` and the
    /// redaction starts one prefix too late.
    #[test]
    fn a_transfer_is_not_read_as_a_ticket_after_an_i() {
        let redacted = redact_secrets("take iskt1_AAaa-_09 please");
        assert_eq!(redacted, "take iskt1_… please");
        assert!(!redacted.contains("itkt1_"));
    }

    /// A `pvk_` id is not a `pvk1_` secret, and neither is an `enk_` one.
    #[test]
    fn identifiers_that_merely_look_similar_are_left_alone() {
        assert_eq!(
            redact_secrets("key pvk_AbC12345 made grant gr_AbC12345 for enk_AbC12345"),
            "key pvk_AbC12345 made grant gr_AbC12345 for enk_AbC12345",
        );
    }

    #[test]
    fn redaction_keeps_the_prefix_and_drops_the_secret() {
        let line = "redeeming tkt1_QA81kTj0cA4Q8gL9 now";
        assert_eq!(redact_secrets(line), "redeeming tkt1_… now");
        // The longer prefix must win. Matching `tkt1_` first would leave the
        // `is` behind and redact from inside the word: `is` + `kt1_…`.
        let packed = ticket_transfer("proxy.test", "tkt1_abc");
        assert_eq!(
            redact_secrets(&format!("hand over {packed}")),
            "hand over iskt1_…"
        );
        // Both kinds on one line, each cut at its own end.
        assert_eq!(
            redact_secrets("iskt1_AAaa-_09 then tkt1_BBbb, done"),
            "iskt1_… then tkt1_…, done"
        );
    }

    #[test]
    fn redaction_leaves_everything_else_alone() {
        assert_eq!(redact_secrets("nothing to see"), "nothing to see");
        assert_eq!(
            redact_secrets("grant gr_AbC12345 from ticket tkt_AbC12345"),
            // `tkt_` is the id, not the secret, and is meant to be readable —
            // only `tkt1_` is the thing worth hiding.
            "grant gr_AbC12345 from ticket tkt_AbC12345"
        );
    }

    /// A scanner sees whatever is in front of it. Only this project's own QR
    /// should turn into a request; everything else has to read as "keep
    /// looking" rather than as a code the proxy will refuse.
    #[test]
    fn only_our_own_uri_counts_as_a_scan() {
        assert_eq!(
            pairing_code_in_uri(&pairing_uri("K7M2-QX4P")),
            Some("K7M2-QX4P")
        );
        assert_eq!(
            pairing_code_in_uri("isekai://pair?code=K7M2-QX4P&v=1"),
            Some("K7M2-QX4P")
        );
        for other in [
            "K7M2-QX4P",                                // a bare code is typed, not scanned
            "https://example.test/pair?code=K7M2-QX4P", // someone else's link
            "WIFI:S=cafe;T=WPA;P=hunter2;;",            // a wifi QR
            "isekai://pair?code=",                      // ours, but carrying nothing
            "",
        ] {
            assert_eq!(pairing_code_in_uri(other), None, "{other:?}");
        }
    }
}
