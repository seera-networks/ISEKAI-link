//! Identity API client (spec §8.1 / §8.2 / §8.7 / §8.8): Endpoint registration,
//! Endpoint Token acquisition and renewal, unattended enrolment, and revocation.
//!
//! The Identity API (`ISEKAI-identity`) is HTTPS-only and serves HTTP/1.1 and
//! HTTP/2 on TCP plus HTTP/3 on QUIC at the same port, so this client is generic
//! over [`ControlPlaneTransport`]: pair it with [`crate::https::HttpsTransport`]
//! for h1/h2 or [`crate::transport::MasqueH3Transport`] for h3.
//!
//! # Three ways of saying who you are
//!
//! Most calls carry the user's Auth0 Access Token as `Authorization: Bearer`.
//! Token issuance and renewal additionally require Proof-of-Possession over the
//! request. Signatures use base64url(DER), the encoding the Identity API
//! requires.
//!
//! The unattended routes (§8.8) take a **third kind of credential**, and it does
//! not go in `Authorization`: it is neither an Auth0 token nor an Endpoint
//! Token, and mixing it into that header would leave "what is this checked
//! against?" unreadable from both ends. It goes in the body. [`IdentityAuth`] is
//! that choice, made once and threaded through.
//!
//! **PoP does not move.** §8.8.7 replaces the Auth0 side of "Auth0
//! authentication state plus possession of the Endpoint private key" and
//! nothing else — every route that wanted a PoP still wants one.

use std::time::Duration;

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
    Api {
        status: u16,
        body: String,
        /// What `Retry-After` said, when it said anything.
        ///
        /// **Carried because guessing is worse than obeying.** §8.8.6 puts the
        /// sweep interval *into* this number on purpose: a slot frees at the
        /// next sweep rather than at the expiry, so a client that computes its
        /// own wait from the expiry comes back too early and takes a second
        /// `429`. The same applies to `503 enrollment-unavailable`, where what
        /// is being waited on is the issuer's JWKS coming back.
        retry_after: Option<Duration>,
    },
    #[error("failed to format timestamp")]
    Time,
}

impl IdentityError {
    /// How long the server asked the caller to wait, if it did.
    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            IdentityError::Api { retry_after, .. } => *retry_after,
            _ => None,
        }
    }

    /// The HTTP status, for the few decisions that turn on it.
    ///
    /// Most do not: §8.8.4's `403 enrollment-key-invalid` is deliberately
    /// uniform over unknown, expired, revoked and revoked-owner, and a caller
    /// that tries to tell those apart has rebuilt the oracle the uniformity
    /// exists to deny. The ones that do are `429` and `503`, which are about
    /// capacity and availability rather than authorization.
    pub fn status(&self) -> Option<u16> {
        match self {
            IdentityError::Api { status, .. } => Some(*status),
            _ => None,
        }
    }
}

/// How a request to the Identity API says who is making it.
///
/// **The unattended arm carries no `Authorization` header.** §8.8.4 puts the
/// enrolment key in the body precisely so that the header keeps one meaning,
/// and the server reads it from there.
#[derive(Debug, Clone, Copy)]
pub enum IdentityAuth<'a> {
    /// Route A: a human's Auth0 access token.
    Auth0(&'a str),
    /// §8.8: an Enrollment Key, plus the `binding` evidence when the key was
    /// issued with `binding.type: "oidc"`.
    ///
    /// **The assertion is minted per request, not per job.** §8.8.7 verifies
    /// `binding` on every renewal — that is the brake that stops a key
    /// outliving the job it was issued for — and a workload ID token lives
    /// 5–15 minutes against a renewal interval that is longer than that.
    Enrollment {
        key: &'a str,
        /// Present when the key was issued with `binding.type: "oidc"`.
        assertion: Option<&'a str>,
        /// **Present when the binding is `sub` or `tenant`** (§8.8.3), where
        /// the comparison is against an Auth0 principal that has to be there
        /// to compare with. Those two types are the attended case — rolling
        /// out fifty devices without walking each one through a challenge —
        /// and the server answers `400 assertion-required` without this.
        ///
        /// A key route carrying an Auth0 token is not a contradiction: the
        /// key still says which key, and the header says which person.
        auth0: Option<&'a str>,
    },
}

impl<'a> IdentityAuth<'a> {
    /// An enrolment key on its own — the `binding: none` case.
    pub const fn enrollment(key: &'a str) -> Self {
        IdentityAuth::Enrollment {
            key,
            assertion: None,
            auth0: None,
        }
    }

    /// Add the workload identity token an `oidc` binding wants.
    pub const fn with_assertion(self, assertion: &'a str) -> Self {
        match self {
            IdentityAuth::Enrollment { key, auth0, .. } => IdentityAuth::Enrollment {
                key,
                assertion: Some(assertion),
                auth0,
            },
            other => other,
        }
    }

    /// Add the Auth0 token a `sub` or `tenant` binding wants.
    pub const fn with_auth0(self, token: &'a str) -> Self {
        match self {
            IdentityAuth::Enrollment { key, assertion, .. } => IdentityAuth::Enrollment {
                key,
                assertion,
                auth0: Some(token),
            },
            other => other,
        }
    }
}

impl IdentityAuth<'_> {
    /// Add whatever this credential contributes to a JSON request body.
    fn apply_to_body(&self, body: &mut Value) {
        if let IdentityAuth::Enrollment { key, assertion, .. } = self {
            body["enrollment_key"] = json!(key);
            if let Some(assertion) = assertion {
                body["assertion"] = json!(assertion);
            }
        }
    }

    /// The `Authorization` bearer this credential contributes, if any.
    fn bearer(&self) -> Option<&str> {
        match self {
            IdentityAuth::Auth0(token) => Some(token),
            // **`None` unless a `sub`/`tenant` binding put one here**, and that
            // is load bearing on the self-revoke route: the server only reads
            // the body's key once Auth0 authentication has failed, so a token
            // sent needlessly takes the other branch.
            IdentityAuth::Enrollment { auth0, .. } => *auth0,
        }
    }
}

/// Why an Endpoint is being revoked (§8.7).
///
/// Typed because the vocabulary is closed and half of it is **not the
/// caller's**: `enrollment_idle` and `enrollment_key_revoked` are reasons
/// Identity writes itself (§8.8.8 / §8.8.9), and a request naming one is
/// refused. They appear in responses and listings, never in a request, so they
/// are absent here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokeReason {
    DeviceLost,
    EndpointDeleted,
    AdminRevoke,
    SecurityIncident,
}

impl RevokeReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            RevokeReason::DeviceLost => "device_lost",
            RevokeReason::EndpointDeleted => "endpoint_deleted",
            RevokeReason::AdminRevoke => "admin_revoke",
            RevokeReason::SecurityIncident => "security_incident",
        }
    }
}

/// Who is asking for an Endpoint to be revoked (§8.7, §8.8.7).
///
/// **Separate from [`IdentityAuth`] because the required fields swap.** On the
/// Auth0 route `reason` is mandatory; on the key route it must be absent —
/// Identity writes `enrollment_released` so that "the job tidied up" and "time
/// tidied up" stay tellable apart, which is the difference worth watching in a
/// CI deployment. Threading one `Option<&str>` through both would defer that to
/// a `400` from the server, which is late.
///
/// The key route also carries **no assertion**, and that is not an omission.
/// `binding` answers "who may *get* something with this key", and revocation
/// gets nothing; the job that died badly enough to be unable to mint an OIDC
/// token is exactly the job whose slot should come back.
///
/// **The two arms name their target differently, and have to.** An owner
/// revoking a lost device does not hold that device's private key — that is
/// what `device_lost` means — so the Auth0 arm takes an id. The key arm takes
/// the key itself, because it signs a PoP with it, and that is precisely what
/// confines self-revocation to the one Endpoint whose private key is in hand.
#[derive(Debug, Clone, Copy)]
pub enum RevokeAuth<'a> {
    Auth0 {
        token: &'a str,
        /// Any Endpoint this caller owns, or any at all for an admin.
        endpoint_id: &'a str,
        reason: RevokeReason,
    },
    Enrollment {
        key: &'a str,
        /// **This Endpoint and no other.** The PoP signed with it is the
        /// proof, so a leaked enrolment key alone stops nothing — not the
        /// other Endpoints it grew, and not an attended one.
        endpoint: &'a EndpointKey,
    },
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

/// Response of `POST /v1/endpoints/enroll` (§8.8.5) — registration and the
/// first Endpoint Token in one round trip.
///
/// **Only two fields are required, and everything else is optional**, which is
/// the same call the `Ticket` and `Grant` types in [`crate::proxy`] make and
/// for a stronger reason. A response this cannot parse is an enrolment that
/// *succeeded*: a slot is spent, the Challenge is consumed, and — because one
/// key registers exactly one Endpoint — **that keypair can never be registered
/// again**. Every retry is `409`. A missing `device_id` is not worth that.
#[derive(Debug, Clone, Deserialize)]
pub struct Enrolled {
    pub endpoint_id: String,
    pub endpoint_token: String,
    /// Absent means the server did not say. Callers that drive a renewal loop
    /// should treat that as the §8.2.1 floor (300) rather than as zero.
    #[serde(default)]
    pub expires_in: Option<i64>,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub registered_at: Option<String>,
    #[serde(default)]
    pub enrollment_key_id: Option<String>,
    /// Whether idle sweeping will retire this Endpoint (§8.8.8).
    #[serde(default)]
    pub ephemeral: Option<bool>,
    /// When the idle sweep would retire it. Present only when `ephemeral`.
    #[serde(default)]
    pub expires_at: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
}

impl Enrolled {
    /// The Endpoint Token, in the shape the rest of this crate passes around.
    ///
    /// `expires_in` falls back to **300**, the floor §8.2.1 clamps a `ttl` to.
    /// Zero would be the wrong guess in the expensive direction: a renewal loop
    /// reading it would fall to its own 30-second minimum and hammer Identity
    /// for the length of the job.
    pub fn token(&self) -> EndpointToken {
        EndpointToken {
            endpoint_token: self.endpoint_token.clone(),
            token_type: "Bearer".to_owned(),
            expires_in: self.expires_in.unwrap_or(MIN_TOKEN_TTL_SECS),
            endpoint_id: self.endpoint_id.clone(),
            permissions: self.permissions.clone(),
            protocols: self.protocols.clone(),
        }
    }
}

/// The shortest Endpoint Token lifetime §8.2.1 will issue.
const MIN_TOKEN_TTL_SECS: i64 = 300;

/// What binds an Enrollment Key to something other than its own possession
/// (§8.8.3).
///
/// **`audience` is not here on purpose.** Both servers take it from operator
/// configuration and refuse to let a caller name one, because a workload can
/// mint a token for whatever audience it asks for — a key naming another
/// service's audience would accept the tokens that service is holding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Binding {
    /// A bearer credential and nothing else. Never for a public repository's CI.
    None,
    /// A workload identity token from `issuer`, whose `sub` matches exactly.
    Oidc { issuer: String, subject: String },
    /// The Auth0 `sub` of whoever presents it. **Not usable unattended.**
    Sub,
    /// The Auth0 tenant of whoever presents it. **Not usable unattended.**
    Tenant,
}

impl Binding {
    fn to_json(&self) -> Value {
        match self {
            Binding::None => json!({ "type": "none" }),
            Binding::Sub => json!({ "type": "sub" }),
            Binding::Tenant => json!({ "type": "tenant" }),
            Binding::Oidc { issuer, subject } => json!({
                "type": "oidc",
                "issuer": issuer,
                "subject": subject,
            }),
        }
    }
}

/// What to ask for when issuing an Enrollment Key (§8.8.2).
///
/// `binding` has no default **because the server has none**: every other knob
/// here fails closed, and letting an omitted `binding` mean `none` would make
/// the shortest request the most dangerous one.
#[derive(Debug, Clone)]
pub struct NewEnrollmentKey {
    pub binding: Binding,
    pub permissions: Option<Vec<String>>,
    pub protocols: Option<Vec<String>>,
    pub ttl: Option<i64>,
    pub ephemeral: Option<bool>,
    pub endpoint_idle_ttl: Option<i64>,
    pub max_live_endpoints: Option<i64>,
    pub device_id_prefix: Option<String>,
    pub device_name_template: Option<String>,
    pub label: Option<String>,
}

impl NewEnrollmentKey {
    /// A key bound to `binding` and otherwise left to the server's defaults.
    pub fn new(binding: Binding) -> Self {
        Self {
            binding,
            permissions: None,
            protocols: None,
            ttl: None,
            ephemeral: None,
            endpoint_idle_ttl: None,
            max_live_endpoints: None,
            device_id_prefix: None,
            device_name_template: None,
            label: None,
        }
    }
}

/// An Enrollment Key as issued (§8.8.2).
///
/// Lax for the same reason [`Enrolled`] is: `key` is **returned by this call
/// only and never re-fetchable**, so a response this cannot parse is a key the
/// server has minted, counted against the quota, and will never show again.
#[derive(Debug, Clone, Deserialize)]
pub struct IssuedEnrollmentKey {
    /// The secret, `enr1_`-prefixed. Store it now or lose it.
    ///
    /// **The wire name is `key_plaintext`.** §8.8.2's example used to say
    /// `key` and has been corrected (ISEKAI-identity#36) to match the server
    /// and its OpenAPI, which always said `key_plaintext`.
    ///
    /// `key` is still accepted, because the cost of not accepting it is
    /// asymmetric: the key is minted, counted against the quota and never
    /// shown again, so a name this cannot match costs the caller a key rather
    /// than a retry. That is worth one `alias` against a deployment running
    /// something older.
    #[serde(rename = "key_plaintext", alias = "key")]
    pub key: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub owner_sub: Option<String>,
    #[serde(default)]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub ephemeral: Option<bool>,
    #[serde(default)]
    pub endpoint_idle_ttl: Option<i64>,
    #[serde(default)]
    pub max_live_endpoints: Option<i64>,
    #[serde(default)]
    pub binding: Option<crate::proxy::BindingView>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
    /// **Not authorization.** §8.8.2 says so outright: these flag the §8.8.10
    /// mismatches at issue time rather than in CI, and issuing succeeds with
    /// them present. Show them; do not act on them.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// One row of `GET /v1/enrollment-keys` (§8.8.9) — the issue response without
/// the secret, plus how full it is.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentKeyRecord {
    pub key_id: String,
    #[serde(default)]
    pub status: Option<String>,
    /// Slots in use right now. Not a running total.
    #[serde(default)]
    pub live_endpoints: Option<i64>,
    #[serde(default)]
    pub max_live_endpoints: Option<i64>,
    /// Registrations within the retention window.
    #[serde(default)]
    pub enrollment_count: Option<i64>,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub ephemeral: Option<bool>,
    #[serde(default)]
    pub binding: Option<crate::proxy::BindingView>,
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub created_at: Option<String>,
    #[serde(default)]
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnrollmentKeyList {
    /// **Not defaulted, unlike most fields here.** A listing is idempotent and
    /// costs nothing to repeat, so a shape this cannot read should say so: a
    /// silent empty list reads as "this owner has no keys", and an operator
    /// acting on that issues past the quota of 4 until the `429`.
    #[serde(alias = "keys")]
    items: Vec<EnrollmentKeyRecord>,
}

/// One Endpoint an Enrollment Key registered (§8.8.9).
///
/// **This outlives the key.** Revoking or expiring a key does not erase it,
/// because the moment a key is stopped — a leak, a compromise, someone leaving
/// — is the moment "who came in on it" matters most.
#[derive(Debug, Clone, Deserialize)]
pub struct EnrollmentRecord {
    pub endpoint_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    /// The `sub` of the workload that enrolled, when the binding was `oidc`.
    /// **Recorded as it was at enrolment**, not as the key reads now.
    #[serde(default)]
    pub binding_subject: Option<String>,
    #[serde(default)]
    pub enrolled_at: Option<String>,
    #[serde(default)]
    pub last_token_issued_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    /// `enrollment_released` means the job tidied up after itself;
    /// `enrollment_idle` means nothing did and the sweep got there. **The
    /// second one climbing is a CI problem, not a capacity one.**
    #[serde(default)]
    pub revoke_reason: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct EnrollmentList {
    #[serde(default)]
    enrollments: Vec<EnrollmentRecord>,
    #[serde(default)]
    next_cursor: Option<String>,
}

/// One row of `GET /v1/endpoints` (§8.1.3).
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointSummary {
    pub endpoint_id: String,
    #[serde(default)]
    pub device_id: Option<String>,
    #[serde(default)]
    pub device_name: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub registered_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    #[serde(default)]
    pub revoke_reason: Option<String>,
    /// **Another live Endpoint shares this public key** (ISEKAI-identity#16).
    ///
    /// While this is true, **revoking this row does not stop the key** — the
    /// other row keeps working. §8.7 is the emergency exit, and an exit that
    /// looks taken while the door is open is the one thing it must not be, so
    /// anything that revokes has to say this out loud.
    #[serde(default)]
    pub duplicate_key: bool,
    /// Which Enrollment Key grew this row; `None` for an attended registration.
    #[serde(default)]
    pub enrollment_key_id: Option<String>,
    /// Whether the idle sweep will retire it (§8.8.8) — so a row visible today
    /// may not be tomorrow.
    #[serde(default)]
    pub ephemeral: bool,
    /// Last time a token was issued or renewed. **Not "connected now".**
    #[serde(default)]
    pub last_token_issued_at: Option<String>,
}

/// `GET /v1/endpoints` (§8.1.3).
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointList {
    /// **Not defaulted**, for the reason the enrolment-key listing is not: an
    /// empty answer to a shape this cannot read says "you have no Endpoints",
    /// which is the worst possible answer to somebody looking for one to stop.
    pub items: Vec<EndpointSummary>,
    /// How many rows this filter hid because they are revoked.
    ///
    /// **`Some(0)` and `None` mean different things**, and the server is
    /// deliberate about it: `Some(0)` is "nothing revoked matched", `None` is
    /// "not counted, because you asked for revoked rows anyway". Showing them
    /// as the same would undo what the field is for — making the default
    /// filter's hiding visible.
    #[serde(default)]
    pub revoked_count: Option<u64>,
    /// **`None` is "no more here", not "that was everything"** — rows can be
    /// registered or revoked while a listing is being paged.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// `GET /v1/endpoints/{endpoint_id}` (§8.1.4) — a row, plus what shares its key.
#[derive(Debug, Clone, Deserialize)]
pub struct EndpointDetail {
    #[serde(flatten)]
    pub summary: EndpointSummary,
    /// The other live Endpoints holding this same public key, within this
    /// tenant. **These are what keeps working after revoking this one.**
    #[serde(default)]
    pub duplicate_key_siblings: Vec<String>,
}

/// What revoking an Endpoint did (§8.7).
#[derive(Debug, Clone, Deserialize)]
pub struct Revoked {
    pub endpoint_id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub reason: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    /// `delivered` | `partial` | `failed` | `disabled`.
    ///
    /// **A `200` does not mean the Endpoint stopped.** Identity's own record is
    /// settled either way (fail-safe), but `failed` leaves the proxy's grants
    /// standing and `partial` means the proxy discarded them while its auth
    /// layer keeps letting the Endpoint through.
    #[serde(default)]
    pub proxy_notification: Option<String>,
    #[serde(default)]
    pub proxy_notification_detail: Option<String>,
    #[serde(default)]
    pub effects: Option<RevokeEffects>,
}

/// What a revocation tore down (§8.7).
///
/// **Every field is optional and zero is not silence.** "Nothing was there to
/// remove" and "the proxy was never told" both produce zeros, which is why
/// [`Revoked::proxy_notification`] has to be read beside this rather than
/// instead of it.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RevokeEffects {
    #[serde(default)]
    pub revoked_tokens: Option<u64>,
    #[serde(default)]
    pub deleted_peer_listeners: Option<u64>,
    #[serde(default)]
    pub deleted_public_listeners: Option<u64>,
    #[serde(default)]
    pub deleted_capabilities: Option<u64>,
    #[serde(default)]
    pub closed_connections: Option<u64>,
    #[serde(default)]
    pub deleted_grants: Option<u64>,
    #[serde(default)]
    pub deleted_pairing_codes: Option<u64>,
    /// Absent rather than zero when the store could not be reached, so that a
    /// failure is not read as "there were none".
    #[serde(default)]
    pub revoked_policy_leases: Option<u64>,
    /// Whether this call is what made it stick.
    ///
    /// **`false` means somebody already revoked it** — a previous attempt, or
    /// the idle sweep. Worth printing: repeating a revocation whose
    /// notification failed is the documented recovery, and this says whether
    /// the repeat did anything.
    #[serde(default)]
    pub newly_revoked: Option<bool>,
}

/// What revoking an Enrollment Key did (§8.8.9).
#[derive(Debug, Clone, Deserialize)]
pub struct RevokedEnrollmentKey {
    pub key_id: String,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
    /// Whether the cascade reached the proxy: `delivered` | `partial` |
    /// `failed` | `disabled`, and absent when there was nothing to revoke.
    ///
    /// **Carried for the same reason [`Revoked`] carries it.** A `200` here
    /// does not mean the Endpoints this key grew have stopped — one
    /// undelivered notification leaves their grants standing at the proxy,
    /// and revoking a key is what somebody does about a leak.
    #[serde(default)]
    pub proxy_notification: Option<String>,
    #[serde(default)]
    pub effects: Option<RevokeKeyEffects>,
}

/// Which derived Endpoints a key revocation took with it (§8.8.9).
///
/// **The two lists are the whole point.** An `ephemeral` key takes its
/// Endpoints down; a non-`ephemeral` one leaves them standing, because an
/// Endpoint revocation cannot be undone and one key registers one Endpoint —
/// retiring a long-lived runner's Endpoint means it cannot come back until
/// someone makes it a new keypair.
#[derive(Debug, Clone, Deserialize)]
pub struct RevokeKeyEffects {
    #[serde(default)]
    pub revoked_endpoints: Vec<String>,
    #[serde(default)]
    pub remaining_endpoints: Vec<String>,
    #[serde(default)]
    pub newly_revoked: Option<bool>,
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
        self.post(
            "/v1/endpoints/register/challenge",
            IdentityAuth::Auth0(auth0_token),
            None,
            body,
        )
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
        self.post(
            "/v1/endpoints/register",
            IdentityAuth::Auth0(auth0_token),
            None,
            body,
        )
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
        self.post_bytes("/v1/tokens/endpoint", Some(auth0_token), Some(&pop), bytes)
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

    // ---- §8.2.2 / §8.2.3: renewal ----

    /// §8.2.2 — a challenge for renewing this Endpoint's token.
    ///
    /// **No assertion, even on the key route.** §8.8.7 verifies `binding` at
    /// the refresh itself and not here, the same judgement §8.8.4 makes about
    /// enrolment: requiring the evidence twice only widens the window in which
    /// a short-lived OIDC token can expire between the two calls. A challenge
    /// lasts 120 seconds, is bound to the credential that fetched it, and
    /// mints nothing on its own.
    pub async fn refresh_challenge(
        &self,
        auth: IdentityAuth<'_>,
        endpoint_id: &str,
    ) -> Result<Challenge, IdentityError> {
        let mut body = json!({ "endpoint_id": endpoint_id });
        // The key, but never the assertion: see above.
        if let IdentityAuth::Enrollment { key, .. } = auth {
            body["enrollment_key"] = json!(key);
        }
        self.post("/v1/tokens/endpoint/refresh/challenge", auth, None, body)
            .await
    }

    /// §8.2.3 — renew the Endpoint Token by signing the challenge.
    ///
    /// **Renewal never widens.** The result is
    /// `current ceiling ∩ the token being refreshed`, monotonically, so
    /// `requested_*` is not sent: it exists only to narrow further, and asking
    /// for the ceiling back is what re-issuing (§8.2.1) is for.
    ///
    /// PoP is required here whichever credential is used — §8.8.7 substitutes
    /// for the Auth0 half of §17's pair and leaves the key-possession half
    /// exactly where it was.
    pub async fn refresh_token(
        &self,
        auth: IdentityAuth<'_>,
        key: &EndpointKey,
        challenge: &Challenge,
        ttl: Option<i64>,
    ) -> Result<EndpointToken, IdentityError> {
        let endpoint_id = key.endpoint_id();
        let timestamp = now_rfc3339()?;
        let signature = sign_challenge(key, &challenge.challenge, &endpoint_id, &timestamp);
        let mut body = json!({
            "challenge_id": challenge.challenge_id,
            "endpoint_id": endpoint_id,
            "timestamp": timestamp,
            "signature": signature,
        });
        if let Some(t) = ttl {
            body["ttl"] = json!(t);
        }
        auth.apply_to_body(&mut body);
        self.post_signed("/v1/tokens/endpoint/refresh", auth, key, body)
            .await
    }

    // ---- §8.8.4 / §8.8.5: unattended enrolment ----

    /// §8.8.4 — a challenge for enrolling `key` under `enrollment_key`.
    ///
    /// Carries no `Authorization` and creates no Endpoint. The challenge is
    /// bound to both the keypair and the enrolment key, so one taken with a
    /// different key cannot be spent here.
    pub async fn enroll_challenge(
        &self,
        auth: IdentityAuth<'_>,
        key: &EndpointKey,
    ) -> Result<Challenge, IdentityError> {
        let mut body = json!({
            "endpoint_id": key.endpoint_id(),
            "public_key": key.public_jwk(),
        });
        // The key, but not the assertion: `binding` is checked at §8.8.5 and
        // not here, so asking for the evidence twice only widens the window in
        // which a short-lived OIDC token can expire between the two calls.
        if let IdentityAuth::Enrollment { key, .. } = auth {
            body["enrollment_key"] = json!(key);
        }
        // `auth.bearer()` rather than nothing: a `sub`/`tenant` key needs the
        // Auth0 token here too, and §8.8.4's ordering puts the existing-
        // registration check behind it.
        self.post_bytes(
            "/v1/endpoints/enroll/challenge",
            auth.bearer(),
            None,
            serde_json::to_vec(&body).expect("json body serializes"),
        )
        .await
    }

    /// §8.8.5 — register unattended, receiving the first Endpoint Token with
    /// the registration.
    ///
    /// **One round trip on purpose.** §8.2.1 wants an Auth0 token, so a job
    /// handed only a registration would stop right there.
    ///
    /// The private key does not leave: what is sent is the public key from
    /// [`Self::enroll_challenge`] and a signature over
    /// `challenge ‖ endpoint_id ‖ timestamp` — **the same signed message
    /// §8.1.2 uses**, which is why [`sign_challenge`] serves both.
    pub async fn enroll(
        &self,
        auth: IdentityAuth<'_>,
        key: &EndpointKey,
        challenge: &Challenge,
        device_name: Option<&str>,
        ttl: Option<i64>,
    ) -> Result<Enrolled, IdentityError> {
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
        if let Some(t) = ttl {
            body["ttl"] = json!(t);
        }
        auth.apply_to_body(&mut body);
        self.post("/v1/endpoints/enroll", auth, None, body).await
    }

    /// §8.1.3 — the Endpoints this caller owns.
    ///
    /// **Revoked rows are hidden unless asked for**, which is why
    /// [`EndpointList::revoked_count`] exists and why anything showing this
    /// should show that too.
    pub async fn list_endpoints(
        &self,
        auth0_token: &str,
        status: Option<&str>,
        cursor: Option<&str>,
    ) -> Result<EndpointList, IdentityError> {
        let mut query = Vec::new();
        if let Some(status) = status {
            query.push(format!("status={status}"));
        }
        if let Some(cursor) = cursor {
            query.push(format!("cursor={cursor}"));
        }
        let path = if query.is_empty() {
            "/v1/endpoints".to_owned()
        } else {
            format!("/v1/endpoints?{}", query.join("&"))
        };
        self.request(
            "GET",
            &path,
            IdentityAuth::Auth0(auth0_token),
            None,
            Vec::new(),
        )
        .await
    }

    /// §8.1.4 — one Endpoint, and what else holds its key.
    pub async fn get_endpoint(
        &self,
        auth0_token: &str,
        endpoint_id: &str,
    ) -> Result<EndpointDetail, IdentityError> {
        self.request(
            "GET",
            &format!("/v1/endpoints/{endpoint_id}"),
            IdentityAuth::Auth0(auth0_token),
            None,
            Vec::new(),
        )
        .await
    }

    // ---- §8.7: revocation ----

    /// §8.7 — revoke an Endpoint, as its owner or as itself.
    ///
    /// [`RevokeAuth`] carries the asymmetry: the Auth0 route states a reason,
    /// the key route states none and gets `enrollment_released`. The key route
    /// signs a PoP, which is what confines it to **this** Endpoint — a leaked
    /// key alone stops nothing, including the other Endpoints it grew.
    ///
    /// **Best-effort at the end of a job.** The idle sweep is behind this, so a
    /// failure here costs a slot until then and nothing else; it is not a
    /// reason to fail work that otherwise succeeded.
    pub async fn revoke_endpoint(
        &self,
        auth: RevokeAuth<'_>,
        note: Option<&str>,
    ) -> Result<Revoked, IdentityError> {
        let mut body = json!({});
        if let Some(note) = note {
            body["note"] = json!(note);
        }
        match auth {
            RevokeAuth::Auth0 {
                token,
                endpoint_id,
                reason,
            } => {
                body["reason"] = json!(reason.as_str());
                let path = format!("/v1/endpoints/{endpoint_id}/revoke");
                self.post(&path, IdentityAuth::Auth0(token), None, body)
                    .await
            }
            RevokeAuth::Enrollment { key, endpoint } => {
                let path = format!("/v1/endpoints/{}/revoke", endpoint.endpoint_id());
                // No assertion, and no `Authorization`: the server only looks
                // for a key in the body once Auth0 auth has failed, so sending
                // a token here would take the other branch.
                let auth = IdentityAuth::enrollment(key);
                auth.apply_to_body(&mut body);
                self.post_signed(&path, auth, endpoint, body).await
            }
        }
    }

    // ---- §8.8.2 / §8.8.9: managing the keys themselves ----

    /// §8.8.2 — issue an Enrollment Key. Route A; **no PoP**, because the
    /// caller is a person and has no Endpoint key to bind to.
    ///
    /// The secret comes back once. Whatever the response `warnings` say is
    /// worth showing the operator: they name the §8.8.10 mismatches that
    /// otherwise surface as a failure in CI, days later.
    pub async fn create_enrollment_key(
        &self,
        auth0_token: &str,
        request: &NewEnrollmentKey,
    ) -> Result<IssuedEnrollmentKey, IdentityError> {
        let mut body = json!({ "binding": request.binding.to_json() });
        if let Some(v) = &request.permissions {
            body["permissions"] = json!(v);
        }
        if let Some(v) = &request.protocols {
            body["protocols"] = json!(v);
        }
        if let Some(v) = request.ttl {
            body["ttl"] = json!(v);
        }
        if let Some(v) = request.ephemeral {
            body["ephemeral"] = json!(v);
        }
        if let Some(v) = request.endpoint_idle_ttl {
            body["endpoint_idle_ttl"] = json!(v);
        }
        if let Some(v) = request.max_live_endpoints {
            body["max_live_endpoints"] = json!(v);
        }
        if let Some(v) = &request.device_id_prefix {
            body["device_id_prefix"] = json!(v);
        }
        if let Some(v) = &request.device_name_template {
            body["device_name_template"] = json!(v);
        }
        if let Some(v) = &request.label {
            body["label"] = json!(v);
        }
        self.post(
            "/v1/enrollment-keys",
            IdentityAuth::Auth0(auth0_token),
            None,
            body,
        )
        .await
    }

    /// §8.8.9 — this caller's Enrollment Keys, newest first.
    pub async fn list_enrollment_keys(
        &self,
        auth0_token: &str,
    ) -> Result<Vec<EnrollmentKeyRecord>, IdentityError> {
        let list: EnrollmentKeyList = self
            .request(
                "GET",
                "/v1/enrollment-keys",
                IdentityAuth::Auth0(auth0_token),
                None,
                Vec::new(),
            )
            .await?;
        Ok(list.items)
    }

    /// §8.8.9 — which Endpoints a key registered, and how each of them ended.
    ///
    /// A separate route from the listing because this grows: it is the audit
    /// face that makes a bearer credential acceptable to operate.
    pub async fn enrollment_key_enrollments(
        &self,
        auth0_token: &str,
        key_id: &str,
        cursor: Option<&str>,
    ) -> Result<(Vec<EnrollmentRecord>, Option<String>), IdentityError> {
        let path = match cursor {
            Some(cursor) => format!("/v1/enrollment-keys/{key_id}/enrollments?cursor={cursor}"),
            None => format!("/v1/enrollment-keys/{key_id}/enrollments"),
        };
        let list: EnrollmentList = self
            .request(
                "GET",
                &path,
                IdentityAuth::Auth0(auth0_token),
                None,
                Vec::new(),
            )
            .await?;
        Ok((list.enrollments, list.next_cursor))
    }

    /// §8.8.9 — stop a key, and say what became of what it grew.
    ///
    /// `revoke_endpoints` forces the derived Endpoints down whatever the key's
    /// `ephemeral` says. Leave it `None` for the default, which differs by
    /// key: `ephemeral` keys take their Endpoints with them, and others leave
    /// them running and name them in `remaining_endpoints`.
    pub async fn revoke_enrollment_key(
        &self,
        auth0_token: &str,
        key_id: &str,
        revoke_endpoints: Option<bool>,
        note: Option<&str>,
    ) -> Result<RevokedEnrollmentKey, IdentityError> {
        let mut body = json!({});
        if let Some(v) = revoke_endpoints {
            body["revoke_endpoints"] = json!(v);
        }
        if let Some(note) = note {
            body["note"] = json!(note);
        }
        self.post(
            &format!("/v1/enrollment-keys/{key_id}/revoke"),
            IdentityAuth::Auth0(auth0_token),
            None,
            body,
        )
        .await
    }

    /// POST a body that has to be signed by the Endpoint key.
    ///
    /// Separate from [`Self::post`] because the PoP covers a hash of the exact
    /// bytes sent, so the body has to be serialized once and both signed and
    /// sent — serializing twice risks two different byte strings.
    async fn post_signed<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        auth: IdentityAuth<'_>,
        key: &EndpointKey,
        body: Value,
    ) -> Result<R, IdentityError> {
        let bytes = serde_json::to_vec(&body).expect("json body serializes");
        let pop = pop::sign_request(key, "POST", path, &bytes);
        self.post_bytes(path, auth.bearer(), Some(&pop), bytes)
            .await
    }

    async fn post<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        auth: IdentityAuth<'_>,
        pop: Option<&pop::PopHeaders>,
        body: Value,
    ) -> Result<R, IdentityError> {
        let bytes = serde_json::to_vec(&body).expect("json body serializes");
        self.post_bytes(path, auth.bearer(), pop, bytes).await
    }

    async fn post_bytes<R: for<'de> Deserialize<'de>>(
        &self,
        path: &str,
        bearer: Option<&str>,
        pop: Option<&pop::PopHeaders>,
        body: Vec<u8>,
    ) -> Result<R, IdentityError> {
        self.request_raw("POST", path, bearer, pop, body).await
    }

    async fn request<R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        auth: IdentityAuth<'_>,
        pop: Option<&pop::PopHeaders>,
        body: Vec<u8>,
    ) -> Result<R, IdentityError> {
        self.request_raw(method, path, auth.bearer(), pop, body)
            .await
    }

    /// The one place a request is actually built and its answer read.
    ///
    /// **`bearer` is an `Option` and not a `&str`.** The unattended routes send
    /// no `Authorization` at all — and on the self-revoke route that is load
    /// bearing rather than cosmetic: the server only looks for a key in the
    /// body *after* Auth0 authentication has failed, so a request carrying both
    /// would take the other branch and be judged as a person.
    async fn request_raw<R: for<'de> Deserialize<'de>>(
        &self,
        method: &str,
        path: &str,
        bearer: Option<&str>,
        pop: Option<&pop::PopHeaders>,
        body: Vec<u8>,
    ) -> Result<R, IdentityError> {
        let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
        if let Some(token) = bearer {
            headers.push(("authorization".to_owned(), format!("Bearer {token}")));
        }
        if let Some(pop) = pop {
            headers.extend(
                pop.as_pairs()
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), value.to_owned())),
            );
        }
        let resp = self.transport.send(method, path, &headers, body).await?;
        if !(200..300).contains(&resp.status) {
            return Err(IdentityError::Api {
                status: resp.status,
                body: String::from_utf8_lossy(&resp.body).into_owned(),
                retry_after: resp.retry_after(),
            });
        }
        serde_json::from_slice(&resp.body).map_err(|e| IdentityError::Api {
            status: resp.status,
            body: format!("invalid response JSON: {e}"),
            // A body this cannot read is not a wait-and-retry, whatever the
            // header says.
            retry_after: None,
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
