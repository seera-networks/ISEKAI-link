//! Shared configuration and Endpoint Token acquisition.
//!
//! A [`P2pConfig`] says how to reach the Identity API and the proxy, which Auth0
//! token authenticates to the Identity API, and which Endpoint key to prove
//! possession of. [`issue_endpoint_token`] turns that into an Endpoint Token,
//! which the session facades then use for the proxy control plane and relay
//! data path.

use std::path::Path;
use std::time::Duration;

use anyhow::Context as _;
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::Narrowing;
use isekai_p2p_core::identity::{EndpointToken, IdentityAuth, IdentityClient, RevokeAuth};
use isekai_p2p_core::proxy::{ControlPlaneTransport, ProxyClient};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::auth::{Credential, Enrollment};

/// Everything a P2P session needs to reach the services and identify itself.
///
/// Cloneable because a session keeps one: issuing an Endpoint Token is not a
/// startup step but something that happens every few minutes for as long as the
/// session lives, and all of this is what it takes.
#[derive(Clone)]
pub struct P2pConfig {
    /// Identity API base URL (HTTPS), e.g. `https://identity.isekai.tools:9443`.
    pub identity_url: String,
    /// Reach the Identity API over HTTP/3 (QUIC) instead of HTTP/1.1 + HTTP/2.
    pub identity_http3: bool,
    /// Proxy base URL, e.g. `https://link.isekai.tools:6443`.
    pub proxy_url: String,
    /// How this session proves who it is to the Identity API — a person's Auth0
    /// sign-in, or an Enrollment Key for a job with nobody at the keyboard.
    ///
    /// **Never sent to the proxy**, whichever it is: the proxy sees only the
    /// Endpoint Token this obtains, and a PoP over each request.
    pub credential: Credential,
    /// P2P protocol string, e.g. `isekai-validator-v1`.
    pub protocol: String,
    /// Device display name recorded at registration.
    pub device_name: Option<String>,
    /// Requested Endpoint Token TTL, in seconds (`None` = server default).
    pub token_ttl: Option<i64>,
    /// The Endpoint keypair, proven on every proxy request via PoP.
    pub key: EndpointKey,
    /// What the Endpoint Token should be narrowed to, and which Gateways
    /// should hear about this Endpoint.
    ///
    /// **The two halves travel differently.** A renewal cannot widen, so the
    /// remembered axes — permissions and protocols — are asked for once, at
    /// issue. The selector is not remembered and goes out again at every
    /// renewal; see `IdentityClient::refresh_token`. Leaving this at its
    /// default is what every caller before agent mode did, and gets the
    /// ceiling.
    pub narrowing: Narrowing,
}

impl P2pConfig {
    /// This Endpoint's ID (`ep:...`), derived from [`P2pConfig::key`].
    pub fn endpoint_id(&self) -> String {
        self.key.endpoint_id()
    }
}

/// Load a PKCS#8 PEM Endpoint key from `path`, generating and persisting one on
/// first use.
///
/// A generated key is written with owner-only (`0600`) permissions on Unix — it
/// is long-lived material that must never leave the Endpoint.
pub fn load_or_generate_key(path: &Path) -> anyhow::Result<EndpointKey> {
    if path.exists() {
        let pem = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read Endpoint key at {}", path.display()))?;
        return EndpointKey::from_pkcs8_pem(&pem).map_err(anyhow::Error::from);
    }
    let key = EndpointKey::generate();
    let pem = key.to_pkcs8_pem()?;
    write_private(path, &pem)?;
    Ok(key)
}

/// Obtain an Endpoint Token over whichever Identity API transport the config
/// selects, registering or enrolling first when that is what is needed.
pub async fn issue_endpoint_token(cfg: &P2pConfig) -> anyhow::Result<EndpointToken> {
    // The Identity API serves h1/h2 on TCP+TLS and h3 on QUIC at the same port;
    // pick one. The two branches build different concrete transports, so the
    // register/issue work is shared via the generic `issue`.
    if cfg.identity_http3 {
        let client = IdentityClient::new(MasqueH3Transport::connect(&cfg.identity_url)?);
        issue(&client, cfg).await
    } else {
        let client = IdentityClient::new(HttpsTransport::connect(&cfg.identity_url)?);
        issue(&client, cfg).await
    }
}

/// Read the policies in force for this Endpoint as a Gateway (identity §8.10.2).
///
/// **Branches on the transport like [`issue_endpoint_token`] does**, and for the
/// same reason: which one Identity is reached over is a deployment's choice, and
/// both can answer a plain GET. (The *stream* is a different matter — only the
/// H3 transport implements `EventStreamTransport` today, which is a later
/// phase's problem.)
pub async fn list_policies(
    cfg: &P2pConfig,
    endpoint_token: &str,
) -> anyhow::Result<isekai_p2p_core::identity::PolicySnapshot> {
    if cfg.identity_http3 {
        let client = IdentityClient::new(MasqueH3Transport::connect(&cfg.identity_url)?);
        Ok(client.list_policies(endpoint_token, &cfg.key).await?)
    } else {
        let client = IdentityClient::new(HttpsTransport::connect(&cfg.identity_url)?);
        Ok(client.list_policies(endpoint_token, &cfg.key).await?)
    }
}

/// Subscribe to the policy stream (identity §8.10.3).
///
/// **Only the H3 transport could do this until now.** `EventStreamTransport`
/// is implemented for both since this phase, so the branch here is the same
/// runtime choice every other Identity call makes rather than a limitation.
pub async fn policy_stream(
    cfg: &P2pConfig,
    endpoint_token: &str,
    after: Option<i64>,
) -> anyhow::Result<PolicyStream> {
    if cfg.identity_http3 {
        let client = IdentityClient::new(MasqueH3Transport::connect(&cfg.identity_url)?);
        let events = client
            .policy_stream(endpoint_token, &cfg.key, after)
            .await?;
        Ok(PolicyStream {
            events,
            _transport: Box::new(client),
        })
    } else {
        let client = IdentityClient::new(HttpsTransport::connect(&cfg.identity_url)?);
        let events = client
            .policy_stream(endpoint_token, &cfg.key, after)
            .await?;
        Ok(PolicyStream {
            events,
            _transport: Box::new(client),
        })
    }
}

/// A policy stream, and the client it is being read over.
///
/// **The client has to outlive the stream.** Returning the receiver alone left
/// the `IdentityClient` — and with it the last handle on the H3 channel — to be
/// dropped at the end of the call that opened it, tearing the QUIC connection
/// down while the stream was still being read. `listener_events` escapes this
/// only because its caller happens to keep the client alive.
///
/// The HTTPS transport survives either way, since `reqwest`'s response owns
/// what it needs — which is exactly why this would have gone unnoticed on the
/// deployment it was tested against.
pub struct PolicyStream {
    events: tokio::sync::mpsc::Receiver<isekai_p2p_core::identity::PolicyEvent>,
    /// Held, not read.
    _transport: Box<dyn std::any::Any + Send>,
}

impl PolicyStream {
    /// The next event, or `None` when the stream has ended.
    pub async fn recv(&mut self) -> Option<isekai_p2p_core::identity::PolicyEvent> {
        self.events.recv().await
    }
}

/// Give an unattended Endpoint's slot back (§8.7 with an Enrollment Key).
///
/// **Only meaningful on [`Credential::Enrollment`]**, and an error on anything
/// else: an attended Endpoint is a device's identity, not something a process
/// exiting should retire.
///
/// The request carries the key and a PoP and nothing else. No `binding`
/// evidence — that answers "who may *get* something with this key", and this
/// gets nothing, so the job that died badly enough to be unable to mint an OIDC
/// token is exactly the one whose slot should come back. No reason either:
/// Identity writes `enrollment_released`, which is what keeps "the job tidied
/// up" tellable apart from "the sweep did".
/// Returns whether anything was actually revoked. `false` means this run has no
/// slot to give back — either it never enrolled, or the Endpoint was already
/// there and somebody else's process is using it.
pub async fn release_enrollment(cfg: &P2pConfig) -> anyhow::Result<bool> {
    let Credential::Enrollment(enrollment) = &cfg.credential else {
        anyhow::bail!("only an Endpoint enrolled with a key can return its own slot");
    };
    // **Only the run that took a slot owes one back**, which covers two cases at
    // once. A run that failed before enrolling — a bound key with no workload
    // identity to mint from, an unreachable Identity — never spent one, and
    // revoking would buy a round trip to be told so plus a warning about
    // leaking something nobody took. And a run that found the Endpoint already
    // registered did not spend one either; revoking there destroys an Endpoint
    // another process is still serving on.
    if !enrollment.registered_here() {
        return Ok(false);
    }
    let auth = RevokeAuth::Enrollment {
        key: &enrollment.key,
        endpoint: &cfg.key,
    };
    if cfg.identity_http3 {
        let client = IdentityClient::new(MasqueH3Transport::connect(&cfg.identity_url)?);
        client.revoke_endpoint(auth, None).await?;
    } else {
        let client = IdentityClient::new(HttpsTransport::connect(&cfg.identity_url)?);
        client.revoke_endpoint(auth, None).await?;
    }
    Ok(true)
}

/// A control-plane client for `cfg`'s proxy, authenticated with `endpoint_token`.
///
/// Handed out rather than built per call, so
/// a caller that needs more than one call — issuing a certificate takes two —
/// does not open a connection per request.
pub fn proxy_client(
    cfg: &P2pConfig,
    endpoint_token: &str,
) -> anyhow::Result<ProxyClient<MasqueH3Transport>> {
    Ok(ProxyClient::new(
        MasqueH3Transport::connect(&cfg.proxy_url)?,
        cfg.key.clone(),
        endpoint_token,
    ))
}

async fn issue<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
) -> anyhow::Result<EndpointToken> {
    match &cfg.credential {
        Credential::Auth0 {
            token,
            source,
            register,
            registered,
            // Set through `mark_registration_attempt` below, which takes it on
            // the credential rather than from here.
            attempted: _,
        } => {
            // The source when there is one, and only then the starting token:
            // this runs again every few minutes for the life of the session, so
            // by the second call the captured token may already be the stale
            // one.
            let auth0 = match source {
                Some(source) => source
                    .auth0_token()
                    .await
                    .context("could not obtain a current Auth0 token")?,
                None => token.clone(),
            };
            // **The narrowing goes to both arms.** It used to reach neither:
            // `issue_token` was called with `None, None` and
            // `register_and_issue` ended the same way, so a caller that had
            // asked for one protocol got a token carrying every protocol its
            // user is entitled to. An agent runtime registers a fresh key for
            // every task, so it takes the `register` arm every time — the one
            // where the narrowing was furthest from reaching the wire.
            if !*register {
                return Ok(client
                    .issue_token(&auth0, &cfg.key, &cfg.narrowing, cfg.token_ttl)
                    .await?);
            }
            // **Registration happens once; the renewals issue.** `register`
            // is a static argument re-read on every renewal, so without this
            // the second one would register the same keypair again and take
            // `409`, and every renewal after it would too. A task outliving one
            // token would lose its Endpoint Token partway through.
            //
            // **The cell settles on the registration, not on the token.**
            // `register_and_issue` does both and returns one `Result`, so an
            // issue that failed after a registration that succeeded reported a
            // failure — leaving the cell empty and the Endpoint registered. For
            // agent mode that is an Endpoint nothing revokes and no sweep
            // reaches, made by exactly the ordinary case: a narrowing the
            // server refuses, which is refused at the issue and not at the
            // registration.
            let registered_id = registered
                .get_or_try_init(|| async {
                    let challenge = client.register_challenge(&auth0, &cfg.key).await;
                    let registered = match challenge {
                        Ok(challenge) => {
                            // **Here, and not one call earlier.** What this
                            // guards against is never learning the outcome: a
                            // registration the server accepts whose answer is
                            // lost leaves the cell empty and the Endpoint in
                            // existence. Marking before the *challenge* would
                            // claim an Endpoint for every run that could not
                            // reach Identity at all, and send its operator
                            // hunting one that was never made.
                            cfg.credential.mark_registration_attempt();
                            client
                                .register(
                                    &auth0,
                                    &cfg.key,
                                    &challenge,
                                    cfg.device_name.as_deref(),
                                )
                                .await
                                .map(|_| ())
                        }
                        Err(e) => Err(e),
                    };
                    match registered {
                        // **The keypair's id, not the one the response echoed**
                        // — the same reasoning the enrolment cell gives. What
                        // this records is which keypair this credential spent
                        // its registration on, which is a local fact.
                        Ok(()) => anyhow::Ok(cfg.key.endpoint_id()),
                        // **`409` means it is already there, which is what this
                        // cell wanted.** Registration can reach the server and
                        // still fail here — a dropped response, a body that will
                        // not parse — and `get_or_try_init` does not remember
                        // failures, so without this arm every renewal would
                        // register again, take `409` again, and keep doing that
                        // while a plain issue would have worked.
                        Err(e) if e.status() == Some(409) => {
                            tracing::info!("this Endpoint is already registered; issuing instead");
                            Ok(cfg.key.endpoint_id())
                        }
                        Err(e) => Err(e.into()),
                    }
                })
                .await?;

            // **The cell belongs to the credential; the registration belongs
            // to the keypair.** Sharing one `Credential` between configs with
            // different keys would let the second skip registration and issue
            // for an Endpoint that was never registered — which fails at the
            // proxy, naming nothing that points back here.
            if registered_id != &cfg.key.endpoint_id() {
                anyhow::bail!(
                    "this credential already registered {registered_id}, but this config \
                     carries {}. Give each keypair its own Credential.",
                    cfg.key.endpoint_id(),
                );
            }
            // **Always a separate call**, which costs nothing: §8.1's
            // registration answers with the Endpoint's record and no token, so
            // `register_and_issue` made this same call itself.
            Ok(client
                .issue_token(&auth0, &cfg.key, &cfg.narrowing, cfg.token_ttl)
                .await?)
        }
        Credential::Enrollment(enrollment) => unattended(client, cfg, enrollment).await,
    }
}

/// The audience Identity checks a `binding` assertion against (§8.8.3).
///
/// **Not the proxy's.** Both servers take this from operator configuration and
/// refuse to let a caller name one, and the two defaults differ on purpose: a
/// token minted for one is then refused by the other.
const IDENTITY_AUDIENCE: &str = "isekai-identity";

/// Enrol once, and renew from then on (§8.8.5 / §8.8.7).
///
/// **The first call registers and the rest refresh**, and which one this is has
/// to be decided by shared state rather than by asking the server: a second
/// enrolment presents the same keypair, takes `409 endpoint-already-registered`
/// — one key registers exactly one Endpoint — and does not free the slot it
/// spent. `Enrollment::cell` is an `Arc<OnceCell<_>>` so that every clone of the
/// config, including the renewal task's, sees the same answer.
async fn unattended<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
    enrollment: &Enrollment,
) -> anyhow::Result<EndpointToken> {
    // Set by whichever caller actually enrols, and read back below. The
    // enrolment response carries the first Endpoint Token with it (§8.8.5), so
    // the caller that did the work already holds one and must not go on to
    // spend a renewal round trip getting a second.
    let mut minted: Option<EndpointToken> = None;
    let enrolled_id = enrollment
        .cell()
        .get_or_try_init(|| async {
            // Taken before the attempt, so the `409` arm can tell "somebody
            // else registered this" from "our own earlier attempt did".
            let attempted_before = enrollment.mark_attempt();
            match enrol(client, cfg, enrollment).await {
                Ok(enrolled) => {
                    minted = Some(enrolled.token());
                    // **The keypair's id, not the one the response echoed.**
                    // What this records is which keypair this credential has
                    // spent itself on, and that is a local fact — §8.8.4 has
                    // already bound the id to the public key, so the echo adds
                    // nothing and would make the guard depend on the server
                    // agreeing about a value we derived.
                    Ok(crate::auth::Registered {
                        endpoint_id: cfg.key.endpoint_id(),
                        by_us: true,
                    })
                }
                // **`409` means it is already there, which is a success for
                // this cell's purpose.** The enrolment can reach the server and
                // still fail here — the connection drops while the body is
                // read, or the body is a shape `Enrolled` cannot parse, which
                // is a case that type documents. `get_or_try_init` does not
                // remember failures, so without this every later call would
                // enrol again, take `409` again, and the renewal loop would
                // retry that forever while a plain refresh would have worked.
                Err(e) if already_registered(&e) => {
                    tracing::info!(
                        "this Endpoint is already enrolled; renewing instead of registering",
                    );
                    Ok(crate::auth::Registered {
                        endpoint_id: cfg.key.endpoint_id(),
                        // **Whose slot this is turns on whether we tried
                        // before.** A `409` on the first attempt means somebody
                        // else registered — another process, an earlier run —
                        // and the slot is not ours. A `409` after an attempt of
                        // our own means that attempt reached the server and the
                        // answer did not come back, which is the very case the
                        // comment above cites: **we spent the slot**, and
                        // recording otherwise would leak it silently until the
                        // idle sweep.
                        by_us: attempted_before,
                    })
                }
                Err(e) => Err(e),
            }
        })
        .await?;

    // **The cell belongs to the credential; the registration belongs to the
    // keypair.** One Enrollment Key may grow several Endpoints (that is what
    // `max_live_endpoints` counts), so sharing one `Credential` between configs
    // with different keys would otherwise let the second skip enrolment and
    // renew an Endpoint that was never registered. Each keypair needs its own
    // `Credential`, and saying so here beats a `403` from §8.2.3 that names
    // nothing.
    if enrolled_id.endpoint_id != cfg.key.endpoint_id() {
        anyhow::bail!(
            "this Enrollment Key credential already enrolled {}, but this config carries {}. \
             One key registers one Endpoint per keypair — give each keypair its own Credential.",
            enrolled_id.endpoint_id,
            cfg.key.endpoint_id(),
        );
    }

    match minted {
        Some(token) => Ok(token),
        // Somebody else enrolled — either a previous call of ours, or a
        // concurrent one that won. Either way this Endpoint exists now and the
        // way to a token is a renewal.
        None => refresh(client, cfg, enrollment).await,
    }
}

/// Whether this failure is the Identity API saying the Endpoint is already
/// registered (§8.8.5).
///
/// Looked at by status rather than by the problem's slug: `409` is the only one
/// that route answers, and the body is not worth parsing twice.
fn already_registered(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<isekai_p2p_core::identity::IdentityError>()
        .and_then(|e| e.status())
        == Some(409)
}

/// §8.8.4 → §8.8.5: a challenge, then registration and the first token.
async fn enrol<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
    enrollment: &Enrollment,
) -> anyhow::Result<isekai_p2p_core::identity::Enrolled> {
    let auth0 = enrollment_auth0(enrollment).await?;
    // **Minted before the challenge so that a failed mint costs nothing.** A
    // challenge is one-shot and lives 120 seconds, so taking one and then
    // discovering the runner cannot mint a token wastes it. The assertion is
    // one round trip older by the time §8.8.5 checks it, which is nothing
    // against the 5–15 minutes it lives.
    let assertion = enrollment_assertion(enrollment).await?;
    let auth = identity_auth(enrollment, assertion.as_deref(), auth0.as_deref());
    // The challenge takes no assertion (§8.8.4); `enroll_challenge` drops it.
    let challenge = client
        .enroll_challenge(auth, &cfg.key)
        .await
        .context("could not obtain an enrolment challenge")?;
    client
        .enroll(
            auth,
            &cfg.key,
            &challenge,
            cfg.device_name.as_deref(),
            cfg.token_ttl,
        )
        .await
        .context("could not enrol this Endpoint")
}

/// §8.2.2 → §8.2.3 with an Enrollment Key in place of the Auth0 token (§8.8.7).
async fn refresh<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
    enrollment: &Enrollment,
) -> anyhow::Result<EndpointToken> {
    let auth0 = enrollment_auth0(enrollment).await?;
    // **Minted again, every renewal**, and before the challenge for the same
    // reason as in `enrol`. §8.8.7 verifies the binding each time, which is
    // exactly what stops the key working after the job that owns the workload
    // identity has ended.
    let assertion = enrollment_assertion(enrollment).await?;
    let auth = identity_auth(enrollment, assertion.as_deref(), auth0.as_deref());
    let challenge = client
        .refresh_challenge(auth, &cfg.key.endpoint_id())
        .await
        .context("could not obtain a renewal challenge")?;
    client
        // **The selector is re-sent, unlike the other two axes.** The server
        // remembers a narrowing of permissions and protocols and does not
        // remember this one, so a renewal that stayed quiet about it would
        // renew the lease at every Gateway offering the class — undoing at the
        // first renewal what the issue had asked for.
        .refresh_token(
            auth,
            &cfg.key,
            &challenge,
            cfg.narrowing.gateways.as_deref(),
            cfg.token_ttl,
        )
        .await
        .context("could not renew the endpoint token")
}

fn identity_auth<'a>(
    enrollment: &'a Enrollment,
    assertion: Option<&'a str>,
    auth0: Option<&'a str>,
) -> IdentityAuth<'a> {
    IdentityAuth::Enrollment {
        key: &enrollment.key,
        assertion,
        auth0,
    }
}

async fn enrollment_assertion(enrollment: &Enrollment) -> anyhow::Result<Option<String>> {
    match &enrollment.assertion {
        Some(source) => Ok(Some(source.assertion(IDENTITY_AUDIENCE).await.context(
            "could not mint a workload identity token for the Identity API",
        )?)),
        None => Ok(None),
    }
}

async fn enrollment_auth0(enrollment: &Enrollment) -> anyhow::Result<Option<String>> {
    match &enrollment.auth0 {
        Some(source) => Ok(Some(
            source
                .auth0_token()
                .await
                .context("could not obtain a current Auth0 token")?,
        )),
        None => Ok(None),
    }
}

/// How long before an Endpoint Token expires to replace it.
///
/// A renewal is one Identity round-trip; a token that lapses stops every proxy
/// call the session makes, including the bind that admits a new viewer. The
/// margin is generous for that reason.
const RENEW_MARGIN: Duration = Duration::from_secs(60);
/// Never renew more often than this, whatever a server says the TTL is.
const RENEW_MIN: Duration = Duration::from_secs(30);
/// How often to renew a token whose lifetime is **not** known.
///
/// Under the shortest TTL the spec recommends (§5.3 says 5–15 minutes), so a
/// token that might be a five-minute one is still replaced before the earliest
/// moment it could expire. This is a floor for ignorance and nothing else — a
/// token that *states* its lifetime is renewed against that instead, or a camera
/// running for weeks would reissue a fifteen-minute token every four minutes for
/// no reason.
const RENEW_UNKNOWN: Duration = Duration::from_secs(240);

/// How often to re-ask after a refusal that only a person can lift.
///
/// **Slow because nothing here changes it, and finite because somebody else
/// might.** An entitlement added while this process runs should reach it
/// without a restart, and five minutes is short against how long it takes to
/// notice an error and act on it, long against the transient retries this must
/// not be confused with.
const REFUSED_RETRY: Duration = Duration::from_secs(300);

/// When to renew, given what the Identity API said the token's lifetime is.
///
/// `None` — the caller supplied a token rather than issuing one, so its lifetime
/// is not known here — takes the interval that is safe without knowing.
fn renew_delay(expires_in: Option<i64>) -> Duration {
    let Some(expires_in) = expires_in else {
        return RENEW_UNKNOWN;
    };
    let lifetime = Duration::from_secs(expires_in.max(0) as u64);
    // No upper bound: the peer said how long it is good for, and renewing more
    // often than that is traffic nobody asked for. The lower bound stops a
    // lapsed or absurdly short TTL turning into a busy loop.
    lifetime.saturating_sub(RENEW_MARGIN).max(RENEW_MIN)
}

/// How long to wait after `failures` consecutive renewal failures.
///
/// Doubling from [`RENEW_MIN`], capped at [`RENEW_UNKNOWN`]. Some failures never
/// stop being failures — a revoked refresh token means "sign in again", and
/// nothing this loop does will change that — so retrying every thirty seconds
/// forever is a request the Identity API can never satisfy, repeated for as long
/// as the camera is on. Backing off keeps the transient case fast and stops the
/// permanent one being a stream of traffic.
fn retry_delay(failures: u32) -> Duration {
    let doublings = failures.saturating_sub(1).min(8);
    (RENEW_MIN * 2u32.saturating_pow(doublings)).min(RENEW_UNKNOWN)
}

/// Whether retrying this failure could ever produce a different answer.
///
/// **`403` is the line.** The Identity API answers `403` when a rule refused
/// the request — `protocol-not-allowed` when the ceiling does not hold the
/// protocol asked for, `insufficient-permission`, `endpoint-revoked` — and none
/// of those turns on anything the caller can do from here. Everything else is
/// left retryable on purpose: `429` and `503` say when to come back, a `401`
/// is usually an Auth0 token the source is about to replace, and a transport
/// error is the network.
fn is_permanent(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|e| e.downcast_ref::<isekai_p2p_core::identity::IdentityError>())
        .any(|e| e.status() == Some(403))
}

/// Keep `proxy`'s Endpoint Token current for as long as the returned guard
/// lives.
///
/// `expires_in` is the lifetime of the token the session started with, when it
/// is known. Failures are logged and retried rather than propagated: the token
/// in force keeps working until it expires, so a transient Identity outage costs
/// nothing, and the alternative — ending a session that is streaming fine — is
/// worse than trying again.
pub fn spawn_token_renewal(
    cfg: P2pConfig,
    proxy: ProxyClient<MasqueH3Transport>,
    expires_in: Option<i64>,
) -> TokenRenewal {
    let mut delay = renew_delay(expires_in);
    let mut failures = 0u32;
    // Whether the refusal has already been reported, so it is said once rather
    // than every time the slow retry comes round.
    let mut refused = false;
    TokenRenewal(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            match issue_endpoint_token(&cfg).await {
                Ok(token) => {
                    proxy.set_endpoint_token(&token.endpoint_token);
                    failures = 0;
                    // Whoever was going to act has acted; if it is ever refused
                    // again, that is news.
                    refused = false;
                    delay = renew_delay(Some(token.expires_in));
                    tracing::debug!(
                        expires_in = token.expires_in,
                        next = ?delay,
                        "endpoint token renewed",
                    );
                }
                Err(e) if is_permanent(&e) => {
                    // **Said once, loudly, and then asked for rarely.** A `403`
                    // is an authorization decision: the ceiling has to gain the
                    // protocol, or the Endpoint has to stop being revoked, and
                    // nothing this loop does brings either about. Retrying it
                    // every thirty seconds at `warn`, among the transient
                    // failures that look identical, is how the one failure
                    // somebody must act on becomes invisible.
                    //
                    // **But it is not asked for never.** Somebody reads that
                    // error and adds the entitlement a minute later, and a loop
                    // that had given up would let this process's token lapse
                    // anyway — every proxy call failing, nothing further
                    // logged, and a restart the only way back. So the asking
                    // slows to [`REFUSED_RETRY`] rather than stopping, and says
                    // nothing more unless the answer changes.
                    //
                    // The session is left alone either way: the token in force
                    // keeps working until it expires, and ending one that is
                    // forwarding fine is the worse of the two answers.
                    if !refused {
                        refused = true;
                        tracing::error!(
                            "the Endpoint Token cannot be renewed, and retrying will not \
                             change that: {e:#}. Somebody has to grant it — a narrowed run \
                             asks for one protocol, so the usual cause is an account not \
                             entitled to it. This keeps asking every {}s in case that \
                             happens; the session works until the current token expires",
                            REFUSED_RETRY.as_secs(),
                        );
                    } else {
                        tracing::debug!("still refused: {e:#}");
                    }
                    failures = 0;
                    delay = REFUSED_RETRY;
                }
                Err(e) => {
                    failures += 1;
                    delay = retry_delay(failures);
                    // A failure here is not the end of the session — the token
                    // in force keeps working until it expires — but it is the
                    // beginning of one, so it is worth saying loudly once the
                    // retries start piling up. Where the cause is "sign in
                    // again", the source says so and the app's sign-in state has
                    // already been marked (see `auth0::RefreshingAuth0Token`);
                    // there is nothing this loop can do about it but keep asking
                    // more and more slowly.
                    tracing::warn!(
                        failures,
                        retry_in = ?delay,
                        "could not renew the endpoint token; the session keeps working \
                         until the current one expires: {e:#}",
                    );
                }
            }
        }
    }))
}

/// Stops the renewal when the session it belongs to goes away.
///
/// A detached renewal would keep asking the Identity API for tokens nobody
/// holds, for as long as the process runs.
pub struct TokenRenewal(tokio::task::JoinHandle<()>);

impl Drop for TokenRenewal {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    crate::secret::write_secret(path, contents.as_bytes())
        .with_context(|| format!("failed to write key at {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;


    fn api_error(status: u16) -> anyhow::Error {
        anyhow::Error::from(isekai_p2p_core::identity::IdentityError::Api {
            status,
            body: String::new(),
            retry_after: None,
        })
        .context("could not renew the endpoint token")
    }

    /// **A rule refused, and asking again asks the same rule.** `403` is the
    /// only status the renewal loop stops on, because it is the only one whose
    /// answer is settled somewhere the caller cannot reach.
    #[test]
    fn a_refusal_is_permanent_and_the_rest_are_not() {
        assert!(is_permanent(&api_error(403)));
        for retryable in [401, 429, 500, 503] {
            assert!(
                !is_permanent(&api_error(retryable)),
                "{retryable} may well succeed next time",
            );
        }
    }

    /// The loop's errors arrive wrapped in context, so a check that only looked
    /// at the outermost error would find an `anyhow` string and retry forever.
    #[test]
    fn the_status_is_found_under_the_context() {
        let wrapped = api_error(403).context("issue the endpoint token");
        assert!(is_permanent(&wrapped));
    }

    #[test]
    fn a_transport_failure_is_not_permanent() {
        assert!(!is_permanent(&anyhow::anyhow!("connection reset")));
    }
    /// A token is replaced a margin before it lapses, not as it lapses: the
    /// renewal is a round-trip that can fail, and there has to be room to try
    /// again while the current token still works.
    #[test]
    fn a_token_is_replaced_before_it_expires() {
        assert_eq!(renew_delay(Some(300)), Duration::from_secs(240));
        assert_eq!(renew_delay(Some(180)), Duration::from_secs(120));
    }

    /// An unknown lifetime — the caller issued the token itself and only handed
    /// over the string — is treated as the shortest the spec recommends (§5.3
    /// says 5–15 minutes), so the replacement still lands before the earliest
    /// moment it could expire.
    #[test]
    fn an_unknown_lifetime_renews_inside_the_shortest_ttl() {
        assert_eq!(renew_delay(None), Duration::from_secs(240));
        assert!(renew_delay(None) < Duration::from_secs(300));
    }

    /// A stated lifetime is believed, however long. Clamping it to the
    /// unknown-lifetime interval would have a camera running for weeks reissue
    /// a fifteen-minute token every four minutes — four times the traffic the
    /// token's own expiry asks for, forever.
    #[test]
    fn a_stated_lifetime_is_not_shortened_to_the_unknown_one() {
        assert_eq!(renew_delay(Some(900)), Duration::from_secs(840));
        assert_eq!(renew_delay(Some(86_400)), Duration::from_secs(86_340));
        assert!(renew_delay(Some(900)) > RENEW_UNKNOWN);
    }

    /// A lapsed or absurdly short TTL must not turn into a busy loop against
    /// the Identity API.
    #[test]
    fn a_short_lifetime_still_has_a_floor() {
        assert_eq!(renew_delay(Some(0)), RENEW_MIN);
        assert_eq!(renew_delay(Some(-1)), RENEW_MIN);
        assert_eq!(renew_delay(Some(60)), RENEW_MIN);
    }

    #[test]
    fn load_or_generate_key_persists_then_reloads_the_same_key() {
        let path = std::env::temp_dir().join(format!("isekai-p2p-key-{}.pem", std::process::id()));
        let _ = std::fs::remove_file(&path);

        // First call generates and persists.
        let generated = load_or_generate_key(&path).expect("generate");
        assert!(path.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600, "key file must be owner-only");
        }

        // Second call reloads the identical key (same Endpoint ID).
        let reloaded = load_or_generate_key(&path).expect("reload");
        assert_eq!(generated.endpoint_id(), reloaded.endpoint_id());

        std::fs::remove_file(&path).unwrap();
    }
}
