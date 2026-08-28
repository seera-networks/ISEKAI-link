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
use isekai_p2p_core::identity::{EndpointToken, IdentityAuth, IdentityClient};
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
    /// Proxy base URL, e.g. `https://tokyo.link.isekai.tools:8443`.
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
            let token = if *register {
                client
                    .register_and_issue(&auth0, &cfg.key, cfg.device_name.as_deref(), cfg.token_ttl)
                    .await?
            } else {
                client
                    .issue_token(&auth0, &cfg.key, None, None, cfg.token_ttl)
                    .await?
            };
            Ok(token)
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
            match enrol(client, cfg, enrollment).await {
                Ok(enrolled) => {
                    minted = Some(enrolled.token());
                    // **The keypair's id, not the one the response echoed.**
                    // What this records is which keypair this credential has
                    // spent itself on, and that is a local fact — §8.8.4 has
                    // already bound the id to the public key, so the echo adds
                    // nothing and would make the guard depend on the server
                    // agreeing about a value we derived.
                    Ok(cfg.key.endpoint_id())
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
                    Ok(cfg.key.endpoint_id())
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
    if enrolled_id != &cfg.key.endpoint_id() {
        anyhow::bail!(
            "this Enrollment Key credential already enrolled {enrolled_id}, but this config              carries {}. One key registers one Endpoint per keypair — give each keypair its              own Credential.",
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
        .refresh_token(auth, &cfg.key, &challenge, cfg.token_ttl)
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
    TokenRenewal(tokio::spawn(async move {
        loop {
            tokio::time::sleep(delay).await;
            match issue_endpoint_token(&cfg).await {
                Ok(token) => {
                    proxy.set_endpoint_token(&token.endpoint_token);
                    failures = 0;
                    delay = renew_delay(Some(token.expires_in));
                    tracing::debug!(
                        expires_in = token.expires_in,
                        next = ?delay,
                        "endpoint token renewed",
                    );
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
