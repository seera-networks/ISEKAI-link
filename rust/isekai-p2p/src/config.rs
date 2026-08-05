//! Shared configuration and Endpoint Token acquisition.
//!
//! A [`P2pConfig`] says how to reach the Identity API and the proxy, which Auth0
//! token authenticates to the Identity API, and which Endpoint key to prove
//! possession of. [`issue_endpoint_token`] turns that into an Endpoint Token,
//! which the session facades then use for the proxy control plane and relay
//! data path.

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use isekai_p2p_core::endpoint::EndpointKey;
use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{EndpointToken, IdentityClient};
use isekai_p2p_core::proxy::{CertBundle, ControlPlaneTransport, ProxyClient};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::auth::Auth0TokenSource;

/// Everything a P2P session needs to reach the services and identify itself.
///
/// Cloneable because a session keeps one: issuing an Endpoint Token is not a
/// startup step but something that happens every few minutes for as long as the
/// session lives, and all of this is what it takes.
#[derive(Clone)]
pub struct P2pConfig {
    /// Identity API base URL (HTTPS), e.g. `https://identity.isekai.link:8443`.
    pub identity_url: String,
    /// Reach the Identity API over HTTP/3 (QUIC) instead of HTTP/1.1 + HTTP/2.
    pub identity_http3: bool,
    /// Proxy base URL, e.g. `https://proxy.isekai.link:8443`.
    pub proxy_url: String,
    /// Auth0 access token — used **only** to obtain the Endpoint Token from the
    /// Identity API. It is never sent to the proxy.
    ///
    /// The starting token. An Endpoint Token lasts minutes and is reissued for
    /// the life of the session, so once this one expires renewal needs a fresh
    /// one from [`P2pConfig::auth0`].
    pub auth0_token: String,
    /// Where to get a *current* Auth0 token when the Endpoint Token is renewed.
    ///
    /// `None` keeps using [`P2pConfig::auth0_token`], which works until that
    /// token expires and then stops — see [`crate::auth`].
    pub auth0: Option<Arc<dyn Auth0TokenSource>>,
    /// P2P protocol string, e.g. `isekai-validator-v1`.
    pub protocol: String,
    /// Register the Endpoint before issuing a token (needed on first use of a
    /// freshly generated key).
    pub register: bool,
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

/// Register (when [`P2pConfig::register`] is set) and issue an Endpoint Token,
/// over whichever Identity API transport the config selects.
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

/// Download this Endpoint's per-endpoint relay TLS certificate from the proxy,
/// using an Endpoint Token the caller already holds.
///
/// Returns `Ok(None)` when the proxy has relay certificates disabled — the
/// listener then presents a dev certificate and the initiator skips validation.
/// A returned bundle is issued for a loopback FQDN (see
/// [`PeerConnection::video_host`](isekai_p2p_core::proxy::PeerConnection::video_host)),
/// which the listener presents on the video QUIC and the initiator validates.
pub async fn fetch_relay_certificate(
    cfg: &P2pConfig,
    endpoint_token: &str,
) -> anyhow::Result<Option<CertBundle>> {
    let proxy = ProxyClient::new(
        MasqueH3Transport::connect(&cfg.proxy_url)?,
        cfg.key.clone(),
        endpoint_token,
    );
    Ok(proxy.get_certificate().await?)
}

async fn issue<T: ControlPlaneTransport>(
    client: &IdentityClient<T>,
    cfg: &P2pConfig,
) -> anyhow::Result<EndpointToken> {
    // The source when there is one, and only then the starting token: this runs
    // again every few minutes for the life of the session, so by the second call
    // the captured token may already be the stale one.
    let auth0 = match &cfg.auth0 {
        Some(source) => source
            .auth0_token()
            .await
            .context("could not obtain a current Auth0 token")?,
        None => cfg.auth0_token.clone(),
    };
    let token = if cfg.register {
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
