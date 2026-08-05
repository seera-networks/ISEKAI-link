//! Signing in to Auth0 from a device with no browser of its own, and staying
//! signed in.
//!
//! A camera runs for weeks and its Endpoint Token lasts minutes, so something
//! has to keep producing Auth0 tokens to issue new ones with (spec §5.3 requires
//! Auth0 authentication state on every issue). Pasting an access token covers
//! the first few hours and then stops, which is the failure this exists to
//! remove.
//!
//! The **device authorization grant** (RFC 8628) is the flow for it: the device
//! shows a short code, the operator types it into a browser anywhere, and the
//! device polls until the login lands. What it gets back includes a refresh
//! token — `offline_access` — and that is what outlives everything else.
//!
//! ```text
//! start_device_login()  ─▶ show user_code + verification_uri
//!         │
//!         └─ poll_device_login() ─▶ Auth0Tokens { access, refresh }
//!                                        │
//!                                        └─ RefreshingAuth0Token: a live
//!                                           `Auth0TokenSource` that refreshes
//!                                           when the access token runs out
//! ```

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

use crate::auth::Auth0TokenSource;

/// How close to expiry an access token is replaced.
///
/// An issue that starts inside this window would otherwise race the expiry it
/// is trying to stay ahead of.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// The grant URN, spelled out once.
const DEVICE_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Which Auth0 application to sign in to, and what to ask a token for.
///
/// None of this is secret. A native application has no client secret — that is
/// what makes it a *public* client — and the client id travels in every request
/// a device makes, so it is an identifier rather than a credential. The same
/// three values are in the iOS app's `Auth0Config.swift`, and `issuer` and
/// `audience` have to match the Identity API's own configuration or the token it
/// receives is rejected.
#[derive(Debug, Clone)]
pub struct Auth0Config {
    pub domain: String,
    pub client_id: String,
    pub audience: String,
    /// `offline_access` is what makes Auth0 return a refresh token. Without it
    /// the login works and the session simply ends when the access token does,
    /// which is the thing being fixed — so it is in the default.
    pub scope: String,
}

impl Default for Auth0Config {
    fn default() -> Self {
        Self {
            domain: "seera-networks.jp.auth0.com".to_owned(),
            client_id: "FeDSXYhJsfV1d9v6JyBte874R6En4tok".to_owned(),
            audience: "https://masque.seera-networks.com/".to_owned(),
            scope: "openid profile email offline_access".to_owned(),
        }
    }
}

impl Auth0Config {
    fn url(&self, path: &str) -> String {
        format!("https://{}{path}", self.domain.trim_end_matches('/'))
    }
}

/// What to show the operator, and what to poll with.
#[derive(Debug, Clone)]
pub struct DeviceLogin {
    /// The short code the operator types.
    pub user_code: String,
    /// Where they type it.
    pub verification_uri: String,
    /// The same page with the code already filled in — worth showing as a QR
    /// code or a link, since it saves transcribing `user_code` by hand.
    pub verification_uri_complete: String,
    /// When the code stops being accepted.
    pub expires_at: SystemTime,
    /// How often Auth0 is willing to be polled.
    pub interval: Duration,
    device_code: String,
}

#[derive(Deserialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    #[serde(default)]
    verification_uri_complete: Option<String>,
    expires_in: u64,
    #[serde(default = "default_interval")]
    interval: u64,
}

fn default_interval() -> u64 {
    5
}

/// Tokens from a login or a refresh.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth0Tokens {
    pub access_token: String,
    /// Present when `offline_access` was granted. Without one the session ends
    /// with the access token and the operator has to sign in again.
    pub refresh_token: Option<String>,
    /// Unix seconds. Stored absolute rather than as a duration so it survives
    /// being written to disk and read back later.
    pub expires_at_unix: u64,
}

impl Auth0Tokens {
    fn expires_at(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(self.expires_at_unix)
    }

    /// Whether the access token is past use — counting the margin, so "still
    /// valid" means valid for long enough to finish an issue with it.
    fn is_stale(&self) -> bool {
        SystemTime::now() + REFRESH_MARGIN >= self.expires_at()
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    refresh_token: Option<String>,
    expires_in: u64,
}

#[derive(Deserialize)]
struct ErrorResponse {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Ask Auth0 for a code to show the operator.
pub async fn start_device_login(cfg: &Auth0Config) -> anyhow::Result<DeviceLogin> {
    let http = client()?;
    let resp = http
        .post(cfg.url("/oauth/device/code"))
        .form(&[
            ("client_id", cfg.client_id.as_str()),
            ("scope", cfg.scope.as_str()),
            ("audience", cfg.audience.as_str()),
        ])
        .send()
        .await
        .context("could not reach Auth0 to start the device login")?;
    let status = resp.status();
    let body = resp.bytes().await.context("device code response")?;
    if !status.is_success() {
        anyhow::bail!(
            "Auth0 refused the device login: {}",
            describe(&body, status)
        );
    }
    let body: DeviceCodeResponse =
        serde_json::from_slice(&body).context("could not read the device code response")?;
    Ok(DeviceLogin {
        verification_uri_complete: body
            .verification_uri_complete
            .unwrap_or_else(|| body.verification_uri.clone()),
        user_code: body.user_code,
        verification_uri: body.verification_uri,
        expires_at: SystemTime::now() + Duration::from_secs(body.expires_in),
        interval: Duration::from_secs(body.interval),
        device_code: body.device_code,
    })
}

/// Wait for the operator to finish signing in.
///
/// Polls at the interval Auth0 asked for, backing off when told to, until the
/// login lands or the code expires. `authorization_pending` is the normal
/// answer for as long as the operator is still typing, so it is not an error
/// until the code runs out.
pub async fn poll_device_login(
    cfg: &Auth0Config,
    login: &DeviceLogin,
) -> anyhow::Result<Auth0Tokens> {
    let http = client()?;
    let mut interval = login.interval;
    loop {
        if SystemTime::now() >= login.expires_at {
            anyhow::bail!("the device code expired before the sign-in completed");
        }
        tokio::time::sleep(interval).await;
        let resp = http
            .post(cfg.url("/oauth/token"))
            .form(&[
                ("grant_type", DEVICE_CODE_GRANT),
                ("device_code", login.device_code.as_str()),
                ("client_id", cfg.client_id.as_str()),
            ])
            .send()
            .await
            .context("could not reach Auth0 while waiting for the sign-in")?;
        let status = resp.status();
        let body = resp.bytes().await.context("token response")?;
        if status.is_success() {
            return Ok(tokens_from(
                serde_json::from_slice(&body).context("could not read the token response")?,
            ));
        }
        match serde_json::from_slice::<ErrorResponse>(&body) {
            // Still waiting on the operator.
            Ok(e) if e.error == "authorization_pending" => {}
            // Polling too fast. Auth0 asks for one more second each time.
            Ok(e) if e.error == "slow_down" => interval += Duration::from_secs(1),
            Ok(e) => anyhow::bail!(
                "Auth0 ended the device login: {}",
                e.error_description.unwrap_or(e.error)
            ),
            Err(_) => anyhow::bail!("Auth0 ended the device login: {}", describe(&body, status)),
        }
    }
}

/// Exchange a refresh token for a fresh access token.
///
/// Auth0 returns a new refresh token only when rotation is enabled; the caller
/// keeps the one it has when this comes back `None`.
pub async fn refresh(cfg: &Auth0Config, refresh_token: &str) -> anyhow::Result<Auth0Tokens> {
    let http = client()?;
    let resp = http
        .post(cfg.url("/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", cfg.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("could not reach Auth0 to refresh the access token")?;
    let status = resp.status();
    let body = resp.bytes().await.context("refresh response")?;
    if !status.is_success() {
        anyhow::bail!(
            "Auth0 rejected the refresh token, so signing in again is the only way on: {}",
            describe(&body, status)
        );
    }
    Ok(tokens_from(
        serde_json::from_slice(&body).context("could not read the refresh response")?,
    ))
}

fn tokens_from(body: TokenResponse) -> Auth0Tokens {
    Auth0Tokens {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        expires_at_unix: unix_now() + body.expires_in,
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .build()
        .context("failed to build the Auth0 HTTPS client")
}

/// Auth0's own words when it has them, the status code when it does not.
fn describe(body: &[u8], status: reqwest::StatusCode) -> String {
    match serde_json::from_slice::<ErrorResponse>(body) {
        Ok(e) => e.error_description.unwrap_or(e.error),
        Err(_) => format!("HTTP {status}"),
    }
}

/// A device sign-in in progress, as an app's UI sees it.
///
/// The flow is two awaits and a poll loop, but an app drawing a window at 60fps
/// cannot await anything — so this runs it on a task and leaves the answer
/// somewhere the UI thread can read on its next frame. Both desktop apps drive
/// it the same way, and neither has to know what the flow does.
#[derive(Debug, Default, Clone)]
pub enum SignInState {
    #[default]
    SignedOut,
    /// Show the operator `user_code`, and `url` to type it into.
    Waiting {
        user_code: String,
        url: String,
    },
    SignedIn,
    Failed(String),
}

#[derive(Default)]
struct SignIn {
    state: SignInState,
    /// Left by the task for the UI thread to pick up, since only the UI thread
    /// owns the place a token source is kept.
    tokens: Option<Auth0Tokens>,
}

/// Drives [`start_device_login`] and [`poll_device_login`] behind a UI.
#[derive(Clone, Default)]
pub struct DeviceSignIn(Arc<std::sync::Mutex<SignIn>>);

impl DeviceSignIn {
    /// A sign-in that has already happened — restoring stored tokens, so the UI
    /// does not offer to sign in again.
    pub fn restored() -> Self {
        let this = Self::default();
        this.0.lock().expect("sign-in lock poisoned").state = SignInState::SignedIn;
        this
    }

    pub fn state(&self) -> SignInState {
        self.0.lock().expect("sign-in lock poisoned").state.clone()
    }

    /// Forget the sign-in. The caller drops its token source and any stored
    /// tokens; this is only what the UI shows.
    pub fn sign_out(&self) {
        self.0.lock().expect("sign-in lock poisoned").state = SignInState::SignedOut;
    }

    /// Whatever a finished sign-in produced, once.
    ///
    /// Returns `None` on every call but the first after a sign-in, so a UI can
    /// call it every frame.
    pub fn take_tokens(&self) -> Option<Auth0Tokens> {
        self.0.lock().expect("sign-in lock poisoned").tokens.take()
    }

    /// Begin. Needs a tokio runtime, and persists to `store` when given one.
    pub fn start(&self, cfg: Auth0Config, store: Option<PathBuf>) {
        let shared = self.0.clone();
        tokio::spawn(async move {
            let set = |state| shared.lock().expect("sign-in lock poisoned").state = state;
            let started = match start_device_login(&cfg).await {
                Ok(started) => started,
                Err(e) => return set(SignInState::Failed(format!("{e:#}"))),
            };
            set(SignInState::Waiting {
                user_code: started.user_code.clone(),
                url: started.verification_uri_complete.clone(),
            });
            match poll_device_login(&cfg, &started).await {
                Ok(tokens) => {
                    if let Some(store) = &store {
                        if let Err(e) = RefreshingAuth0Token::save(store, &tokens) {
                            // The sign-in worked; only the "still signed in
                            // after a restart" part is lost.
                            tracing::warn!("could not persist the Auth0 tokens: {e:#}");
                        }
                    }
                    let mut shared = shared.lock().expect("sign-in lock poisoned");
                    shared.tokens = Some(tokens);
                    shared.state = SignInState::SignedIn;
                }
                Err(e) => set(SignInState::Failed(format!("{e:#}"))),
            }
        });
    }
}

/// An [`Auth0TokenSource`] that refreshes rather than expiring.
///
/// This is what turns a single sign-in into a session that lasts: the Endpoint
/// Token renewal asks for a token every few minutes, gets the cached one while
/// it is good, and a refreshed one when it is not.
pub struct RefreshingAuth0Token {
    cfg: Auth0Config,
    /// Async because refreshing happens under it: two renewals arriving together
    /// must produce one refresh, not two.
    tokens: tokio::sync::Mutex<Auth0Tokens>,
    /// Where to write tokens as they change, so a restart does not need another
    /// sign-in.
    store: Option<PathBuf>,
}

impl RefreshingAuth0Token {
    pub fn new(cfg: Auth0Config, tokens: Auth0Tokens, store: Option<PathBuf>) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            tokens: tokio::sync::Mutex::new(tokens),
            store,
        })
    }

    /// Load tokens a previous sign-in persisted.
    pub fn load(path: &Path) -> anyhow::Result<Auth0Tokens> {
        let raw = std::fs::read(path)
            .with_context(|| format!("no stored Auth0 tokens at {}", path.display()))?;
        serde_json::from_slice(&raw)
            .with_context(|| format!("could not read the Auth0 tokens at {}", path.display()))
    }

    /// Persist tokens, owner-readable only.
    ///
    /// A refresh token is a standing credential — anyone holding it can mint
    /// access tokens until it is revoked — so it is written with the same care
    /// as the Endpoint key beside it.
    pub fn save(path: &Path, tokens: &Auth0Tokens) -> anyhow::Result<()> {
        let json = serde_json::to_vec_pretty(tokens)?;
        std::fs::write(path, json)
            .with_context(|| format!("failed to write Auth0 tokens at {}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }
}

impl Auth0TokenSource for RefreshingAuth0Token {
    fn auth0_token(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move {
            let mut tokens = self.tokens.lock().await;
            if !tokens.is_stale() {
                return Ok(tokens.access_token.clone());
            }
            let Some(refresh_token) = tokens.refresh_token.clone() else {
                anyhow::bail!(
                    "the Auth0 access token has expired and there is no refresh token \
                     (the login did not grant `offline_access`); sign in again"
                );
            };
            let mut renewed = refresh(&self.cfg, &refresh_token).await?;
            // Auth0 only returns a new refresh token when rotation is enabled;
            // keeping the old one is what makes the next refresh possible.
            if renewed.refresh_token.is_none() {
                renewed.refresh_token = Some(refresh_token);
            }
            if let Some(path) = &self.store {
                if let Err(e) = Self::save(path, &renewed) {
                    // Not fatal: the tokens in hand still work, and the only cost
                    // is another sign-in after a restart.
                    tracing::warn!("could not persist the refreshed Auth0 tokens: {e:#}");
                }
            }
            let access = renewed.access_token.clone();
            *tokens = renewed;
            Ok(access)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tokens(expires_in_secs: i64, refresh: Option<&str>) -> Auth0Tokens {
        Auth0Tokens {
            access_token: "access".to_owned(),
            refresh_token: refresh.map(str::to_owned),
            expires_at_unix: (unix_now() as i64 + expires_in_secs).max(0) as u64,
        }
    }

    /// A token with room to spare is used as it is — the whole point of caching
    /// is that the renewal every few minutes does not become a login every few
    /// minutes.
    #[test]
    fn a_token_with_time_left_is_not_stale() {
        assert!(!tokens(3600, None).is_stale());
    }

    /// Expired is stale, and so is about-to-expire: an issue that begins inside
    /// the margin would race the expiry it is meant to stay ahead of.
    #[test]
    fn a_token_inside_the_margin_is_already_stale() {
        assert!(tokens(-1, None).is_stale());
        assert!(tokens(0, None).is_stale());
        assert!(tokens(REFRESH_MARGIN.as_secs() as i64 / 2, None).is_stale());
    }

    /// Without `offline_access` there is nothing to refresh with, and saying so
    /// is more useful than a generic 401 from the Identity API later.
    #[tokio::test]
    async fn a_stale_token_with_no_refresh_token_says_to_sign_in_again() {
        let source = RefreshingAuth0Token::new(Auth0Config::default(), tokens(-1, None), None);
        let err = source.auth0_token().await.expect_err("no way to refresh");
        assert!(
            err.to_string().contains("sign in again"),
            "unhelpful error: {err}"
        );
    }

    /// The defaults have to match the iOS app's, or the two sign in to
    /// different applications and the Identity API rejects one of them.
    #[test]
    fn the_defaults_match_the_ios_app() {
        let cfg = Auth0Config::default();
        assert_eq!(cfg.domain, "seera-networks.jp.auth0.com");
        assert_eq!(cfg.client_id, "FeDSXYhJsfV1d9v6JyBte874R6En4tok");
        assert_eq!(cfg.audience, "https://masque.seera-networks.com/");
        assert!(
            cfg.scope.contains("offline_access"),
            "without it there is no refresh token and the session ends with the access token",
        );
    }

    #[test]
    fn urls_are_built_off_the_domain_without_doubling_the_slash() {
        let cfg = Auth0Config {
            domain: "example.auth0.com/".to_owned(),
            ..Auth0Config::default()
        };
        assert_eq!(
            cfg.url("/oauth/token"),
            "https://example.auth0.com/oauth/token"
        );
    }
}
