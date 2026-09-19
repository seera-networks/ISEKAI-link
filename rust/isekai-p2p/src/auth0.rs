//! Signing in to Auth0, and staying signed in.
//!
//! A camera runs for weeks and its Endpoint Token lasts minutes, so something
//! has to keep producing Auth0 tokens to issue new ones with (spec §5.3 requires
//! Auth0 authentication state on every issue). Pasting an access token covers
//! the first few hours and then stops, which is the failure this exists to
//! remove.
//!
//! **Authorization code with PKCE, redirected to a loopback port** (RFC 8252)
//! is the flow. The browser is the user's own, the code comes back to a port
//! this process opened on `127.0.0.1`, and the exchange proves possession of a
//! verifier only this process knows — a public client has no secret to prove
//! anything else with.
//!
//! ```text
//! start_browser_login() ─▶ open `url` in a browser ─┐
//!         │                                          │ redirect to
//!         └─ finish_browser_login() ◀────────────────┘ 127.0.0.1:port
//!                     │
//!                     └─▶ Auth0Tokens { access, refresh }
//!                                  │
//!                                  └─ RefreshingAuth0Token: a live
//!                                     `Auth0TokenSource` that refreshes when
//!                                     the access token runs out
//! ```
//!
//! **This is the flow that can name an organization, which is why it replaced
//! the device grant.** A tenant is decided by the `org_id` claim, and `org_id`
//! is put there by an `organization` on the authorize request or by Universal
//! Login's organization prompt. The device grant ([`start_device_login`]) has
//! neither: whatever the operator picks in the browser, the token comes back
//! without `org_id` and Identity files everything under the individual tenant.
//! It is kept for the one case loopback cannot serve — a machine whose browser
//! is not on the same host — and says what it costs.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
    /// Which Auth0 Organization to sign in to, as an `org_…` id.
    ///
    /// **This is what decides the tenant.** Identity reads the `org_id` claim
    /// and files an Endpoint under it; a token without one goes to the
    /// individual tenant, silently. Naming an organization here puts the claim
    /// there.
    ///
    /// `None` leaves the choice to Universal Login, which asks when the
    /// application has the organization prompt enabled — and, when it does
    /// not, signs the person in personally. So `None` is "whatever Auth0
    /// decides", not "no organization".
    pub organization: Option<String>,
    /// The loopback port to come back on, when it cannot be any port.
    ///
    /// **`None` asks the OS for a free one**, which is what RFC 8252 §7.3 tells
    /// a redirect allow-list to accommodate — nothing on the machine can hold a
    /// port this process did not ask for, and two sign-ins at once do not
    /// collide. Set this where the Auth0 application lists an exact callback
    /// URL and will not take an arbitrary port; the sign-in then fails if
    /// something else already holds it, which is the honest outcome.
    pub callback_port: Option<u16>,
}

impl Default for Auth0Config {
    fn default() -> Self {
        Self {
            domain: "seera-networks.jp.auth0.com".to_owned(),
            client_id: "FeDSXYhJsfV1d9v6JyBte874R6En4tok".to_owned(),
            audience: "https://masque.seera-networks.com/".to_owned(),
            scope: "openid profile email offline_access".to_owned(),
            // **From the environment, because the GUIs have no field for it.**
            // A camera app signs in with this default and nothing else, so
            // without a way in from outside its operator could never name an
            // organization — and would land in the individual tenant while
            // believing otherwise. A CLI flag overrides it.
            organization: std::env::var(ORGANIZATION_VAR).ok().filter(|v| !v.is_empty()),
            callback_port: std::env::var(CALLBACK_PORT_VAR)
                .ok()
                .and_then(|v| v.parse().ok()),
        }
    }
}

/// Names the Auth0 Organization to sign in to, for callers with no flag.
pub const ORGANIZATION_VAR: &str = "ISEKAI_AUTH0_ORGANIZATION";

/// Pins the loopback port, for an Auth0 application that lists an exact
/// callback URL.
pub const CALLBACK_PORT_VAR: &str = "ISEKAI_AUTH0_CALLBACK_PORT";

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

/// A sign-in waiting for the browser to come back.
///
/// The loopback listener is already bound when this exists — **bound before the
/// URL is shown**, because the port is in the `redirect_uri` the URL carries,
/// and Auth0 checks that against the application's allow-list.
pub struct BrowserLogin {
    /// Where to send the person. Open it, or print it for them to open.
    pub url: String,
    listener: tokio::net::TcpListener,
    verifier: String,
    state: String,
    redirect_uri: String,
}

/// Bind a loopback port and build the URL that redirects back to it.
///
/// Nothing is sent to Auth0 here: an authorize request *is* the browser
/// navigating, so this only prepares what it navigates to.
pub async fn start_browser_login(cfg: &Auth0Config) -> anyhow::Result<BrowserLogin> {
    // **Port zero, and the port is read back.** A fixed port would collide with
    // whatever else is on the machine and, worse, with a second sign-in; RFC
    // 8252 §7.3 asks registered redirects to allow any port for exactly this.
    let wanted = cfg.callback_port.unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", wanted))
        .await
        .with_context(|| match cfg.callback_port {
            // **Named, because a pinned port is somebody's decision.** "Address
            // in use" on a port this process chose would be a bug; on one an
            // operator pinned it is a fact about their machine.
            Some(port) => format!(
                "open 127.0.0.1:{port} for the sign-in to come back to \
                 ({CALLBACK_PORT_VAR} pins it; something else holds it)"
            ),
            None => "open a loopback port for the sign-in to come back to".to_owned(),
        })?;
    let port = listener
        .local_addr()
        .context("read back the loopback port")?
        .port();
    let redirect_uri = format!("http://127.0.0.1:{port}/callback");

    let verifier = random_urlsafe(32);
    let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
    // **Not decoration.** Without it, anything that can reach this loopback port
    // can hand it an authorization code of its own choosing, and the exchange
    // below would trade that for tokens belonging to somebody else's session.
    let state = random_urlsafe(16);

    let mut url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&audience={}\
         &code_challenge={challenge}&code_challenge_method=S256&state={state}",
        cfg.url("/authorize"),
        urlencode(&cfg.client_id),
        urlencode(&redirect_uri),
        urlencode(&cfg.scope),
        urlencode(&cfg.audience),
    );
    if let Some(org) = &cfg.organization {
        url.push_str(&format!("&organization={}", urlencode(org)));
    }

    Ok(BrowserLogin {
        url,
        listener,
        verifier,
        state,
        redirect_uri,
    })
}

/// Wait for the redirect, then trade the code for tokens.
///
/// **Waits as long as the person takes.** There is no deadline here: Auth0
/// expires the authorization request on its own, and a timeout of this side's
/// invention would abandon a sign-in that was still being typed.
pub async fn finish_browser_login(
    cfg: &Auth0Config,
    login: BrowserLogin,
) -> anyhow::Result<Auth0Tokens> {
    let code = wait_for_the_redirect(&login).await?;
    let http = client()?;
    let resp = http
        .post(cfg.url("/oauth/token"))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", cfg.client_id.as_str()),
            ("code", code.as_str()),
            ("redirect_uri", login.redirect_uri.as_str()),
            // What makes the code useless to anyone who intercepted it: only
            // the process that generated the verifier can spend it.
            ("code_verifier", login.verifier.as_str()),
        ])
        .send()
        .await
        .context("could not reach Auth0 to exchange the authorization code")?;
    let status = resp.status();
    let body = resp.bytes().await.context("token response")?;
    if !status.is_success() {
        anyhow::bail!("Auth0 refused the authorization code: {}", describe(&body, status));
    }
    let parsed: TokenResponse =
        serde_json::from_slice(&body).context("Auth0 token response was not the expected shape")?;
    Ok(tokens_from(parsed))
}

/// Accept one request on the loopback port and read the code out of it.
async fn wait_for_the_redirect(login: &BrowserLogin) -> anyhow::Result<String> {
    loop {
        let (mut sock, _) = login
            .listener
            .accept()
            .await
            .context("wait for the browser to come back")?;
        // The request line is all that is wanted and it comes first, so there
        // is no need to read the headers, let alone a body.
        let mut buf = vec![0u8; 8192];
        let mut filled = 0;
        let line = loop {
            let n = sock.read(&mut buf[filled..]).await.unwrap_or(0);
            if n == 0 {
                break None;
            }
            filled += n;
            if let Some(end) = buf[..filled].windows(2).position(|w| w == b"\r\n") {
                break Some(String::from_utf8_lossy(&buf[..end]).into_owned());
            }
            if filled == buf.len() {
                break None;
            }
        };
        let Some(line) = line else { continue };
        // `GET /callback?code=…&state=… HTTP/1.1`
        let query = line
            .split_whitespace()
            .nth(1)
            .and_then(|target| target.split_once('?'))
            .map(|(_, q)| q.to_owned())
            .unwrap_or_default();
        let mut code = None;
        let mut state = None;
        let mut error = None;
        for pair in query.split('&') {
            match pair.split_once('=') {
                Some(("code", v)) => code = Some(urldecode(v)),
                Some(("state", v)) => state = Some(urldecode(v)),
                Some(("error", v)) => error = Some(urldecode(v)),
                Some(("error_description", v)) if error.is_some() => {
                    error = Some(format!("{}: {}", error.take().unwrap_or_default(), urldecode(v)));
                }
                _ => {}
            }
        }
        // **A browser fetching `/favicon.ico` is not a failed sign-in.** It
        // arrives on this same port, carries no query at all, and answering it
        // as an error would end the wait a moment before the real redirect.
        if code.is_none() && error.is_none() {
            let _ = sock.write_all(page(b"404 Not Found", "Nothing here.")).await;
            continue;
        }
        if let Some(error) = error {
            let _ = sock
                .write_all(page(b"400 Bad Request", "Sign-in failed. You can close this tab."))
                .await;
            anyhow::bail!("Auth0 refused the sign-in: {error}");
        }
        // **Compared before the code is used, not after.** The point of `state`
        // is to refuse a code this process did not ask for, and a comparison
        // made after the exchange refuses nothing.
        if state.as_deref() != Some(login.state.as_str()) {
            let _ = sock
                .write_all(page(b"400 Bad Request", "That sign-in did not start here."))
                .await;
            anyhow::bail!("the sign-in came back with the wrong state; ignoring it");
        }
        let _ = sock
            .write_all(page(b"200 OK", "Signed in. You can close this tab."))
            .await;
        // Let the browser read the page before the socket goes away with the
        // listener; without this the tab can show a connection error instead.
        let _ = sock.flush().await;
        return Ok(code.unwrap_or_default());
    }
}

/// A complete, tiny HTTP response. Leaked on purpose: it is built once per
/// reply and the connection is closed immediately after.
fn page(status: &[u8], message: &str) -> &'static [u8] {
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>ISEKAI</title>\
         <body style=\"font:16px system-ui;margin:3rem\">{message}</body>"
    );
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        String::from_utf8_lossy(status),
        body.len(),
    );
    Box::leak(format!("{head}{body}").into_bytes().into_boxed_slice())
}

/// `len` random bytes as base64url — a PKCE verifier's alphabet, and long
/// enough for RFC 7636's 43-character minimum at `len >= 32`.
fn random_urlsafe(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Percent-encode everything that is not unreserved (RFC 3986 §2.3).
///
/// **Written out rather than pulled in.** The values here are a client id, a
/// scope, an audience URL and an organization id, and a dependency to escape
/// four strings is a dependency to keep up to date.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for b in value.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Undo the encoding a browser applied to a query value.
fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => {
                match u8::from_str_radix(&value[i + 1..i + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        i += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        i += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Ask Auth0 for a code to show the operator (RFC 8628).
///
/// **The fallback, for a browser that is not on this host.** A loopback
/// redirect cannot reach a machine reached over SSH, and this flow can: the
/// code is typed in anywhere.
///
/// **It cannot name an organization.** The device grant carries no
/// `organization` and the token comes back with no `org_id`, so Identity files
/// everything the run registers under the individual tenant — whatever the
/// operator picked in the browser. Use it when loopback is impossible, and
/// expect the tenant to be personal.
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

/// Why a refresh failed, and whether trying again can help.
///
/// The distinction is the difference between backing off and giving up. A
/// revoked refresh token is never going to work, so retrying it every half
/// minute is a request Auth0 can only keep refusing — and, worse, it keeps the
/// operator from being told the one thing they can act on.
#[derive(Debug)]
pub enum RefreshError {
    /// Auth0 rejected the refresh token itself: spent, revoked or expired.
    /// Only signing in again gets past this.
    SignInRequired(String),
    /// Anything else — the network, a 5xx, a body that did not parse. Worth
    /// trying again.
    Transient(anyhow::Error),
}

impl std::fmt::Display for RefreshError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignInRequired(detail) => {
                write!(f, "the Auth0 session has ended, sign in again: {detail}")
            }
            Self::Transient(e) => write!(f, "{e:#}"),
        }
    }
}

impl std::error::Error for RefreshError {}

/// What Auth0 says when the grant itself is the problem rather than the
/// request. Anything else is treated as worth retrying.
fn is_terminal(error: &str) -> bool {
    matches!(
        error,
        "invalid_grant" | "unauthorized_client" | "access_denied" | "invalid_client"
    )
}

/// Exchange a refresh token for a fresh access token.
///
/// Auth0 returns a new refresh token only when rotation is enabled; the caller
/// keeps the one it has when this comes back `None`.
pub async fn refresh(cfg: &Auth0Config, refresh_token: &str) -> Result<Auth0Tokens, RefreshError> {
    let http = client().map_err(RefreshError::Transient)?;
    refresh_with(&http, cfg, refresh_token).await
}

async fn refresh_with(
    http: &reqwest::Client,
    cfg: &Auth0Config,
    refresh_token: &str,
) -> Result<Auth0Tokens, RefreshError> {
    let resp = http
        .post(cfg.url("/oauth/token"))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", cfg.client_id.as_str()),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await
        .context("could not reach Auth0 to refresh the access token")
        .map_err(RefreshError::Transient)?;
    let status = resp.status();
    let body = resp
        .bytes()
        .await
        .context("refresh response")
        .map_err(RefreshError::Transient)?;
    if !status.is_success() {
        return Err(match serde_json::from_slice::<ErrorResponse>(&body) {
            Ok(e) if is_terminal(&e.error) => {
                RefreshError::SignInRequired(e.error_description.unwrap_or(e.error))
            }
            _ => RefreshError::Transient(anyhow::anyhow!(
                "Auth0 could not refresh the access token: {}",
                describe(&body, status)
            )),
        });
    }
    serde_json::from_slice(&body)
        .map(tokens_from)
        .context("could not read the refresh response")
        .map_err(RefreshError::Transient)
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

/// How long any one Auth0 request may take.
///
/// Bounded because a caller waits behind it. `RefreshingAuth0Token` holds its
/// lock across the refresh — deliberately, so two renewals arriving together
/// produce one refresh — and without a limit a blackholed route to Auth0 would
/// park every caller on the OS TCP timeout, which is minutes.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);
/// And how long just to get a connection, which fails faster than the whole
/// request when the network is the problem.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

fn client() -> anyhow::Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
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
    /// Send the operator to `url`. The browser comes back to this process on
    /// its own, so there is nothing for them to transcribe.
    Waiting { url: String },
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

/// Drives [`start_browser_login`] and [`finish_browser_login`] behind a UI.
#[derive(Clone, Default)]
pub struct BrowserSignIn(Arc<std::sync::Mutex<SignIn>>);

impl BrowserSignIn {
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

    /// Report that the session has ended for a reason the operator has to act
    /// on — a revoked refresh token, say. Offers signing in again, and says why.
    pub fn failed(&self, reason: impl Into<String>) {
        self.0.lock().expect("sign-in lock poisoned").state = SignInState::Failed(reason.into());
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
            let started = match start_browser_login(&cfg).await {
                Ok(started) => started,
                Err(e) => return set(SignInState::Failed(format!("{e:#}"))),
            };
            set(SignInState::Waiting {
                url: started.url.clone(),
            });
            match finish_browser_login(&cfg, started).await {
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
    /// One client for the life of the source, so refreshes reuse the connection
    /// instead of building a TLS session every few hours.
    http: reqwest::Client,
    /// Set when Auth0 has rejected the refresh token. Every later call fails on
    /// this without touching the network: the answer cannot change until
    /// somebody signs in, and the caller retries on a timer.
    spent: std::sync::atomic::AtomicBool,
    /// The app's sign-in state, so "sign in again" reaches a person rather than
    /// only a log line.
    sign_in: Option<BrowserSignIn>,
}

impl RefreshingAuth0Token {
    pub fn new(cfg: Auth0Config, tokens: Auth0Tokens, store: Option<PathBuf>) -> Arc<Self> {
        Self::with_sign_in(cfg, tokens, store, None)
    }

    /// As [`new`](Self::new), reporting a session that has ended into `sign_in`
    /// so the UI can offer to sign in again.
    ///
    /// Without this the only sign is a warning every renewal, and the first
    /// thing an operator notices is a camera that has quietly stopped accepting
    /// viewers — which is the failure this whole change is about.
    pub fn with_sign_in(
        cfg: Auth0Config,
        tokens: Auth0Tokens,
        store: Option<PathBuf>,
        sign_in: Option<BrowserSignIn>,
    ) -> Arc<Self> {
        Arc::new(Self {
            cfg,
            tokens: tokio::sync::Mutex::new(tokens),
            store,
            http: client().unwrap_or_else(|e| {
                // Building a client only fails on a broken TLS backend, and the
                // fallback loses the timeouts — so say which one is in use
                // rather than leave a hang unexplained later.
                tracing::warn!("Auth0 client built without timeouts: {e:#}");
                reqwest::Client::new()
            }),
            spent: std::sync::atomic::AtomicBool::new(false),
            sign_in,
        })
    }

    /// Record that the session is over: fail fast from now on, and say so where
    /// the UI will see it.
    fn give_up(&self, detail: &str) {
        self.spent.store(true, std::sync::atomic::Ordering::Relaxed);
        if let Some(sign_in) = &self.sign_in {
            sign_in.failed(format!("signed out: {detail}"));
        }
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
        crate::secret::write_secret(path, &json)
            .with_context(|| format!("failed to write Auth0 tokens at {}", path.display()))
    }
}

impl Auth0TokenSource for RefreshingAuth0Token {
    fn auth0_token(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        Box::pin(async move {
            // Before the lock: once the session is over, every caller can be
            // told so without queueing behind a refresh that cannot succeed.
            if self.spent.load(std::sync::atomic::Ordering::Relaxed) {
                anyhow::bail!("the Auth0 session has ended; sign in again");
            }
            let mut tokens = self.tokens.lock().await;
            if !tokens.is_stale() {
                return Ok(tokens.access_token.clone());
            }
            let Some(refresh_token) = tokens.refresh_token.clone() else {
                self.give_up("the sign-in did not grant `offline_access`");
                anyhow::bail!(
                    "the Auth0 access token has expired and there is no refresh token \
                     (the login did not grant `offline_access`); sign in again"
                );
            };
            let mut renewed = match refresh_with(&self.http, &self.cfg, &refresh_token).await {
                Ok(renewed) => renewed,
                Err(e @ RefreshError::SignInRequired(_)) => {
                    self.give_up(&e.to_string());
                    return Err(anyhow::anyhow!(e));
                }
                Err(e) => return Err(anyhow::anyhow!(e)),
            };
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


    /// **Everything Auth0 needs to make the token carry an organization.**
    /// The claim that decides the tenant comes from this request and nowhere
    /// else, so a missing parameter here is an Endpoint filed personally.
    #[tokio::test]
    async fn the_authorize_url_asks_for_what_the_tenant_depends_on() {
        let cfg = Auth0Config {
            organization: Some("org_abc".to_owned()),
            ..Auth0Config::default()
        };
        let login = start_browser_login(&cfg).await.expect("a loopback port");
        assert!(login.url.starts_with("https://seera-networks.jp.auth0.com/authorize?"));
        for wanted in [
            "response_type=code",
            "code_challenge_method=S256",
            "organization=org_abc",
            &format!("state={}", login.state),
        ] {
            assert!(login.url.contains(wanted), "missing {wanted} in {}", login.url);
        }
        // **The redirect names the port that is already listening.** Building
        // the URL first and binding afterwards would send the browser to
        // whatever else had taken the port.
        let port = login.listener.local_addr().unwrap().port();
        assert!(
            login.url.contains(&urlencode(&format!("http://127.0.0.1:{port}/callback"))),
            "{}",
            login.url,
        );
        // The verifier is sent later, so it must not be in what the browser
        // carries; only its hash is.
        assert!(!login.url.contains(&login.verifier));
        assert!(login.verifier.len() >= 43, "RFC 7636 asks for 43 or more");
    }

    /// Without one, the URL simply does not carry the parameter — Universal
    /// Login then decides, which is what the prompt is for.
    #[tokio::test]
    async fn no_organization_names_none() {
        let cfg = Auth0Config {
            organization: None,
            ..Auth0Config::default()
        };
        let login = start_browser_login(&cfg).await.expect("a loopback port");
        assert!(!login.url.contains("organization="), "{}", login.url);
    }

    async fn get(port: u16, target: &str) {
        let mut sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect to the loopback");
        sock.write_all(format!("GET {target} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .expect("send the redirect");
        // Read the reply so the server's write does not race the close.
        let mut buf = [0u8; 64];
        let _ = sock.read(&mut buf).await;
    }

    #[tokio::test]
    async fn the_code_comes_back_off_the_redirect() {
        let login = start_browser_login(&Auth0Config::default()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move { get(port, &format!("/callback?code=THE_CODE&state={state}")).await });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "THE_CODE");
    }

    /// **A code this process did not ask for is refused.** Anything on the
    /// machine can reach a loopback port; without this check it could hand one
    /// over and have it exchanged for somebody else's tokens.
    #[tokio::test]
    async fn a_code_with_the_wrong_state_is_refused() {
        let login = start_browser_login(&Auth0Config::default()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        tokio::spawn(async move { get(port, "/callback?code=THE_CODE&state=somebody_else").await });
        let e = wait_for_the_redirect(&login).await.expect_err("refused");
        assert!(e.to_string().contains("state"), "{e}");
    }

    /// **A browser asks for more than the redirect.** `/favicon.ico` arrives on
    /// this same port with no query at all, and treating it as an answer would
    /// end the wait a moment before the real one arrived.
    #[tokio::test]
    async fn an_unrelated_request_does_not_end_the_wait() {
        let login = start_browser_login(&Auth0Config::default()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move {
            get(port, "/favicon.ico").await;
            get(port, &format!("/callback?code=AFTER_THE_NOISE&state={state}")).await;
        });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "AFTER_THE_NOISE");
    }

    /// Auth0 reports a refusal on the redirect rather than by not arriving.
    #[tokio::test]
    async fn a_refusal_on_the_redirect_is_reported() {
        let login = start_browser_login(&Auth0Config::default()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            get(port, "/callback?error=access_denied&error_description=No%20thanks").await
        });
        let e = wait_for_the_redirect(&login).await.expect_err("reported");
        assert!(e.to_string().contains("access_denied"), "{e}");
    }

    #[test]
    fn a_query_value_survives_the_browser_encoding_it() {
        assert_eq!(urldecode("a%2Fb+c"), "a/b c");
        assert_eq!(urldecode("plain"), "plain");
        // A stray `%` is kept rather than swallowed: what matters is that the
        // value read back is wrong-looking rather than silently truncated.
        assert_eq!(urldecode("100%"), "100%");
        assert_eq!(urlencode("https://a/b c"), "https%3A%2F%2Fa%2Fb%20c");
    }
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
