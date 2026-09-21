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
use serde_json::Value;
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
            // **Not read here.** A value that will not parse has to be
            // refused, and this function cannot refuse anything;
            // `start_browser_login` reads it instead. Dropping a typo silently
            // would hand back "any ephemeral port", and the operator's tunnel
            // forwards the one they meant.
            callback_port: None,
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
    /// What the sign-in reported about its organization, if anything.
    ///
    /// **The name is the part worth keeping; the id is not from here.** An
    /// access token carries `org_id` and no name, and an ID token carries both
    /// but is not stored — so this records what the ID token said, and
    /// [`organization`](Self::organization) is what answers the question,
    /// reading the id from the access token and borrowing the name from here
    /// only when the two agree.
    ///
    /// That is also what makes a store written before this field existed still
    /// answer correctly: the id was in it all along.
    #[serde(rename = "organization", default)]
    pub recorded_organization: Option<Organization>,
    /// Present when `offline_access` was granted. Without one the session ends
    /// with the access token and the operator has to sign in again.
    pub refresh_token: Option<String>,
    /// Unix seconds. Stored absolute rather than as a duration so it survives
    /// being written to disk and read back later.
    pub expires_at_unix: u64,
}

impl Auth0Tokens {
    /// Which organization these tokens belong to, if any.
    ///
    /// **The id comes from the access token**, which is the same claim Identity
    /// reads to decide the tenant — so this answers with the organization that
    /// actually governs what this machine registers, rather than with what a
    /// sign-in once said. The name is added from
    /// [`recorded_organization`](Self::recorded_organization) when it is about
    /// the same organization; a stale one is dropped rather than shown against
    /// somebody else's id.
    pub fn organization(&self) -> Option<Organization> {
        let TokenOrganization::In(mut org) = organization_in(&self.access_token) else {
            return None;
        };
        if org.name.is_none() {
            org.name = self
                .recorded_organization
                .as_ref()
                .filter(|seen| seen.id == org.id)
                .and_then(|seen| seen.name.clone());
        }
        Some(org)
    }

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
    /// Present because `openid` is in the scope. **Kept only to say which
    /// organization the sign-in landed in** — see [`Auth0Tokens::organization`].
    #[serde(default)]
    id_token: Option<String>,
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
    let pinned = match cfg.callback_port {
        Some(port) => Some(port),
        None => parse_pinned_port(std::env::var(CALLBACK_PORT_VAR).ok().as_deref())?,
    };
    let wanted = pinned.unwrap_or(0);
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", wanted))
        .await
        .with_context(|| match pinned {
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

/// The pinned loopback port named by [`CALLBACK_PORT_VAR`], if any.
///
/// **A value that will not parse is an error, not an absence.** "Any port" and
/// "port 38700, mistyped" lead to different URLs, and only one of them matches
/// the tunnel the operator set up — so a typo that quietly meant the first
/// would fail in the browser with nothing pointing back at the variable.
///
/// **The raw value is a parameter**, so what is tested is the parsing rather
/// than the process's environment: a test that set the variable would change
/// the port every concurrent sign-in binds, and they would take each other's
/// redirects.
fn parse_pinned_port(raw: Option<&str>) -> anyhow::Result<Option<u16>> {
    let Some(raw) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let port: u16 = raw
        .parse()
        .map_err(|_| anyhow::anyhow!("{CALLBACK_PORT_VAR} is `{raw}`, which is not a port"))?;
    anyhow::ensure!(port != 0, "{CALLBACK_PORT_VAR} is 0, which asks for any port");
    Ok(Some(port))
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

/// Accept requests on the loopback port until one is the redirect.
///
/// **No deadline on the wait, and one on each connection.** How long a person
/// takes in a browser is their business, so nothing here gives up on the
/// sign-in; but a connection that opens and says nothing must not become that
/// wait. Anything on the machine can open one — a preconnect, a scanner, an
/// `ssh -L` channel opened early — and reading it to EOF would leave the real
/// redirect sitting unread in the accept backlog, forever.
async fn wait_for_the_redirect(login: &BrowserLogin) -> anyhow::Result<String> {
    loop {
        let (mut sock, _) = login
            .listener
            .accept()
            .await
            .context("wait for the browser to come back")?;
        let line = match tokio::time::timeout(REQUEST_LINE_WAIT, request_line(&mut sock)).await {
            Ok(Some(line)) => line,
            // Both are "this connection had nothing to say": dropped, and back
            // to waiting for one that has.
            Ok(None) | Err(_) => continue,
        };
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
            let _ = sock.write_all(&page("404 Not Found", "Nothing here.")).await;
            continue;
        }
        // **`state` decides first, for a refusal as much as for a code.** It is
        // what says a message belongs to this sign-in; checking it only on the
        // code path leaves `?error=access_denied` as a way for anything on the
        // machine to end somebody else's sign-in before their browser arrives.
        if state.as_deref() != Some(login.state.as_str()) {
            let _ = sock
                .write_all(&page("400 Bad Request", "That sign-in did not start here."))
                .await;
            continue;
        }
        if let Some(error) = error {
            let _ = sock
                .write_all(&page("400 Bad Request", "Sign-in failed. You can close this tab."))
                .await;
            anyhow::bail!("Auth0 refused the sign-in: {error}");
        }
        let _ = sock
            .write_all(&page("200 OK", "Signed in. You can close this tab."))
            .await;
        // Let the browser read the page before the socket goes away with the
        // listener; without this the tab can show a connection error instead.
        let _ = sock.flush().await;
        return Ok(code.unwrap_or_default());
    }
}

/// How long one connection has to produce a request line before it is dropped.
const REQUEST_LINE_WAIT: Duration = Duration::from_secs(5);

/// Read just the request line. The headers and any body are not wanted, and
/// the line comes first.
async fn request_line(sock: &mut tokio::net::TcpStream) -> Option<String> {
    let mut buf = vec![0u8; 8192];
    let mut filled = 0;
    loop {
        let n = sock.read(&mut buf[filled..]).await.ok()?;
        if n == 0 {
            return None;
        }
        filled += n;
        if let Some(end) = buf[..filled].windows(2).position(|w| w == b"\r\n") {
            return Some(String::from_utf8_lossy(&buf[..end]).into_owned());
        }
        if filled == buf.len() {
            return None;
        }
    }
}

/// A complete, tiny HTTP response.
fn page(status: &str, message: &str) -> Vec<u8> {
    // **The empty icon is not decoration.** Without a `rel="icon"` a browser
    // asks for `/favicon.ico` after rendering, and by then this flow has its
    // code and the listener is gone — so the request is refused. Locally that
    // is invisible; over an `ssh -L` tunnel it surfaces as
    // `channel N: open failed: connect failed: Connection refused`, which reads
    // like the sign-in failed at the moment it has just succeeded. `data:,` is
    // an icon the browser already has.
    let body = format!(
        "<!doctype html><meta charset=utf-8><title>ISEKAI</title>\
         <link rel=icon href=\"data:,\">\
         <body style=\"font:16px system-ui;margin:3rem\">{message}</body>"
    );
    let head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len(),
    );
    format!("{head}{body}").into_bytes()
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

/// Two ASCII hex digits as a byte, or `None` if they are not that.
fn hex_pair(high: u8, low: u8) -> Option<u8> {
    let digit = |b: u8| match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    };
    Some(digit(high)? * 16 + digit(low)?)
}

/// Undo the encoding a browser applied to a query value.
fn urldecode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // **Bytes, not a string slice.** `&value[i + 1..i + 3]` indexes a
            // `&str`, and `i + 2 < bytes.len()` counts bytes — so a multi-byte
            // character after a `%` lands mid-codepoint and panics. The query
            // comes off a socket any local process can reach, which makes that
            // a way to kill a sign-in from outside.
            b'%' if i + 2 < bytes.len() => match hex_pair(bytes[i + 1], bytes[i + 2]) {
                Some(byte) => {
                    out.push(byte);
                    i += 3;
                }
                None => {
                    out.push(b'%');
                    i += 1;
                }
            },
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
/// **It cannot name an organization**, and this was measured rather than
/// assumed: `/authorize` refuses an organization that does not exist with
/// `400`, `/oauth/device/code` answers `200` for the same one, and a login
/// completed with the parameter attached comes back with no `org_id`. Auth0
/// takes the field and ignores it.
///
/// So Identity files everything such a run registers under the individual
/// tenant — whatever the operator picked in the browser. Before reaching for
/// this over SSH, forward the loopback port instead
/// ([`CALLBACK_PORT_VAR`]): the browser stays where it is and the organization
/// survives.
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
    refresh_with(&http, cfg, refresh_token, None).await
}

/// `held` is what this session is holding now, so a name it already knows
/// survives a refresh that does not repeat it — see [`carry_name`].
///
/// **Carried here rather than by the caller.** This is the only place a
/// refreshed `Auth0Tokens` is built, so doing it here is the difference between
/// a rule and a step somebody has to remember: a call site can be deleted and
/// leave every test passing, which is how the first version of this lost the
/// name minutes after a sign-in recorded it.
async fn refresh_with(
    http: &reqwest::Client,
    cfg: &Auth0Config,
    refresh_token: &str,
    held: Option<&Auth0Tokens>,
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
    let mut renewed: Auth0Tokens = serde_json::from_slice(&body)
        .map(tokens_from)
        .context("could not read the refresh response")
        .map_err(RefreshError::Transient)?;
    if let Some(held) = held {
        carry_name(held, &mut renewed);
    }
    Ok(renewed)
}

/// Keep a known organization name across a refresh that did not repeat it.
///
/// **The name is what is carried, not the record.** A refresh answers with an
/// ID token only sometimes, and when it does it may carry `org_id` and no name
/// — which is not `None`, so a guard on the whole record lets it overwrite the
/// name with nothing, and `--whoami` stops naming the organization after the
/// first refresh.
///
/// **A function so that the test can call it.** Written inline, the test could
/// only restate it, and deleting the original left that test passing.
fn carry_name(held: &Auth0Tokens, renewed: &mut Auth0Tokens) {
    let Some(known) = held
        .recorded_organization
        .as_ref()
        .filter(|seen| seen.name.is_some())
    else {
        return;
    };
    match &mut renewed.recorded_organization {
        Some(fresh) if fresh.id == known.id && fresh.name.is_none() => {
            fresh.name = known.name.clone();
        }
        None => renewed.recorded_organization = Some(known.clone()),
        // A name of its own, or a different organization: the new answer stands.
        Some(_) => {}
    }
}

fn tokens_from(body: TokenResponse) -> Auth0Tokens {
    Auth0Tokens {
        access_token: body.access_token,
        refresh_token: body.refresh_token,
        expires_at_unix: unix_now() + body.expires_in,
        recorded_organization: body.id_token.as_deref().and_then(organization_of),
    }
}

/// The organization an ID token says the sign-in was for.
///
/// **Read, never trusted.** Nothing is decided by this — Identity reads the
/// access token's `org_id` and makes its own judgement. What this is for is
/// telling the person at the keyboard which organization they just signed in
/// to, in the words the Auth0 dashboard shows them, because `org_a1b2c3` is not
/// something anyone can check by looking at it.
///
/// The signature is not verified for that reason: an attacker able to alter
/// this has already replaced Auth0's response to a request made over TLS, and
/// the access token beside it is what everything else stands on.
fn organization_of(id_token: &str) -> Option<Organization> {
    match organization_in(id_token) {
        TokenOrganization::In(org) => Some(org),
        _ => None,
    }
}

/// The organization an access token belongs to, if any.
///
/// **The `org_id` claim is the one Identity reads to decide the tenant**, so
/// this says which organization governs what the holder registers — for a
/// pasted `--auth0-token` as much as for a saved sign-in. The name comes along
/// when a claim carries it; see [`ORG_NAME_CLAIM`].
pub fn organization_in(access_token: &str) -> TokenOrganization {
    let Some(claims) = claims_of(access_token) else {
        return TokenOrganization::Unreadable;
    };
    let Some(id) = string_claim(&claims, "org_id") else {
        return TokenOrganization::Personal;
    };
    TokenOrganization::In(Organization {
        name: string_claim(&claims, "org_name")
            .or_else(|| string_claim(&claims, ORG_NAME_CLAIM)),
        id,
    })
}

/// What a token says about its organization, including "it does not say".
///
/// **Three answers, because a caller prints them and two of them are not the
/// same statement.** "Personal" is read out of a token: it has claims, and no
/// `org_id` among them. "Unreadable" is the absence of anything to read — an
/// opaque token, a truncated one, a payload that is not JSON. Reporting the
/// second as the first tells somebody their Endpoints register personally on
/// the strength of a token nobody could parse.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenOrganization {
    In(Organization),
    Personal,
    Unreadable,
}

/// A claim an Auth0 Action can add to say what an organization is called.
///
/// **Because `org_name` is not always there.** Auth0 puts `org_id` in both
/// tokens and the name in neither, on some tenants — and an id is the one
/// thing nobody can check by looking at it, which is the whole reason this is
/// printed at all. A tenant that already runs an Action (ISEKAI's adds
/// `…/tenant_roles`) can add the name in one line, and it is then read from
/// whichever token carries it.
pub const ORG_NAME_CLAIM: &str = "https://identity.isekai.tools/org_name";



/// A JWT's payload, without verifying anything.
///
/// **Read, never trusted** — see [`organization_of`]. Nothing is decided by
/// what comes out of here.
fn claims_of(jwt: &str) -> Option<Value> {
    let payload = jwt.split('.').nth(1)?;
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).ok()?).ok()
}

fn string_claim(claims: &Value, name: &str) -> Option<String> {
    Some(claims.get(name)?.as_str()?.to_owned())
}

/// Which organization a sign-in was for.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Organization {
    /// `org_…`, which is what Auth0 put in the token.
    pub id: String,
    /// The name the dashboard shows, when the tenant includes it.
    #[serde(default)]
    pub name: Option<String>,
}

impl std::fmt::Display for Organization {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // **The name first and the id after it**, because the name is what the
        // person recognises and the id is what they would have to paste into
        // `--organization`. Dropping either would cost one of those.
        match &self.name {
            Some(name) => write!(f, "{name} ({})", self.id),
            None => write!(f, "{}", self.id),
        }
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
    /// The sign-in in flight, so a new one can replace it.
    ///
    /// **Its listener goes when it does.** Abandoned, the task holds the
    /// loopback port for the life of the process — and with
    /// [`CALLBACK_PORT_VAR`] pinned, which is what an `ssh -L` operator does,
    /// the next attempt cannot bind at all and no amount of retrying frees it.
    task: Option<tokio::task::JoinHandle<()>>,
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
    /// tokens; this is only what the UI shows — and whatever sign-in was still
    /// in flight, which is no longer wanted and is holding a port.
    pub fn sign_out(&self) {
        let mut shared = self.0.lock().expect("sign-in lock poisoned");
        shared.state = SignInState::SignedOut;
        if let Some(task) = shared.task.take() {
            task.abort();
        }
    }

    /// Report that the session has ended for a reason the operator has to act
    /// on — a revoked refresh token, say. Offers signing in again, and says why.
    pub fn failed(&self, reason: impl Into<String>) {
        let mut shared = self.0.lock().expect("sign-in lock poisoned");
        // **A sign-in already under way is not overwritten.** This is called by
        // the token renewal, which fails every few minutes once a refresh token
        // is revoked — and the operator answering that by signing in would
        // watch the URL they were told to open disappear from the window.
        if matches!(shared.state, SignInState::Waiting { .. }) {
            return;
        }
        shared.state = SignInState::Failed(reason.into());
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
        let task = tokio::spawn(async move {
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
        // **Whatever was running stops here.** A second press means the first
        // attempt is not the one being waited on any more, and leaving it
        // listening would keep its port — the one the next attempt needs when
        // it is pinned.
        let mut shared = self.0.lock().expect("sign-in lock poisoned");
        if let Some(previous) = shared.task.replace(task) {
            previous.abort();
        }
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
            let mut renewed = match refresh_with(
                &self.http,
                &self.cfg,
                &refresh_token,
                Some(&tokens),
            )
            .await
            {
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
            // **Carried across the same way, and for the same reason.** A
            // refresh answers with an ID token only sometimes, and the one
            // thing this field is for is telling an operator which
            // organization a machine is signed in to — a fact that does not
            // change on a refresh, and that writing `null` over would quietly
            // erase within minutes of the sign-in that established it.

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
    /// **Built field by field, not from `Default`.** `Auth0Config::default()`
    /// reads the environment, and `docs/portal.md` tells operators to export
    /// both variables — so a test that went through it would fail on the
    /// machine of the person most likely to run it.
    fn test_config() -> Auth0Config {
        Auth0Config {
            domain: "seera-networks.jp.auth0.com".to_owned(),
            client_id: "test-client".to_owned(),
            audience: "https://masque.seera-networks.com/".to_owned(),
            scope: "openid profile email offline_access".to_owned(),
            organization: None,
            callback_port: None,
        }
    }

    #[tokio::test]
    async fn the_authorize_url_asks_for_what_the_tenant_depends_on() {
        let cfg = Auth0Config {
            organization: Some("org_abc".to_owned()),
            ..test_config()
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
        let login = start_browser_login(&test_config())
            .await
            .expect("a loopback port");
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
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move { get(port, &format!("/callback?code=THE_CODE&state={state}")).await });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "THE_CODE");
    }

    /// **A code this process did not ask for is ignored, not obeyed — and not
    /// fatal either.** Anything on the machine can reach a loopback port. If a
    /// wrong `state` were exchanged, it would buy somebody else's tokens; if it
    /// ended the wait, anyone could stop a sign-in by sending one. So it is
    /// dropped and the wait goes on.
    #[tokio::test]
    async fn a_code_with_the_wrong_state_is_ignored() {
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move {
            get(port, "/callback?code=NOT_OURS&state=somebody_else").await;
            get(port, &format!("/callback?code=OURS&state={state}")).await;
        });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "OURS");
    }

    /// **A browser asks for more than the redirect.** `/favicon.ico` arrives on
    /// this same port with no query at all, and treating it as an answer would
    /// end the wait a moment before the real one arrived.
    #[tokio::test]
    async fn an_unrelated_request_does_not_end_the_wait() {
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move {
            get(port, "/favicon.ico").await;
            get(port, &format!("/callback?code=AFTER_THE_NOISE&state={state}")).await;
        });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "AFTER_THE_NOISE");
    }

    /// Auth0 reports a refusal on the redirect rather than by not arriving —
    /// **carrying the `state` it was given**, which is what makes this one
    /// belong to this sign-in and end it, where the previous test's does not.
    #[tokio::test]
    async fn a_refusal_on_the_redirect_is_reported() {
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move {
            get(
                port,
                &format!("/callback?error=access_denied&error_description=No%20thanks&state={state}"),
            )
            .await
        });
        let e = wait_for_the_redirect(&login).await.expect_err("reported");
        assert!(e.to_string().contains("access_denied"), "{e}");
        assert!(e.to_string().contains("No thanks"), "{e}");
    }

    /// **The reply has to leave the browser with nothing more to ask for.**
    /// A `/favicon.ico` fetched after this flow has finished is refused, and
    /// through an `ssh -L` tunnel that refusal is printed as if the sign-in had
    /// failed.
    #[test]
    fn the_reply_asks_the_browser_for_nothing() {
        let reply = String::from_utf8_lossy(&page("200 OK", "Signed in.")).into_owned();
        assert!(reply.contains("rel=icon"), "{reply}");
        assert!(reply.contains("Connection: close"));
        // Nothing else to fetch: no script, style or image of its own.
        for asks_for_more in ["<script", "<img", "<link rel=stylesheet"] {
            assert!(!reply.contains(asks_for_more), "{asks_for_more} in {reply}");
        }
        // The length has to match the body, or the browser waits for the rest.
        let (head, body) = reply.split_once("\r\n\r\n").expect("a complete reply");
        let declared: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .expect("a length")
            .trim()
            .parse()
            .expect("a number");
        assert_eq!(declared, body.len());
    }


    fn jwt(claims: serde_json::Value) -> String {
        let payload = URL_SAFE_NO_PAD.encode(claims.to_string());
        // Header and signature are not read; only the claims are, and only to
        // say a name out loud.
        format!("header.{payload}.signature")
    }

    fn id_token(claims: serde_json::Value) -> String {
        jwt(claims)
    }

    fn signed_in_to(org_id: Option<&str>, recorded: Option<Organization>) -> Auth0Tokens {
        Auth0Tokens {
            access_token: jwt(match org_id {
                Some(id) => serde_json::json!({ "sub": "auth0|u", "org_id": id }),
                None => serde_json::json!({ "sub": "auth0|u" }),
            }),
            refresh_token: Some("RT".to_owned()),
            expires_at_unix: unix_now() + 900,
            recorded_organization: recorded,
        }
    }

    /// **The id comes off the access token**, which is the claim Identity reads
    /// to decide the tenant — so this answers with the organization that
    /// actually governs what the machine registers.
    ///
    /// It is also what makes a store written before any of this was recorded
    /// answer correctly: the id was in it all along, and asking somebody to
    /// sign in again to learn something already on their disk is a poor trade.
    #[test]
    fn the_organization_is_read_from_the_access_token() {
        let tokens = signed_in_to(Some("org_tAUNRLW8USki2Big"), None);
        let org = tokens.organization().expect("an organization");
        assert_eq!(org.id, "org_tAUNRLW8USki2Big");
        assert_eq!(org.to_string(), "org_tAUNRLW8USki2Big");
    }

    /// **The name can arrive on the access token too**, put there by an Action,
    /// which is the only route on a tenant whose ID token carries `org_id` and
    /// no `org_name`. Taken from there it needs no recording and survives a
    /// store written before any of this.
    #[test]
    fn a_namespaced_name_on_the_access_token_is_used() {
        let tokens = Auth0Tokens {
            access_token: jwt(serde_json::json!({
                "org_id": "org_tAUNRLW8USki2Big",
                ORG_NAME_CLAIM: "seera-networks",
            })),
            refresh_token: None,
            expires_at_unix: unix_now() + 900,
            recorded_organization: None,
        };
        assert_eq!(
            tokens.organization().expect("an organization").to_string(),
            "seera-networks (org_tAUNRLW8USki2Big)",
        );
    }

    /// **A refresh that names the organization without naming it must not
    /// erase the name.** An ID token carrying `org_id` and no `org_name` parses
    /// to `Some(Organization { name: None })`, which is not `None` — so a guard
    /// on the record let it overwrite the name with nothing, and `--whoami`
    /// stopped naming the organization after the first refresh.
    #[test]
    fn a_refresh_without_a_name_keeps_the_one_already_known() {
        let known = Organization {
            id: "org_a1b2c3".to_owned(),
            name: Some("seera-networks".to_owned()),
        };
        let nameless = Organization {
            id: "org_a1b2c3".to_owned(),
            name: None,
        };
        let mut renewed = signed_in_to(Some("org_a1b2c3"), Some(nameless));
        carry_name(&signed_in_to(Some("org_a1b2c3"), Some(known.clone())), &mut renewed);
        assert_eq!(
            renewed.organization().expect("an organization").to_string(),
            "seera-networks (org_a1b2c3)",
        );

        // A refresh that says nothing at all about the organization keeps it too.
        let mut silent = signed_in_to(Some("org_a1b2c3"), None);
        carry_name(&signed_in_to(Some("org_a1b2c3"), Some(known.clone())), &mut silent);
        assert_eq!(silent.recorded_organization.as_ref().and_then(|o| o.name.clone()),
                   Some("seera-networks".to_owned()));

        // **And a name from another organization is not carried onto it.**
        let mut elsewhere = signed_in_to(Some("org_new"), None);
        carry_name(&signed_in_to(Some("org_a1b2c3"), Some(known)), &mut elsewhere);
        assert_eq!(
            elsewhere.organization().expect("an organization").to_string(),
            "org_new",
            "the record belongs to the organization that was left",
        );
    }

    /// **An opaque or truncated token is not a statement about anything.**
    /// Reading `None` out of it and printing "registers personally" asserts a
    /// fact nobody established.
    #[test]
    fn a_token_that_cannot_be_read_says_so() {
        assert_eq!(organization_in("not-a-jwt"), TokenOrganization::Unreadable);
        assert_eq!(organization_in("h..s"), TokenOrganization::Unreadable);
        assert_eq!(
            organization_in(&jwt(serde_json::json!({ "sub": "auth0|u" }))),
            TokenOrganization::Personal,
        );
        assert!(matches!(
            organization_in(&jwt(serde_json::json!({ "org_id": "org_x" }))),
            TokenOrganization::In(_),
        ));
    }

    /// The recorded name fills in the half the access token does not carry.
    #[test]
    fn a_recorded_name_is_used_for_the_same_organization() {
        let tokens = signed_in_to(
            Some("org_a1b2c3"),
            Some(Organization {
                id: "org_a1b2c3".to_owned(),
                name: Some("seera-networks".to_owned()),
            }),
        );
        assert_eq!(
            tokens.organization().expect("an organization").to_string(),
            "seera-networks (org_a1b2c3)",
        );
    }

    /// **A name left over from another organization is dropped, not shown.**
    /// Signing in somewhere else and seeing the old name against the new id is
    /// worse than seeing no name: it answers the question wrongly rather than
    /// admitting it cannot.
    #[test]
    fn a_name_from_another_organization_is_not_borrowed() {
        let tokens = signed_in_to(
            Some("org_new"),
            Some(Organization {
                id: "org_old".to_owned(),
                name: Some("the-other-one".to_owned()),
            }),
        );
        assert_eq!(
            tokens.organization().expect("an organization").to_string(),
            "org_new",
        );
    }

    /// A personal sign-in has none, and says so by having none.
    #[test]
    fn no_org_id_in_the_access_token_is_no_organization() {
        assert!(signed_in_to(None, None).organization().is_none());
    }

    /// **`org_a1b2c3` is not something anyone can check by looking at it.** The
    /// name is what the person recognises, the id is what they would paste into
    /// `--organization`, so the line carries both.
    #[test]
    fn the_organization_is_read_for_saying_out_loud() {
        let org = organization_of(&id_token(serde_json::json!({
            "org_id": "org_a1b2c3",
            "org_name": "seera-networks",
        })))
        .expect("an organization");
        assert_eq!(org.id, "org_a1b2c3");
        assert_eq!(org.to_string(), "seera-networks (org_a1b2c3)");
    }

    /// A tenant that sends no name still leaves the id worth printing.
    #[test]
    fn an_organization_without_a_name_is_still_the_id() {
        let org = organization_of(&id_token(serde_json::json!({ "org_id": "org_x" })))
            .expect("an organization");
        assert_eq!(org.to_string(), "org_x");
    }

    /// **Absent is the ordinary answer**, and it has to survive every shape of
    /// nothing: a personal sign-in, a token that is not a JWT, one whose claims
    /// will not decode.
    #[test]
    fn no_organization_reads_as_none() {
        assert!(organization_of(&id_token(serde_json::json!({ "sub": "auth0|u" }))).is_none());
        assert!(organization_of("not-a-jwt").is_none());
        assert!(organization_of("header..signature").is_none());
        assert!(organization_of("header.!!!.signature").is_none());
    }

    /// **The store has to keep it across a refresh.** An Auth0 refresh answers
    /// with an ID token only sometimes; writing `null` over the organization
    /// would erase it within minutes of the sign-in that established it, and
    /// `--whoami` would stop being able to say where this machine belongs.
    #[test]
    fn the_organization_survives_a_round_trip_through_the_store() {
        let dir = std::env::temp_dir().join(format!("isekai-auth0-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("a directory");
        let path = dir.join("tokens.json");
        let tokens = Auth0Tokens {
            access_token: "AT".to_owned(),
            refresh_token: Some("RT".to_owned()),
            expires_at_unix: unix_now() + 900,
            recorded_organization: Some(Organization {
                id: "org_a1b2c3".to_owned(),
                name: Some("seera-networks".to_owned()),
            }),
        };
        RefreshingAuth0Token::save(&path, &tokens).expect("saved");
        let read = RefreshingAuth0Token::load(&path).expect("loaded");
        assert_eq!(read.recorded_organization, tokens.recorded_organization);
        // And a store written before this field existed still loads.
        std::fs::write(
            &path,
            r#"{"access_token":"AT","refresh_token":"RT","expires_at_unix":1}"#,
        )
        .expect("written");
        assert_eq!(
            RefreshingAuth0Token::load(&path)
                .expect("loaded")
                .recorded_organization,
            None,
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// **A query a local process can send must not be able to stop a sign-in.**
    /// `%` followed by a multi-byte character once panicked the task: the
    /// guard counted bytes and the slice indexed a `&str`, so it landed
    /// mid-codepoint.
    #[test]
    fn a_percent_before_a_multibyte_character_is_not_a_panic() {
        assert_eq!(urldecode("%a€"), "%a€");
        assert_eq!(urldecode("%"), "%");
        assert_eq!(urldecode("%zz"), "%zz");
        assert_eq!(urldecode("%e3%81%82"), "あ");
    }

    /// **The refusal path is guarded by `state` too.** Without that, one
    /// `?error=access_denied` from anything on the machine ends a sign-in that
    /// the operator's browser is still on its way to.
    #[tokio::test]
    async fn an_error_from_another_sign_in_is_ignored() {
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        tokio::spawn(async move {
            get(port, "/callback?error=access_denied&state=somebody_else").await;
            get(port, &format!("/callback?code=THE_REAL_ONE&state={state}")).await;
        });
        let code = wait_for_the_redirect(&login).await.expect("the code");
        assert_eq!(code, "THE_REAL_ONE");
    }

    /// **A connection that says nothing must not become the wait.** Anything
    /// can open one, and reading it to EOF left the real redirect unread in the
    /// accept backlog — forever, since this flow has no deadline of its own.
    #[tokio::test]
    async fn a_silent_connection_does_not_hold_the_port() {
        let login = start_browser_login(&test_config()).await.unwrap();
        let port = login.listener.local_addr().unwrap().port();
        let state = login.state.clone();
        // Opened and held, saying nothing, for longer than the redirect takes.
        let quiet = tokio::spawn(async move {
            let sock = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await
                .expect("connect");
            tokio::time::sleep(Duration::from_secs(30)).await;
            drop(sock);
        });
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            get(port, &format!("/callback?code=PAST_THE_QUIET_ONE&state={state}")).await;
        });
        let code = tokio::time::timeout(Duration::from_secs(20), wait_for_the_redirect(&login))
            .await
            .expect("the wait is not held by a silent connection")
            .expect("the code");
        assert_eq!(code, "PAST_THE_QUIET_ONE");
        quiet.abort();
    }

    /// **Refused rather than dropped.** A typo that quietly meant "any port"
    /// sends the operator an authorize URL naming a port their tunnel does not
    /// carry, and the failure arrives in the browser with nothing pointing
    /// back at the variable.
    #[test]
    fn a_pinned_port_that_is_not_a_port_is_refused() {
        let e = parse_pinned_port(Some("thirty-eight-seven-hundred")).expect_err("refused");
        assert!(e.to_string().contains(CALLBACK_PORT_VAR), "{e}");
        assert!(parse_pinned_port(Some("0")).is_err(), "0 is not a pinned port");
        assert_eq!(parse_pinned_port(Some(" 38700 ")).unwrap(), Some(38700));
        assert_eq!(parse_pinned_port(None).unwrap(), None);
        assert_eq!(parse_pinned_port(Some("")).unwrap(), None);
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
            recorded_organization: None,
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
