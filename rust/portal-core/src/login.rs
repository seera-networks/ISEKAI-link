//! Signing in once, and staying signed in.
//!
//! **The problem is that an Auth0 access token expires and portal is meant to
//! be left running.** `--auth0-token` takes one that was minted somewhere else;
//! when it goes, so does the ability to issue Endpoint Tokens, and the session
//! ends a few minutes later with a renewal that cannot be authorised. For a
//! camera app someone is watching that is a prompt to sign in again. For a
//! forward nobody is watching it is the service stopping in the night.
//!
//! ```text
//!   portal-* --login          device flow: a code, a browser, once
//!        └─ tokens on disk ─▶ RefreshingAuth0Token ─▶ every later run
//! ```
//!
//! The whole flow is `isekai_p2p::auth0`, which the camera apps drive from a
//! GUI. What is here is the headless half: a terminal has no window to put a
//! sign-in button in, so the code is printed and the process waits.
//!
//! # The file is a credential
//!
//! A refresh token mints access tokens until it is revoked, so what this writes
//! is as sensitive as the Endpoint key beside it — `RefreshingAuth0Token::save`
//! writes it owner-readable for that reason. It is also the thing that makes
//! `--login` a one-time act rather than a daily one.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use isekai_p2p::auth::Auth0TokenSource;
use isekai_p2p::auth0::{
    finish_browser_login, poll_device_login, start_browser_login, start_device_login, Auth0Config,
    RefreshingAuth0Token,
};

/// Where the tokens live, given the Endpoint key's path.
///
/// Beside the key and named after it, the way `portal-server --cert-key`
/// defaults: the two belong to the same identity, so one `--key` names both and
/// two installations on one machine do not collide.
///
/// **Which means processes sharing a `--key` share this file**, and today that
/// is fine: Auth0 rotates refresh tokens only when the application asks it to,
/// and this one does not, so two portal processes reading the same store both
/// keep working. With rotation on they would not — the first to refresh
/// invalidates the token the second is holding, and the second would take that
/// for a revoked session and stop. If rotation is ever enabled, this is the
/// thing to fix first, and `--auth0-tokens` is the way out until then.
pub fn tokens_beside(key: &Path) -> PathBuf {
    let mut path = key.to_path_buf();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "portal".to_owned());
    path.set_file_name(format!("{stem}-auth0.json"));
    path
}

/// The Auth0 settings a sign-in uses, with the flag taking precedence.
///
/// **A struct-update from the default would undo the default.**
/// `Auth0Config::default()` reads `ISEKAI_AUTH0_ORGANIZATION`, which is how the
/// camera apps name an organization at all, and `Auth0Config { organization:
/// flag, ..default() }` overwrites that with `None` whenever the flag is
/// absent. Nobody sees it: the sign-in succeeds, and the tenant is personal.
fn sign_in_config(organization: Option<&str>) -> Auth0Config {
    let mut cfg = Auth0Config::default();
    if let Some(named) = organization {
        cfg.organization = Some(named.to_owned());
    }
    cfg
}

/// What is known about the organization a credential belongs to.
///
/// **Three answers, because there are three truths** and the first version of
/// this collapsed the last two. "Personal" is a fact read out of a token;
/// "unknown" is the absence of a token to read. Printing the first when the
/// second holds tells an operator their Endpoints register personally on a run
/// where nothing here could know that — `--auth0-token` carries its own
/// credential, and a store that will not parse is not a statement about
/// anything.
pub enum SignedIn {
    Organization(isekai_p2p::auth0::Organization),
    Personal,
    Unknown,
}

impl std::fmt::Display for SignedIn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Organization(org) => write!(f, "{org}"),
            Self::Personal => write!(f, "none (Endpoints here register personally)"),
            Self::Unknown => write!(f, "unknown (no sign-in readable here)"),
        }
    }
}

/// Which organization this run's credential belongs to.
///
/// `token` is a pasted access token where there is one: it is the credential on
/// that run, and the saved sign-in beside it says nothing about it.
pub fn signed_in_organization(store: &Path, token: Option<&str>) -> SignedIn {
    let organization = match token {
        Some(token) => isekai_p2p::auth0::organization_in(token),
        None => match RefreshingAuth0Token::load(store) {
            Ok(tokens) => tokens.organization(),
            Err(_) => return SignedIn::Unknown,
        },
    };
    match organization {
        Some(org) => SignedIn::Organization(org),
        None => SignedIn::Personal,
    }
}

/// Refuse sign-in flags on a run that is not signing in.
///
/// **Refused rather than dropped.** Both of these change which tenant an
/// Endpoint is registered under, and a run that accepted `--organization` and
/// ignored it would register personally while its operator believed the
/// opposite — which is the confusion the browser flow was introduced to end.
pub fn check_sign_in_args(
    login: bool,
    organization: bool,
    device_code: bool,
) -> anyhow::Result<()> {
    if login {
        return Ok(());
    }
    anyhow::ensure!(
        !organization,
        "--organization is chosen while signing in; this run is not. Pass it with --login",
    );
    anyhow::ensure!(
        !device_code,
        "--device-code chooses how to sign in; this run is not. Pass it with --login",
    );
    Ok(())
}

/// The ordinary flow: a browser on this host, redirected to a loopback port.
async fn browser_sign_in(cfg: &Auth0Config) -> anyhow::Result<isekai_p2p::auth0::Auth0Tokens> {
    // **Bound before anything is printed.** The port is inside the URL, so
    // there is no URL to show until the listener exists.
    let login = start_browser_login(cfg)
        .await
        .context("prepare the sign-in")?;

    // On stdout, because this is the output of the command rather than a
    // remark about it — somebody piping the rest of portal's chatter to a file
    // still has to be able to read this.
    println!("To sign in, open:\n");
    println!("    {}\n", login.url);
    println!("Waiting for the browser to come back…");

    finish_browser_login(cfg, login)
        .await
        .context("wait for the sign-in to finish")
}

/// The fallback, for a host whose browser is somewhere else.
async fn device_code_sign_in(
    cfg: &Auth0Config,
) -> anyhow::Result<isekai_p2p::auth0::Auth0Tokens> {
    // **Refused rather than ignored, and read off the config rather than the
    // flag.** The device grant has nowhere to put an organization, so honouring
    // either is impossible and dropping one would register everything under the
    // individual tenant while the operator believed otherwise -- which is the
    // confusion this whole flow replaced. Checking the flag alone let
    // `ISEKAI_AUTH0_ORGANIZATION` through in silence, which is that same
    // confusion wearing the other hat.
    anyhow::ensure!(
        cfg.organization.is_none(),
        "an organization was named ({}), and --device-code cannot carry one: the device grant \
         has no way to name it, so the token comes back with no org_id and Identity files this \
         Endpoint personally. \
         Over SSH, forward the callback instead -- `ssh -L 38700:127.0.0.1:38700 <host>` and \
         `ISEKAI_AUTH0_CALLBACK_PORT=38700` -- and sign in in the browser you already have. \
         Or unset it and accept the individual tenant",
        cfg.organization.as_deref().unwrap_or_default(),
    );
    let login = start_device_login(cfg)
        .await
        .context("ask Auth0 for a device code")?;
    println!("To sign in, open:\n");
    println!("    {}\n", login.verification_uri_complete);
    println!("and confirm the code:  {}\n", login.user_code);
    println!(
        "(the plain URL is {}, if the one above will not open)",
        login.verification_uri,
    );
    println!("\nWaiting…");
    // **Said plainly, because the consequence outlives the sign-in.** Endpoints
    // registered with this token go to the individual tenant, and nothing later
    // says why.
    tracing::warn!(
        "the device grant cannot name an organization; this sign-in will register \
         Endpoints under the individual tenant",
    );
    poll_device_login(cfg, &login)
        .await
        .context("wait for the sign-in to finish")
}

/// Sign in and persist what it returns.
///
/// Prints where to go, then waits — which is the whole difference from the
/// camera apps' version, and the reason this is not simply `auth0::` used
/// directly: finishing blocks until the operator does, and a GUI cannot block
/// while a terminal is *expected* to.
///
/// `organization` names an Auth0 Organization, which is **what decides the
/// tenant an Endpoint is registered under**. `device_code` falls back to the
/// flow for a browser that is not on this host, which cannot carry one.
pub async fn sign_in(
    store: &Path,
    organization: Option<&str>,
    device_code: bool,
) -> anyhow::Result<()> {
    // **Before the flow, not after it.** What follows is a person in a browser,
    // and a save that fails at the end of it throws away work only they can
    // redo. The common cause is a `--auth0-tokens` under a directory that does
    // not exist yet, which costs nothing to fix here and a whole sign-in to
    // discover at the other end.
    if let Some(parent) = store.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("make {} to save the sign-in into", parent.display()))?;
    }
    // What is already there, so a login that comes back without a refresh token
    // does not throw away one that works — see below.
    let existing = RefreshingAuth0Token::load(store).ok();

    let cfg = sign_in_config(organization);
    let mut tokens = if device_code {
        device_code_sign_in(&cfg).await?
    } else {
        browser_sign_in(&cfg).await?
    };

    // **What was asked for and what arrived are compared.** Auth0 answers a
    // refused organization at the authorize step, so reaching here with none
    // means the request carried none — the flag was absent and the tenant's
    // organization prompt did not appear. Left unsaid, that is a machine
    // registering personally while its operator believes otherwise, which is
    // the whole failure this flow was built to end.
    // **Read off the config, not the flag.** `sign_in_config` lets
    // `ISEKAI_AUTH0_ORGANIZATION` answer when the flag is absent — that is the
    // only way the camera apps name one — so comparing against the flag would
    // check nothing on exactly the path with no other safeguard. (The
    // `--device-code` guard above learned this the same way.)
    if let Some(asked) = cfg.organization.as_deref() {
        match tokens.organization() {
            Some(got) if got.id == asked => {}
            Some(got) => tracing::warn!(
                "asked to sign in to {asked} and signed in to {got}; the Endpoints this \
                 machine registers will belong to the second",
            ),
            None => tracing::warn!(
                "asked to sign in to {asked}, and the token names no organization at all. \
                 Endpoints registered from this machine will go to the individual tenant",
            ),
        }
    }

    // **A sign-in with no refresh token is the failure this feature exists to
    // remove**, so it is not announced as a success. Auth0 returns one only
    // when `offline_access` is granted; without it the store buys hours rather
    // than an installation that keeps working.
    //
    // Any refresh token already on disk is kept rather than overwritten: if
    // there was a working one, this login has not invalidated it, and replacing
    // it with nothing would turn a partial success into a regression.
    let mut usable = tokens.refresh_token.is_some();
    if !usable {
        if let Some(previous) = existing.and_then(|t| t.refresh_token) {
            tokens.refresh_token = Some(previous);
            usable = true;
            tracing::warn!("Auth0 returned no refresh token; keeping the one already saved here",);
        }
    }

    // **Said out loud, because `org_a1b2c3` is not something anyone can check
    // by looking at it.** Which organization a machine signed in to decides
    // which tenant its Endpoints register into, and until now the only way to
    // find out was to decode the token by hand — so an operator who mistyped
    // the id, or whose organization prompt never appeared, learned it much
    // later from a `401` that names neither.
    match tokens.organization() {
        Some(org) => println!("\nSigned in to {org}."),
        None => println!(
            "\nSigned in with no organization: Endpoints registered from this machine go to \
             the individual tenant.\nPass --organization org_… to choose one.",
        ),
    }

    RefreshingAuth0Token::save(store, &tokens)
        .with_context(|| format!("save the Auth0 tokens to {}", store.display()))?;

    if usable {
        println!("\nSigned in. Tokens saved to {}.", store.display());
        Ok(())
    } else {
        println!("\nSaved to {}.", store.display());
        anyhow::bail!(
            "Auth0 returned no refresh token, so this sign-in expires with its access \
             token and cannot be renewed — which is the thing `--login` exists to fix. \
             The Auth0 application has to grant `offline_access`",
        )
    }
}

/// What the two ways of being authenticated hand back.
pub struct Authenticated {
    /// A token valid now, for [`isekai_p2p::P2pConfig::auth0_token`].
    pub token: String,
    /// Where later renewals get a fresh one, for
    /// [`isekai_p2p::P2pConfig::auth0`]. `None` with `--auth0-token`, which is
    /// the case that stops working when that token expires.
    pub source: Option<Arc<dyn Auth0TokenSource>>,
}

/// Resolve however this process is authenticated: a saved sign-in if there is
/// one, otherwise the token on the command line.
///
/// **The saved sign-in wins**, and that ordering is deliberate: `--auth0-token`
/// is the older way and a stale one left in a script would otherwise quietly
/// override a `--login` that was done to fix exactly that.
pub async fn authenticate(store: &Path, given: Option<&str>) -> anyhow::Result<Authenticated> {
    if store.exists() {
        match from_store(store).await {
            Ok(authenticated) => return Ok(authenticated),
            // **Not fatal while there is a token in hand**, which the first
            // version of this got wrong: a revoked sign-in or a truncated file
            // made `--auth0-token` unusable, in the one situation where somebody
            // reaches for it. "The saved sign-in wins" is about a *working* one
            // winning over a stale flag, not about a broken one taking the
            // process down with it.
            Err(e) if given.is_some() => tracing::warn!(
                store = %store.display(),
                "the saved sign-in is unusable, falling back to --auth0-token: {e:#}",
            ),
            Err(e) => {
                return Err(e.context(format!(
                    "the saved sign-in at {} cannot be used. Run `--login` again, or \
                     pass --auth0-token",
                    store.display(),
                )))
            }
        }
    }

    let token = given.map(str::to_owned).with_context(|| {
        format!(
            "not signed in and no --auth0-token given. Run `--login` once to sign in; \
             it saves to {}",
            store.display(),
        )
    })?;
    // Said every time, because the failure it predicts arrives hours later and
    // looks like the proxy refusing a renewal.
    tracing::warn!(
        "using --auth0-token, which cannot be refreshed: this session ends when that \
         token expires. `--login` is the way to keep one running",
    );
    Ok(Authenticated {
        token,
        source: None,
    })
}

/// Build a refreshing source from a saved sign-in.
async fn from_store(store: &Path) -> anyhow::Result<Authenticated> {
    let tokens = RefreshingAuth0Token::load(store).context("read the saved tokens")?;
    let source = RefreshingAuth0Token::new(
        Auth0Config::default(),
        tokens,
        // The same path, so a rotated refresh token replaces the one that was
        // used. Auth0 only rotates when the application asks it to, but an
        // installation that keeps working depends on this either way.
        Some(store.to_path_buf()),
    );
    // Asked for now rather than trusting what was on disk: the file may be days
    // old, and this is the call that refreshes it if so — which also means a
    // revoked sign-in is reported here, with a message, rather than several
    // minutes into a session.
    let token = source
        .auth0_token()
        .await
        .context("refresh the Auth0 access token")?;
    tracing::info!(store = %store.display(), "signed in; tokens will refresh as needed");
    Ok(Authenticated {
        token,
        source: Some(source),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The token file has to land beside the key it belongs to, or two
    /// installations sharing a directory would overwrite each other's sign-in.
    #[test]
    fn the_tokens_are_named_after_the_key() {
        assert_eq!(
            tokens_beside(Path::new("/etc/portal/server.pem")),
            PathBuf::from("/etc/portal/server-auth0.json"),
        );
        assert_eq!(
            tokens_beside(Path::new("portal-client.pem")),
            PathBuf::from("portal-client-auth0.json"),
        );
    }

    /// **`--auth0-token` is refused as a substitute for signing in**, rather
    /// than accepted and left to fail hours later — and the message names the
    /// flag that fixes it and the file it would write.
    #[tokio::test]
    async fn a_missing_sign_in_says_what_to_run() {
        let missing = PathBuf::from("/nonexistent/portal-auth0.json");
        let Err(e) = authenticate(&missing, None).await else {
            panic!("there was nothing to go on");
        };
        let err = format!("{e:#}");
        assert!(err.contains("--login"), "says how to fix it: {err}");
        assert!(
            err.contains("portal-auth0.json"),
            "and where it lands: {err}"
        );
    }

    /// **A broken store must not make `--auth0-token` unusable**, which is the
    /// situation somebody reaches for it in. The first version of this failed
    /// outright once a file existed, in the exact case — a revoked or corrupt
    /// sign-in — where the flag is the way out.
    #[tokio::test]
    async fn a_broken_store_falls_back_to_the_token_in_hand() {
        let dir = std::env::temp_dir().join(format!("portal-login-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("make a scratch directory");
        let store = dir.join("broken-auth0.json");
        std::fs::write(&store, b"this is not json").expect("write a broken store");

        let out = authenticate(&store, Some("header.payload.signature"))
            .await
            .expect("the token in hand is still good");
        assert_eq!(out.token, "header.payload.signature");
        assert!(out.source.is_none());

        // And with nothing to fall back to it is an error that names both ways
        // out rather than a bare parse failure.
        let Err(e) = authenticate(&store, None).await else {
            panic!("a broken store and no token is not something to carry on from");
        };
        let err = format!("{e:#}");
        assert!(
            err.contains("--login") && err.contains("--auth0-token"),
            "names both ways out: {err}",
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The old way still works, because a script that already has a token
    /// should not have to change — it just cannot be refreshed.
    #[tokio::test]
    async fn a_given_token_is_used_when_there_is_no_sign_in() {
        let missing = PathBuf::from("/nonexistent/portal-auth0.json");
        let out = authenticate(&missing, Some("header.payload.signature"))
            .await
            .expect("a token was given");
        assert_eq!(out.token, "header.payload.signature");
        assert!(
            out.source.is_none(),
            "and nothing claims it can be refreshed",
        );
    }
}

#[cfg(test)]
mod sign_in_tests {
    use super::*;

    /// **The flag wins, and its absence does not lose.** The environment is the
    /// only way a camera GUI names an organization, and an organization is what
    /// decides which tenant an Endpoint is filed under.
    #[test]
    fn the_flag_overrides_the_environment_and_absence_does_not() {
        let var = isekai_p2p::auth0::ORGANIZATION_VAR;
        // SAFETY: single-threaded test, and the variable is restored below.
        unsafe { std::env::set_var(var, "org_from_env") };
        assert_eq!(
            sign_in_config(None).organization.as_deref(),
            Some("org_from_env"),
            "an absent flag must not erase the environment",
        );
        assert_eq!(
            sign_in_config(Some("org_from_flag")).organization.as_deref(),
            Some("org_from_flag"),
        );
        unsafe { std::env::remove_var(var) };
        assert_eq!(sign_in_config(None).organization, None);
    }
}
