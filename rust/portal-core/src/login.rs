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
use isekai_p2p::auth0::{poll_device_login, start_device_login, Auth0Config, RefreshingAuth0Token};

/// Where the tokens live, given the Endpoint key's path.
///
/// Beside the key and named after it, the way `portal-server --cert-key`
/// defaults: the two belong to the same identity, so one `--key` names both and
/// two installations on one machine do not collide.
pub fn tokens_beside(key: &Path) -> PathBuf {
    let mut path = key.to_path_buf();
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| "portal".to_owned());
    path.set_file_name(format!("{stem}-auth0.json"));
    path
}

/// Run the device flow and persist what it returns.
///
/// Prints the code and the URL, then waits — which is the whole difference from
/// the camera apps' version, and the reason this is not simply `auth0::` used
/// directly: `poll_device_login` blocks until the operator finishes, and a GUI
/// cannot block while a terminal is *expected* to.
pub async fn sign_in(store: &Path) -> anyhow::Result<()> {
    let cfg = Auth0Config::default();
    let login = start_device_login(&cfg)
        .await
        .context("ask Auth0 for a device code")?;

    // On stdout, because this is the output of the command rather than a
    // remark about it — somebody piping the rest of portal's chatter to a file
    // still has to be able to read this.
    println!("To sign in, open:\n");
    println!("    {}\n", login.verification_uri_complete);
    println!("and confirm the code:  {}\n", login.user_code);
    println!(
        "(the plain URL is {}, if the one above will not open)",
        login.verification_uri
    );
    println!("\nWaiting…");

    let tokens = poll_device_login(&cfg, &login)
        .await
        .context("wait for the sign-in to finish")?;
    if tokens.refresh_token.is_none() {
        // Worth saying rather than discovering: without one this file buys a
        // few hours, not an installation that keeps working.
        tracing::warn!(
            "Auth0 returned no refresh token, so this sign-in expires with its \
             access token. Check that the application allows `offline_access`.",
        );
    }
    RefreshingAuth0Token::save(store, &tokens)
        .with_context(|| format!("save the Auth0 tokens to {}", store.display()))?;
    println!("\nSigned in. Tokens saved to {}.", store.display());
    Ok(())
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
        let tokens = RefreshingAuth0Token::load(store)
            .with_context(|| format!("read the Auth0 tokens at {}", store.display()))?;
        let source = RefreshingAuth0Token::new(
            Auth0Config::default(),
            tokens,
            // The same path, so a rotated refresh token replaces the one that
            // was used. Auth0 only rotates when the application asks it to, but
            // an installation that keeps working depends on this either way.
            Some(store.to_path_buf()),
        );
        // Asked for now rather than trusting what was on disk: the file may be
        // days old, and this is the call that refreshes it if so — which also
        // means a revoked sign-in fails here, with a message, rather than
        // several minutes into a session.
        let token = source
            .auth0_token()
            .await
            .context("refresh the Auth0 access token")?;
        tracing::info!(store = %store.display(), "signed in; tokens will refresh as needed");
        return Ok(Authenticated {
            token,
            source: Some(source),
        });
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
