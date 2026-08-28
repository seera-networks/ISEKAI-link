//! Where a workload identity assertion comes from.
//!
//! An Enrollment Key bound with `binding.type: "oidc"` is not usable on its
//! own: every call that spends it has to carry a fresh token from the issuer
//! the key names (§8.8.3). This module has the two ways a CI job gets one.
//!
//! **Nothing here caches.** §8.8.7 verifies the binding on every renewal — that
//! is what stops a key from outliving the job it was issued for — and the
//! renewal interval (`expires_in − 60s`, so about fourteen minutes for a
//! fifteen-minute token) is longer than a GitHub ID token lives. A cache would
//! never hit, and would add a way to hold an expired token.
//!
//! **Two audiences, always.** Identity wants `isekai-identity` and the proxy
//! wants `isekai-proxy`, deliberately different so that a token handed to one
//! is refused by the other. [`AssertionSource::assertion`] takes the audience
//! for that reason, and both implementations here honour it per call.

use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use anyhow::Context as _;

use crate::auth::AssertionSource;

/// GitHub Actions' OIDC endpoint.
///
/// The runner exposes a URL and a bearer for it in the job's environment, but
/// **only when the workflow asks for it**:
///
/// ```yaml
/// permissions:
///   id-token: write
/// ```
///
/// Without that the variables are simply absent, which is why
/// [`GithubActionsOidc::from_env`] fails loudly and names the fix — the
/// alternative is a `403 enrollment-binding-invalid` from Identity that says
/// nothing about the workflow file.
///
/// **No `Debug`.** It holds the runner's bearer, and a derived `Debug` is how a
/// secret ends up in a log line somebody pasted into an issue.
pub struct GithubActionsOidc {
    /// `ACTIONS_ID_TOKEN_REQUEST_URL`, already carrying its `api-version`.
    url: String,
    /// `ACTIONS_ID_TOKEN_REQUEST_TOKEN`. Valid for the life of the job, which
    /// is the property §8.8.7 leans on: when the job ends, renewal stops.
    request_token: String,
    http: reqwest::Client,
}

/// How long to wait for the runner to mint a token.
///
/// Generous for a call to a service on the same network, and short enough that
/// a job fails with a message instead of sitting until the workflow's own
/// timeout.
const MINT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

const URL_VAR: &str = "ACTIONS_ID_TOKEN_REQUEST_URL";
const TOKEN_VAR: &str = "ACTIONS_ID_TOKEN_REQUEST_TOKEN";

impl GithubActionsOidc {
    /// Read the runner's environment, or say what the workflow is missing.
    pub fn from_env() -> anyhow::Result<Self> {
        let url = std::env::var(URL_VAR).ok().filter(|v| !v.is_empty());
        let request_token = std::env::var(TOKEN_VAR).ok().filter(|v| !v.is_empty());
        match (url, request_token) {
            (Some(url), Some(request_token)) => Ok(Self {
                url,
                request_token,
                // **Bounded, because this runs inside the enrolment's
                // `OnceCell` initializer.** Every concurrent caller on the same
                // credential waits behind whoever is initializing, so a runner
                // endpoint that accepts the connection and then says nothing
                // would hang the whole session rather than fail it.
                http: reqwest::Client::builder()
                    .timeout(MINT_TIMEOUT)
                    .build()
                    .context("could not build an HTTP client")?,
            }),
            _ => anyhow::bail!(
                "{URL_VAR} and {TOKEN_VAR} are not set, so no workload identity token can be \
                 minted.\nGitHub Actions provides them only when the job asks:\n\n  \
                 permissions:\n    id-token: write\n\nAdd that to the job (not only the \
                 workflow) and run again."
            ),
        }
    }
}

#[derive(serde::Deserialize)]
struct IdToken {
    value: String,
}

impl AssertionSource for GithubActionsOidc {
    fn assertion<'a>(
        &'a self,
        audience: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(async move {
            // Appended rather than formatted in: the runner's URL already has a
            // query string (`?api-version=…`), and an audience is a value that
            // has to be escaped like any other.
            let mut url = reqwest::Url::parse(&self.url)
                .with_context(|| format!("{URL_VAR} is not a URL"))?;
            url.query_pairs_mut().append_pair("audience", audience);
            let response = self
                .http
                .get(url)
                .bearer_auth(&self.request_token)
                .send()
                .await
                .context("could not reach the GitHub Actions token endpoint")?;
            let status = response.status();
            if !status.is_success() {
                // The body is the runner's, not a user's, and it is what says
                // whether the permission is missing or the audience refused.
                let body = response.text().await.unwrap_or_default();
                anyhow::bail!(
                    "GitHub Actions refused an id token for `{audience}`: {status} {body}"
                );
            }
            let token: IdToken = response
                .json()
                .await
                .context("the GitHub Actions token endpoint answered something unexpected")?;
            Ok(token.value)
        })
    }
}

/// Assertions read from files, one per audience.
///
/// The Kubernetes shape: a projected service account token is mounted per
/// audience, so there is a path for each rather than one token that covers
/// both.
///
/// **Read on every call, never held.** The kubelet rewrites a projected token
/// in place as it approaches expiry, so a value read once at startup is stale
/// by the time it matters — which is the same reason nothing else here caches.
pub struct TokenFiles {
    files: HashMap<String, PathBuf>,
}

impl TokenFiles {
    /// Build from `audience=path` pairs.
    pub fn new(pairs: impl IntoIterator<Item = (String, PathBuf)>) -> Self {
        Self {
            files: pairs.into_iter().collect(),
        }
    }

    /// Parse one `audience=path` argument.
    pub fn parse_pair(arg: &str) -> anyhow::Result<(String, PathBuf)> {
        let (audience, path) = arg.split_once('=').with_context(|| {
            format!("expected `audience=path`, got `{arg}` — one file per audience")
        })?;
        if audience.is_empty() || path.is_empty() {
            anyhow::bail!("expected `audience=path`, got `{arg}`");
        }
        Ok((audience.to_owned(), PathBuf::from(path)))
    }
}

impl AssertionSource for TokenFiles {
    fn assertion<'a>(
        &'a self,
        audience: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> {
        Box::pin(async move {
            let path = self.files.get(audience).with_context(|| {
                // Naming what is configured is the whole of the diagnosis here:
                // the usual mistake is mounting one audience and not the other.
                let known: Vec<&str> = self.files.keys().map(String::as_str).collect();
                format!(
                    "no token file for audience `{audience}` (have: {})",
                    if known.is_empty() {
                        "none".to_owned()
                    } else {
                        known.join(", ")
                    }
                )
            })?;
            let token = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("could not read {}", path.display()))?;
            // Trailing newlines are usual in a mounted file and are not part of
            // the JWT.
            Ok(token.trim().to_owned())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pair_is_split_on_the_first_equals() {
        let (audience, path) = TokenFiles::parse_pair("isekai-identity=/var/run/id").unwrap();
        assert_eq!(audience, "isekai-identity");
        assert_eq!(path, PathBuf::from("/var/run/id"));
    }

    /// A path may contain `=`; an audience may not, so the first one splits.
    #[test]
    fn a_path_may_contain_an_equals() {
        let (audience, path) = TokenFiles::parse_pair("aud=/var/run/a=b").unwrap();
        assert_eq!(audience, "aud");
        assert_eq!(path, PathBuf::from("/var/run/a=b"));
    }

    #[test]
    fn a_pair_without_both_halves_is_refused() {
        assert!(TokenFiles::parse_pair("/var/run/id").is_err());
        assert!(TokenFiles::parse_pair("=/var/run/id").is_err());
        assert!(TokenFiles::parse_pair("aud=").is_err());
    }

    /// The error names what *is* mounted, because mounting one audience and
    /// not the other is the mistake this shape invites.
    #[tokio::test]
    async fn an_unknown_audience_names_the_ones_there_are() {
        let files =
            TokenFiles::new([("isekai-identity".to_owned(), PathBuf::from("/nonexistent"))]);
        let err = files.assertion("isekai-proxy").await.unwrap_err();
        let message = format!("{err:#}");
        assert!(message.contains("isekai-proxy"), "{message}");
        assert!(message.contains("isekai-identity"), "{message}");
    }

    #[tokio::test]
    async fn a_mounted_token_is_read_and_trimmed() {
        let dir = std::env::temp_dir().join(format!("isekai-oidc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("token");
        std::fs::write(&path, "header.payload.signature\n").unwrap();

        let files = TokenFiles::new([("isekai-identity".to_owned(), path.clone())]);
        assert_eq!(
            files.assertion("isekai-identity").await.unwrap(),
            "header.payload.signature"
        );

        // Re-read rather than remembered: the kubelet rewrites these in place.
        std::fs::write(&path, "second.token.value\n").unwrap();
        assert_eq!(
            files.assertion("isekai-identity").await.unwrap(),
            "second.token.value"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The absence of the runner's variables is not a mystery to be debugged
    /// three calls later.
    #[test]
    fn a_missing_runner_environment_names_the_permission() {
        // Only meaningful when the variables really are absent, which is the
        // case everywhere except inside a GitHub Actions job that asked for
        // them — including this repository's own CI, which does not.
        if std::env::var(URL_VAR).is_ok() {
            return;
        }
        // Destructured rather than `unwrap_err`, which would want `Debug` on
        // a type holding the runner's bearer.
        let Err(err) = GithubActionsOidc::from_env() else {
            panic!("no runner environment, so this cannot succeed");
        };
        let message = format!("{err:#}");
        assert!(message.contains("id-token: write"), "{message}");
    }
}
