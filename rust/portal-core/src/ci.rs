//! Credentials for a run with nobody at the keyboard.
//!
//! **Shared because both binaries need it and neither should own it.** A CI job
//! runs `portal-client` to reach services and, in a self-contained test, a
//! `portal-server` to offer them; the rules about how a secret is read and where
//! a workload identity token comes from are the same either way. Two copies
//! would be two things to keep in step, and the half that drifts would be the
//! one nobody was looking at.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context as _;
use isekai_p2p::{AssertionSource, Credential, Enrollment};

/// Where a client's Enrollment Key is looked for.
pub const ENROLLMENT_KEY_VAR: &str = "ISEKAI_ENROLLMENT_KEY";
/// Where a server's Enrollment Key is looked for.
///
/// **A different variable from the client's, because it is a different key.**
/// The two carry different permissions — a server has to create a listener and
/// accept connections — and putting them in one variable would mean one key
/// with both, which is the ceiling problem §8.8.2 exists to avoid.
pub const SERVER_ENROLLMENT_KEY_VAR: &str = "ISEKAI_SERVER_ENROLLMENT_KEY";
/// Where a Provisioning Key is looked for.
pub const PROVISIONING_KEY_VAR: &str = "ISEKAI_PROVISIONING_KEY";

/// A secret from a file, or from the environment variable that carries it.
///
/// **There is deliberately no flag that takes the value itself.** On Linux any
/// process running as the same user can read `/proc/<pid>/cmdline`, and a CI
/// runner is a machine that runs other people's code; `set -x`, a failed step's
/// log and a stray `ps` all print an argument list too.
///
/// Both sources are trimmed. A key written with `echo "K=$(cat f)" >> $GITHUB_ENV`
/// or pasted into a secret carries a trailing newline, and sending it makes the
/// server hash a different string and answer `403 …-key-invalid` — which says
/// nothing about whitespace.
pub fn secret_from(file: Option<&Path>, var: &str) -> anyhow::Result<Option<String>> {
    if let Some(path) = file {
        let value = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read the key at {}", path.display()))?;
        let value = value.trim();
        if value.is_empty() {
            anyhow::bail!("{} is empty", path.display());
        }
        return Ok(Some(value.to_owned()));
    }
    // An empty variable is the same as an unset one: that is what a workflow
    // referencing a secret nobody configured actually produces.
    Ok(std::env::var(var)
        .ok()
        .map(|v| v.trim().to_owned())
        .filter(|v| !v.is_empty()))
}

/// Where a bound key's workload identity tokens come from.
///
/// Both servers want one, for **different audiences**, so this hands back a
/// source rather than a value — see `isekai_p2p::oidc`.
pub fn assertions(
    oidc: &str,
    token_files: &[String],
) -> anyhow::Result<Option<Arc<dyn AssertionSource>>> {
    match oidc {
        "none" => Ok(None),
        "github" => Ok(Some(Arc::new(
            isekai_p2p::oidc::GithubActionsOidc::from_env()?,
        ))),
        "files" => {
            let pairs = token_files
                .iter()
                .map(|arg| isekai_p2p::oidc::TokenFiles::parse_pair(arg))
                .collect::<anyhow::Result<Vec<_>>>()?;
            Ok(Some(Arc::new(isekai_p2p::oidc::TokenFiles::new(pairs))))
        }
        other => anyhow::bail!("--oidc takes `github`, `files` or `none`, not `{other}`"),
    }
}

/// The unattended credential, with whatever its binding needs attached.
///
/// **No sign-in happens on this path.** That is the point: §4.3 registration
/// wants Auth0 authentication state and a job has none, so the key stands in
/// for it — under a binding, a slot count and a finite life.
pub fn enrollment_credential(
    key_file: Option<&Path>,
    var: &str,
    oidc: &str,
    token_files: &[String],
) -> anyhow::Result<Credential> {
    let key = secret_from(key_file, var)?.with_context(|| {
        format!(
            "--enroll needs an Enrollment Key in {var} or the matching --*-key-file. It is not \
             an argument on purpose: an argument list is readable by anything running as this user"
        )
    })?;
    let mut enrollment = Enrollment::new(key);
    if let Some(source) = assertions(oidc, token_files)? {
        enrollment = enrollment.with_assertions(source);
    }
    Ok(enrollment.into())
}

/// Check that the key `--enroll` needs is actually there.
///
/// **Separate from building the credential, because of where each belongs.**
/// The credential is built after the catalogue is read — deliberately, so a
/// typo there costs a message rather than a registered Endpoint — but a missing
/// key is a fact about the arguments, and reporting it behind an unrelated
/// failure tells the operator to fix the wrong thing. Naming the variable is
/// most of the value: the client's and the server's are different.
pub fn require_key(file: Option<&Path>, var: &str) -> anyhow::Result<()> {
    secret_from(file, var)?.map(|_| ()).with_context(|| {
        format!(
            "--enroll needs an Enrollment Key in {var} or the matching --*-key-file. It is not \
             an argument on purpose: an argument list is readable by anything running as this user"
        )
    })
}

/// Refuse the argument combinations that cannot mean anything.
///
/// **Refused rather than dropped**, which is the mistake `--allow` on the
/// server's side exists to avoid: a run that ignored these would look like it
/// worked and fail later against a bound key, naming nothing.
pub fn check_unattended_args(
    enroll: bool,
    auth0_token: bool,
    register: bool,
    oidc: &str,
    token_files: &[String],
) -> anyhow::Result<()> {
    if enroll && auth0_token {
        anyhow::bail!("--enroll registers with an Enrollment Key; --auth0-token is the other way");
    }
    // §8.1 registration wants Auth0 authentication state, so it is not a choice
    // the unattended path has — enrolling *is* the registration.
    if enroll && register {
        anyhow::bail!("--enroll already registers this Endpoint; --register is the attended way");
    }
    if oidc != "files" && !token_files.is_empty() {
        anyhow::bail!("--oidc-token-file describes `--oidc files`, which this run is not using");
    }
    if oidc == "files" && token_files.is_empty() {
        anyhow::bail!("--oidc files needs at least one --oidc-token-file `audience=path`");
    }
    Ok(())
}

/// Give an enrolment slot back, best effort.
///
/// **Never changes the exit code.** The idle sweep is behind this, so failing
/// costs a slot until then and nothing else; work that otherwise succeeded must
/// not be reported as failed because the tidying up did not land. It is bounded
/// for the same reason: this runs after the work is done.
pub async fn release_the_slot(cfg: &isekai_p2p::P2pConfig) {
    let released = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        isekai_p2p::config::release_enrollment(cfg),
    )
    .await;
    match released {
        Ok(Ok(true)) => tracing::info!("returned the enrolment slot"),
        // Nothing was taken, so say nothing: a run that failed before enrolling
        // has no slot out, and announcing one would report something that did
        // not happen.
        Ok(Ok(false)) => {}
        Ok(Err(e)) => {
            tracing::warn!("could not return the enrolment slot; the idle sweep will: {e:#}")
        }
        Err(_) => tracing::warn!("timed out returning the enrolment slot; the idle sweep will"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unset_variable_and_an_empty_one_are_the_same() {
        let var = "ISEKAI_TEST_ABSENT_KEY_VAR";
        unsafe { std::env::remove_var(var) };
        assert_eq!(secret_from(None, var).unwrap(), None);
        unsafe { std::env::set_var(var, "   \n") };
        assert_eq!(secret_from(None, var).unwrap(), None);
        unsafe { std::env::remove_var(var) };
    }

    /// Whitespace is what a secret picks up on its way through a workflow, and
    /// sending it means the server hashes a different string.
    #[test]
    fn a_padded_variable_is_trimmed() {
        let var = "ISEKAI_TEST_PADDED_KEY_VAR";
        unsafe { std::env::set_var(var, "  enr1_SECRET\n") };
        assert_eq!(
            secret_from(None, var).unwrap().as_deref(),
            Some("enr1_SECRET")
        );
        unsafe { std::env::remove_var(var) };
    }

    #[test]
    fn the_combinations_that_cannot_mean_anything_are_refused() {
        assert!(check_unattended_args(true, true, false, "none", &[]).is_err());
        assert!(check_unattended_args(true, false, true, "none", &[]).is_err());
        let files = vec!["aud=/p".to_owned()];
        assert!(check_unattended_args(true, false, false, "none", &files).is_err());
        assert!(check_unattended_args(true, false, false, "files", &[]).is_err());
        assert!(check_unattended_args(true, false, false, "files", &files).is_ok());
        assert!(check_unattended_args(false, true, true, "none", &[]).is_ok());
    }

    /// The two keys are different keys, so they are different variables — one
    /// holding both would be one key carrying both roles' permissions.
    #[test]
    fn the_two_roles_read_different_variables() {
        assert_ne!(ENROLLMENT_KEY_VAR, SERVER_ENROLLMENT_KEY_VAR);
    }
}
