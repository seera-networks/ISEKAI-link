//! What agent mode refuses before it starts (`docs/portal_agent_plan.md` P1).
//!
//! **Only the arguments.** Agent mode runs one task under a key that never
//! reaches the filesystem, and the combinations that contradict that are facts
//! about the command line — knowable before a single byte is spent. Refused
//! here, the operator reads one sentence naming the flag; refused later, they
//! read whatever failed first and fix the wrong thing.
//!
//! The lifecycle those refusals guard — the in-memory key, the narrowed token,
//! the revocation on the way out — is P2 onwards.

/// Refuse the combinations agent mode cannot honour.
///
/// Each of these is a request the run cannot satisfy in the shape it was
/// asked. Choosing one half quietly is the failure mode that matters: an
/// operator who asked for a task-scoped Endpoint and got a stored one is
/// **separated in their own mind and not in fact**.
pub fn check_args(
    agent: bool,
    key_given: bool,
    auth0_tokens_given: bool,
    auth0_token_given: bool,
    enroll: bool,
) -> anyhow::Result<()> {
    if !agent {
        return Ok(());
    }
    // §2.1. A task key and a stored key are two different answers to "who is
    // this Endpoint next time" — the stored one continues, the task one is
    // meant not to.
    if key_given {
        anyhow::bail!(
            "--agent keeps its key in memory for the task; --key stores one that outlives it"
        );
    }
    // §2.2. The Auth0 token store is normally derived from the key's path, and
    // agent mode has no path to derive it from.
    if !auth0_tokens_given {
        anyhow::bail!("--agent needs --auth0-tokens: with no key file there is nowhere to default");
    }
    // §2.3. The Endpoint is revoked when the task ends, which is an
    // authenticated call made at the *end* — so the run needs credentials that
    // are still valid then. A pasted access token is not refreshed, and a long
    // task would reach its own cleanup holding an expired one.
    if auth0_token_given {
        anyhow::bail!(
            "--agent needs the refreshing sign-in (--login/--auth0-tokens): \
             --auth0-token cannot be renewed, and revoking at the end would fail on a long task"
        );
    }
    // §1.1. Enrolling authenticates as a workload with an Enrollment Key;
    // agent mode authenticates as the person whose entitlements the task runs
    // under. They are different doors, and they end differently too — one
    // returns a slot, the other revokes an Endpoint.
    if enroll {
        anyhow::bail!("--enroll is the unattended way in; --agent runs as the signed-in person");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Nothing here applies to a run that did not ask for agent mode.
    #[test]
    fn without_agent_every_combination_passes() {
        check_args(false, true, false, true, true).expect("not agent mode, not our business");
    }

    #[test]
    fn a_stored_key_is_refused() {
        let e = check_args(true, true, true, false, false).expect_err("refused");
        assert!(e.to_string().contains("--key"), "{e}");
    }

    /// The store cannot be defaulted from a key path that does not exist.
    #[test]
    fn the_token_store_has_to_be_named() {
        let e = check_args(true, false, false, false, false).expect_err("refused");
        assert!(e.to_string().contains("--auth0-tokens"), "{e}");
    }

    /// A token that cannot be refreshed outlives nothing, least of all the
    /// revocation at the end.
    #[test]
    fn a_pasted_access_token_is_refused() {
        let e = check_args(true, false, true, true, false).expect_err("refused");
        assert!(e.to_string().contains("--auth0-token"), "{e}");
    }

    #[test]
    fn enrolling_is_the_other_door() {
        let e = check_args(true, false, true, false, true).expect_err("refused");
        assert!(e.to_string().contains("--enroll"), "{e}");
    }

    #[test]
    fn the_shape_agent_mode_wants_is_accepted() {
        check_args(true, false, true, false, false).expect("--agent --auth0-tokens <path>");
    }
}
