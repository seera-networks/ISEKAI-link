//! What agent mode refuses before it starts (`docs/portal_agent_plan.md` P1).
//!
//! **Only the arguments.** Agent mode runs one task under a key that never
//! reaches the filesystem, and the combinations that contradict that are facts
//! about the command line — knowable before a single byte is spent. Refused
//! here, the operator reads one sentence naming the flag; refused later, they
//! read whatever failed first and fix the wrong thing.

/// Which of the flags agent mode cares about were given.
///
/// **Named fields rather than a row of positional `bool`s.** Every one of these
/// is the same type, so at a call site of eight the compiler stops helping:
/// transposing two would move a refusal onto the wrong flag and still build.
#[derive(Debug, Clone, Copy, Default)]
pub struct Given {
    pub agent: bool,
    pub key: bool,
    pub auth0_tokens: bool,
    pub auth0_token: bool,
    pub enroll: bool,
    pub whoami: bool,
    pub pair: bool,
    pub redeem: bool,
}

/// Refuse the combinations agent mode cannot honour.
///
/// Each of these is a request the run cannot satisfy in the shape it was
/// asked. Choosing one half quietly is the failure mode that matters: an
/// operator who asked for a task-scoped Endpoint and got a stored one is
/// **separated in their own mind and not in fact**.
pub fn check_args(given: Given) -> anyhow::Result<()> {
    if !given.agent {
        return Ok(());
    }
    // §2.1. A task key and a stored key are two different answers to "who is
    // this Endpoint next time" — the stored one continues, the task one is
    // meant not to.
    if given.key {
        anyhow::bail!(
            "--agent keeps its key in memory for the task; --key stores one that outlives it"
        );
    }
    // §2.2. The Auth0 token store is normally derived from the key's path, and
    // agent mode has no path to derive it from.
    if !given.auth0_tokens {
        anyhow::bail!("--agent needs --auth0-tokens: with no key file there is nowhere to default");
    }
    // §2.3. The Endpoint is revoked when the task ends, which is an
    // authenticated call made at the *end* — so the run needs credentials that
    // are still valid then. A pasted access token is not refreshed, and a long
    // task would reach its own cleanup holding an expired one.
    if given.auth0_token {
        anyhow::bail!(
            "--agent needs the refreshing sign-in (--login/--auth0-tokens): \
             --auth0-token cannot be renewed, and revoking at the end would fail on a long task"
        );
    }
    // §1.1. Enrolling authenticates as a workload with an Enrollment Key;
    // agent mode authenticates as the person whose entitlements the task runs
    // under. They are different doors, and they end differently too — one
    // returns a slot, the other revokes an Endpoint.
    if given.enroll {
        anyhow::bail!("--enroll is the unattended way in; --agent runs as the signed-in person");
    }
    // The answer would be a fresh random id that this run invents and then
    // throws away. Printing it invites the workflow agent mode replaces —
    // handing an id to the other side for `--allow` — and the operator would
    // be waiting on a peer that authorised an Endpoint no later run will use.
    if given.whoami {
        anyhow::bail!(
            "--whoami has no answer under --agent: the key is made for this task and \
             the reachability comes from an entitlement, not from being named"
        );
    }
    // §1.1 again, from the other side. Pairing and tickets are ways of being
    // let in by a peer; agent mode is let in by an entitlement that raised a
    // lease at the Gateway. Two authorities for one connection is a question
    // about which one is meant to be in force.
    if given.pair || given.redeem {
        anyhow::bail!(
            "--agent is authorised by an entitlement, not by being let in; \
             --pair/--redeem are the other way"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent() -> Given {
        Given {
            agent: true,
            auth0_tokens: true,
            ..Default::default()
        }
    }

    /// Nothing here applies to a run that did not ask for agent mode.
    #[test]
    fn without_agent_every_combination_passes() {
        check_args(Given {
            agent: false,
            key: true,
            auth0_token: true,
            enroll: true,
            whoami: true,
            pair: true,
            ..Default::default()
        })
        .expect("not agent mode, not our business");
    }

    #[test]
    fn a_stored_key_is_refused() {
        let e = check_args(Given { key: true, ..agent() }).expect_err("refused");
        assert!(e.to_string().contains("--key"), "{e}");
    }

    /// The store cannot be defaulted from a key path that does not exist.
    #[test]
    fn the_token_store_has_to_be_named() {
        let e = check_args(Given {
            auth0_tokens: false,
            ..agent()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--auth0-tokens"), "{e}");
    }

    /// A token that cannot be refreshed outlives nothing, least of all the
    /// revocation at the end.
    #[test]
    fn a_pasted_access_token_is_refused() {
        let e = check_args(Given {
            auth0_token: true,
            ..agent()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--auth0-token"), "{e}");
    }

    #[test]
    fn enrolling_is_the_other_door() {
        let e = check_args(Given {
            enroll: true,
            ..agent()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--enroll"), "{e}");
    }

    #[test]
    fn a_throwaway_id_is_not_worth_printing() {
        let e = check_args(Given {
            whoami: true,
            ..agent()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--whoami"), "{e}");
    }

    #[test]
    fn being_let_in_is_the_other_authority() {
        for given in [
            Given { pair: true, ..agent() },
            Given { redeem: true, ..agent() },
        ] {
            let e = check_args(given).expect_err("refused");
            assert!(e.to_string().contains("--pair/--redeem"), "{e}");
        }
    }

    #[test]
    fn the_shape_agent_mode_wants_is_accepted() {
        check_args(agent()).expect("--agent --auth0-tokens <path>");
    }
}
