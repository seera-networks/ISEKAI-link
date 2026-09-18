//! What agent mode refuses before it starts (`docs/portal_agent_plan.md` P1).
//!
//! **Only the arguments.** Agent mode runs one task under a key that never
//! reaches the filesystem, and the combinations that contradict that are facts
//! about the command line — knowable before a single byte is spent. Refused
//! here, the operator reads one sentence naming the flag; refused later, they
//! read whatever failed first and fix the wrong thing.
//!
//! **Accepting a flag and dropping it is the failure this file exists to
//! prevent**, so the list is long on purpose: `portal-client` has several modes
//! that return before a key is ever made, and `--agent` means nothing to any of
//! them.

/// Which of the flags agent mode cares about were given.
///
/// **Named fields rather than a row of positional `bool`s.** Every one of these
/// is the same type, so at a call site of this size the compiler stops helping:
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
    /// A Provisioning Key, from the flag **or the environment variable**.
    pub provisioning: bool,
    /// `--capability` or `--listener`.
    pub capability: bool,
    /// Any of the account-level commands, which return before a key is made.
    pub admin: bool,
    pub login: bool,
    pub relays: bool,
    pub gateway: bool,
    pub task: bool,
}

/// Refuse the combinations agent mode cannot honour.
///
/// Each of these is a request the run cannot satisfy in the shape it was
/// asked. Choosing one half quietly is the failure mode that matters: an
/// operator who asked for a task-scoped Endpoint and got a stored one is
/// **separated in their own mind and not in fact**.
pub fn check_args(given: Given) -> anyhow::Result<()> {
    if !given.agent {
        // **These two describe an agent run and nothing else.** `narrowing()`
        // ignores them without `--agent`, so accepting them here would send no
        // selector at all — raising a lease at every Gateway, which is the
        // outcome `--gateway` exists to prevent.
        if given.gateway {
            anyhow::bail!("--gateway selects which Gateway --agent's lease starts at; \
                           without --agent nothing is narrowed");
        }
        if given.task {
            anyhow::bail!("--task names an --agent run; --device-name is what an \
                           attended registration records");
        }
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
    // §1.1 again, from the other side. Pairing, tickets and Provisioning Keys
    // are ways of being let in by a peer; agent mode is let in by an
    // entitlement that raised a lease at the Gateway. Two authorities for one
    // connection is a question about which one is meant to be in force.
    //
    // **A Provisioning Key arrives from the environment**, so leaving it out
    // of this list would be the quiet version of the same bug — the key read,
    // never redeemed, and its absence from the result looking like the key was
    // wrong.
    if given.pair || given.redeem || given.provisioning {
        anyhow::bail!(
            "--agent is authorised by an entitlement, not by being let in; \
             --pair/--redeem and a Provisioning Key are the other way"
        );
    }
    // A capability names *an* Endpoint, and agent mode's was made seconds ago,
    // so no capability the server ever issued can match it. Left to run, this
    // signs in, registers an Endpoint and fails at the proxy with
    // `capability-endpoint-mismatch` — the same dead end the `--whoami`
    // refusal above is written to keep an operator out of.
    if given.capability {
        anyhow::bail!(
            "--capability/--listener were issued for an Endpoint that already existed; \
             --agent makes a new one for this task, so none of them can match it"
        );
    }
    // **These return before a key is ever made**, so `--agent` would be
    // accepted, mean nothing, and exit 0 — which is how an operator comes to
    // believe a task-scoped run happened when an ordinary one did.
    if given.admin {
        anyhow::bail!(
            "the account-level commands run as the person, not as an Endpoint; \
             --agent has nothing to do in them"
        );
    }
    if given.login {
        anyhow::bail!("--login only signs in; run it on its own, then --agent");
    }
    // Registering a throwaway Endpoint permanently, to answer a question about
    // the network. Worse than useless while P4 is unwritten: nothing revokes
    // it, and no sweep reaches the Auth0 route (§2.4).
    if given.relays {
        anyhow::bail!(
            "--relays only measures and prints; running it under --agent would register \
             an Endpoint for the task and leave it there"
        );
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
    // §2.2. The Auth0 token store is normally derived from the key's path, and
    // agent mode has no path to derive it from.
    //
    // **Last, because it is the only one that asks for something rather than
    // saying no.** Put first, it answered `--agent --whoami` with "you need
    // --auth0-tokens" — advice beside the point for a command that makes no
    // network call, and which the operator would follow only to be told the
    // real reason on the next run.
    if !given.auth0_tokens {
        anyhow::bail!("--agent needs --auth0-tokens: with no key file there is nowhere to default");
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

    /// Nothing about agent mode applies to a run that did not ask for it.
    #[test]
    fn without_agent_the_ordinary_flags_pass() {
        check_args(Given {
            agent: false,
            key: true,
            auth0_token: true,
            enroll: true,
            whoami: true,
            pair: true,
            relays: true,
            admin: true,
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

    /// **The refusal has to survive the command an operator actually types.**
    /// `--agent --whoami` carries no `--auth0-tokens`, so a requirement checked
    /// first would answer with that instead — and `--whoami` makes no network
    /// call, so the advice would be beside the point.
    #[test]
    fn the_reason_that_helps_is_the_one_given() {
        let e = check_args(Given {
            agent: true,
            whoami: true,
            ..Default::default()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--whoami"), "{e}");
    }

    #[test]
    fn being_let_in_is_the_other_authority() {
        for given in [
            Given { pair: true, ..agent() },
            Given { redeem: true, ..agent() },
            Given { provisioning: true, ..agent() },
        ] {
            let e = check_args(given).expect_err("refused");
            assert!(e.to_string().contains("--pair/--redeem"), "{e}");
        }
    }

    /// No capability can name an Endpoint that did not exist when it was
    /// issued.
    #[test]
    fn a_capability_cannot_match_a_key_made_after_it() {
        let e = check_args(Given {
            capability: true,
            ..agent()
        })
        .expect_err("refused");
        assert!(e.to_string().contains("--capability"), "{e}");
    }

    /// **The modes that return before a key is made.** Each of these would
    /// otherwise accept `--agent`, ignore it, and exit 0.
    #[test]
    fn the_modes_that_never_reach_a_key_refuse_it() {
        for (given, want) in [
            (Given { admin: true, ..agent() }, "account-level"),
            (Given { login: true, ..agent() }, "--login"),
            (Given { relays: true, ..agent() }, "--relays"),
        ] {
            let e = check_args(given).expect_err("refused");
            assert!(e.to_string().contains(want), "{e}");
        }
    }

    /// The other direction: flags that describe an agent run and are dropped
    /// without one.
    #[test]
    fn the_agent_only_flags_need_agent_mode() {
        for (given, want) in [
            (
                Given {
                    gateway: true,
                    ..Default::default()
                },
                "--gateway",
            ),
            (
                Given {
                    task: true,
                    ..Default::default()
                },
                "--task",
            ),
        ] {
            let e = check_args(given).expect_err("refused");
            assert!(e.to_string().contains(want), "{e}");
        }
    }

    #[test]
    fn the_shape_agent_mode_wants_is_accepted() {
        check_args(Given {
            gateway: true,
            task: true,
            ..agent()
        })
        .expect("--agent --auth0-tokens <path> --gateway ep:R1 --task nightly");
    }
}
