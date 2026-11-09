//! Which grants a policy wants, and what has to change at the proxy to match.
//!
//! **P3 of `docs/portal_gateway_plan.md`.** The table says what the control
//! plane wants; this works out what has to change — and, more importantly,
//! what has to be left alone.
//!
//! **The ledger itself is [`isekai_p2p::grants`]**, because the bookkeeping a
//! grant upsert needs is not specific to this Gateway: anything creating grants
//! on a schedule needs it. The rules that live there — a grant is keyed by the
//! pair, and only what this process made may be removed — are what [`plan`]
//! reads. What stays here is the half that knows about access leases, windows
//! and refusals, which is this crate's business and nobody else's.

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;

// `GrantKey` and `Ledger` because [`plan`]'s signature and [`Changes`] name
// them. Not `already_existed`/`existed_before`: a second path to a function
// this crate does not itself call is just a name to keep in step.
pub use isekai_p2p::grants::{GrantKey, Ledger};

use super::{Refusal, Table};

/// One grant to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wanted {
    pub allowed_endpoint: String,
    pub protocol: String,
    /// Shorter than every lease behind it — see [`super::Entry::grant_ttl`].
    pub ttl: u64,
    /// The leases asking for it, for the log and for the label.
    pub leases: BTreeSet<String>,
}

impl Wanted {
    pub fn key(&self) -> GrantKey {
        (self.allowed_endpoint.clone(), self.protocol.clone())
    }

    /// What to write in the grant's `label`.
    ///
    /// **Not a mark to recognise it by** — any re-creation overwrites it, so it
    /// cannot be trusted for that (§ the module header). It is for an operator
    /// reading the grant list and wondering where a row came from.
    pub fn label(&self) -> String {
        match self.leases.len() {
            1 => format!("gw:{}", self.leases.iter().next().expect("one")),
            n => format!("gw:{n} leases"),
        }
    }
}

/// What has to change at the proxy.
///
/// **Removals go first when these are carried out.** At the per-Endpoint grant
/// quota, a pass that drops one pair and adds another would take `429` on the
/// create although the delete just behind it frees the slot — leaving the new
/// grant missing until something else happens to trigger another pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Changes {
    /// Create or refresh these.
    pub create: Vec<Wanted>,
    /// Already covered by a grant that was here first — nothing to do.
    ///
    /// **Not merged into `create`.** Touching one would rewrite its TTL and
    /// label, and an operator's indefinite grant would acquire an expiry.
    pub served: Vec<Wanted>,
    /// Remove these, by pair and grant id. **Do these first.**
    pub remove: Vec<(GrantKey, String)>,
    /// Rows that could not be turned into a grant, and why.
    pub refused: Vec<(String, Refusal)>,
}

/// What the proxy would have to do to match `table`.
///
/// **Nothing is done here.** The caller performs the changes and reports back
/// what succeeded, so a failure cannot leave the ledger claiming a grant that
/// was never made.
///
/// A free function rather than a method on [`Ledger`]: the ledger lives in
/// `isekai-p2p` and knows nothing of a policy table, which is the split that
/// lets anything else creating grants reuse it.
pub fn plan(ledger: &Ledger, table: &Table, now: OffsetDateTime) -> Changes {
    let mut wanted: BTreeMap<GrantKey, Wanted> = BTreeMap::new();
    let mut refused = Vec::new();

    for entry in table.entries() {
        let ttl = match entry.grant_ttl(now) {
            Ok(ttl) => ttl,
            Err(why) => {
                refused.push((entry.access_lease_id.clone(), why));
                continue;
            }
        };
        let (endpoint, protocol) = entry.grant_key();
        let key = (endpoint.to_owned(), protocol.to_owned());
        let slot = wanted.entry(key).or_insert_with(|| Wanted {
            allowed_endpoint: endpoint.to_owned(),
            protocol: protocol.to_owned(),
            ttl,
            leases: BTreeSet::new(),
        });
        // **The shortest wins.** Two leases on one pair share a grant, and it
        // must not outlive the one that ends first.
        slot.ttl = slot.ttl.min(ttl);
        slot.leases.insert(entry.access_lease_id.clone());
    }

    let remove = ledger
        .ours()
        .filter(|(key, _)| !wanted.contains_key(*key))
        .map(|(key, id)| (key.clone(), id.clone()))
        .collect();

    // **A pair the operator already covers is not created either.** Re-creating
    // is an upsert: it would write *our* TTL and label onto their grant, so an
    // indefinite one they made would acquire an expiry and then die when the
    // lease stopped refreshing it. That destroys it more completely than the
    // revocation the ledger already refuses, and silently. Their grant permits
    // the connection already, so there is nothing this pass needs to add.
    let (served, create): (Vec<_>, Vec<_>) = wanted
        .into_values()
        .partition(|w| ledger.is_operators(&w.key()));

    Changes {
        create,
        served,
        remove,
        refused,
    }
}

/// [`plan`] against the clock now.
pub fn plan_now(ledger: &Ledger, table: &Table) -> Changes {
    plan(ledger, table, OffsetDateTime::now_utc())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::table::tests_support::*;

    #[test]
    fn a_lease_asks_for_a_grant() {
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = plan_now(&Ledger::new(), &table);
        assert_eq!(changes.create.len(), 1);
        assert_eq!(changes.create[0].allowed_endpoint, "ep:a7");
        assert!(changes.create[0].ttl < 1800);
        assert!(changes.remove.is_empty());
    }

    #[test]
    fn two_leases_on_one_pair_are_one_grant() {
        // **The case the draft calls normal**, and the one a ledger keyed by
        // lease would get wrong.
        let table = table_with(&[
            ("al_1", "ep:a7", "pg-sales-ro-v1", 1800),
            ("al_2", "ep:a7", "pg-sales-ro-v1", 1800),
        ]);
        let changes = plan_now(&Ledger::new(), &table);
        assert_eq!(changes.create.len(), 1, "{:?}", changes.create);
        assert_eq!(changes.create[0].leases.len(), 2);
    }

    #[test]
    fn a_shared_grant_takes_the_shorter_lease() {
        // It must not outlive the lease that ends first.
        let table = table_with(&[
            ("al_1", "ep:a7", "pg-sales-ro-v1", 1800),
            ("al_2", "ep:a7", "pg-sales-ro-v1", 600),
        ]);
        let changes = plan_now(&Ledger::new(), &table);
        assert!(changes.create[0].ttl < 600, "{:?}", changes.create[0]);
    }

    #[test]
    fn a_grant_goes_when_the_last_lease_wanting_it_goes() {
        let mut ledger = Ledger::new();
        let both = table_with(&[
            ("al_1", "ep:a7", "pg-sales-ro-v1", 1800),
            ("al_2", "ep:a7", "pg-sales-ro-v1", 1800),
        ]);
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.made(key.clone(), "gr_1".to_owned());

        // One lease left: the grant stays.
        let one = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        assert!(plan_now(&ledger, &one).remove.is_empty());
        assert!(plan_now(&ledger, &both).remove.is_empty());

        // None left: now it goes.
        let none = table_with(&[]);
        assert_eq!(
            plan_now(&ledger, &none).remove,
            vec![(key, "gr_1".to_owned())]
        );
    }

    #[test]
    fn a_grant_this_process_did_not_make_is_left_alone() {
        // **The operator's own.** It is indistinguishable from ours at the
        // proxy, so the rule is "only remove what we created" -- and an empty
        // ledger, which is what a restart leaves, removes nothing at all.
        let ledger = Ledger::new();
        assert!(plan_now(&ledger, &table_with(&[])).remove.is_empty());
    }

    #[test]
    fn a_lease_too_short_to_serve_is_reported_rather_than_skipped() {
        // Silently making no grant would look identical to making one.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 30)]);
        let changes = plan_now(&Ledger::new(), &table);
        assert!(changes.create.is_empty());
        assert_eq!(changes.refused.len(), 1);
        assert!(matches!(
            changes.refused[0].1,
            Refusal::LeaseTooShort { .. }
        ));
    }

    #[test]
    fn a_pair_the_operator_already_had_is_served_but_never_removed() {
        // **The accident the ledger exists to prevent, and counting alone does
        // not.** Creating a grant for a pair that already has one is an update
        // answering with the operator's id, so adopting it means revoking their
        // grant when the last lease ends.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.note_existing(key.clone());
        assert!(ledger.is_operators(&key));

        // It is served by the grant that is already there -- and **not
        // re-created**, since that would upsert our TTL onto it.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = plan_now(&ledger, &table);
        assert!(changes.create.is_empty(), "{:?}", changes.create);
        assert_eq!(changes.served.len(), 1);

        // ...and when every lease goes, nothing is removed, because the ledger
        // never recorded it as ours.
        assert!(plan_now(&ledger, &table_with(&[])).remove.is_empty());
    }

    #[test]
    fn creating_over_an_operators_grant_does_not_adopt_it() {
        // **The path the server actually takes**, which the previous test did
        // not: mark the pair, serve it, record what the proxy answered. The
        // proxy returns the operator's own id for an existing pair, so
        // recording it would put their grant in `remove` the moment the last
        // lease ended.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.note_existing(key.clone());

        assert!(
            !ledger.made(key.clone(), "gr_theirs".to_owned()),
            "the operator's grant was adopted",
        );
        assert!(plan_now(&ledger, &table_with(&[])).remove.is_empty());
        // And it is not offered for creation either, which is the stronger
        // guarantee: an upsert would rewrite its TTL.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        assert!(plan_now(&ledger, &table).create.is_empty());
    }

    #[test]
    fn our_own_grant_does_not_become_the_operators_on_the_next_pass() {
        // A grant this process made appears in the proxy's list like any other,
        // so re-reading that list must not turn it into something we may never
        // remove.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        assert!(ledger.made(key.clone(), "gr_ours".to_owned()));

        assert!(!ledger.note_existing(key.clone()), "ours was marked theirs");
        assert_eq!(
            plan_now(&ledger, &table_with(&[])).remove,
            vec![(key, "gr_ours".to_owned())],
        );
    }

    #[test]
    fn a_withdrawn_lease_takes_its_grant_with_it() {
        // **The order draft §7.2 fixes**, expressed as a property of the two
        // steps rather than of the code between them: once the table no longer
        // holds the lease, the plan says to remove the grant. Reversed -- grant
        // first -- there would be a moment with a live table row and no grant,
        // and the habit is what matters once enforcement exists.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.made(key.clone(), "gr_1".to_owned());

        let mut table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        assert!(
            plan_now(&ledger, &table).remove.is_empty(),
            "removed too soon"
        );

        // What `policy.revoked` does to the table, and only then the plan.
        assert!(table.withdraw("al_1", 2));
        assert_eq!(
            plan_now(&ledger, &table).remove,
            vec![(key, "gr_1".to_owned())],
        );
    }

    #[test]
    fn a_revocation_for_something_never_held_changes_nothing() {
        // The stream can carry one for a lease this Gateway never applied --
        // refused on its attributes, say. It must not disturb what is held.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.made(key, "gr_1".to_owned());
        let mut table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);

        assert!(!table.withdraw("al_never", 9));
        assert!(plan_now(&ledger, &table).remove.is_empty());
        assert_eq!(plan_now(&ledger, &table).create.len(), 1);
    }

    #[test]
    fn an_operators_grant_is_never_written_to() {
        // **The failure this closes is worse than the one it was guarding
        // against.** Re-creating is an upsert, so an indefinite grant an
        // operator made would take on our TTL and then expire when the lease
        // stopped refreshing it -- destroyed rather than merely revoked, and
        // without a line saying so.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.note_existing(key);

        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = plan_now(&ledger, &table);
        assert!(changes.create.is_empty(), "their grant would be rewritten");
        assert_eq!(
            changes.served.len(),
            1,
            "and the policy still counts as met"
        );
    }

    #[test]
    fn a_mark_does_not_outlive_the_grant_it_described() {
        // Insert-only was a trap: the operator deletes their grant, a lease
        // later arrives, and a grant that really is ours could never be
        // recorded -- so `plan` could never remove it either.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        ledger.note_existing(key.clone());

        // A listing that no longer shows it.
        assert_eq!(ledger.prune_theirs(&BTreeSet::new()), 1);
        assert!(!ledger.is_operators(&key));
        assert!(ledger.made(key.clone(), "gr_ours".to_owned()));
        assert_eq!(
            plan_now(&ledger, &table_with(&[])).remove,
            vec![(key, "gr_ours".to_owned())],
        );
    }

    #[test]
    fn the_label_says_where_the_grant_came_from() {
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = plan_now(&Ledger::new(), &table);
        assert_eq!(changes.create[0].label(), "gw:al_1");
    }
}
