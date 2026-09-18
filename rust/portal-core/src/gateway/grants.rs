//! Which grants this Gateway made, and which it must not touch.
//!
//! **P3 of `docs/portal_gateway_plan.md`.** The table says what the control
//! plane wants; this works out what has to change at the proxy to match, and —
//! more importantly — what has to be left alone.
//!
//! # A grant is keyed by the pair, not by the lease
//!
//! The proxy keys a grant on `(owner, allowed_endpoint, protocol)` and
//! re-creating one answers `200` with the same id. So **two leases for the same
//! pair are one grant**, which the draft calls the normal case for an agent
//! running two tasks. A ledger that assumed one grant per lease would delete a
//! grant the other lease still needs the moment either ended.
//!
//! Carrying the lease id in the grant's key is what would fix that properly,
//! and it needs a change at the proxy (draft §3.4.2, stage 6). Until then the
//! ledger counts: a grant goes when the last lease wanting it goes.
//!
//! # It only removes what it made
//!
//! An operator's hand-made grant for the same pair is indistinguishable from
//! ours — same `origin`, and the label is overwritten by any re-creation. So
//! the rule is not "recognise ours" but **"only remove what this process
//! created"**. On a restart the ledger is empty, so nothing is removed until it
//! has been created again, and a grant that is no longer wanted lapses on its
//! own TTL instead.
//!
//! That is the safe direction: **forgetting to remove costs a grant that
//! expires anyway; removing too much takes away an operator's own.**

use std::collections::{BTreeMap, BTreeSet};

use time::OffsetDateTime;

use super::{Refusal, Table};

/// A grant's identity at the proxy.
pub type GrantKey = (String, String);

/// What this process has created, and for whom.
#[derive(Debug, Clone, Default)]
pub struct Ledger {
    /// The grant id for each pair we made one for.
    made: BTreeMap<GrantKey, String>,
    /// Pairs that already had a grant before we touched them.
    ///
    /// Held separately because these are served and never removed — see
    /// [`adopted_from_operator`](Ledger::adopted_from_operator).
    theirs: BTreeSet<GrantKey>,
}

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
    /// Remove these, by pair and grant id. **Do these first.**
    pub remove: Vec<(GrantKey, String)>,
    /// Rows that could not be turned into a grant, and why.
    pub refused: Vec<(String, Refusal)>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.made.len()
    }

    pub fn is_empty(&self) -> bool {
        self.made.is_empty()
    }

    /// What the proxy would have to do to match `table`.
    ///
    /// **Nothing is done here.** The caller performs the changes and reports
    /// back what succeeded, so a failure cannot leave the ledger claiming a
    /// grant that was never made.
    pub fn plan(&self, table: &Table, now: OffsetDateTime) -> Changes {
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
            // **The shortest wins.** Two leases on one pair share a grant, and
            // it must not outlive the one that ends first.
            slot.ttl = slot.ttl.min(ttl);
            slot.leases.insert(entry.access_lease_id.clone());
        }

        let remove = self
            .made
            .iter()
            .filter(|(key, _)| !wanted.contains_key(*key))
            .map(|(key, id)| (key.clone(), id.clone()))
            .collect();

        Changes {
            create: wanted.into_values().collect(),
            remove,
            refused,
        }
    }

    /// [`plan`](Self::plan) against the clock now.
    pub fn plan_now(&self, table: &Table) -> Changes {
        self.plan(table, OffsetDateTime::now_utc())
    }

    /// Record a grant this process created.
    pub fn made(&mut self, key: GrantKey, grant_id: String) {
        self.made.insert(key, grant_id);
    }

    /// Note a pair that already had a grant when we first looked.
    ///
    /// **Creating a grant for an existing pair is an update, not a refusal.**
    /// The proxy answers `200` with the *operator's* grant id — so recording
    /// that as ours would adopt their grant, and the last lease ending would
    /// then revoke it. That is the accident the ledger exists to prevent, and
    /// counting alone does not prevent it.
    ///
    /// A pair marked here is served but never removed: the policy still gets
    /// its grant, and what the operator made stays theirs.
    pub fn adopted_from_operator(&mut self, key: GrantKey) {
        self.theirs.insert(key);
    }

    /// Whether this pair is one the operator already had.
    pub fn is_operators(&self, key: &GrantKey) -> bool {
        self.theirs.contains(key)
    }

    /// Forget one that was removed.
    ///
    /// **Only on success.** A delete that failed leaves the grant standing, and
    /// forgetting it here would mean never trying again — the grant would sit
    /// until its TTL with nothing tracking it.
    pub fn removed(&mut self, key: &GrantKey) {
        self.made.remove(key);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::table::tests_support::*;

    #[test]
    fn a_lease_asks_for_a_grant() {
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = Ledger::new().plan_now(&table);
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
        let changes = Ledger::new().plan_now(&table);
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
        let changes = Ledger::new().plan_now(&table);
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
        assert!(ledger.plan_now(&one).remove.is_empty());
        assert!(ledger.plan_now(&both).remove.is_empty());

        // None left: now it goes.
        let none = table_with(&[]);
        assert_eq!(
            ledger.plan_now(&none).remove,
            vec![(key, "gr_1".to_owned())]
        );
    }

    #[test]
    fn a_grant_this_process_did_not_make_is_left_alone() {
        // **The operator's own.** It is indistinguishable from ours at the
        // proxy, so the rule is "only remove what we created" -- and an empty
        // ledger, which is what a restart leaves, removes nothing at all.
        let ledger = Ledger::new();
        assert!(ledger.plan_now(&table_with(&[])).remove.is_empty());
    }

    #[test]
    fn a_lease_too_short_to_serve_is_reported_rather_than_skipped() {
        // Silently making no grant would look identical to making one.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 30)]);
        let changes = Ledger::new().plan_now(&table);
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
        ledger.adopted_from_operator(key.clone());
        assert!(ledger.is_operators(&key));

        // It is still served...
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        assert_eq!(ledger.plan_now(&table).create.len(), 1);

        // ...and when every lease goes, nothing is removed, because the ledger
        // never recorded it as ours.
        assert!(ledger.plan_now(&table_with(&[])).remove.is_empty());
    }

    #[test]
    fn the_label_says_where_the_grant_came_from() {
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = Ledger::new().plan_now(&table);
        assert_eq!(changes.create[0].label(), "gw:al_1");
    }
}
