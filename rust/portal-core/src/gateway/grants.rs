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

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use super::{Refusal, Table};

/// How old a freshly returned grant may be and still be one we just made.
///
/// Generous, because it covers a round trip and any clock skew between here and
/// the proxy — and being wrong in this direction costs a grant we decline to
/// track rather than one we delete.
struct ExistedBefore;
impl ExistedBefore {
    const WINDOW: time::Duration = time::Duration::seconds(30);
}

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
    /// [`note_existing`](Ledger::note_existing).
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

        // **A pair the operator already covers is not created either.**
        // Re-creating is an upsert: it would write *our* TTL and label onto
        // their grant, so an indefinite one they made would acquire an expiry
        // and then die when the lease stopped refreshing it. That destroys it
        // more completely than the revocation the ledger already refuses, and
        // silently. Their grant permits the connection already, so there is
        // nothing this pass needs to add.
        let (served, create): (Vec<_>, Vec<_>) = wanted
            .into_values()
            .partition(|w| self.theirs.contains(&w.key()));

        Changes {
            create,
            served,
            remove,
            refused,
        }
    }

    /// [`plan`](Self::plan) against the clock now.
    pub fn plan_now(&self, table: &Table) -> Changes {
        self.plan(table, OffsetDateTime::now_utc())
    }

    /// Record a grant this process created.
    ///
    /// **A pair the operator already had is not recorded**, whatever the proxy
    /// answered. Creating over an existing grant succeeds and returns *their*
    /// id, so a caller that recorded the result would adopt it — and this is
    /// the only place that can be stopped without every caller remembering to
    /// ask first.
    ///
    /// Returns whether it was recorded.
    pub fn made(&mut self, key: GrantKey, grant_id: String) -> bool {
        if self.theirs.contains(&key) {
            return false;
        }
        self.made.insert(key, grant_id);
        true
    }

    /// Record what a create answered, deciding from its age whether we made it.
    ///
    /// **The listing at the top of a pass can be a quarter of an hour old.** A
    /// grant the operator created after it is invisible to [`note_existing`],
    /// so the create upserts theirs and the ledger would claim it. The answer
    /// carries `created_at`, and the proxy leaves that untouched on an
    /// update — so a grant that reports being older than this call is one that
    /// was already there.
    ///
    /// A pair already recorded as ours keeps its record whatever the age says,
    /// since `created_at` is the *original* creation and ours will look old
    /// from the second pass onwards.
    pub fn record(&mut self, key: GrantKey, grant_id: String, created_at: Option<&str>) -> bool {
        if let std::collections::btree_map::Entry::Occupied(mut ours) = self.made.entry(key.clone())
        {
            ours.insert(grant_id);
            return true;
        }
        let existed_before = created_at
            .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok())
            .is_some_and(|at| OffsetDateTime::now_utc() - at > ExistedBefore::WINDOW);
        if existed_before {
            self.theirs.insert(key);
            return false;
        }
        self.made(key, grant_id)
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
    ///
    /// **A pair this process already made is not marked**, because it would
    /// otherwise become un-removable on the second pass: our own grant appears
    /// in the proxy's list like any other, and calling this on it would make it
    /// permanent.
    ///
    /// Returns whether it was marked.
    pub fn note_existing(&mut self, key: GrantKey) -> bool {
        if self.made.contains_key(&key) || self.theirs.contains(&key) {
            return false;
        }
        self.theirs.insert(key);
        true
    }

    /// Whether this pair is one the operator already had.
    pub fn is_operators(&self, key: &GrantKey) -> bool {
        self.theirs.contains(key)
    }

    /// Forget every pair the operator no longer has a grant for.
    ///
    /// **Insert-only was a trap.** If the operator deletes their grant, the
    /// mark would outlive it: a later lease for that pair would be refused a
    /// record, so `plan` could never remove what we then made, and the log
    /// would call it theirs when it was not.
    ///
    /// `present` is what a **successful** listing said. Nothing is pruned from
    /// a failed one — not knowing is not the same as their being none, which
    /// is the distinction that runs through all of this.
    pub fn prune_theirs(&mut self, present: &BTreeSet<GrantKey>) -> usize {
        let before = self.theirs.len();
        self.theirs.retain(|key| present.contains(key));
        before - self.theirs.len()
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
        ledger.note_existing(key.clone());
        assert!(ledger.is_operators(&key));

        // It is served by the grant that is already there -- and **not
        // re-created**, since that would upsert our TTL onto it.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = ledger.plan_now(&table);
        assert!(changes.create.is_empty(), "{:?}", changes.create);
        assert_eq!(changes.served.len(), 1);

        // ...and when every lease goes, nothing is removed, because the ledger
        // never recorded it as ours.
        assert!(ledger.plan_now(&table_with(&[])).remove.is_empty());
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
        assert!(ledger.plan_now(&table_with(&[])).remove.is_empty());
        // And it is not offered for creation either, which is the stronger
        // guarantee: an upsert would rewrite its TTL.
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        assert!(ledger.plan_now(&table).create.is_empty());
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
            ledger.plan_now(&table_with(&[])).remove,
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
            ledger.plan_now(&table).remove.is_empty(),
            "removed too soon"
        );

        // What `policy.revoked` does to the table, and only then the plan.
        assert!(table.withdraw("al_1", 2));
        assert_eq!(
            ledger.plan_now(&table).remove,
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
        assert!(ledger.plan_now(&table).remove.is_empty());
        assert_eq!(ledger.plan_now(&table).create.len(), 1);
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
        let changes = ledger.plan_now(&table);
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
            ledger.plan_now(&table_with(&[])).remove,
            vec![(key, "gr_ours".to_owned())],
        );
    }

    #[test]
    fn a_grant_that_answers_with_an_age_was_already_there() {
        // The listing at the top of a pass can be a quarter of an hour old, so
        // a grant the operator made since then is invisible to `note_existing`.
        // The proxy leaves `created_at` alone on an update, so the answer says.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(2))
            .format(&Rfc3339)
            .expect("formats");

        assert!(
            !ledger.record(key.clone(), "gr_theirs".to_owned(), Some(&old)),
            "an existing grant was claimed",
        );
        assert!(ledger.is_operators(&key));
    }

    #[test]
    fn a_grant_we_just_made_is_ours() {
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("formats");
        assert!(ledger.record(key.clone(), "gr_ours".to_owned(), Some(&now)));

        // And on a later pass its `created_at` is old -- the proxy keeps the
        // original -- which must not turn it into somebody else's.
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(2))
            .format(&Rfc3339)
            .expect("formats");
        assert!(ledger.record(key.clone(), "gr_ours".to_owned(), Some(&old)));
        assert!(!ledger.is_operators(&key));
    }

    #[test]
    fn the_label_says_where_the_grant_came_from() {
        let table = table_with(&[("al_1", "ep:a7", "pg-sales-ro-v1", 1800)]);
        let changes = Ledger::new().plan_now(&table);
        assert_eq!(changes.create[0].label(), "gw:al_1");
    }
}
