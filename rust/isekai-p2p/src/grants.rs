//! Which grants this process made, and which it must not touch.
//!
//! Creating a grant is an upsert, and the answer to one cannot be taken at face
//! value. Anything that creates grants on a schedule needs this bookkeeping, so
//! it lives here rather than in whichever application happens to have needed it
//! first — `portal-core`'s Gateway, which still owns the part that decides
//! *which* grants a policy wants (`docs/portal_gateway_plan.md` P3).
//!
//! # A grant is keyed by the pair, not by the reason for it
//!
//! The proxy keys a grant on `(owner, allowed_endpoint, protocol)` and
//! re-creating one answers `200` with the same id. So **two reasons to want the
//! same pair are one grant**. A ledger that assumed one grant per reason would
//! delete a grant the other reason still needs the moment either ended.
//!
//! # It only removes what it made
//!
//! An operator's hand-made grant for the same pair is indistinguishable from
//! one of ours — same `origin`, and the label is overwritten by any
//! re-creation. So the rule is not "recognise ours" but **"only remove what
//! this process created"**. On a restart the ledger is empty, so nothing is
//! removed until it has been created again, and a grant that is no longer
//! wanted lapses on its own TTL instead.
//!
//! That is the safe direction: **forgetting to remove costs a grant that
//! expires anyway; removing too much takes away an operator's own.**

use std::collections::{BTreeMap, BTreeSet};

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::agent::Made;

/// How old a freshly returned grant may be and still be one we just made.
///
/// Generous, because it covers a round trip and any clock skew between here and
/// the proxy — and being wrong in this direction costs a grant we decline to
/// track rather than one we delete.
struct ExistedBefore;
impl ExistedBefore {
    const WINDOW: time::Duration = time::Duration::seconds(30);
}

/// Whether a create answered with a grant that was **already there**, from
/// everything the answer said.
///
/// **The two readings are not trusted equally, and the asymmetry is the
/// point.** Which success status this route uses is the proxy's to choose, and
/// nothing outside this workspace's own notes establishes that a fresh create
/// answers `201` — so:
///
/// * [`Made::Fresh`] **is** believed. A `201` cannot plausibly mean "already
///   there", and believing it fixes the case the age gets wrong in the
///   dangerous direction: a grant we just made whose round trip was slow looks
///   old, lands in `theirs`, and then nothing refreshes it — so the grant our
///   own create wrote a short TTL onto lapses, and whatever it served goes
///   unserved until a restart re-lists.
/// * [`Made::Existing`] is **not**. If the proxy answers `200` on a fresh
///   create too, believing it would put *every* grant this process makes into
///   `theirs` — same starvation, on every create rather than in a race. So it
///   defers to the age, which is what decided this before the status was kept.
/// * [`Made::Unknown`] defers for the same reason.
///
/// Promoting `Existing` to authoritative needs the control plane's fresh-create
/// status confirmed first.
pub fn existed_before(made: Made, created_at: Option<&str>) -> bool {
    match made {
        Made::Fresh => false,
        Made::Existing | Made::Unknown => already_existed(created_at),
    }
}

/// Whether the age of what came back says it was already there.
///
/// The fallback [`existed_before`] uses, and the answer on its own for a caller
/// that has no status to read. The proxy leaves `created_at` untouched on an
/// update, so a grant reporting itself older than this call is one that was
/// already there.
pub fn already_existed(created_at: Option<&str>) -> bool {
    created_at
        .and_then(|text| OffsetDateTime::parse(text, &Rfc3339).ok())
        .is_some_and(|at| OffsetDateTime::now_utc() - at > ExistedBefore::WINDOW)
}

/// A grant's identity at the proxy: the Endpoint being let in, and over what.
pub type GrantKey = (String, String);

/// What this process has created, and for whom.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ledger {
    /// Pairs this process created a grant for, and the id it was given.
    made: BTreeMap<GrantKey, String>,
    /// Pairs that already had a grant somebody else made.
    ///
    /// Held separately because these are served and never removed — see
    /// [`Ledger::note_existing`].
    theirs: BTreeSet<GrantKey>,
}

impl Ledger {
    pub fn new() -> Self {
        Self::default()
    }

    /// How many grants this process is tracking.
    pub fn len(&self) -> usize {
        self.made.len()
    }

    pub fn is_empty(&self) -> bool {
        self.made.is_empty()
    }

    /// The pairs this process made a grant for, and the ids.
    ///
    /// **For working out what to remove**, which is the one thing a caller
    /// cannot ask about pair by pair: it has to compare everything this made
    /// against everything it still wants. `portal-core`'s `plan` is the caller;
    /// deciding *which* grants are wanted is its business and not this
    /// module's, so what it needs from here is exposed rather than the decision
    /// being moved in.
    pub fn ours(&self) -> impl Iterator<Item = (&GrantKey, &String)> {
        self.made.iter()
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

    /// Record what a create answered, from what its status said — or, failing
    /// that, from how old it looks.
    ///
    /// **A listing taken at the top of a pass can be minutes old.** A grant the
    /// operator created after it is invisible to [`Self::note_existing`], so the
    /// create upserts theirs and the ledger would claim it.
    ///
    /// `made` is what the create's status said, read by [`existed_before`] —
    /// which believes a `201` and defers to the age of `created_at` otherwise,
    /// for the reasons recorded there.
    ///
    /// A pair already recorded as ours keeps its record whatever either says,
    /// since `created_at` is the *original* creation and ours will look old
    /// from the second pass onwards.
    pub fn record(
        &mut self,
        key: GrantKey,
        grant_id: String,
        made: Made,
        created_at: Option<&str>,
    ) -> bool {
        if let std::collections::btree_map::Entry::Occupied(mut ours) = self.made.entry(key.clone())
        {
            ours.insert(grant_id);
            return true;
        }
        if existed_before(made, created_at) {
            self.theirs.insert(key);
            return false;
        }
        self.made(key, grant_id)
    }

    /// Note a pair that already had a grant when we first looked.
    ///
    /// **Creating a grant for an existing pair is an update, not a refusal.**
    /// The proxy answers `200` with the *operator's* grant id — so recording
    /// that as ours would adopt their grant, and the last reason for it ending
    /// would then revoke it. That is the accident the ledger exists to prevent,
    /// and counting alone does not prevent it.
    ///
    /// A pair marked here is served but never removed: whatever wanted the
    /// grant still has one, and what the operator made stays theirs.
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
    /// mark would outlive it: a later reason to want that pair would be refused
    /// a record, so nothing could remove what we then made, and the log would
    /// call it theirs when it was not.
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

    /// The age fallback, for a proxy whose success status says nothing.
    #[test]
    fn a_grant_that_answers_with_an_age_was_already_there() {
        // A listing taken at the top of a pass can be minutes old, so a grant
        // the operator made since then is invisible to `note_existing`. The
        // proxy leaves `created_at` alone on an update, so the answer says.
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(2))
            .format(&Rfc3339)
            .expect("formats");

        assert!(
            !ledger.record(
                key.clone(),
                "gr_theirs".to_owned(),
                Made::Unknown,
                Some(&old)
            ),
            "an existing grant was claimed",
        );
        assert!(ledger.is_operators(&key));
    }

    #[test]
    fn a_grant_we_just_made_is_ours() {
        let mut ledger = Ledger::new();
        let key = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("formats");
        assert!(ledger.record(key.clone(), "gr_ours".to_owned(), Made::Unknown, Some(&now)));

        // And on a later pass its `created_at` is old -- the proxy keeps the
        // original -- which must not turn it into somebody else's.
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(2))
            .format(&Rfc3339)
            .expect("formats");
        assert!(ledger.record(key.clone(), "gr_ours".to_owned(), Made::Unknown, Some(&old)));
        assert!(!ledger.is_operators(&key));
    }

    /// **A `201` beats the age. A `200` does not.**
    ///
    /// The asymmetry is the whole policy, so it is pinned rather than left to
    /// the reader of [`existed_before`]: believing a `201` fixes the case the
    /// age gets wrong in the direction that starves a grant, and believing a
    /// `200` would risk starving every grant this process makes if the proxy
    /// turns out to answer `200` on a fresh create too.
    #[test]
    fn a_fresh_status_beats_the_age_and_an_existing_one_defers_to_it() {
        let old = (OffsetDateTime::now_utc() - time::Duration::hours(2))
            .format(&Rfc3339)
            .expect("formats");
        let now = OffsetDateTime::now_utc().format(&Rfc3339).expect("formats");

        // Looks old because the round trip was slow; the `201` says otherwise.
        let mut ledger = Ledger::new();
        let slow = ("ep:a7".to_owned(), "pg-sales-ro-v1".to_owned());
        assert!(
            ledger.record(slow.clone(), "gr_ours".to_owned(), Made::Fresh, Some(&old)),
            "a 201 says we made it, however old the timestamp looks",
        );
        assert!(!ledger.is_operators(&slow));

        // A `200` with a fresh timestamp reads as ours, exactly as it did
        // before the status was kept: the age still decides this one.
        let mut ledger = Ledger::new();
        let fresh = ("ep:b8".to_owned(), "pg-sales-ro-v1".to_owned());
        assert!(
            ledger.record(
                fresh.clone(),
                "gr_ours".to_owned(),
                Made::Existing,
                Some(&now)
            ),
            "a 200 defers to the age, which says this one is ours",
        );
        assert!(!ledger.is_operators(&fresh));

        // And with an old timestamp the two agree.
        let mut ledger = Ledger::new();
        let theirs = ("ep:c9".to_owned(), "pg-sales-ro-v1".to_owned());
        assert!(!ledger.record(
            theirs.clone(),
            "gr_theirs".to_owned(),
            Made::Existing,
            Some(&old)
        ));
        assert!(ledger.is_operators(&theirs));
    }

    /// **What `plan` needs, and only that.** Deciding which grants are wanted
    /// belongs to the caller; comparing that against what this made is the one
    /// thing it cannot do pair by pair.
    #[test]
    fn what_was_made_can_be_read_back() {
        let mut ledger = Ledger::new();
        ledger.made(("ep:a".to_owned(), "pg".to_owned()), "gr_1".to_owned());
        ledger.note_existing(("ep:b".to_owned(), "pg".to_owned()));

        let ours: Vec<_> = ledger
            .ours()
            .map(|(key, id)| (key.clone(), id.clone()))
            .collect();
        assert_eq!(
            ours,
            vec![(("ep:a".to_owned(), "pg".to_owned()), "gr_1".to_owned())],
            "the operator's pair is not ours to remove, so it is not here",
        );
    }
}
