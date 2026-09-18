//! What the Gateway currently believes it has been told.
//!
//! **P1 of `docs/portal_gateway_plan.md`.** Rows arrive from Identity — from
//! `GET /v1/policies` when reconciling, and later from the stream — and this is
//! where they are checked against the operator's envelope
//! ([`crate::gateway::GatewayPolicy`]) and kept.
//!
//! Nothing is enforced here and no grant is made. What this buys today is that
//! the two checks stage 2 rests on — the attribute range and the window label —
//! run on every row, on the path that runs most often, before anything else is
//! built on top.
//!
//! # The order is fixed
//!
//! Validate, write the table, then create the grant (identity §8.10.4).
//! Reversed, it opens a window where the grant is live and no scope describes
//! it. The third step is a later phase; the first two are here, in that order,
//! so that adding the third is an addition rather than a repair.
//!
//! # Reconciliation is the correctness guarantee
//!
//! The stream is only fast. The table is rebuilt from a snapshot on the rule
//! **anything not in this list is dropped** — which is exactly why
//! [`Table::reconcile`] takes a snapshot rather than a `Result`, and why its
//! caller must not turn a failed read into an empty one.

use std::collections::BTreeMap;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use isekai_p2p::agent::{PolicyEvent, PolicySnapshot};

use super::{AttributeRefusal, GatewayPolicy};

/// One row the Gateway is holding to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub access_lease_id: String,
    pub decision_id: String,
    pub version: i64,
    /// The agent Endpoint this is about.
    pub allowed_endpoint: String,
    pub protocol: String,
    /// Seconds the lease had left when it was issued.
    pub ttl: Option<i64>,
    /// When the lease lapses, as the centre stated it.
    ///
    /// **Expiry never arrives as an event**, so this is the only way the row is
    /// ever dropped for age. Silence on the stream does not mean still valid.
    pub expires_at: Option<String>,
    pub attributes: BTreeMap<String, String>,
    pub window: Option<String>,
    pub max_concurrent: Option<u32>,
    pub grant_ttl: Option<u32>,
}

/// The shortest grant the proxy will make. Anything below is clamped up to it,
/// which is why a lease shorter than [`MIN_LEASE_SECS`] cannot be served.
pub const GRANT_TTL_FLOOR: u64 = 60;

/// How much shorter than its lease a grant is made.
///
/// **The grant must expire before the policy row does**, so that the window
/// where a grant is live and no policy describes it cannot open. Reconciliation
/// closes it too, but only on its own schedule.
pub const GRANT_TTL_MARGIN: i64 = 60;

/// The shortest lease that can be served at all.
///
/// `GRANT_TTL_FLOOR + GRANT_TTL_MARGIN`: below this there is no grant TTL both
/// shorter than the lease and above the proxy's floor.
pub const MIN_LEASE_SECS: i64 = GRANT_TTL_FLOOR as i64 + GRANT_TTL_MARGIN;

impl Entry {
    /// How long a grant for this row should live.
    ///
    /// **Shorter than the lease, always.** Identity says the Gateway makes the
    /// grant with a TTL below the policy's `ttl`; the centre's own
    /// `constraints.grant_ttl` is an upper bound on top of that, not a licence
    /// to exceed it.
    ///
    /// **Never `None`.** `create_grant` reads that as "until revoked", and a
    /// policy-driven grant that outlives every trace of its policy is the one
    /// thing this must not produce.
    pub fn grant_ttl(&self, now: OffsetDateTime) -> Result<u64, Refusal> {
        // **From the deadline, not from `ttl`.** `ttl` is what the lease had
        // left *when the row was issued*, and a grant is re-created on every
        // settle pass — which the proxy treats as an update, pushing the
        // deadline out by that stale figure each time. A grant so refreshed
        // walks past the lease it was derived from, which is the inversion this
        // whole rule exists to prevent.
        let lease = match self.remaining(now) {
            Some(left) => left,
            None => return Err(Refusal::NoDeadline),
        };
        if lease < MIN_LEASE_SECS {
            return Err(Refusal::LeaseTooShort { ttl: lease });
        }
        let under_lease = (lease - GRANT_TTL_MARGIN).max(GRANT_TTL_FLOOR as i64) as u64;
        let capped = match self.grant_ttl {
            Some(asked) => under_lease.min(u64::from(asked)),
            None => under_lease,
        };
        Ok(capped.max(GRANT_TTL_FLOOR))
    }

    /// Seconds of lease left at `now`, from the deadline the centre stated.
    ///
    /// `None` when there is no deadline to work from — `ttl` alone cannot say,
    /// because it was measured at some earlier instant nobody recorded.
    pub fn remaining(&self, now: OffsetDateTime) -> Option<i64> {
        let text = self.expires_at.as_deref()?;
        let at = OffsetDateTime::parse(text, &Rfc3339).ok()?;
        Some((at - now).whole_seconds())
    }

    /// What a grant for this row is keyed by, at the proxy.
    ///
    /// **Not the lease.** The proxy keys a grant on
    /// `(owner, allowed_endpoint, protocol)`, so two leases for the same pair
    /// are one grant — which is why the ledger counts leases per pair rather
    /// than assuming one each.
    pub fn grant_key(&self) -> (&str, &str) {
        (&self.allowed_endpoint, &self.protocol)
    }
}

/// Why a row was not applied.
///
/// **Refusals are values rather than logs**, because the count of them is the
/// number an operator needs before enforcement is switched on: a policy the
/// centre believes is in force and the Gateway has refused is a disagreement,
/// not a detail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
    /// This Gateway serves no such class.
    UnknownProtocol { protocol: String },
    /// The window label is not one this Gateway understands.
    ///
    /// **Not "ignore the label and apply the row".** That is the failure
    /// Identity's spec names outright: it turns a window into round-the-clock
    /// access.
    UnknownWindow { window: String },
    /// An attribute is missing, undeclared, or outside its range.
    Attribute(AttributeRefusal),
    /// There is no deadline to bound a grant by.
    ///
    /// **Not "too short".** `ttl` alone was measured at an instant nobody
    /// recorded, so it cannot say how long is left; saying "a lease of 0s"
    /// would name an invented cause for a row that may carry a perfectly good
    /// `expires_at` this could not read.
    NoDeadline,
    /// The lease is too short for a grant to be made that outlives it.
    ///
    /// The proxy clamps a grant's TTL to at least 60 seconds, so a lease
    /// shorter than [`MIN_LEASE_SECS`] cannot be given a grant that expires
    /// first — and a grant outliving the row that asked for it inverts the
    /// direction the whole design leans.
    LeaseTooShort { ttl: i64 },
    /// A `version` older than one already seen.
    ///
    /// Keyed on `access_lease_id`, because `version` is a per-lease sequence.
    /// **Equal is not stale** — a snapshot repeats what is in force, so the same
    /// row arriving again is the normal case rather than a replay.
    Stale { seen: i64 },
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownProtocol { protocol } => {
                write!(f, "this gateway serves no protocol `{protocol}`")
            }
            Self::UnknownWindow { window } => {
                write!(f, "window `{window}` is not one this gateway understands")
            }
            Self::Attribute(inner) => write!(f, "{inner}"),
            Self::NoDeadline => write!(
                f,
                "no `expires_at` to bound a grant by; `ttl` alone cannot say how \
                 much is left",
            ),
            Self::LeaseTooShort { ttl } => write!(
                f,
                "a lease of {ttl}s is too short: a grant cannot be clamped below \
                 {GRANT_TTL_FLOOR}s, so it would outlive the policy",
            ),
            Self::Stale { seen } => write!(f, "version is older than {seen}"),
        }
    }
}

/// What a reconciliation did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Outcome {
    /// Rows now held.
    pub applied: usize,
    /// Rows the snapshot carried that were refused, and why.
    pub refused: Vec<(String, Refusal)>,
    /// Rows that were held before and are not in the snapshot.
    pub dropped: usize,
}

/// The rows this Gateway is holding, keyed by lease.
#[derive(Debug, Clone, Default)]
pub struct Table {
    entries: BTreeMap<String, Entry>,
    /// The highest `version` seen per lease, kept across a drop so a replay
    /// cannot reinstate an old row.
    ///
    /// **Survives the entry itself.** A lease that was revoked and whose old
    /// `policy.granted` is then replayed would otherwise be applied again.
    seen: BTreeMap<String, i64>,
}

impl Table {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Every row currently held.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// What each Endpoint is allowed, for matching an arriving connection.
    ///
    /// **The smallest `max_concurrent` among that Endpoint's leases**, because
    /// two policies covering one agent do not add up to permission for more —
    /// the tighter one is a limit the looser one does not lift.
    ///
    /// `None` against a name means the leases set no limit. An Endpoint absent
    /// from the map has no policy here at all, which is a different answer
    /// again and the one that will be refused once enforcement exists.
    ///
    /// # Two things this is coarser than the table
    ///
    /// **Keyed on the Endpoint alone, though rows are per
    /// `(endpoint, protocol)`.** A connection notification names the peer and
    /// not the protocol, so that is all there is to match on — which means a
    /// tight limit on one class caps another class's connections too. Erring
    /// tight is the right direction while nothing is enforced, and the
    /// enforcement phase will need the protocol carried through to do better.
    ///
    /// **And it counts rows that have lapsed but not yet been swept**, up to
    /// the sweep interval. The same direction: a moment of saying "covered"
    /// about something just expired, rather than of refusing something live.
    pub fn limits(&self) -> BTreeMap<String, Option<u32>> {
        let mut out: BTreeMap<String, Option<u32>> = BTreeMap::new();
        for entry in self.entries.values() {
            match out.entry(entry.allowed_endpoint.clone()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(entry.max_concurrent);
                }
                std::collections::btree_map::Entry::Occupied(mut slot) => {
                    let tighter = match (*slot.get(), entry.max_concurrent) {
                        (Some(a), Some(b)) => Some(a.min(b)),
                        // One lease setting no limit does not lift another's.
                        (Some(a), None) => Some(a),
                        (None, Some(b)) => Some(b),
                        (None, None) => None,
                    };
                    slot.insert(tighter);
                }
            }
        }
        out
    }

    /// What is held for `allowed_endpoint`, which is what a connection is
    /// matched against.
    pub fn for_endpoint<'a>(&'a self, endpoint: &'a str) -> impl Iterator<Item = &'a Entry> {
        self.entries
            .values()
            .filter(move |e| e.allowed_endpoint == endpoint)
    }

    /// Rebuild from a snapshot: **anything not in it is dropped.**
    ///
    /// **The caller must not hand an empty snapshot in place of a failed read.**
    /// Identity's spec says so by name — an empty list is an instruction to drop
    /// everything, so representing "could not read" that way deletes a live
    /// policy over one bad moment. The signature takes a `PolicySnapshot` rather
    /// than a `Result` so that turning an error into one is a thing a caller has
    /// to write on purpose.
    pub fn reconcile(&mut self, snapshot: &PolicySnapshot, policy: &GatewayPolicy) -> Outcome {
        let mut next = BTreeMap::new();
        let mut refused = Vec::new();

        for event in &snapshot.items {
            // A snapshot is what is *in force*; a revocation in it is the
            // centre saying the lease is over, which is the same as absence.
            if !event.is_granted() {
                continue;
            }
            match self.check(event, policy) {
                Ok(entry) => {
                    self.remember(event);
                    next.insert(entry.access_lease_id.clone(), entry);
                }
                Err(why) => refused.push((event.access_lease_id.clone(), why)),
            }
        }

        let dropped = self
            .entries
            .keys()
            .filter(|id| !next.contains_key(*id))
            .count();
        self.entries = next;
        Outcome {
            applied: self.entries.len(),
            refused,
            dropped,
        }
    }

    /// Check one row against the operator's envelope.
    ///
    /// **Shared by reconciliation and (later) the stream.** Reconciliation runs
    /// on every restart and at least once per token lifetime, so it is the
    /// busier path; validating in one and not the other would let the common
    /// route be the unchecked one.
    pub fn check(&self, event: &PolicyEvent, policy: &GatewayPolicy) -> Result<Entry, Refusal> {
        // **Strictly older, not "no newer".** Reconciling runs at startup and
        // once per token lifetime against whatever is still in force, so the
        // same row arrives again with the same version as a matter of course.
        // Refusing an equal version made the second reconcile of an unchanged
        // snapshot drop every policy it had just applied -- and at P3 that is a
        // routine re-read revoking every live grant.
        if let Some(seen) = self.seen.get(&event.access_lease_id) {
            if event.version < *seen {
                return Err(Refusal::Stale { seen: *seen });
            }
        }

        let class = policy
            .protocol(&event.protocol)
            .ok_or_else(|| Refusal::UnknownProtocol {
                protocol: event.protocol.clone(),
            })?;

        let window = event.constraints.as_ref().and_then(|c| c.window.as_deref());
        if !class.accepts_window(window) {
            return Err(Refusal::UnknownWindow {
                window: window.unwrap_or_default().to_owned(),
            });
        }

        let attributes = event.attributes.clone().unwrap_or_default();
        class
            .accepts_attributes(&attributes)
            .map_err(Refusal::Attribute)?;

        let constraints = event.constraints.as_ref();
        Ok(Entry {
            access_lease_id: event.access_lease_id.clone(),
            decision_id: event.decision_id.clone(),
            version: event.version,
            allowed_endpoint: event.allowed_endpoint.clone(),
            protocol: event.protocol.clone(),
            ttl: event.ttl,
            expires_at: event.expires_at.clone(),
            attributes,
            window: window.map(str::to_owned),
            max_concurrent: constraints.and_then(|c| c.max_concurrent),
            grant_ttl: constraints.and_then(|c| c.grant_ttl),
        })
    }

    /// Apply one row, as the stream will.
    ///
    /// **The counterpart to [`check`](Self::check) being public.** Factoring the
    /// validation out for P2 is pointless if the stream has no way to write the
    /// result, and advancing the high-water mark is part of applying a row
    /// rather than of checking it.
    pub fn apply(&mut self, event: &PolicyEvent, policy: &GatewayPolicy) -> Result<(), Refusal> {
        let entry = self.check(event, policy)?;
        self.remember(event);
        self.entries.insert(entry.access_lease_id.clone(), entry);
        Ok(())
    }

    /// Drop every row whose lease has run out, by this host's clock.
    ///
    /// **The only way expiry is ever detected.** Identity does not stream it —
    /// a lease that simply runs out writes no row, so no `policy.revoked`
    /// appears. A subscriber waiting to be told waits forever, and the rows it
    /// is holding are ones the centre stopped counting on long ago.
    ///
    /// Rows with no `expires_at` are kept: the centre did not say when, and
    /// inventing a deadline for it would drop a live policy on a guess. The
    /// reconciliation is what catches those.
    pub fn expire(&mut self, now: OffsetDateTime) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| match &entry.expires_at {
            Some(text) => match OffsetDateTime::parse(text, &Rfc3339) {
                Ok(at) => at > now,
                // Unparseable is kept rather than dropped. It is the centre's
                // field and this is not the place to decide a policy is over
                // because a timestamp could not be read; reconciliation settles
                // it within the token lifetime either way.
                Err(_) => true,
            },
            None => true,
        });
        before - self.entries.len()
    }

    /// [`expire`](Self::expire) against the clock now.
    ///
    /// The deadline is a parameter on `expire` so tests need not wait; callers
    /// want this one.
    pub fn expire_now(&mut self) -> usize {
        self.expire(OffsetDateTime::now_utc())
    }

    /// Drop one row, as a `policy.revoked` on the stream will.
    ///
    /// `version` is the revocation's own, and it **advances the high-water
    /// mark**. Without that, a `policy.granted v4` re-delivered after a
    /// `policy.revoked v5` is not older than anything remembered — the mark
    /// still said 4 — so the row came back. Re-delivery is exactly what the
    /// rollback rule is for.
    pub fn withdraw(&mut self, access_lease_id: &str, version: i64) -> bool {
        let seen = self.seen.entry(access_lease_id.to_owned()).or_default();
        *seen = (*seen).max(version);
        self.entries.remove(access_lease_id).is_some()
    }

    fn remember(&mut self, event: &PolicyEvent) {
        let seen = self.seen.entry(event.access_lease_id.clone()).or_default();
        *seen = (*seen).max(event.version);
    }
}

/// Fixtures shared with `grants`'s tests.
#[cfg(test)]
pub(crate) mod tests_support {
    use super::*;
    use isekai_p2p::agent::PolicyConstraints;

    pub fn policy() -> GatewayPolicy {
        crate::gateway::parse(crate::gateway::EXAMPLE).expect("the example parses")
    }

    pub fn granted(lease: &str, version: i64) -> PolicyEvent {
        PolicyEvent {
            kind: "policy.granted".into(),
            access_lease_id: lease.into(),
            decision_id: "dec_1".into(),
            version,
            allowed_endpoint: "ep:a7".into(),
            protocol: "pg-sales-ro-v1".into(),
            ttl: Some(1800),
            expires_at: Some("2026-09-17T09:30:00Z".into()),
            attributes: Some(BTreeMap::from([("region".into(), "kanto".into())])),
            constraints: Some(PolicyConstraints {
                grant_ttl: Some(3600),
                max_concurrent: Some(2),
                window: Some("business_hours".into()),
            }),
            reason: None,
        }
    }

    /// A table holding one row per `(lease, endpoint, protocol, ttl)`.
    pub fn table_with(rows: &[(&str, &str, &str, i64)]) -> Table {
        let mut table = Table::new();
        for (lease, endpoint, protocol, ttl) in rows {
            let mut event = granted(lease, 1);
            event.allowed_endpoint = (*endpoint).to_owned();
            event.protocol = (*protocol).to_owned();
            event.ttl = Some(*ttl);
            // A deadline that matches the lease, since `grant_ttl` reads the
            // deadline rather than the seconds-at-issue.
            event.expires_at = Some(
                (OffsetDateTime::now_utc() + time::Duration::seconds(*ttl))
                    .format(&Rfc3339)
                    .expect("formats"),
            );
            // The fixtures ask for a grant longer than the lease on purpose, so
            // that the lease is what bounds it.
            event.constraints.as_mut().unwrap().grant_ttl = Some(86_400);
            // A short lease is refused by `grant_ttl`, not by `apply`, so it
            // still belongs in the table.
            let _ = table.apply(&event, &policy());
        }
        table
    }
}

#[cfg(test)]
mod tests {
    use super::tests_support::{granted, policy};
    use super::*;

    fn snapshot(items: Vec<PolicyEvent>) -> PolicySnapshot {
        PolicySnapshot {
            gateway: "ep:r1".into(),
            cursor: 12,
            items,
        }
    }

    #[test]
    fn a_row_inside_the_envelope_is_held() {
        let mut table = Table::new();
        let out = table.reconcile(&snapshot(vec![granted("al_1", 1)]), &policy());
        assert_eq!(out.applied, 1);
        assert!(out.refused.is_empty(), "{:?}", out.refused);
        let entry = table.entries().next().unwrap();
        assert_eq!(entry.allowed_endpoint, "ep:a7");
        assert_eq!(entry.window.as_deref(), Some("business_hours"));
        assert_eq!(entry.max_concurrent, Some(2));
    }

    #[test]
    fn an_unknown_window_refuses_the_row() {
        // **The failure Identity's spec names outright.** Applying the row and
        // ignoring the label is round-the-clock access for a policy written to
        // be office hours.
        let mut event = granted("al_1", 1);
        event.constraints.as_mut().unwrap().window = Some("after_hours".into());
        let mut table = Table::new();
        let out = table.reconcile(&snapshot(vec![event]), &policy());
        assert_eq!(out.applied, 0);
        assert!(matches!(out.refused[0].1, Refusal::UnknownWindow { .. }));
    }

    #[test]
    fn an_attribute_outside_its_range_refuses_the_row() {
        // The centre choosing a value the operator did not offer, which is the
        // one thing the envelope exists to stop.
        let mut event = granted("al_1", 1);
        event.attributes = Some(BTreeMap::from([("region".into(), "*".into())]));
        let mut table = Table::new();
        let out = table.reconcile(&snapshot(vec![event]), &policy());
        assert_eq!(out.applied, 0);
        assert!(matches!(out.refused[0].1, Refusal::Attribute(_)));
    }

    #[test]
    fn a_class_this_gateway_does_not_serve_refuses_the_row() {
        let mut event = granted("al_1", 1);
        event.protocol = "pg-payroll-rw-v1".into();
        let mut table = Table::new();
        let out = table.reconcile(&snapshot(vec![event]), &policy());
        assert_eq!(out.applied, 0);
        assert!(matches!(out.refused[0].1, Refusal::UnknownProtocol { .. }));
    }

    #[test]
    fn anything_not_in_the_snapshot_is_dropped() {
        // The rule that makes reconciliation the correctness guarantee.
        let mut table = Table::new();
        table.reconcile(
            &snapshot(vec![granted("al_1", 1), granted("al_2", 1)]),
            &policy(),
        );
        assert_eq!(table.len(), 2);

        let out = table.reconcile(&snapshot(vec![granted("al_1", 2)]), &policy());
        assert_eq!(out.applied, 1);
        assert_eq!(out.dropped, 1);
        assert_eq!(table.entries().next().unwrap().access_lease_id, "al_1");
    }

    #[test]
    fn an_empty_snapshot_drops_everything() {
        // **It is an instruction, and this pins that reading.** Which is also
        // why a caller must never render a failed read as one -- the table has
        // no way to tell the difference, so the distinction has to be kept
        // above it.
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 1)]), &policy());
        let out = table.reconcile(&snapshot(vec![]), &policy());
        assert_eq!(out.applied, 0);
        assert_eq!(out.dropped, 1);
        assert!(table.is_empty());
    }

    #[test]
    fn an_older_version_of_a_lease_is_refused() {
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 5)]), &policy());
        let out = table.reconcile(&snapshot(vec![granted("al_1", 4)]), &policy());
        assert_eq!(out.applied, 0);
        assert!(matches!(out.refused[0].1, Refusal::Stale { seen: 5 }));
    }

    #[test]
    fn reconciling_an_unchanged_snapshot_changes_nothing() {
        // **The regression.** Refusing an equal version made the second
        // reconcile drop everything the first had applied -- and this runs at
        // startup and once per token lifetime, so at P3 it would be a routine
        // re-read revoking every live grant.
        let mut table = Table::new();
        let snap = snapshot(vec![granted("al_1", 1)]);
        let first = table.reconcile(&snap, &policy());
        let second = table.reconcile(&snap, &policy());
        assert_eq!(first, second, "a second look changed the answer");
        assert_eq!(second.applied, 1);
        assert_eq!(second.dropped, 0);
        assert!(second.refused.is_empty(), "{:?}", second.refused);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn an_older_version_cannot_reinstate_a_dropped_lease() {
        // The high-water mark outlives the entry on purpose: a lease that went
        // away and whose *older* grant is replayed must not come back. The same
        // version may -- a snapshot is authoritative about what is in force.
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 5)]), &policy());
        table.reconcile(&snapshot(vec![]), &policy());
        assert!(table.is_empty());

        let out = table.reconcile(&snapshot(vec![granted("al_1", 4)]), &policy());
        assert_eq!(out.applied, 0);
        assert!(matches!(out.refused[0].1, Refusal::Stale { seen: 5 }));

        let back = table.reconcile(&snapshot(vec![granted("al_1", 5)]), &policy());
        assert_eq!(back.applied, 1);
    }

    #[test]
    fn a_revocation_in_a_snapshot_is_simply_absence() {
        // A snapshot lists what is in force. A `policy.revoked` in one says the
        // lease is over, which the rebuild already expresses by leaving it out.
        let mut revoked = granted("al_1", 2);
        revoked.kind = "policy.revoked".into();
        revoked.reason = Some("entitlement-removed".into());

        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 1)]), &policy());
        let out = table.reconcile(&snapshot(vec![revoked]), &policy());
        assert_eq!(out.applied, 0);
        assert_eq!(out.dropped, 1);
        assert!(out.refused.is_empty(), "{:?}", out.refused);
    }

    fn at(text: &str) -> OffsetDateTime {
        OffsetDateTime::parse(text, &Rfc3339).expect("a timestamp")
    }

    #[test]
    fn a_lapsed_lease_is_dropped_by_our_own_clock() {
        // **The only way expiry is ever noticed.** Identity streams nothing
        // when a lease simply runs out, so a table that waited to be told would
        // hold it forever.
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 1)]), &policy());
        assert_eq!(table.len(), 1);

        assert_eq!(table.expire(at("2026-09-17T09:29:59Z")), 0, "dropped early");
        assert_eq!(table.expire(at("2026-09-17T09:30:01Z")), 1);
        assert!(table.is_empty());
    }

    #[test]
    fn a_row_with_no_deadline_is_kept() {
        // The centre did not say when, so there is nothing to have passed.
        let mut event = granted("al_1", 1);
        event.expires_at = None;
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![event]), &policy());
        assert_eq!(table.expire(at("2099-01-01T00:00:00Z")), 0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn a_deadline_that_cannot_be_read_is_kept() {
        // Dropping a live policy because a timestamp would not parse is a
        // decision this is not the place to make; reconciliation settles it.
        let mut event = granted("al_1", 1);
        event.expires_at = Some("not a timestamp".into());
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![event]), &policy());
        assert_eq!(table.expire(at("2099-01-01T00:00:00Z")), 0);
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn the_stream_can_apply_and_withdraw() {
        // What `check` being public is for: P2 writes through these.
        let mut table = Table::new();
        assert!(table.apply(&granted("al_1", 1), &policy()).is_ok());
        assert_eq!(table.len(), 1);

        // And the mark still advances, so a later older row is refused.
        assert!(matches!(
            table.apply(&granted("al_1", 0), &policy()),
            Err(Refusal::Stale { seen: 1 })
        ));

        assert!(table.withdraw("al_1", 2));
        assert!(!table.withdraw("al_1", 2));
        assert!(table.is_empty());
    }

    #[test]
    fn a_grant_redelivered_after_a_revocation_does_not_come_back() {
        // **Re-delivery is what the rollback rule is for.** The stream replays
        // nothing, but a reconnect can carry a row the other path already
        // withdrew, and the revocation's version is what makes the older grant
        // older than something.
        let mut table = Table::new();
        table.apply(&granted("al_1", 4), &policy()).unwrap();
        table.withdraw("al_1", 5);
        assert!(table.is_empty());

        assert!(matches!(
            table.apply(&granted("al_1", 4), &policy()),
            Err(Refusal::Stale { seen: 5 })
        ));
    }

    fn entry(ttl: Option<i64>, grant_ttl: Option<u32>) -> Entry {
        let mut event = granted("al_1", 1);
        event.ttl = ttl;
        event.expires_at = ttl.map(|t| {
            (OffsetDateTime::now_utc() + time::Duration::seconds(t))
                .format(&Rfc3339)
                .expect("formats")
        });
        event.constraints.as_mut().unwrap().grant_ttl = grant_ttl;
        let mut table = Table::new();
        table.apply(&event, &policy()).expect("inside the envelope");
        let entry = table.entries().next().unwrap().clone();
        entry
    }

    #[test]
    fn a_grant_expires_before_the_policy_that_asked_for_it() {
        // The direction the whole design leans: the grant goes first, so a
        // window where it is live and no policy describes it cannot open.
        let e = entry(Some(1800), None);
        let ttl = e.grant_ttl(OffsetDateTime::now_utc()).unwrap();
        // The property, not the arithmetic: the grant goes first, by at least
        // the margin. An exact number would pin the second the test ran in.
        assert!(ttl <= 1800 - GRANT_TTL_MARGIN as u64, "grant {ttl}s");
        assert!(ttl > 1800 - 2 * GRANT_TTL_MARGIN as u64, "grant {ttl}s");
    }

    #[test]
    fn the_centres_cap_is_an_upper_bound_and_not_a_licence() {
        // A shorter `grant_ttl` is honoured...
        assert_eq!(
            entry(Some(1800), Some(300))
                .grant_ttl(OffsetDateTime::now_utc())
                .unwrap(),
            300
        );
        // ...and a longer one does not let the grant outlive the lease.
        let ttl = entry(Some(1800), Some(86_400))
            .grant_ttl(OffsetDateTime::now_utc())
            .unwrap();
        assert!(
            ttl < 1800,
            "the centre talked the grant past its lease: {ttl}s"
        );
    }

    #[test]
    fn a_lease_too_short_to_serve_is_refused() {
        // **The proxy clamps a grant up to 60s**, so below this there is no TTL
        // both shorter than the lease and above that floor -- the grant would
        // outlive the policy, which is the inversion this refuses rather than
        // quietly accepts.
        for lease in [1, 59, 60, MIN_LEASE_SECS - 1] {
            assert!(
                matches!(
                    entry(Some(lease), None).grant_ttl(OffsetDateTime::now_utc()),
                    Err(Refusal::LeaseTooShort { .. })
                ),
                "a {lease}s lease was served"
            );
        }
        assert!(entry(Some(MIN_LEASE_SECS + 1), None)
            .grant_ttl(OffsetDateTime::now_utc())
            .is_ok());
    }

    #[test]
    fn a_row_with_no_deadline_gets_no_grant() {
        // `None` on `create_grant` means "until revoked". A policy-driven grant
        // that outlives every trace of its policy is the one thing this must
        // not make.
        assert!(matches!(
            entry(None, Some(3600)).grant_ttl(OffsetDateTime::now_utc()),
            Err(Refusal::NoDeadline)
        ));
    }

    #[test]
    fn a_refreshed_grant_cannot_walk_past_its_lease() {
        // **The regression.** A grant is re-created on every settle pass, which
        // the proxy treats as an update -- so a TTL taken from `ttl`, the
        // seconds left *when the row was issued*, pushed the deadline out again
        // each time until the grant outlived the lease it came from.
        let mut event = granted("al_1", 1);
        event.ttl = Some(1800);
        let deadline = OffsetDateTime::now_utc() + time::Duration::seconds(1800);
        event.expires_at = Some(deadline.format(&Rfc3339).expect("formats"));
        event.constraints.as_mut().unwrap().grant_ttl = None;

        let mut table = Table::new();
        table.apply(&event, &policy()).unwrap();
        let e = table.entries().next().unwrap();

        // Later in the lease, the same row asks for a proportionally shorter
        // grant rather than the full span over again.
        // 200s left: under the old rule this asked for 1740 all over again.
        let late = deadline - time::Duration::seconds(200);
        let ttl = e.grant_ttl(late).unwrap();
        assert!(
            ttl <= 200 - GRANT_TTL_MARGIN as u64,
            "with 200s of lease left the grant asked for {ttl}s",
        );
    }

    #[test]
    fn the_tighter_limit_is_the_one_that_holds() {
        // Two policies covering one agent do not add up to permission for more.
        let mut a = granted("al_1", 1);
        a.constraints.as_mut().unwrap().max_concurrent = Some(5);
        let mut b = granted("al_2", 1);
        b.constraints.as_mut().unwrap().max_concurrent = Some(2);

        let mut table = Table::new();
        table.apply(&a, &policy()).unwrap();
        table.apply(&b, &policy()).unwrap();
        assert_eq!(table.limits()["ep:a7"], Some(2));
    }

    #[test]
    fn a_lease_with_no_limit_does_not_lift_another() {
        let mut a = granted("al_1", 1);
        a.constraints.as_mut().unwrap().max_concurrent = Some(2);
        let mut b = granted("al_2", 1);
        b.constraints.as_mut().unwrap().max_concurrent = None;

        let mut table = Table::new();
        table.apply(&a, &policy()).unwrap();
        table.apply(&b, &policy()).unwrap();
        assert_eq!(table.limits()["ep:a7"], Some(2));
    }

    #[test]
    fn an_endpoint_with_no_policy_is_absent_rather_than_unlimited() {
        // Absent and "no limit" are different answers, and the first is the one
        // enforcement will refuse.
        let table = Table::new();
        assert!(!table.limits().contains_key("ep:a7"));
    }

    #[test]
    fn rows_are_findable_by_the_endpoint_a_connection_names() {
        let mut second = granted("al_2", 1);
        second.allowed_endpoint = "ep:b8".into();
        let mut table = Table::new();
        table.reconcile(&snapshot(vec![granted("al_1", 1), second]), &policy());
        assert_eq!(table.for_endpoint("ep:a7").count(), 1);
        assert_eq!(table.for_endpoint("ep:nobody").count(), 0);
    }
}
