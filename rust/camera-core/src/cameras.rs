//! The decisions every viewer makes the same way.
//!
//! Which rows to show, what to call them, and which instrument authorizes a
//! connect. Getting any of them wrong shows up as a row that will not connect,
//! one nobody recognises, or a capability carried where a grant was meant — and
//! each is the kind of thing that gets written twice and then diverges. They
//! live here so the desktop client and the iOS one cannot.

use isekai_p2p::agent::ReachableListener;

/// One row per camera, not per listener.
///
/// A grant is against the Endpoint, so the proxy answers with every listener
/// that Endpoint is running — and a camera that crashed without withdrawing its
/// listener runs two until the old lease ends, one of which cannot be connected
/// to. The operator has one camera and should be offered one entry; the live
/// one is the listener with the later deadline, since both were leased for the
/// same span and the survivor was leased later.
///
/// **That rests on two things being true, and the listing does not carry enough
/// to check either.**
///
/// - Every listener of one camera is created with the same TTL. Vary it and a
///   long-leased dead listener outranks a short-leased live one, leaving a row
///   that cannot connect. Anyone changing the TTL passed to
///   `ListenerSession::create` should come back here; the durable fix is a
///   `created_at` on `GET /v1/peer/listeners`, which the proxy does not return.
/// - `expires_at` is compared as a string, so the proxy has to keep formatting
///   it the way it does today — UTC, `Z`, whole seconds. An offset form or a
///   fractional part would sort by text in a way that is not time order, and
///   would do it quietly.
pub fn one_per_camera(mut listeners: Vec<ReachableListener>) -> Vec<ReachableListener> {
    // Latest deadline first, so the first row seen for an owner is the keeper.
    listeners.sort_by(|a, b| {
        b.expires_at
            .cmp(&a.expires_at)
            .then_with(|| a.listener_id.cmp(&b.listener_id))
    });
    let mut seen = std::collections::HashSet::new();
    listeners.retain(|l| seen.insert(l.owner_endpoint.clone()));
    listeners
}

/// Whether a connect should use a standing grant rather than a capability.
///
/// An empty capability is not a missing value to complain about: it is how a
/// caller says "the proxy already holds the authorization" (spec §8.4). Blank
/// counts as empty, because the field is typed into by hand and a stray space
/// would otherwise send a capability of one space and be refused.
pub fn connects_on_grant(capability: &str) -> bool {
    capability.trim().is_empty()
}

/// What to call a camera on screen: the name its owner gave it, falling back to
/// the listener id, which is at least unambiguous.
pub fn display_name(camera: &ReachableListener) -> Option<&str> {
    camera
        .metadata
        .as_ref()
        .and_then(|m| m.get("label"))
        .and_then(|l| l.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn listener(id: &str, owner: &str, expires_at: &str) -> ReachableListener {
        ReachableListener {
            listener_id: id.to_owned(),
            owner_endpoint: owner.to_owned(),
            protocol: "mjpeg".to_owned(),
            metadata: None,
            expires_at: expires_at.to_owned(),
        }
    }

    /// A camera that restarted without withdrawing its old listener is still
    /// one camera. Offering both would mean half the rows do not connect.
    #[test]
    fn a_restarted_camera_is_one_row_and_it_is_the_live_one() {
        let rows = one_per_camera(vec![
            listener("pl_old", "ep:B", "2026-08-02T09:00:00Z"),
            listener("pl_new", "ep:B", "2026-08-02T10:00:00Z"),
            listener("pl_other", "ep:C", "2026-08-02T09:30:00Z"),
        ]);
        assert_eq!(
            rows.iter()
                .map(|l| l.listener_id.as_str())
                .collect::<Vec<_>>(),
            ["pl_new", "pl_other"],
            "the later deadline is the listener that is actually up"
        );
    }

    /// Two listeners leased in the same second must still resolve the same way
    /// on every refresh, or the selected camera moves under the operator.
    #[test]
    fn an_exact_tie_is_broken_the_same_way_every_time() {
        let same = "2026-08-02T10:00:00Z";
        let first = one_per_camera(vec![
            listener("pl_b", "ep:B", same),
            listener("pl_a", "ep:B", same),
        ]);
        let second = one_per_camera(vec![
            listener("pl_a", "ep:B", same),
            listener("pl_b", "ep:B", same),
        ]);
        assert_eq!(first[0].listener_id, "pl_a");
        assert_eq!(first[0].listener_id, second[0].listener_id);
    }

    /// The two clients have to agree on what an empty capability means, or one
    /// of them refuses a connect the other makes.
    #[test]
    fn a_blank_capability_means_connect_on_the_grant() {
        assert!(connects_on_grant(""));
        assert!(connects_on_grant("   "));
        assert!(!connects_on_grant("cap_abc"));
        assert!(!connects_on_grant("  cap_abc  "));
    }

    /// The label an owner gave a camera is what a person recognises; without
    /// one there is still the listener id, which at least identifies it.
    #[test]
    fn a_camera_is_named_by_its_label_when_it_has_one() {
        let mut named = listener("pl_1", "ep:B", "t");
        named.metadata = Some(serde_json::json!({ "label": "居間のカメラ" }));
        assert_eq!(display_name(&named), Some("居間のカメラ"));
        assert_eq!(display_name(&listener("pl_1", "ep:B", "t")), None);
    }
}
