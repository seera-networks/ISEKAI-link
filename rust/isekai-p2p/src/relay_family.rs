//! The family the control plane chose for both ends of a relay leg.
//!
//! One place, because the answer must come out the same on both sides and the
//! two sides are different code reading different fields — the initiator
//! `RelayInfo::family`, the listener `PeerConnection::relay_family` (plan Q4).

use isekai_p2p_core::transport::{AddressFamily, family_from_name};

/// The family both ends should dial in, or `None` for no constraint.
///
/// **Computed from both fields, not from whichever one this end reads.** The
/// two carry the same value by design, and reading only your own would make
/// the ends disagree the moment a control plane populates one and not the
/// other — a partial rollout, say. One end constrained and the other free is
/// the state the plan calls worse than neither: the initiator pins v4 while
/// the listener keeps the v6 both would have chosen, and a direct path that
/// would have formed does not.
///
/// Both ends see the same response, so a rule over both fields is the same
/// rule on both sides:
///
/// | `RelayInfo::family` | `PeerConnection::relay_family` | result |
/// |---|---|---|
/// | absent | absent | no constraint — no common family, or a control plane that does not choose (Q5) |
/// | `"v6"` | absent | v6 — one field populated is still an unambiguous instruction |
/// | absent | `"v6"` | v6 |
/// | `"v6"` | `"v6"` | v6 — the ordinary case |
/// | `"v4"` | `"v6"` | **no constraint** — they contradict, and neither end can know which the other would obey |
///
/// A spelling this build does not know is treated as absent, so a control
/// plane newer than this binary costs the direct path and never the
/// connection.
pub fn chosen(
    relay_family: Option<&str>,
    connection_family: Option<&str>,
    context: &str,
) -> Option<AddressFamily> {
    let named = |field: Option<&str>| -> Option<AddressFamily> {
        let name = field?;
        match family_from_name(name) {
            Some(family) => Some(family),
            None => {
                // `warn!`, not `debug!`: a line nobody sees is not a line, and
                // a deployment typo (`"ipv6"`, `"V4"`) would otherwise cost
                // the direct path silently. The comparable degradations in
                // this stack -- a CLAT stub, no routable address -- warn for
                // the same reason.
                tracing::warn!(
                    family = name,
                    context,
                    "the control plane named an address family this build does not know; \
                     letting the leg choose, so the two ends may not line up"
                );
                None
            }
        }
    };
    match (named(relay_family), named(connection_family)) {
        (Some(a), Some(b)) if a != b => {
            tracing::warn!(
                ?a,
                ?b,
                context,
                "the control plane named two different address families for the two ends; \
                 letting both legs choose, because obeying either would leave them \
                 mismatched"
            );
            None
        }
        (Some(family), _) | (None, Some(family)) => Some(family),
        (None, None) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use AddressFamily::{V4, V6};

    #[test]
    fn the_ordinary_case_is_both_fields_agreeing() {
        assert_eq!(chosen(Some("v6"), Some("v6"), "t"), Some(V6));
        assert_eq!(chosen(Some("v4"), Some("v4"), "t"), Some(V4));
    }

    #[test]
    fn one_field_populated_still_constrains_both_ends() {
        // The point of reading both: a control plane mid-rollout that fills
        // only one would otherwise constrain one end and not the other, and
        // one end choosing is worse than neither.
        assert_eq!(chosen(Some("v6"), None, "t"), Some(V6));
        assert_eq!(chosen(None, Some("v6"), "t"), Some(V6));
    }

    #[test]
    fn two_fields_that_contradict_constrain_neither() {
        // Neither end can know which the other would obey, so obeying either
        // is how they end up mismatched. Both ends compute this from the same
        // response, so both drop it.
        assert_eq!(chosen(Some("v4"), Some("v6"), "t"), None);
        assert_eq!(chosen(Some("v6"), Some("v4"), "t"), None);
    }

    #[test]
    fn no_field_is_no_constraint() {
        // A control plane that does not choose, or two ends with nothing in
        // common: the leg picks for itself, which is what it always did.
        assert_eq!(chosen(None, None, "t"), None);
    }

    #[test]
    fn an_unknown_spelling_is_treated_as_absent() {
        // Never a failure, and it must not turn into a contradiction either:
        // a known value beside an unknown one is still an instruction.
        for name in ["", "V4", "ipv6", "inet", "v46", "4"] {
            assert_eq!(chosen(Some(name), None, "t"), None, "{name:?}");
            assert_eq!(chosen(Some(name), Some("v6"), "t"), Some(V6), "{name:?}");
            assert_eq!(chosen(Some("v6"), Some(name), "t"), Some(V6), "{name:?}");
        }
    }
}
