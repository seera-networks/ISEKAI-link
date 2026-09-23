//! Who the signed-in person is, and under what terms (`GET /v1/me`).
//!
//! **Asked rather than worked out.** The access token in hand carries an
//! `org_id` and nothing else this answers: whether the tenant resolves, whether
//! an administrator is recognised by a claim or by configuration, and whether a
//! guest membership narrows everything down — all of those are deployment
//! settings that Identity applies when it enforces. A client deciding for
//! itself would hold a second copy of those rules and drift from the one that
//! counts (`multitenancy.md` §5.4).
//!
//! Route A, no PoP: this is about the person, not about an Endpoint.

use isekai_p2p_core::https::HttpsTransport;
use isekai_p2p_core::identity::{IdentityClient, Membership};
use isekai_p2p_core::transport::MasqueH3Transport;

use crate::enrollment::Identity;

macro_rules! on_transport {
    ($identity:expr, |$client:ident| $body:expr) => {{
        if $identity.http3 {
            let $client = IdentityClient::new(MasqueH3Transport::connect(&$identity.url)?);
            $body
        } else {
            let $client = IdentityClient::new(HttpsTransport::connect(&$identity.url)?);
            $body
        }
    }};
}

/// Ask Identity what this sign-in is, here.
pub async fn me(identity: &Identity, auth0_token: &str) -> anyhow::Result<Membership> {
    Ok(on_transport!(identity, |client| {
        client.me(auth0_token).await?
    }))
}

/// One line saying what this person is in this tenant.
///
/// **A guest is told when their contract ends**, because that date is the
/// answer to every refusal they are about to meet and it is not written
/// anywhere else they can see. A membership that has *already* ended is told
/// too, with which of the three ways it ended: "expired" and "revoked" are
/// different things to take to whoever invited them, and `promoted` is not a
/// refusal at all.
pub fn describe(me: &Membership) -> String {
    let mut line = match me.membership_ended.as_deref() {
        // **The end, not the role.** Once a membership is over the role has
        // gone back to what it would have been, so printing that alone says
        // "member" to somebody whose every request is refused.
        Some("expired") => format!(
            "guest -- membership expired{}",
            me.not_after
                .as_deref()
                .map(|t| format!(" at {t}"))
                .unwrap_or_default()
        ),
        Some("revoked") => "guest -- membership was revoked".to_owned(),
        // Not a refusal: the row is a record, and this person is an ordinary
        // member again. Saying it keeps a stale "guest" out of the answer.
        Some("promoted") => format!("{} (was a guest; promoted)", me.role),
        Some(other) => format!("{} (membership ended: {other})", me.role),
        None if me.is_guest() => match me.not_after.as_deref() {
            Some(until) => format!("guest (until {until})"),
            // **The deadline is required of a guest**, so its absence is a
            // disagreement with the server rather than an unlimited guest.
            None => "guest (the server did not say until when)".to_owned(),
        },
        None => me.role.clone(),
    };
    // **Only while the membership is the thing in force.** Once it has ended
    // the narrowing is over and the administration is back, so saying "the
    // guest membership wins" beside "membership expired" asserts the opposite
    // of what is true. Identity does not send the flag then either; this is
    // belt and braces for the answer, not for the field.
    if me.demoted_to_guest && me.membership_ended.is_none() {
        line.push_str(" -- an administrator here, but the guest membership wins");
    }
    line
}

#[cfg(test)]
mod tests {
    use super::*;

    fn membership(role: &str) -> Membership {
        Membership {
            sub: "auth0|contractor".into(),
            tenant_id: "org_1".into(),
            tenant_kind: "organization".into(),
            role: role.into(),
            not_after: None,
            membership_ended: None,
            demoted_to_guest: false,
            admin_source: None,
        }
    }

    /// The date is the whole point: it is what every refusal this person is
    /// about to meet will be about, and nothing else on their machine knows it.
    #[test]
    fn a_guest_is_told_when_it_ends() {
        let mut me = membership("guest");
        me.not_after = Some("2027-01-31T23:59:59Z".into());
        assert_eq!(describe(&me), "guest (until 2027-01-31T23:59:59Z)");
    }

    /// **The role has already gone back** when a membership ends, so reporting
    /// it alone tells somebody they are a member while every issue is refused.
    /// Expired and revoked are told apart because what to do about them is not
    /// the same request to the same person.
    #[test]
    fn an_ended_membership_is_not_reported_as_the_role_it_left_behind() {
        let mut me = membership("member");
        me.not_after = Some("2026-09-01T00:00:00Z".into());
        me.membership_ended = Some("expired".into());
        let text = describe(&me);
        assert!(text.contains("expired"), "{text}");
        assert!(text.contains("2026-09-01T00:00:00Z"), "{text}");
        assert!(!text.starts_with("member"), "{text}");

        me.membership_ended = Some("revoked".into());
        let text = describe(&me);
        assert!(text.contains("revoked"), "{text}");
        // The contract date is not the reason this one stopped, and printing it
        // beside "revoked" reads as "revoked until then".
        assert!(!text.contains("2026-09-01"), "{text}");
    }

    /// `promoted` is the one ending that is not a refusal. Treating it like the
    /// others would tell a restored member that they are locked out.
    #[test]
    fn promotion_is_not_reported_as_being_stopped() {
        let mut me = membership("member");
        me.membership_ended = Some("promoted".into());
        let text = describe(&me);
        assert!(text.starts_with("member"), "{text}");
        assert!(
            !text.contains("expired") && !text.contains("revoked"),
            "{text}"
        );
    }

    /// **The narrowing is over when the membership is.** Printing "the guest
    /// membership wins" beside "expired" tells an administrator they are shut
    /// out of their own tenant, which is the reverse of the truth.
    #[test]
    fn an_ended_membership_does_not_still_outrank_an_administrator() {
        let mut me = membership("tenant_admin");
        me.not_after = Some("2026-09-01T00:00:00Z".into());
        me.membership_ended = Some("expired".into());
        me.demoted_to_guest = true;
        let text = describe(&me);
        assert!(!text.contains("wins"), "{text}");
    }

    /// Being an administrator who is nonetheless narrowed to a guest is the
    /// state nobody guesses: the dashboard is gone and the claim still says
    /// otherwise.
    #[test]
    fn a_demoted_administrator_is_told_why() {
        let mut me = membership("guest");
        me.not_after = Some("2027-01-31T23:59:59Z".into());
        me.demoted_to_guest = true;
        let text = describe(&me);
        assert!(text.contains("administrator"), "{text}");
        assert!(text.contains("2027-01-31T23:59:59Z"), "{text}");
    }
}
