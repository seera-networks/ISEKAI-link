//! Keeping a Provisioning Key's Grant alive for as long as the work runs.
//!
//! **A provisioning Grant is short on purpose.** §8.13.3 caps `grant_ttl` at an
//! hour where a Ticket's is a day, and §8.13.5 explains the asymmetry: this one
//! is meant to be *extended* by redeeming again, so the window in which a
//! revoked key still lets somebody in stays small. A client that redeems once
//! and settles down inherits the narrow ceiling without the thing that makes it
//! workable — and a job longer than `grant_ttl` loses its authorization partway
//! through, having done nothing wrong.
//!
//! So this re-redeems while the forwards are up. Redeeming again is not a
//! failure: the proxy answers `200` and moves `expires_at` to
//! `max(existing, now + grant_ttl)` — never backwards, so a second job cannot
//! shorten a running one's grant.

use std::sync::Arc;
use std::time::Duration;

use isekai_p2p::AssertionSource;
use isekai_p2p::PeerDirectory;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio_util::sync::CancellationToken;

/// The audience the **proxy** checks a binding assertion against (§8.13.4).
///
/// Not Identity's. The two defaults differ deliberately so that a token minted
/// for one is refused by the other, and this is the half that goes to the proxy.
const PROXY_AUDIENCE: &str = "isekai-proxy";

/// How long before a grant lapses to redeem again.
///
/// Half of what is left, so a failure has as much room to be retried as it had
/// to happen in.
fn renew_delay(expires_at: Option<&str>) -> Duration {
    let Some(remaining) = expires_at.and_then(remaining_secs) else {
        // The proxy did not say, so fall back to half the shortest grant it
        // will issue (§8.13.3 clamps `grant_ttl` to 60 at the low end).
        return Duration::from_secs(30);
    };
    // At least a minute between attempts however little is left: a grant that
    // is already expiring is not fixed by asking faster, and the forwards go
    // down on their own if the session is withdrawn.
    Duration::from_secs((remaining / 2).clamp(60, 1800) as u64)
}

/// Seconds from now until `expires_at`, or `None` if it cannot be read.
fn remaining_secs(expires_at: &str) -> Option<i64> {
    let at = OffsetDateTime::parse(expires_at, &Rfc3339).ok()?;
    Some((at - OffsetDateTime::now_utc()).whole_seconds().max(0))
}

/// Re-redeem `key` for as long as the returned guard lives.
///
/// The directory is moved in rather than borrowed: this outlives the call that
/// set the grant up, and opening a second one would mean a second Endpoint
/// Token and a second renewal loop against the same Endpoint.
///
/// **Failures are logged, not propagated.** The grant in force lasts until it
/// lapses, so a transient proxy outage costs nothing; ending a session that is
/// forwarding fine would be worse than trying again.
pub fn keep_the_grant(
    directory: PeerDirectory,
    key: String,
    assertions: Option<Arc<dyn AssertionSource>>,
    expires_at: Option<String>,
    label: Option<String>,
    shutdown: CancellationToken,
) -> GrantKeeper {
    let mut delay = renew_delay(expires_at.as_deref());
    GrantKeeper(tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(delay) => {}
            }
            // **Minted again, every time.** §8.13.4 verifies the binding on
            // each redemption, which is what stops a leaked key working after
            // the job that owns the workload identity has ended.
            let assertion = match &assertions {
                Some(source) => match source.assertion(PROXY_AUDIENCE).await {
                    Ok(assertion) => Some(assertion),
                    Err(e) => {
                        tracing::warn!(
                            retry_in = ?delay,
                            "could not mint a token to extend the grant: {e:#}",
                        );
                        continue;
                    }
                },
                None => None,
            };
            match directory
                .redeem_provisioning_key(&key, assertion.as_deref(), label.as_deref())
                .await
            {
                Ok(redeemed) => {
                    delay = renew_delay(redeemed.grant.expires_at.as_deref());
                    tracing::debug!(
                        expires_at = redeemed.grant.expires_at.as_deref().unwrap_or("?"),
                        next = ?delay,
                        "extended the grant",
                    );
                }
                Err(e) => {
                    // Deliberately not fatal: see the function's documentation.
                    tracing::warn!(
                        retry_in = ?delay,
                        "could not extend the grant; it stands until it lapses: {e:#}",
                    );
                }
            }
        }
    }))
}

/// Stops the renewal when the session it belongs to goes away.
pub struct GrantKeeper(tokio::task::JoinHandle<()>);

impl Drop for GrantKeeper {
    fn drop(&mut self) {
        self.0.abort();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Half of what is left, so a failure has as much room to be retried as it
    /// had to happen in.
    #[test]
    fn the_next_attempt_is_halfway_through_what_is_left() {
        let at = OffsetDateTime::now_utc() + time::Duration::seconds(1800);
        let formatted = at.format(&Rfc3339).unwrap();
        let delay = renew_delay(Some(&formatted));
        // Within a second either way of half an hour's half.
        assert!(delay.as_secs().abs_diff(900) <= 1, "{delay:?}");
    }

    /// A grant already expiring is not fixed by asking faster.
    #[test]
    fn a_grant_about_to_lapse_still_waits_a_minute() {
        let at = OffsetDateTime::now_utc() + time::Duration::seconds(10);
        let formatted = at.format(&Rfc3339).unwrap();
        assert_eq!(renew_delay(Some(&formatted)), Duration::from_secs(60));

        let past = OffsetDateTime::now_utc() - time::Duration::seconds(500);
        let formatted = past.format(&Rfc3339).unwrap();
        assert_eq!(renew_delay(Some(&formatted)), Duration::from_secs(60));
    }

    /// A long grant does not mean a long silence: the ceiling keeps the loop
    /// checking in, so a revoked key is noticed within half an hour.
    #[test]
    fn a_long_grant_is_still_checked_on() {
        let at = OffsetDateTime::now_utc() + time::Duration::hours(10);
        let formatted = at.format(&Rfc3339).unwrap();
        assert_eq!(renew_delay(Some(&formatted)), Duration::from_secs(1800));
    }

    /// A date this cannot read is not a reason to stop keeping the grant.
    #[test]
    fn an_unreadable_expiry_falls_back_rather_than_giving_up() {
        assert_eq!(renew_delay(None), Duration::from_secs(30));
        assert_eq!(renew_delay(Some("not a date")), Duration::from_secs(30));
    }
}
