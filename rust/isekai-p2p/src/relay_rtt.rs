//! Measuring the relays, so the control plane can choose a near one.
//!
//! Relay selection has two stages (`docs/relay_proximity_client.md`, and the
//! relay proximity plan in ISEKAI-link-server whose § numbers are cited here).
//! The
//! first — *which pool* — is a tenant boundary and nothing here touches it. The
//! second — *which node in that pool* — used to be `created_at DESC` and pick
//! the first, which was the right answer while a tenant had one relay and
//! became "two people in Tokyo route through Frankfurt" the moment it had two.
//! A relay sits on both directions of the path, so getting it wrong costs the
//! round trip twice.
//!
//! **The control plane cannot measure this and neither can the relay.** Neither
//! of them is on the path between a party and a node. The endpoints are the
//! only things standing on the actual route, so the parties measure and the
//! control plane chooses (§3).
//!
//! # What is measured
//!
//! An HTTP/3 `GET /health` on the relay's own origin — the same host a leg
//! would be dialled at, over the same QUIC stack it would use.
//!
//! **The handshake is deliberately excluded.** The first exchange on a fresh
//! connection pays for the QUIC handshake, certificate verification and a cold
//! congestion window, none of which a long-lived relay leg pays again. Counting
//! it would rank on the cost of *setting up* a path rather than the cost of
//! *using* one. So the first request is a warm-up and is thrown away.
//!
//! **The minimum of several probes**, not the mean or the median. The quantity
//! wanted is the path's floor; anything above it is queueing, scheduler delay
//! or a busy relay, and those add noise that does not belong to the route. The
//! plan leaves this choice to the client (§10.3), and this is the choice.
//!
//! # Honesty is not assumed
//!
//! These numbers are attacker-controlled input, and the design survives that
//! because **they cannot widen the pool**: the candidate set is fixed by stage
//! one before any measurement is read, and a lie only reorders what is already
//! there (§3.1). Lying about a relay's speed makes the liar's own session
//! slower — with one exception the plan accepts, which is that it also moves
//! the party on the other end of that session, who has already authorized the
//! connection and can read where it was routed.
//!
//! That is also why `/health` is probed without pinning the relay's
//! `spki_sha256`. The probe carries no credential and reads one word back, so
//! the most a machine in the middle can do is make a relay look fast or slow —
//! which is exactly what the reporting party could already do by hand, and is
//! bounded the same way.

use std::time::{Duration, Instant};

use isekai_p2p_core::proxy::{ProxyClient, RelayCandidate, RelayRttSample};
use isekai_p2p_core::transport::MasqueH3Transport;
use tokio::task::JoinSet;

/// How long a relay's measurements stay usable at the control plane.
///
/// **This mirrors the server's `RELAY_RTT_RETAIN_SECS` and is not learned from
/// it** — nothing in `GET /v1/peer/relays` says what the window is. If the
/// server's window shrinks, this has to follow, or reports will land already
/// stale and every selection will quietly fall back to pool order.
pub const FRESHNESS_WINDOW: Duration = Duration::from_secs(3_600);

/// How often a listener re-measures and reports.
///
/// **Half the window, for the reason every other renewal in this codebase is
/// half of something.** Reporting exactly at the window guarantees a gap: the
/// rows lapse at the same instant their replacement is being measured, and any
/// connection arriving in between is ranked as though nothing had ever been
/// reported.
pub const REPORT_INTERVAL: Duration = Duration::from_secs(FRESHNESS_WINDOW.as_secs() / 2);

/// How a round of measurement is bounded.
#[derive(Debug, Clone)]
pub struct ProbeOptions {
    /// Timed exchanges per relay, after the warm-up. The minimum is kept.
    pub probes: usize,
    /// The whole of one relay's probe — handshake, warm-up and all of it.
    ///
    /// Running out here is a *result*: the relay was measured and could not be
    /// reached.
    pub per_relay: Duration,
    /// The whole round, across every relay in parallel.
    ///
    /// Running out here is **not** a result. Whatever has not finished is left
    /// out of the report rather than called unreachable, because the difference
    /// between those two is the difference between "do not route me through it"
    /// and "I have nothing to say about it" (§5).
    pub budget: Duration,
}

impl Default for ProbeOptions {
    fn default() -> Self {
        Self {
            probes: 3,
            per_relay: Duration::from_secs(3),
            // Generous for a listener on its own schedule, and the initiator
            // path overrides it — see [`initiator_defaults`].
            budget: Duration::from_secs(10),
        }
    }
}

impl ProbeOptions {
    /// What an initiator uses, where this sits in front of `connect` and every
    /// millisecond is one the user waits.
    ///
    /// Fewer probes and a short budget: a rough number now beats an exact one
    /// after the connection should already have been made. Anything that does
    /// not finish is omitted, so a tight budget degrades to the target's
    /// measurements deciding alone (stage B) rather than to a bad answer.
    pub fn initiator_defaults() -> Self {
        Self {
            probes: 2,
            per_relay: Duration::from_millis(1_200),
            budget: Duration::from_millis(1_500),
        }
    }
}

/// Measure every candidate in parallel and report what finished in time.
///
/// Each entry in the result is a candidate that was *measured*: `Some(ms)` for
/// one that answered, `None` for one that did not. A candidate that the budget
/// cut short appears in neither state — it is simply absent.
pub async fn measure(candidates: &[RelayCandidate], opts: &ProbeOptions) -> Vec<RelayRttSample> {
    measure_with(candidates, opts, |base_url, probes| async move {
        probe(&base_url, probes).await
    })
    .await
}

/// [`measure`] with the probe itself supplied.
///
/// Split out so the part that decides — what the budget omits, what a timeout
/// condemns — can be tested without a relay to point at. Opening a real QUIC
/// connection from a unit test also leaves msquic holding handles the test
/// binary then aborts on, which is a poor reason to have weaker tests.
async fn measure_with<F, Fut>(
    candidates: &[RelayCandidate],
    opts: &ProbeOptions,
    prober: F,
) -> Vec<RelayRttSample>
where
    F: Fn(String, usize) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Option<u32>> + Send + 'static,
{
    if candidates.is_empty() {
        return Vec::new();
    }
    let deadline = Instant::now() + opts.budget;
    let mut set = JoinSet::new();
    for candidate in candidates {
        let dp_id = candidate.dp_id.clone();
        let base_url = candidate.base_url.clone();
        let per_relay = opts.per_relay;
        let probes = opts.probes;
        let prober = prober.clone();
        set.spawn(async move {
            let rtt = tokio::time::timeout(per_relay, prober(base_url, probes))
                .await
                .unwrap_or(None);
            RelayRttSample { dp_id, rtt_ms: rtt }
        });
    }

    let mut out = Vec::new();
    // `join_next` under a deadline: what is done by then is kept, and the rest
    // is dropped rather than guessed at.
    while let Ok(Some(joined)) = tokio::time::timeout_at(deadline.into(), set.join_next()).await {
        match joined {
            Ok(sample) => out.push(sample),
            // A panicking probe is a bug in this file, not a statement about
            // the relay, so it must not be reported as unreachable.
            Err(err) => tracing::warn!(%err, "a relay probe did not finish"),
        }
    }
    set.abort_all();
    out
}

/// One relay: connect, warm up, and time `probes` exchanges.
///
/// `None` at any step means unreachable — there is no partial credit, because a
/// relay that cannot complete the cheapest possible request is not one to hand
/// a session to.
async fn probe(base_url: &str, probes: usize) -> Option<u32> {
    let transport = match MasqueH3Transport::connect(base_url) {
        Ok(transport) => transport,
        Err(err) => {
            tracing::debug!(%err, base_url, "could not open a probe connection");
            return None;
        }
    };
    time_exchanges(probes, || health(&transport)).await
}

/// Warm up once, then time `probes` exchanges and keep the fastest.
///
/// The warm-up's result is thrown away on purpose: it is the handshake, the
/// certificate check and a cold congestion window, none of which a leg pays
/// twice. What is left is the round trip.
async fn time_exchanges<F, Fut>(probes: usize, exchange: F) -> Option<u32>
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<()>>,
{
    exchange().await?;

    let mut best: Option<u32> = None;
    for _ in 0..probes {
        let started = Instant::now();
        // A relay that answered once and then stopped has still told us
        // something; keep the samples that landed rather than discarding them,
        // and stop asking.
        if exchange().await.is_none() {
            break;
        }
        let ms = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
        best = Some(best.map_or(ms, |b| b.min(ms)));
    }
    best
}

/// One `GET /health`. `None` unless the relay answered a success status.
async fn health(transport: &MasqueH3Transport) -> Option<()> {
    use isekai_p2p_core::proxy::ControlPlaneTransport as _;
    let response = transport
        .send("GET", "/health", &[], Vec::new())
        .await
        .ok()?;
    (200..300).contains(&response.status).then_some(())
}

/// A listener's standing measurement task.
///
/// **The target has to be ranked before anyone connects to it**, which is the
/// whole reason a relay can be chosen with only the initiator present: the
/// listener exists first, so it can have measured first. Nothing else it does
/// carries this, so it gets its own task (§4.1).
pub struct RelayRttReporter(tokio::task::JoinHandle<()>);

impl RelayRttReporter {
    /// Start reporting for `listener_id`, immediately and then every
    /// [`REPORT_INTERVAL`].
    ///
    /// **The first round runs at once rather than after a wait.** A listener
    /// that has just come up is exactly the one an initiator is about to reach,
    /// and until it has reported, selection has nothing from this side to go on.
    pub fn spawn(
        proxy: ProxyClient<MasqueH3Transport>,
        listener_id: String,
        opts: ProbeOptions,
    ) -> Self {
        Self(tokio::spawn(async move {
            loop {
                if let Err(err) = round(&proxy, &listener_id, &opts).await {
                    // Never fatal. Losing a round costs ranking, never the
                    // listener: the control plane falls back to pool order,
                    // which is where it was before any of this existed.
                    tracing::debug!(%err, listener_id, "a relay measurement round did not land");
                }
                tokio::time::sleep(REPORT_INTERVAL).await;
            }
        }))
    }

    /// Stop reporting. The rows already stored lapse on their own window.
    pub fn stop(&self) {
        self.0.abort();
    }
}

impl Drop for RelayRttReporter {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Read the candidates, measure them, report what was measured.
async fn round(
    proxy: &ProxyClient<MasqueH3Transport>,
    listener_id: &str,
    opts: &ProbeOptions,
) -> anyhow::Result<()> {
    let Some(candidates) = proxy.list_relays().await? else {
        // A proxy from before relay selection. Nothing to measure, and nothing
        // wrong: this is an optimization on top of a control plane that already
        // worked.
        return Ok(());
    };
    if candidates.is_empty() {
        // No registered relay: the control plane's own data path is the only
        // one there is, and there is nothing to choose between.
        return Ok(());
    }
    let samples = measure(&candidates, opts).await;
    if samples.is_empty() {
        // **Not the same as reporting nothing.** An empty report would replace
        // the stored set with nothing, throwing away measurements that are
        // still fresh because this one round ran out of budget.
        anyhow::bail!("no relay finished its probe within the budget");
    }
    let stored = proxy.report_relay_rtt(listener_id, &samples).await?;
    tracing::debug!(
        listener_id,
        measured = samples.len(),
        unreachable = samples.iter().filter(|s| s.rtt_ms.is_none()).count(),
        stored,
        "reported relay round trips"
    );
    Ok(())
}

/// Measure for a one-shot initiator, swallowing every failure.
///
/// An initiator that cannot measure still connects. Its measurements are an
/// optimization on which relay gets chosen, so failing to produce them falls
/// back to the target's alone — never to no connection.
pub async fn measure_for_connect(
    proxy: &ProxyClient<MasqueH3Transport>,
    opts: &ProbeOptions,
) -> Vec<RelayRttSample> {
    match proxy.list_relays().await {
        Ok(Some(candidates)) if !candidates.is_empty() => measure(&candidates, opts).await,
        Ok(_) => Vec::new(),
        Err(err) => {
            tracing::debug!(%err, "could not read the relay candidates; connecting unmeasured");
            Vec::new()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn reporting_is_well_inside_the_window() {
        // The property that matters is not the number but the gap: a report has
        // to land while the previous one is still fresh.
        assert!(REPORT_INTERVAL < FRESHNESS_WINDOW);
        assert!(REPORT_INTERVAL * 2 <= FRESHNESS_WINDOW);
    }

    #[test]
    fn an_initiator_will_not_wait_longer_than_its_budget() {
        let opts = ProbeOptions::initiator_defaults();
        // A single relay's probe must be able to finish inside the round, or
        // the tight path could never produce a measurement at all.
        assert!(opts.per_relay <= opts.budget);
        assert!(opts.budget <= Duration::from_secs(2));
    }

    #[tokio::test]
    async fn no_candidates_means_no_probing() {
        let samples = measure(&[], &ProbeOptions::default()).await;
        assert!(samples.is_empty());
    }

    fn candidate(dp_id: &str) -> RelayCandidate {
        RelayCandidate {
            dp_id: dp_id.into(),
            // Distinct per node, so an injected prober can behave differently
            // for each the way a real network does.
            base_url: format!("https://{dp_id}.relay.invalid:8443"),
            spki_sha256: Vec::new(),
        }
    }

    #[tokio::test]
    async fn a_relay_that_cannot_be_reached_is_measured_and_null() {
        let samples = measure_with(
            &[candidate("dp1_gone")],
            &ProbeOptions::default(),
            |_, _| async { None },
        )
        .await;
        // **Present with a null, not absent.** Absent would say "not measured",
        // and the control plane would leave it in this session's candidates
        // instead of dropping it.
        assert_eq!(
            samples,
            vec![RelayRttSample {
                dp_id: "dp1_gone".into(),
                rtt_ms: None,
            }]
        );
    }

    #[tokio::test]
    async fn a_relay_that_runs_out_of_its_own_time_is_also_null() {
        // Its own limit is a verdict on the relay: it was given a fair chance
        // and did not answer.
        let opts = ProbeOptions {
            probes: 1,
            per_relay: Duration::from_millis(30),
            budget: Duration::from_secs(5),
        };
        let samples = measure_with(&[candidate("dp1_slow")], &opts, |_, _| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(1)
        })
        .await;
        assert_eq!(samples.first().map(|s| s.rtt_ms), Some(None));
    }

    #[tokio::test]
    async fn the_budget_omits_rather_than_condemns() {
        // The round's limit says nothing about any one relay, so nothing may be
        // reported about the ones it cut short.
        let opts = ProbeOptions {
            probes: 1,
            per_relay: Duration::from_secs(30),
            budget: Duration::from_millis(30),
        };
        let samples = measure_with(&[candidate("dp1_slow")], &opts, |_, _| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Some(1)
        })
        .await;
        assert!(samples.is_empty(), "got {samples:?}");
    }

    #[tokio::test]
    async fn a_dark_relay_does_not_cost_the_ones_that_answered() {
        // Probing is parallel so that one node nobody can reach does not spend
        // the budget the rest needed. A pool is not uniformly healthy, and this
        // is the first thing the feature meets in the field: without it, adding
        // a broken relay would silently stop *every* measurement from
        // finishing, and selection would fall back to pool order everywhere.
        let opts = ProbeOptions {
            probes: 1,
            per_relay: Duration::from_secs(30),
            budget: Duration::from_millis(300),
        };
        let samples = measure_with(
            &[candidate("dp1_near"), candidate("dp1_stuck")],
            &opts,
            |base_url, _| async move {
                if base_url.contains("dp1_stuck") {
                    // Never answers, and outlives both the budget and its own
                    // per-relay limit.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                Some(7)
            },
        )
        .await;
        // The reachable one is reported; the hung one is left out, because the
        // budget ran out rather than the relay having answered.
        assert_eq!(
            samples,
            vec![RelayRttSample {
                dp_id: "dp1_near".into(),
                rtt_ms: Some(7),
            }]
        );
    }

    #[tokio::test]
    async fn the_warm_up_is_not_counted() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let rtt = time_exchanges(3, || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(())
            }
        })
        .await;
        assert!(rtt.is_some());
        // Three timed exchanges plus the one that paid for the handshake.
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn a_relay_that_fails_its_warm_up_is_unreachable() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let rtt = time_exchanges(3, || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            }
        })
        .await;
        assert_eq!(rtt, None);
        // And it stopped there rather than timing three more failures.
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_fastest_exchange_is_the_one_kept() {
        // The floor of the path is what is wanted; a slow sample is queueing,
        // not distance.
        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rtt = time_exchanges(3, || {
            let nth = nth.clone();
            async move {
                let n = nth.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Warm-up is n == 0; the timed ones are slow, fast, slow.
                let ms = if n == 2 { 5 } else { 120 };
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Some(())
            }
        })
        .await
        .expect("the relay answered");
        assert!(rtt < 60, "kept {rtt}ms, which is not the fastest");
    }

    #[tokio::test]
    async fn a_relay_that_stops_answering_keeps_what_it_gave() {
        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let rtt = time_exchanges(3, || {
            let nth = nth.clone();
            async move {
                let n = nth.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Warm-up, one good exchange, then silence.
                (n < 2).then_some(())
            }
        })
        .await;
        // It answered once, so it is reachable. Reporting `None` here would
        // drop a working relay from the session over a single lost exchange.
        assert!(rtt.is_some());
    }

    #[test]
    fn a_null_survives_serialization() {
        // The wire form is the whole point of the distinction, so pin it here
        // rather than trusting that `Option` does the obvious thing.
        let body = serde_json::to_value(vec![
            RelayRttSample {
                dp_id: "dp1_near".into(),
                rtt_ms: Some(12),
            },
            RelayRttSample {
                dp_id: "dp1_dark".into(),
                rtt_ms: None,
            },
        ])
        .unwrap();
        assert_eq!(
            body,
            serde_json::json!([
                { "dp_id": "dp1_near", "rtt_ms": 12 },
                { "dp_id": "dp1_dark", "rtt_ms": null },
            ])
        );
    }
}
