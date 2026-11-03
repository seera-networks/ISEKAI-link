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

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use isekai_p2p_core::proxy::{ProxyClient, RelayCandidate, RelayReach, RelayRttSample};
pub use isekai_p2p_core::transport::AddressFamily;
use isekai_p2p_core::transport::{Landing, MasqueH3Transport, family_name};
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

/// How soon to try again after the *first* round that produced nothing worth
/// sending, doubling from there up to [`REPORT_INTERVAL`].
///
/// Short at first, because the usual cause is a moment of local trouble rather
/// than a pool that has gone away, and the cost of waiting is that this side
/// stays unranked.
///
/// **Backed off rather than fixed, because the other cause is a deployment
/// whose relays this host genuinely cannot reach** — a `base_url` on a network
/// this side has no route to, say. That does not get better by asking again,
/// and each attempt costs a QUIC connection whose failure the transport logs at
/// `ERROR`. A fixed minute would make a misconfiguration print an unexplained
/// error every minute for the life of the process.
const RETRY_IN: Duration = Duration::from_secs(60);

/// The retry interval after `failures` consecutive unproductive rounds,
/// doubling and never exceeding the ordinary cadence.
fn retry_delay(failures: u32) -> Duration {
    let doubled = RETRY_IN.saturating_mul(1u32 << failures.min(16));
    doubled.min(REPORT_INTERVAL)
}

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
    /// The whole *measurement*, across every relay in parallel.
    ///
    /// Running out here is **not** a result. Whatever has not finished is left
    /// out of the report rather than called unreachable, because the difference
    /// between those two is the difference between "do not route me through it"
    /// and "I have nothing to say about it" (§5).
    ///
    /// **It does not cover the family observation `round` runs after it.**
    /// That pass is bounded on its own, by one [`per_relay`](Self::per_relay)
    /// per relay with the relays concurrent — so a round can take this plus
    /// roughly one `per_relay`. Said rather than quietly folded in, because
    /// folding it in would mean a measurement and an observation competing for
    /// the same deadline, and the measurement is the one that gets reported.
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
    measure_with(candidates, opts, |base_url, probes, best| async move {
        probe(&base_url, probes, best).await
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
    F: Fn(String, usize, Arc<AtomicU32>) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
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
            // **Samples are published as they land, not returned at the end.**
            // The timeout below cancels the probe wherever it has got to, and a
            // relay that answered and was then cut off must not be reported as
            // unreachable — that is the one verdict this design uses to *remove*
            // a relay from the session. A far relay is slow, not absent, and
            // condemning every relay past a few hundred milliseconds would
            // empty the candidate list of exactly the cross-continent nodes
            // proximity selection exists to rank.
            let best = Arc::new(AtomicU32::new(NOTHING_YET));
            let _ = tokio::time::timeout(per_relay, prober(base_url, probes, best.clone())).await;
            let landed = best.load(Ordering::Relaxed);
            RelayRttSample {
                dp_id,
                // Nothing at all — not even the warm-up — is the verdict the
                // per-relay limit is for.
                rtt_ms: (landed != NOTHING_YET).then_some(landed),
            }
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

/// The sentinel for "no exchange has completed yet".
///
/// Distinct from every value that can be stored because samples are clamped to
/// [`MAX_RTT_MS`], which the control plane clamps to anyway.
const NOTHING_YET: u32 = u32::MAX;

/// The slowest round trip worth recording, mirroring the control plane's own
/// clamp. Anything slower is unusable as a relay.
const MAX_RTT_MS: u32 = 10_000;

/// One relay: connect, warm up, and time `probes` exchanges into `best`.
///
/// **Writes as it goes rather than returning**, so that being cancelled part
/// way keeps what was already measured. Leaving `best` untouched is what says
/// unreachable.
async fn probe(base_url: &str, probes: usize, best: Arc<AtomicU32>) {
    tracing::debug!(base_url, "probing a relay over h3 GET /health");
    let transport = match MasqueH3Transport::connect(base_url) {
        Ok(transport) => transport,
        Err(err) => {
            tracing::debug!(%err, base_url, "could not open a probe connection");
            return;
        }
    };
    time_exchanges(probes, &best, || health(&transport)).await;
    let landed = best.load(Ordering::Relaxed);
    if landed == NOTHING_YET {
        tracing::debug!(
            base_url,
            "nothing came back; reporting this relay as unreachable"
        );
    } else {
        tracing::debug!(base_url, rtt_ms = landed, "measured a relay");
    }
}

/// Warm up once, then time `probes` exchanges and keep the fastest.
///
/// The warm-up's result is thrown away on purpose: it is the handshake, the
/// certificate check and a cold congestion window, none of which a leg pays
/// twice. What is left is the round trip.
async fn time_exchanges<F, Fut>(probes: usize, best: &AtomicU32, exchange: F)
where
    F: Fn() -> Fut,
    Fut: std::future::Future<Output = Option<()>>,
{
    if exchange().await.is_none() {
        return;
    }

    for _ in 0..probes {
        let started = Instant::now();
        // A relay that answered once and then stopped has still told us
        // something; keep the samples that landed rather than discarding them,
        // and stop asking.
        if exchange().await.is_none() {
            break;
        }
        let ms = u32::try_from(started.elapsed().as_millis())
            .unwrap_or(MAX_RTT_MS)
            .min(MAX_RTT_MS);
        // Published on each pass, so a cancellation between here and the next
        // exchange still leaves the measurement behind.
        best.fetch_min(ms, Ordering::Relaxed);
    }
}

/// The families a relay actually answered on, over a socket that really was
/// unconnected.
///
/// **Read from the landing, never from what was asked for.** The family handed
/// to `connect_unconnected` is a preference, not a constraint: a name with only
/// an `A` record, probed asking for v6, connects over v4 and answers. Counting
/// that as "v6 works" is the over-claim this exists to avoid — and it is the
/// one that would matter, because the control plane would then pick v6 as the
/// common family and the leg would have nowhere to go.
///
/// **A connected socket is not an answer either.** The connector answers a
/// request for an unconnected binding with an ordinary connected socket in
/// three cases — a CLAT translator stub, nothing routable to bind, or the
/// QMUX/TCP fallback — and in all three the probe succeeds while measuring
/// something a leg's unconnected binding cannot reproduce. Claiming that
/// family is precisely the mistake this measurement exists to prevent, so such
/// a landing contributes nothing. Nothing is lost by dropping it: a host in
/// that state has no unconnected binding to offer, so it has no direct path to
/// line up in any family.
///
/// The connector reports which it was, so none of this is inferred from the
/// addresses — which is what it took to cover the "nothing routable" case at
/// all (tonic-h3#5).
///
/// Deduplicated, because both probes landing on the same family is the
/// ordinary answer for a single-stack name and says one thing, not two.
fn families_answered(landings: impl IntoIterator<Item = Option<Landing>>) -> Vec<AddressFamily> {
    let mut out = Vec::new();
    for landing in landings.into_iter().flatten() {
        if !landing.binding.is_unconnected() {
            continue;
        }
        let family = if landing.remote.is_ipv6() {
            AddressFamily::V6
        } else {
            AddressFamily::V4
        };
        if !out.contains(&family) {
            out.push(family);
        }
    }
    out
}

/// One relay, one family: `GET /health` asked the way a leg asks, and where
/// the connection ended up.
///
/// `None` for anything that did not answer — a connection that could not be
/// built, a request that failed, or a success whose addresses could not be
/// read.
async fn family_landing(base_url: &str, family: AddressFamily) -> Option<Landing> {
    let transport = match MasqueH3Transport::connect_unconnected(base_url, family) {
        Ok(transport) => transport,
        Err(err) => {
            tracing::debug!(%err, base_url, ?family, "could not open a family probe");
            return None;
        }
    };
    health(&transport).await?;
    transport.landing()
}

/// Which families one relay answers on.
///
/// **The two families are probed at once, each bounded on its own.** Neither
/// can cost the other, which sequentially under one shared budget is exactly
/// what happens — and in the likeliest shape of the problem this measurement
/// exists for. A dual-stack relay whose AAAA address black-holes UDP/443:
/// v4 answers in a moment, v6 then hangs past the budget, and a shared
/// deadline cancels the pair and throws the good v4 landing away, printing
/// `none` for a relay that demonstrably answers on v4. Sequential order makes
/// the mirror case certain rather than likely: a routable-but-dead A record
/// means v6 is never dialled at all. `measure` already keeps what landed
/// before it was cut off, for the same reason.
///
/// Concurrent, so one `per_relay` each still bounds the relay as a whole.
async fn relay_families<F, Fut>(
    candidate: &RelayCandidate,
    per_relay: Duration,
    probe: F,
) -> Vec<AddressFamily>
where
    F: Fn(String, AddressFamily) -> Fut,
    Fut: std::future::Future<Output = Option<Landing>>,
{
    let (v4, v6) = tokio::join!(
        tokio::time::timeout(
            per_relay,
            probe(candidate.base_url.clone(), AddressFamily::V4)
        ),
        tokio::time::timeout(
            per_relay,
            probe(candidate.base_url.clone(), AddressFamily::V6)
        ),
    );
    let v4 = v4.ok().flatten();
    let v6 = v6.ok().flatten();
    let families = families_answered([v4, v6]);
    // **Both landings in the line, not just the verdict.** An empty set has
    // several different causes -- nothing answered, a connected fallback of
    // one kind or another, or an address that could not be read -- and the
    // landings carry the connector's own word on which it was.
    tracing::info!(
        dp_id = candidate.dp_id,
        base_url = candidate.base_url,
        ?families,
        asked_v4_landed = ?v4,
        asked_v6_landed = ?v6,
        "which families this relay answers on, over an unconnected socket",
    );
    families
}

/// Which families each relay answers on, logged **and now reported**.
///
/// The question is whether a relay on a dual-stack host answers on *both*
/// families over the socket mode a leg uses — the premise
/// `docs/relay_address_family_plan.md` rests on, and one nothing here knows
/// the answer to yet for a real deployment, which is why every round still
/// says what it found at `INFO`.
///
/// **What this returns goes on the wire.** `round` sends it as `relay_reach`
/// (plan §4-4), and the control plane intersects it with the far end's set, so
/// an entry means "measured, and it worked" and nothing else. In particular an
/// entry with an empty family list must never be taken as "neither family
/// works": a probe that timed out looks identical. `reach_to_report` drops
/// those, and [`reach_field`](isekai_p2p_core::proxy) drops them again at the
/// request boundary for callers that do not.
///
/// **Concurrent, one `per_relay` budget each.** Sequentially under a single
/// cap, a slow or dark relay early in the list eats the budget and the tail is
/// never probed — and since the candidate order is stable, it would be the
/// same relays going unobserved every round, forever, which is the opposite of
/// the point.
///
/// On the listener's schedule only. It runs every [`REPORT_INTERVAL`] — half
/// an hour — so two extra probes per relay is affordable; the initiator
/// measures inside a connect with a few hundred milliseconds to spare and must
/// not pay for this.
///
/// **It measures a leg that migrates.** A leg's socket is unconnected only
/// when migration is on (`bind::relay_connector` takes it from the caller's
/// options); with migration off there is no direct path to line a family up
/// for, so there is nothing for this to be wrong about.
/// Returns what it logged, keyed by `dp_id`, for the two callers that need it:
/// `round` sends it, and `portal-client show-relays` prints it — an operator
/// explaining a missing direct path does not go looking in a listener's
/// journal.
pub async fn observe_families(
    candidates: &[RelayCandidate],
    per_relay: Duration,
) -> Vec<(String, Vec<AddressFamily>)> {
    observe_families_with(candidates, per_relay, |base_url, family| async move {
        family_landing(&base_url, family).await
    })
    .await
}

/// [`observe_families`] with the probe injected, so the budgeting is testable
/// without a relay — the same seam [`measure_with`] exists for.
async fn observe_families_with<F, Fut>(
    candidates: &[RelayCandidate],
    per_relay: Duration,
    probe: F,
) -> Vec<(String, Vec<AddressFamily>)>
where
    F: Fn(String, AddressFamily) -> Fut + Send + Sync + Clone + 'static,
    Fut: std::future::Future<Output = Option<Landing>> + Send + 'static,
{
    let mut set = JoinSet::new();
    for candidate in candidates {
        let candidate = candidate.clone();
        let probe = probe.clone();
        set.spawn(async move {
            let families = relay_families(&candidate, per_relay, probe).await;
            (candidate.dp_id, families)
        });
    }
    let mut out = Vec::new();
    while let Some(joined) = set.join_next().await {
        // A panicking probe costs its own line, never the pass.
        match joined {
            Ok(observed) => out.push(observed),
            Err(err) => tracing::debug!(%err, "a family probe did not finish"),
        }
    }
    out
}

/// One `GET /health`. `None` unless the relay answered a success status.
async fn health(transport: &MasqueH3Transport) -> Option<()> {
    use isekai_p2p_core::proxy::ControlPlaneTransport as _;
    // **Said out loud rather than swallowed.** A probe that cannot connect is
    // the normal way this is misconfigured, and the QUIC stack's own error
    // names no host — so without this the operator sees
    // `QUIC_STATUS_UNREACHABLE` with nothing to point it at. The span this runs
    // inside carries the relay it belongs to.
    match transport.send("GET", "/health", &[], Vec::new()).await {
        Ok(response) if (200..300).contains(&response.status) => Some(()),
        Ok(response) => {
            tracing::debug!(
                status = response.status,
                "the relay answered /health with a non-success status"
            );
            None
        }
        Err(err) => {
            tracing::debug!(%err, "the relay did not answer /health");
            None
        }
    }
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
            let mut failures = 0u32;
            loop {
                let next = match round(&proxy, &listener_id, &opts).await {
                    Ok(()) => {
                        failures = 0;
                        REPORT_INTERVAL
                    }
                    Err(err) => {
                        // Never fatal. Losing a round costs ranking, never the
                        // listener: the control plane falls back to pool order,
                        // which is where it was before any of this existed.
                        tracing::debug!(
                            %err,
                            listener_id,
                            "a relay measurement round did not land"
                        );
                        // **But it must not spend the margin the half-window
                        // cadence exists to provide.** The interval is half the
                        // freshness window so a report always lands while the
                        // last one is still good; sleeping it after a failure
                        // spends that whole margin on one bad moment, and a
                        // listener whose *first* round fails would go half an
                        // hour with nothing published at all.
                        let delay = retry_delay(failures);
                        failures = failures.saturating_add(1);
                        delay
                    }
                };
                tokio::time::sleep(next).await;
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

/// What an observation round is worth sending.
///
/// **Relays that answered in nothing are left out, not sent empty.** An entry
/// with no families says exactly what omitting it says — "nothing measured" —
/// and the reports are positive-only (plan Q3), so there is no reading under
/// which the empty entry means more. Sending it would invite the control plane
/// to read it as "this relay works in neither family", which is the one thing
/// a probe that timed out does not establish.
fn reach_to_report(observed: Vec<(String, Vec<AddressFamily>)>) -> Vec<RelayReach> {
    observed
        .into_iter()
        .filter(|(_, families)| !families.is_empty())
        .map(|(dp_id, families)| RelayReach {
            dp_id,
            families: families
                .into_iter()
                .map(|family| family_name(family).to_owned())
                .collect(),
        })
        .collect()
}

/// Read the candidates, measure them, report what was measured.
async fn round(
    proxy: &ProxyClient<MasqueH3Transport>,
    listener_id: &str,
    opts: &ProbeOptions,
) -> anyhow::Result<()> {
    tracing::debug!(listener_id, "asking the proxy which relays to measure");
    let Some(candidates) = proxy.list_relays().await? else {
        // A proxy from before relay selection. Nothing to measure, and nothing
        // wrong: this is an optimization on top of a control plane that already
        // worked.
        //
        // **Worth a line even though nothing happens.** "This dialled nothing"
        // is what rules the probe out when some other QUIC connection in the
        // process is failing, and that is the question an operator arrives with.
        tracing::debug!("this proxy does not choose relays; measuring nothing, dialling nothing");
        return Ok(());
    };
    if candidates.is_empty() {
        // No registered relay: the control plane's own data path is the only
        // one there is, and there is nothing to choose between.
        tracing::debug!("the proxy has no registered relays; nothing to measure");
        return Ok(());
    }
    // **The list, before anything is dialled.** These base URLs are the
    // deployment's, not this process's, so when they are unreachable the answer
    // is here rather than in anything this side is configured with.
    for candidate in &candidates {
        tracing::debug!(
            dp_id = candidate.dp_id,
            base_url = candidate.base_url,
            "a relay to measure"
        );
    }
    let samples = measure(&candidates, opts).await;
    if samples.is_empty() {
        // **Not the same as reporting nothing.** An empty report would replace
        // the stored set with nothing, throwing away measurements that are
        // still fresh because this one round ran out of budget.
        anyhow::bail!("no relay finished its probe within the budget");
    }
    if samples.iter().all(|s| s.rtt_ms.is_none()) {
        // **"I cannot reach any relay" is a statement about this host, not
        // about the pool.** A few seconds of local trouble produces it, and
        // reporting it replaces a good set with one that rules every node out,
        // which makes the control plane skip this tenant's pool for half an
        // hour. Retrying shortly is the better answer; if the pool really has
        // gone, the stored rows lapse on their own window anyway.
        anyhow::bail!("every relay was unreachable, which is more likely to be this end");
    }
    // **After the bails on purpose.** It is below them because on a host with
    // no route to the deployment they are where the round ends, and probing
    // anyway would triple the failing dials each retry makes -- see
    // [`RETRY_IN`], whose whole cost model is that each attempt is one QUIC
    // connection whose failure the transport logs at `ERROR`. Past them, at
    // least one relay answered, so there is something to measure.
    let observed = observe_families(&candidates, opts.per_relay).await;
    let reach = reach_to_report(observed);
    let stored = proxy
        .report_relay_rtt(listener_id, &samples, &reach)
        .await?;
    tracing::debug!(
        listener_id,
        measured = samples.len(),
        unreachable = samples.iter().filter(|s| s.rtt_ms.is_none()).count(),
        // Relays, not families: one entry can name both.
        relays_with_families = reach.len(),
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
    // **Inside the budget, because the budget is a promise to the person
    // waiting on `connect`.** The control-plane transport has no request
    // timeout of its own, so an unanswered read here is bounded only by QUIC's
    // 30-second idle timeout — twenty times the delay this path advertises.
    // Half the budget for the read, leaving half to measure with.
    let listed = tokio::time::timeout(opts.budget / 2, proxy.list_relays()).await;
    let candidates = match listed {
        Ok(Ok(Some(candidates))) if !candidates.is_empty() => candidates,
        Ok(Ok(_)) => {
            tracing::debug!("no relays to measure; connecting unmeasured");
            return Vec::new();
        }
        Ok(Err(err)) => {
            tracing::debug!(%err, "could not read the relay candidates; connecting unmeasured");
            return Vec::new();
        }
        Err(_) => {
            tracing::debug!(
                "reading the relay candidates outran the budget; connecting unmeasured"
            );
            return Vec::new();
        }
    };
    let opts = ProbeOptions {
        budget: opts.budget / 2,
        ..opts.clone()
    };
    measure(&candidates, &opts).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use isekai_p2p_core::transport::{Binding, Connected};

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
            |_, _, _| async {},
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
        let samples = measure_with(&[candidate("dp1_slow")], &opts, |_, _, _| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
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
        let samples = measure_with(&[candidate("dp1_slow")], &opts, |_, _, _| async {
            tokio::time::sleep(Duration::from_secs(30)).await;
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
            |base_url, _, best| async move {
                if base_url.contains("dp1_stuck") {
                    // Never answers, and outlives both the budget and its own
                    // per-relay limit.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                }
                best.fetch_min(7, Ordering::Relaxed);
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
        let best = AtomicU32::new(NOTHING_YET);
        time_exchanges(3, &best, || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Some(())
            }
        })
        .await;
        assert_ne!(best.load(Ordering::Relaxed), NOTHING_YET);
        // Three timed exchanges plus the one that paid for the handshake.
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn a_relay_that_fails_its_warm_up_is_unreachable() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let best = AtomicU32::new(NOTHING_YET);
        time_exchanges(3, &best, || {
            let calls = calls.clone();
            async move {
                calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                None
            }
        })
        .await;
        assert_eq!(best.load(Ordering::Relaxed), NOTHING_YET);
        // And it stopped there rather than timing three more failures.
        assert_eq!(seen.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn the_fastest_exchange_is_the_one_kept() {
        // The floor of the path is what is wanted; a slow sample is queueing,
        // not distance.
        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let best = AtomicU32::new(NOTHING_YET);
        time_exchanges(3, &best, || {
            let nth = nth.clone();
            async move {
                let n = nth.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                // Warm-up is n == 0; the timed ones are slow, fast, slow.
                let ms = if n == 2 { 5 } else { 120 };
                tokio::time::sleep(Duration::from_millis(ms)).await;
                Some(())
            }
        })
        .await;
        let rtt = best.load(Ordering::Relaxed);
        assert!(rtt < 60, "kept {rtt}ms, which is not the fastest");
    }

    #[tokio::test]
    async fn a_relay_that_stops_answering_keeps_what_it_gave() {
        let nth = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let best = AtomicU32::new(NOTHING_YET);
        time_exchanges(3, &best, || {
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
        assert_ne!(best.load(Ordering::Relaxed), NOTHING_YET);
    }

    #[tokio::test]
    async fn a_slow_relay_keeps_what_it_measured_when_its_time_runs_out() {
        // **The regression.** The per-relay limit used to wrap the whole probe
        // and throw away everything it had collected, so a relay that answered
        // and was then cut off got reported as unreachable — the one verdict
        // that *removes* a relay from the session. Far is not absent, and at
        // roughly six round trips per probe a limit of 1.2s condemned every
        // relay past about 190ms: precisely the cross-continent nodes this
        // feature exists to rank.
        let opts = ProbeOptions {
            probes: 3,
            per_relay: Duration::from_millis(150),
            budget: Duration::from_secs(5),
        };
        let samples = measure_with(&[candidate("dp1_far")], &opts, |_, _, best| async move {
            // One sample lands, then the probe hangs past its limit.
            best.fetch_min(120, Ordering::Relaxed);
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;
        assert_eq!(
            samples,
            vec![RelayRttSample {
                dp_id: "dp1_far".into(),
                rtt_ms: Some(120),
            }]
        );
    }

    #[tokio::test]
    async fn a_sample_is_clamped_where_the_control_plane_would_clamp_it() {
        // The sentinel has to stay distinct from every storable value, and the
        // control plane clamps to the same ceiling anyway.
        let best = AtomicU32::new(NOTHING_YET);
        time_exchanges(1, &best, || async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            Some(())
        })
        .await;
        assert!(best.load(Ordering::Relaxed) <= MAX_RTT_MS);
        assert_ne!(MAX_RTT_MS, NOTHING_YET);
    }

    #[test]
    fn retrying_backs_off_to_the_ordinary_cadence() {
        // The first failure is probably a moment of trouble, so ask again soon.
        assert_eq!(retry_delay(0), RETRY_IN);
        assert_eq!(retry_delay(1), RETRY_IN * 2);
        // A deployment this host cannot reach does not improve by asking, and
        // every attempt costs a QUIC connection the transport logs at ERROR.
        // Settling at the ordinary cadence stops a misconfiguration printing
        // an unexplained error every minute forever.
        assert_eq!(retry_delay(20), REPORT_INTERVAL);
        assert!(retry_delay(9) <= REPORT_INTERVAL);
        // Doubling must not wrap and hand back something tiny.
        for n in 0..64 {
            assert!(retry_delay(n) >= RETRY_IN, "failure {n} retried too soon");
        }
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

    /// A landing on a real unconnected binding -- the ordinary case.
    fn on(remote: &str) -> Option<Landing> {
        Some(Landing {
            remote: remote.parse().unwrap(),
            binding: Binding::Unconnected,
        })
    }

    /// A landing the connector reports as a connected socket, for one of the
    /// reasons it has.
    fn connected(remote: &str, why: Connected) -> Option<Landing> {
        Some(Landing {
            remote: remote.parse().unwrap(),
            binding: Binding::Connected(why),
        })
    }

    #[test]
    fn a_dual_stack_relay_answers_on_both() {
        assert_eq!(
            families_answered([on("192.0.2.1:443"), on("[2001:db8::1]:443")]),
            vec![AddressFamily::V4, AddressFamily::V6]
        );
    }

    #[test]
    fn a_relay_that_answered_nothing_claims_nothing() {
        // Positive-only: an unreachable relay is reported as an empty set, not
        // as "neither family works" — a few seconds of local trouble looks
        // exactly like this, and it is not the relay's answer.
        assert_eq!(families_answered([None, None]), Vec::new());
    }

    #[test]
    fn a_v4_only_name_probed_for_v6_does_not_claim_v6() {
        // The whole reason the landing is read instead of the preference: the
        // v6 probe connected and answered, over v4. Claiming v6 here is what
        // would send the control plane to pick a family the leg cannot use.
        assert_eq!(
            families_answered([on("192.0.2.1:443"), on("192.0.2.1:443")]),
            vec![AddressFamily::V4]
        );
    }

    #[test]
    fn one_family_failing_leaves_the_other_standing() {
        assert_eq!(
            families_answered([None, on("[2001:db8::1]:443")]),
            vec![AddressFamily::V6]
        );
    }

    #[test]
    fn a_v4_mapped_remote_counts_as_the_family_it_is_on() {
        // `is_ipv6()` asks which socket address this is, not whether the bits
        // happen to spell an IPv4 address. A leg bound to v6 reaching a
        // v4-mapped peer is on v6, and that is the family the other end must
        // match.
        assert_eq!(
            families_answered([on("[::ffff:192.0.2.1]:443")]),
            vec![AddressFamily::V6]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dark_relay_early_in_the_list_does_not_cost_the_tail() {
        // The reason this is concurrent with a budget each rather than
        // sequential under one. The candidate order is stable, so under a
        // single shared cap the same relays at the end of the list would go
        // unobserved every round, forever -- which is the opposite of the
        // point of observing at all.
        let observed = observe_families_with(
            &[
                candidate("dp1_stuck"),
                candidate("dp1_also_stuck"),
                candidate("dp1_fine"),
            ],
            Duration::from_secs(3),
            |base_url, family| async move {
                if base_url.contains("stuck") {
                    // Outlives its own per-relay limit, let alone a shared one.
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                match family {
                    AddressFamily::V4 => on("192.0.2.9:443"),
                    AddressFamily::V6 => None,
                }
            },
        )
        .await;
        // By `dp_id`: a `JoinSet` finishes in whatever order it finishes.
        let mut observed = observed;
        observed.sort_by(|a, b| a.0.cmp(&b.0));
        assert_eq!(
            observed,
            vec![
                ("dp1_also_stuck".to_owned(), vec![]),
                ("dp1_fine".to_owned(), vec![AddressFamily::V4]),
                ("dp1_stuck".to_owned(), vec![]),
            ],
            "the relay at the end of the list was observed too"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_family_that_hangs_does_not_cost_the_one_that_answered() {
        // The likeliest shape of the problem this whole measurement is for: a
        // dual-stack relay whose AAAA address black-holes UDP/443. v4 answers,
        // v6 hangs past the budget -- and the v4 landing must survive. Under
        // one shared deadline the pair is cancelled together and the relay is
        // printed as `none`, which is a claim about a relay that demonstrably
        // answers on v4.
        let observed = observe_families_with(
            &[candidate("dp1_dark_v6")],
            Duration::from_secs(3),
            |_, family| async move {
                if family == AddressFamily::V6 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                on("192.0.2.9:443")
            },
        )
        .await;
        assert_eq!(
            observed,
            vec![("dp1_dark_v6".to_owned(), vec![AddressFamily::V4])]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_dead_v4_record_does_not_stop_v6_being_asked() {
        // The mirror, and sequentially it is certain rather than likely:
        // probing v4 first, a routable-but-dead A record means v6 is never
        // dialled at all and a v6-only relay reports `none`.
        let observed = observe_families_with(
            &[candidate("dp1_dark_v4")],
            Duration::from_secs(3),
            |_, family| async move {
                if family == AddressFamily::V4 {
                    tokio::time::sleep(Duration::from_secs(60)).await;
                }
                on("[2001:db8::9]:443")
            },
        )
        .await;
        assert_eq!(
            observed,
            vec![("dp1_dark_v4".to_owned(), vec![AddressFamily::V6])]
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_relay_that_answers_in_neither_family_claims_neither() {
        // Both hang: the positive-only answer, and still not "both are
        // broken".
        let observed = observe_families_with(
            &[candidate("dp1_dark")],
            Duration::from_secs(3),
            |_, _| async move {
                tokio::time::sleep(Duration::from_secs(60)).await;
                on("192.0.2.9:443")
            },
        )
        .await;
        assert_eq!(observed, vec![("dp1_dark".to_owned(), vec![])]);
    }

    #[test]
    fn what_is_sent_is_the_wire_spelling_the_plan_names() {
        // `["v6", "v4"]` in the plan's §4-4 example, and the same spelling
        // `RelayInfo.family` comes back in. A rename on either side silently
        // stops the two ends' sets from intersecting.
        let reach = reach_to_report(vec![(
            "dp_1".to_owned(),
            vec![AddressFamily::V6, AddressFamily::V4],
        )]);
        assert_eq!(
            serde_json::to_value(&reach).unwrap(),
            serde_json::json!([{ "dp_id": "dp_1", "families": ["v6", "v4"] }])
        );
    }

    #[test]
    fn a_relay_that_answered_in_nothing_is_left_out_rather_than_sent_empty() {
        // An empty entry says what omitting it says, and inviting the control
        // plane to read it as "neither family works" is the one thing a probe
        // that timed out does not establish.
        let reach = reach_to_report(vec![
            ("dp_dark".to_owned(), vec![]),
            ("dp_fine".to_owned(), vec![AddressFamily::V4]),
        ]);
        assert_eq!(
            serde_json::to_value(&reach).unwrap(),
            serde_json::json!([{ "dp_id": "dp_fine", "families": ["v4"] }])
        );
    }

    #[test]
    fn an_observation_round_that_measured_nothing_sends_nothing() {
        assert!(reach_to_report(vec![("dp_a".to_owned(), vec![])]).is_empty());
        assert!(reach_to_report(Vec::new()).is_empty());
    }

    #[test]
    fn a_connected_fallback_claims_nothing_whatever_its_reason() {
        // The probe succeeded, over a *connected* socket the connector
        // substituted. Reporting the family here is exactly the over-claim the
        // plan's Q2 exists to prevent: a leg's unconnected binding cannot
        // reproduce it. All four reasons the connector gives are the same
        // answer to this question -- which is why it is asked of the reported
        // binding and not of the addresses, and why this iterates the variants
        // rather than only those reachable here. `QmuxFallback` is not
        // reachable: the measuring transport is built without a QMUX
        // configuration at all. The property is "no connected binding is ever
        // credited", which has to hold for a variant that becomes reachable
        // later too.
        for why in [
            Connected::AsAsked,
            Connected::ClatStub,
            Connected::NoRoutableAddress,
            Connected::QmuxFallback,
        ] {
            assert_eq!(
                families_answered([connected("192.0.2.1:443", why)]),
                Vec::new(),
                "{why:?} is not an unconnected binding"
            );
        }
    }

    #[test]
    fn a_connected_fallback_does_not_poison_the_other_family() {
        assert_eq!(
            families_answered([
                connected("192.0.2.1:443", Connected::ClatStub),
                on("[2001:db8::1]:443"),
            ]),
            vec![AddressFamily::V6]
        );
    }
}
