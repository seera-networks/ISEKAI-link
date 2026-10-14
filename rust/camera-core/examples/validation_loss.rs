//! Does a lost PATH_RESPONSE still cost the path?
//!
//! H3 of `docs/isekai_p2p_datapath_hook_plan.md`, and the measurement
//! `docs/relay_repath_plan.md` spent four runs and two retractions not being
//! able to make.
//!
//! # What it is asking
//!
//! §7.13 traced why a re-attached relay path never validated: the challenger
//! sends **one** PATH_CHALLENGE, the answerer's PATH_RESPONSE is lost, and
//! nothing recovers it — the challenge packet was acknowledged so loss
//! detection is silent, a responder must not re-send a response, and the
//! validation timer only abandons. The path died at the deadline with the
//! network recovered 200 ms earlier.
//!
//! seera-msquic#130 fixed it by re-sending the challenge at thirds of the
//! deadline. **This asks the question from our side**: lose the response on
//! purpose and see whether the path still comes up.
//!
//! | | |
//! | --- | --- |
//! | before #130 | no `PathAdded`; the path is abandoned at the deadline |
//! | after #130 | `PathAdded`, **late** — at the first retry boundary, not in microseconds |
//!
//! The lateness is the signature. A run that validated in its usual
//! microseconds would mean the drop missed the response, not that the fix
//! worked, so **the time is the assertion** and the two cases are printed
//! side by side.
//!
//! # Why an example and not a test
//!
//! The portal loopback harness dials with migration off, so its client has no
//! multipath and nothing to `add_path` with. Turning it on would also turn on
//! direct-path advertisement, and a path that quietly avoids the seam is the
//! §1.4 failure this plan already made once. Here the endpoints are built for
//! the question and nothing else is in the way.
//!
//! ```sh
//! cargo run -p camera-core --example validation_loss
//! ```

use std::io::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use isekai_p2p::agent::{DatapathHook, Hop, Verdict};
use msquic_async::{msquic, Connection, ConnectionEvent, Listener, Registration};
use std::future::poll_fn;
use tokio_util::sync::CancellationToken;

const ALPN: &str = "validation-loss";

/// Below this a path validated on its own; above it, a timer did it.
///
/// **The discriminator is absolute, not relative.** The earliest a retry can
/// land is `Timeout / 3`, and the smallest `Timeout` in play is the
/// `6 × InitialRtt` floor of 1.998 s, so no retry arrives before ~666 ms, while
/// every ordinary validation measured here is 2.6–17 ms. A multiplier on the
/// control cannot separate those: a control at the fast end of that range sets
/// a bar of ~12 ms, which a lossy run that *missed* the response and validated
/// normally at ~13 ms would clear — and then print the one conclusion this
/// file exists to avoid printing by accident.
const RETRY_FLOOR: Duration = Duration::from_millis(500);

/// The smallest the abandonment deadline gets, and so the latest a `PathAdded`
/// can be and still be plainly a retry.
///
/// The deadline is `PathValidationStartTime + max(3 × PTO, 6 × InitialRtt)`,
/// recomputed every time the timer is armed. Once the challenge has been acked
/// — which it is, within microseconds, and which is §7.13's whole point — the
/// path has an RTT sample, `3 × PTO` collapses, and the `6 × 333 ms` floor is
/// what remains.
const SAMPLED_DEADLINE: Duration = Duration::from_millis(1_998);

/// The largest the deadline gets: a path that never got an RTT sample keeps
/// `SmoothedRtt = InitialRtt = 333 ms` and `RttVariance = SmoothedRtt / 2`
/// (`path.c:38`), so `PTO = 333 + 4 × 166.5 + 25 = 1024 ms` — the 25 being the
/// peer's default `max_ack_delay` — and `3 × PTO = 3.072 s` wins.
///
/// Between the two the answer depends on which regime the path was in, so the
/// verdicts between them say "look", not "the fix worked".
const UNSAMPLED_DEADLINE: Duration = Duration::from_millis(3_072);

/// The padded PATH_CHALLENGE fills the MTU; a PATH_RESPONSE does not.
const BIG: usize = 1000;

/// Passes the challenge out, then eats the replies that would answer it.
///
/// **Size on the way out, count on the way back.** The challenge is padded to
/// the MTU so it is recognisable; the response is small and shares its packet
/// with whatever else the answerer had to say, so there is nothing to recognise
/// it by — the first few packets back after a challenge is the best available
/// aim, and how many is a measurement (see the call site). §3.3 of the plan is
/// the general version of this problem.
struct EatTheAnswer {
    /// Set once the challenge has gone out, so the replies being eaten are the
    /// ones answering it rather than the handshake's.
    challenged: AtomicBool,
    budget: AtomicUsize,
    ate: AtomicUsize,
}

impl EatTheAnswer {
    fn new(replies: usize) -> Arc<Self> {
        Arc::new(Self {
            challenged: AtomicBool::new(false),
            budget: AtomicUsize::new(replies),
            ate: AtomicUsize::new(0),
        })
    }
}

impl DatapathHook for EatTheAnswer {
    fn outbound(&self, packet: &[u8]) -> Verdict {
        if packet.len() >= BIG {
            // `Release`, paired with the `Acquire` below: the two run on
            // different tasks, and a flag seen without its budget would let a
            // reply through and make the run say the fix worked when nothing
            // was dropped.
            self.challenged.store(true, Ordering::Release);
        }
        Verdict::Pass
    }

    fn inbound(&self, _packet: &[u8]) -> Verdict {
        if !self.challenged.load(Ordering::Acquire) {
            return Verdict::Pass;
        }
        if self
            .budget
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
                left.checked_sub(1)
            })
            .is_ok()
        {
            self.ate.fetch_add(1, Ordering::Relaxed);
            Verdict::Drop
        } else {
            Verdict::Pass
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);

    // The control first, so a run that cannot validate at all is obvious before
    // any loss is blamed for it.
    let clean = one_run(&reg, 0).await?;
    report("no loss", &clean);

    // **Two, measured.** One is not enough: a single drop still validates in
    // ~2.6 ms, so the response is not the first packet back -- something else
    // (the answerer's ack, or its own challenge) is ahead of it.
    //
    // Three and four both land at 1.334 s, which is the *second* boundary, and
    // placing it is what turned up the recomputed `Timeout` the two constants
    // above are about: `2 x 1.998/3 = 1.332 s` once the path has an RTT sample,
    // not the `2 x 3.072/3 = 2.048 s` a constant `Timeout` would predict.
    let lossy = one_run(&reg, 2).await?;
    report("the answer lost", &lossy);

    println!();
    let Outcome::Added(fast) = clean.outcome else {
        println!(
            "INCONCLUSIVE: the control did not validate either, so this run says \
             nothing about #130",
        );
        return Ok(());
    };
    // **Every arm that draws a conclusion checks that something was dropped.**
    // If the detector misses -- padding changes, or `add_path` stops routing
    // through the hop -- the lossy run is just another control, and a run that
    // injected no loss must not be allowed to report a verdict about loss.
    match lossy.outcome {
        Outcome::Closed => println!(
            "INCONCLUSIVE: the lossy connection ended rather than running out of \
             window, so the absence of PathAdded says nothing about the path",
        ),
        Outcome::Unwatched => println!(
            "INCONCLUSIVE: the watcher failed, so this run observed nothing -- \
             the connection and the path are both unmeasured",
        ),
        _ if lossy.ate == 0 => println!(
            "INCONCLUSIVE: nothing was dropped -- the challenge detector never \
             tripped, so this was a second control, not a lossy run",
        ),
        Outcome::Abandoned => println!(
            "BEFORE #130: a lost PATH_RESPONSE still costs the path -- the \
             challenge is not being re-sent",
        ),
        Outcome::Added(slow) if slow < RETRY_FLOOR => println!(
            "UNEXPECTED: validated in {slow:?} against a {fast:?} control, with \
             {} packet(s) dropped. Below the {RETRY_FLOOR:?} floor, so no timer \
             was involved -- look at whether the drop hit the response",
            lossy.ate,
        ),
        Outcome::Added(slow) if slow < SAMPLED_DEADLINE => println!(
            "AFTER #130: the path came up anyway, and {slow:?} -- past the \
             {RETRY_FLOOR:?} floor against a {fast:?} control -- is the retry \
             doing it rather than the drop having missed",
        ),
        Outcome::Added(slow) if slow < UNSAMPLED_DEADLINE => println!(
            "LOOK: validated in {slow:?}, which is past the {SAMPLED_DEADLINE:?} \
             deadline a path with an RTT sample has. Only a path that never got \
             one can still be validating here, so say which before calling this \
             the retry",
        ),
        Outcome::Added(slow) => println!(
            "UNEXPECTED: validated in {slow:?}, past the {UNSAMPLED_DEADLINE:?} \
             deadline in every regime -- the path should have been abandoned, so \
             this is not #130's retry",
        ),
    }
    Ok(())
}

struct Run {
    outcome: Outcome,
    ate: usize,
}

/// **Not two outcomes.** "No `PathAdded`" has several causes that mean
/// different things — the path was abandoned at its deadline, which is the
/// result this example exists to see; the connection itself ended, which says
/// nothing about the path; or the watcher died, which says nothing about
/// either. Conflating them would let a failure elsewhere print a conclusion
/// about the path, or point the diagnosis at the wrong subsystem.
enum Outcome {
    /// How long `add_path` took to produce `PathAdded`.
    Added(Duration),
    /// The window passed with the connection still alive.
    Abandoned,
    /// The connection ended first.
    Closed,
    /// The watching task itself failed, so nothing was observed.
    Unwatched,
}

fn report(what: &str, run: &Run) {
    let said = match run.outcome {
        Outcome::Added(took) => format!("PathAdded after {took:?}"),
        Outcome::Abandoned => "no PathAdded within the window".to_owned(),
        Outcome::Closed => "the connection ended before any PathAdded".to_owned(),
        Outcome::Unwatched => "nothing was watching -- the watcher failed".to_owned(),
    };
    println!("{what:>16}: {said} ({} dropped)", run.ate);
}

async fn one_run(reg: &Arc<Registration>, eat: usize) -> anyhow::Result<Run> {
    let (client, _server, listener) = pair(reg).await?;
    let server_addr = listener.local_addr().context("the listener's address")?;

    let hook = EatTheAnswer::new(eat);
    let shutdown = CancellationToken::new();
    let hop = Hop::start(server_addr, hook.clone(), shutdown.clone())
        .await
        .context("start the hop")?;

    // **Polling before the call**, which is what §5-5 had to be re-measured
    // for: a clock that starts after `add_path` returns and nothing draining
    // the queue measures partly how long until somebody looked.
    let mut watcher = {
        let c = client.clone();
        tokio::spawn(async move {
            loop {
                match poll_fn(|cx| c.poll_event(cx)).await {
                    Ok(ConnectionEvent::PathAdded { .. }) => return Some(Instant::now()),
                    Ok(_) => continue,
                    Err(_) => return None,
                }
            }
        })
    };
    tokio::time::sleep(Duration::from_millis(200)).await;

    let began = Instant::now();
    client
        .add_path(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), hop.addr())
        .context("add_path to the hop")?;

    // Past `DEADLINE` with room to spare, so "it never came up" is a measurement
    // rather than a short wait. On expiry the handle is **aborted**, not just
    // dropped: dropping detaches, and the task holds a `Connection` clone, so
    // the connection this run is done with would outlive it.
    let outcome = match tokio::time::timeout(Duration::from_secs(8), &mut watcher).await {
        Ok(Ok(Some(at))) => Outcome::Added(at - began),
        // `poll_event` returned an error, which is the connection ending.
        Ok(Ok(None)) => Outcome::Closed,
        // The watcher panicked. Nothing was observed, and in particular this
        // is not the connection ending -- saying so would blame the wrong
        // thing and bury the panic.
        Ok(Err(_)) => Outcome::Unwatched,
        Err(_) => {
            watcher.abort();
            Outcome::Abandoned
        }
    };

    shutdown.cancel();
    hop.stopped().await;
    Ok(Run {
        outcome,
        ate: hook.ate.load(Ordering::Relaxed),
    })
}

/// A multipath pair over loopback, set up the way the shipping client is.
///
/// The same shape as `path_stats_wedge`'s, which is where it came from —
/// examples cannot import one another, and the alternative is a crate for
/// sixty lines.
async fn pair(reg: &Arc<Registration>) -> anyhow::Result<(Connection, Connection, Listener)> {
    let cert = camera_core::tls::dev_cert(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])?;
    let alpn = [msquic::BufferRef::from(ALPN)];
    let common = || {
        msquic::Settings::new()
            .set_IdleTimeoutMs(30_000)
            .set_DatagramReceiveEnabled()
            .set_ReceiveObservedAddressReports()
            .set_MultipathEnabled()
            .set_PathKeepAliveIntervalMs(5_000)
            .set_AddAddressMode(msquic::AddAddressMode::NatTraversal)
    };

    let server_config = reg.open_configuration(&alpn, Some(&common()))?;
    let mut cert_file = tempfile::NamedTempFile::new()?;
    cert_file.write_all(cert.cert_pem.as_bytes())?;
    let cert_path = cert_file.into_temp_path();
    let mut key_file = tempfile::NamedTempFile::new()?;
    key_file.write_all(cert.key_pem.as_bytes())?;
    let key_path = key_file.into_temp_path();
    server_config.load_credential(&msquic::CredentialConfig::new().set_credential(
        msquic::Credential::CertificateFile(msquic::CertificateFile::new(
            key_path.to_string_lossy().into_owned(),
            cert_path.to_string_lossy().into_owned(),
        )),
    ))?;
    let listener = Listener::new(reg, server_config).context("listener new")?;
    listener
        .start(&alpn, Some("127.0.0.1:0".parse()?))
        .context("listener start")?;
    let addr = listener.local_addr().context("listener local_addr")?;

    let client_config = reg.open_configuration(&alpn, Some(&common()))?;
    client_config.load_credential(
        &msquic::CredentialConfig::new_client()
            .set_credential_flags(msquic::CredentialFlags::NO_CERTIFICATE_VALIDATION),
    )?;

    let client = Connection::new(reg).context("client connection")?;
    // The three `direct_path::prepare` makes before `start`, without which
    // `add_path` has no binding to open a path from.
    client.set_share_binding(true).context("share binding")?;
    client
        .set_unconnected_socket(true)
        .context("unconnected socket")?;
    client
        .set_local_addr(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .context("pinning the client to loopback")?;

    let (started, accepted) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(
            client.start(&client_config, "127.0.0.1", addr.port()),
            listener.accept(),
        )
    })
    .await
    .context("the handshake did not complete within 10s")?;
    started.context("client start")?;
    let server = accepted.context("accept")?;
    Ok((client, server, listener))
}
