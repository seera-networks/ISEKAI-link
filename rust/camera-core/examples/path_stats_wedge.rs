//! When does a blocking path call stop coming back?
//!
//! `multipath_spike`'s question 8 could not ask whether a validated path returns
//! its slot, because asking wedged: straight after question 7's observation
//! window the second `get_path_statistics` never returned, twice, and 900
//! seconds was not a timeout. `get_path_statistics` queues an operation to
//! msquic's connection worker and **blocks the calling thread** until it runs,
//! so a stuck worker takes the caller with it — and under tokio, the runtime.
//!
//! That matters past the spike. `portal_core::path` polls connection events and
//! reads per-path statistics from one loop, and a `select!` whose tick arm wins
//! drops a half-polled `poll_event` and then makes exactly that blocking call.
//! If a cancelled poll is what wedges, the shipping loop can wedge.
//!
//! **The trick that turns a wedge into a measurement** is to make the blocking
//! call on a thread of its own and wait on a channel with a deadline. The stuck
//! thread stays stuck, but this process can say so and go on to the next probe,
//! which is what `gdb` could not do here: `ptrace_scope` is 1, so nothing can
//! attach to a sibling after the fact.
//!
//! Probes, in order, stopping at the first wedge:
//!
//! | # | After this | then N blocking calls |
//! | --- | --- | --- |
//! | 1 | nothing — a quiet connection | the baseline |
//! | 4 | a `poll_event` cancelled while Pending | does cancelling alone do it? |
//! | 5 | a doomed path, its events consumed as they arrive | question 7's shape |
//! | 6 | a doomed path, its events left unread | is it the pending events? |
//! | 7 | a `select!` over two connections, looped | the window's own shape |
//!
//! Probes 2 and 3 are not about the wedge: they are the slot timings
//! `multipath_spike`'s question 8 could not take, and they run first because
//! everything below leaves paths behind.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use msquic_async::{msquic, Connection, ConnectionEvent, Listener, Registration};
use std::future::poll_fn;
use std::io::Write as _;
use std::sync::Arc;

const ALPN: &str = "path-stats-wedge";

/// How long a blocking call gets before it is called wedged.
///
/// Two orders of magnitude over a call that returns in microseconds when the
/// worker is healthy, and short enough that four probes stay a quick run.
const WEDGE_LIMIT: Duration = Duration::from_secs(10);

/// How many blocking calls each probe makes.
///
/// More than one because the wedge was never the first: in the spike the call
/// right after the window returned and the one after it did not.
const CALLS: usize = 3;

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() -> anyhow::Result<()> {
    let reg = Arc::new(Registration::new(&msquic::RegistrationConfig::default())?);
    let (client, _server, _listener) = pair(&reg).await.context("standing up a pair")?;

    // 1. The baseline. If this wedges, nothing below means anything.
    if !probe("1. a quiet connection", &client, || {}).await {
        return Ok(());
    }

    // 2 and 3. How long does a slot take to come back, and for which kind of
    // path? **First, on a connection nothing has perturbed yet.** Run after the
    // wedge probes below, these answered nothing twice over: the count was
    // already at `QUIC_MAX_PATH_COUNT` so there was no room to open anything,
    // and by then removing a path had started the connection closing, so
    // `add_path` came back `QUIC_STATUS_INVALID_STATE` rather than a measurement.
    //
    // The window is generous because the answer depended on it. Measured over
    // fifteen seconds a validated path's slot "never" came back; the very next
    // run of the same binary saw it come back. **One run is not a measurement**
    // — three say 252ms.
    const SLOT_WINDOW: Duration = Duration::from_secs(60);

    // A path that never validates, abandoned by msquic itself.
    let doomed = silent_socket().context("a socket that never answers")?;
    let doomed_addr = doomed.local_addr().context("its address")?;
    client
        .add_path(SocketAddr::new(doomed_addr.ip(), 0), doomed_addr)
        .context("opening a doomed path")?;
    let Some(Ok(with_doomed)) = timed("2. the count with a doomed path", {
        let c = client.clone();
        move || c.get_path_statistics().map(|s| s.len())
    }) else {
        return Ok(());
    };
    match slot_back(&client, with_doomed, SLOT_WINDOW).await {
        Some((took, now)) => println!(
            "ANSWER a path that never validated: slot back after {took:?} \
             ({with_doomed} -> {now})"
        ),
        None => println!(
            "ANSWER a path that never validated: slot NOT back within {SLOT_WINDOW:?} \
             (still {with_doomed})"
        ),
    }

    // And one that does validate, removed by hand. The listener's own address
    // validates, because the far side answers the challenge.
    let server_addr = _listener.local_addr().context("the listener's address")?;
    client
        .add_path(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), server_addr)
        .context("opening a path that should validate")?;
    let events = watch_both(&client, &_server, Duration::from_secs(5)).await;
    let Some(Ok(with_valid)) = timed("3. the count with a validated path", {
        let c = client.clone();
        move || c.get_path_statistics().map(|s| s.len())
    }) else {
        return Ok(());
    };
    println!("      (opened a path to {server_addr}, {events} events, count {with_valid})");
    let Some(removed) = timed("3. remove_path on the validated path", {
        let c = client.clone();
        move || c.remove_path(SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)), server_addr)
    }) else {
        return Ok(());
    };
    match slot_back(&client, with_valid, SLOT_WINDOW).await {
        Some((took, now)) => println!(
            "ANSWER a validated path removed ({removed:?}): slot back after {took:?} \
             ({with_valid} -> {now})"
        ),
        None => println!(
            "ANSWER a validated path removed ({removed:?}): slot NOT back within \
             {SLOT_WINDOW:?} (still {with_valid})"
        ),
    }

    // 4. A cancelled poll on its own. `poll_event` with no event waiting
    // registers a waker and returns Pending; the timeout drops the future with
    // that waker registered, which is what a `select!` tick arm does.
    let cancelled = {
        let c = client.clone();
        move || {
            let handle = tokio::runtime::Handle::current();
            handle.block_on(async {
                let _ = tokio::time::timeout(
                    Duration::from_millis(200),
                    poll_fn(|cx| c.poll_event(cx)),
                )
                .await;
            });
        }
    };
    if !probe(
        "4. a poll_event cancelled while Pending",
        &client,
        cancelled,
    )
    .await
    {
        return Ok(());
    }

    // 5. `multipath_spike`'s question 7 shape: a path that can never validate, its events read as
    // they arrive, then the window ends by dropping a half-polled future.
    let doomed_b = silent_socket().context("another socket that never answers")?;
    let doomed_b_addr = doomed_b.local_addr().context("its address")?;
    client
        .add_path(SocketAddr::new(doomed_b_addr.ip(), 0), doomed_b_addr)
        .context("opening a doomed path")?;
    let mut seen = Vec::new();
    let watching = Instant::now();
    while watching.elapsed() < Duration::from_secs(8) {
        let left = Duration::from_secs(8) - watching.elapsed();
        if let Ok(Ok(ConnectionEvent::PathRemoved { path_id, .. })) =
            tokio::time::timeout(left, poll_fn(|cx| client.poll_event(cx))).await
        {
            seen.push(path_id);
        }
    }
    println!("      (a doomed path was opened; PathRemoved seen for {seen:?})");
    if !probe("5. a doomed path, events consumed", &client, || {}).await {
        return Ok(());
    }

    // 6. The same, with nothing reading the events. If the worker is blocked
    // because the application never took what it was handed, this is where it
    // shows and probe 3 is the accident.
    let doomed2 = silent_socket().context("another socket that never answers")?;
    let doomed2_addr = doomed2.local_addr().context("its address")?;
    client
        .add_path(SocketAddr::new(doomed2_addr.ip(), 0), doomed2_addr)
        .context("opening a second doomed path")?;
    tokio::time::sleep(Duration::from_secs(8)).await;
    println!("      (a second doomed path was opened and its events left unread)");
    if !probe("6. a doomed path, events unread", &client, || {}).await {
        return Ok(());
    }

    // 7. The window's own shape: a `select!` over *both* connections inside a
    // `timeout`, looped, which is what question 7 does and what probe 2 did not.
    // Every iteration drops a half-polled `poll_event` on the losing side.
    let events = watch_both(&client, &_server, Duration::from_secs(10)).await;
    println!("      (watched both connections for 10s, {events} events)");
    if !probe("7. a select! over two connections, looped", &client, || {}).await {
        return Ok(());
    }

    Ok(())
}

/// Run `before`, then [`CALLS`] blocking `get_path_statistics` calls, each on a
/// thread of its own with a deadline.
///
/// Returns whether every call came back, so the caller can stop: once a worker
/// is wedged every later probe reports the same thing for the same reason.
async fn probe<F>(what: &str, conn: &Connection, before: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    let setup = tokio::task::spawn_blocking(before).await;
    if setup.is_err() {
        println!("WEDGE {what}: the setup itself panicked");
        return false;
    }
    for n in 1..=CALLS {
        let c = conn.clone();
        let (tx, rx) = mpsc::channel();
        std::thread::spawn(move || {
            let at = Instant::now();
            let r = c.get_path_statistics().map(|s| s.len());
            let _ = tx.send((at.elapsed(), r));
        });
        match rx.recv_timeout(WEDGE_LIMIT) {
            Ok((took, Ok(paths))) => {
                println!("ok    {what}: call {n}/{CALLS} -> {paths} paths in {took:?}")
            }
            Ok((took, Err(e))) => {
                println!("ok    {what}: call {n}/{CALLS} -> error in {took:?}: {e}");
            }
            Err(_) => {
                println!(
                    "WEDGE {what}: call {n}/{CALLS} did not return within {WEDGE_LIMIT:?} \
                     -- the thread making it is still blocked"
                );
                return false;
            }
        }
    }
    true
}

/// Run one blocking call on a thread of its own, with a deadline.
///
/// `None` means it never came back. The thread stays blocked -- there is no way
/// to cancel a call already inside the core -- so a caller that gets `None`
/// should stop asking rather than pile more threads on a stuck worker.
fn timed<T, F>(what: &str, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    timed_inner(what, f, true)
}

/// [`timed`], printing only when it wedges.
///
/// For a loop that would otherwise bury the answer in its own progress.
fn timed_quiet<T, F>(what: &str, f: F) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    timed_inner(what, f, false)
}

fn timed_inner<T, F>(what: &str, f: F, loud: bool) -> Option<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let at = Instant::now();
        let r = f();
        let _ = tx.send((at.elapsed(), r));
    });
    match rx.recv_timeout(WEDGE_LIMIT) {
        Ok((took, r)) => {
            if loud {
                println!("ok    {what} in {took:?}");
            }
            Some(r)
        }
        Err(_) => {
            println!(
                "WEDGE {what} did not return within {WEDGE_LIMIT:?} -- the thread making \
                 it is still blocked"
            );
            None
        }
    }
}

/// Poll both connections the way `multipath_spike`'s windows do: a `select!`
/// inside a `timeout`, looped, so every iteration drops a half-polled future on
/// whichever connection lost the race.
async fn watch_both(client: &Connection, server: &Connection, how_long: Duration) -> usize {
    let started = Instant::now();
    let mut events = 0;
    while started.elapsed() < how_long {
        let left = how_long - started.elapsed();
        let got = tokio::time::timeout(left, async {
            tokio::select! {
                e = poll_fn(|cx| client.poll_event(cx)) => e.is_ok(),
                e = poll_fn(|cx| server.poll_event(cx)) => e.is_ok(),
            }
        })
        .await;
        match got {
            Ok(true) => events += 1,
            Ok(false) => break,
            Err(_) => break,
        }
    }
    events
}

/// Wait for the path count to fall below `target`, reporting how long it took.
///
/// **Generous, because the answer turned out to depend on it.** A fifteen-second
/// window said a validated path's slot never came back; the next run of the same
/// code said it came back fine. One run is not a measurement.
async fn slot_back(conn: &Connection, target: usize, limit: Duration) -> Option<(Duration, usize)> {
    let started = Instant::now();
    while started.elapsed() < limit {
        let now = timed_quiet("waiting for a slot", {
            let c = conn.clone();
            move || c.get_path_statistics().map(|s| s.len())
        })?
        .ok()?;
        if now < target {
            return Some((started.elapsed(), now));
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    None
}

/// A bound socket nobody reads, so datagrams arrive and nothing answers.
///
/// Held by the caller: dropping it would close the port and turn silence into
/// ICMP, which tears the path down for a different reason.
fn silent_socket() -> anyhow::Result<std::net::UdpSocket> {
    Ok(std::net::UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))?)
}

/// A multipath pair over loopback, set up the way the shipping client is.
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
