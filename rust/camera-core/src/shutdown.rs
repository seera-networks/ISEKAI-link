//! Winding msquic down so the process can actually exit.
//!
//! Dropping a `Registration` calls `RegistrationClose`, which lands in
//! `CxPlatRundownReleaseAndWait` — a synchronous, uninterruptible wait on a
//! rundown reference that every connection, listener and stream derived from it
//! holds. Drop it while anything is still open and the process hangs there with
//! no way out.
//!
//! `Registration::shutdown()` does not fix that on its own: it queues shutdown
//! on connections and stops listeners, but closes nothing. The handles — and
//! their rundown references — live until the tasks owning them drop them.
//! `wait_idle()` is the signal that they have.
//!
//! See `docs/registration-wait-idle-design.md` in the `msquic-async-rs`
//! submodule for the full contract.

use std::time::Duration;

use msquic_async::Registration;

/// Ask `reg` to shut down and wait until no connection or listener holds it.
///
/// Takes a reference and never touches ownership: **closing the registration is
/// the caller's problem, and on an exit path the answer is not to.** `wait_idle`
/// does not cover application-owned client `Configuration`s (see §7 of the
/// design) — one outstanding anywhere and `RegistrationClose` waits on its
/// rundown reference, uninterruptibly, after the timeout has already been
/// satisfied. That is a hang no timeout can save you from, and there is nothing
/// to gain from closing a registration in a process that is about to exit.
///
/// The wait is still worth doing: it gives msquic time to send
/// CONNECTION_CLOSE, so peers learn immediately instead of timing out.
///
/// Cancel whatever owns the connections and listeners *before* calling this —
/// `wait_idle()` waits for them to be dropped, it does not cause it.
///
/// Returns whether everything closed within `timeout`.
pub async fn drain_registration(reg: &Registration, timeout: Duration) -> bool {
    // The rule this encodes is not a camera one: a registration dropped with a
    // live handle blocks forever, whatever the handle was carrying. It lives in
    // `isekai_p2p::peer` now (plan §4.4 slice 1) and this stays as the name the
    // camera apps already call.
    isekai_p2p::peer::drain_registration(reg, timeout).await
}

/// Wind down both registrations a camera app runs on, then leave the process.
///
/// There are two: the application's own, which carries the video listener or
/// connection and the relay legs, and `isekai-p2p-core`'s shared one, which the
/// P2P control-plane transports open for themselves. Draining one and not the
/// other still leaves handles open.
///
/// **Never returns.** Exits via `_exit(2)`, skipping atexit handlers and C++
/// static destructors — which is the point: returning would drop the tokio
/// runtime and then the registrations, and `RegistrationClose` blocks on any
/// `Configuration` still outstanding no matter how long the drain waited. That
/// is the hang this exists to remove, and nothing after this point needs to
/// run. `stdout` and `stderr` are flushed first.
pub async fn shutdown_and_exit(app: &Registration, timeout: Duration, code: i32) -> ! {
    // Independent of each other, but both must happen. Logged step by step:
    // if a future version ever stops here, the last line printed says which
    // registration it stopped on.
    tracing::debug!("draining msquic before exit");
    let core = isekai_p2p::agent::drain_msquic(timeout).await;
    tracing::debug!(drained = core, "control-plane registration done");
    let own = drain_registration(app, timeout).await;
    tracing::debug!(drained = own, "application registration done");

    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    unsafe { libc_exit(code) }
}

// Raw libc `_exit`: terminate now, running nothing on the way out.
unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn registration() -> std::sync::Arc<Registration> {
        std::sync::Arc::new(
            Registration::new(&msquic_async::msquic::RegistrationConfig::default())
                .expect("open a registration"),
        )
    }

    /// Nothing was ever opened, so there is nothing to wait for.
    #[tokio::test]
    async fn an_idle_registration_drains_immediately() {
        assert!(drain_registration(&registration(), Duration::from_secs(5)).await);
    }

    // The timeout branch is deliberately not tested: exercising it means
    // leaving a handle open, and then msquic's static destructors abort the
    // test process at exit. `tokio::time::timeout` is what guarantees it
    // returns rather than hangs, and that needs no test of ours.

    /// The contract that matters: once the listener is gone the registration
    /// drains, so `RegistrationClose` has nothing left to block on. This is
    /// what the camera apps depend on to exit at all.
    #[tokio::test]
    async fn drains_once_the_listener_is_dropped() {
        let reg = registration();
        let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let (reg, listener, _bound) =
            crate::bind_video_listener(Some(reg), addr, None).expect("bind the video listener");
        drop(listener);
        assert!(drain_registration(&reg, Duration::from_secs(5)).await);
    }
}
