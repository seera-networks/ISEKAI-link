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

use std::sync::Arc;
use std::time::Duration;

use msquic_async::Registration;

/// Ask `reg` to shut down, wait until nothing holds it, and drop it.
///
/// Returns whether it drained within `timeout`. On timeout the registration is
/// deliberately **leaked** rather than dropped: something still holds a handle,
/// so dropping it would hang, and the caller is expected to leave the process
/// without running destructors.
///
/// Cancel whatever owns the connections and listeners *before* calling this —
/// `wait_idle()` waits for them to be dropped, it does not cause it.
pub async fn drain_registration(reg: Arc<Registration>, timeout: Duration) -> bool {
    reg.shutdown();
    match tokio::time::timeout(timeout, reg.wait_idle()).await {
        Ok(()) => {
            // Last reference (the caller's tasks are gone by now), so this
            // runs RegistrationClose with nothing left for it to wait on.
            drop(reg);
            true
        }
        Err(_) => {
            tracing::warn!(
                ?timeout,
                "msquic registration still has live handles; leaking it rather than blocking",
            );
            std::mem::forget(reg);
            false
        }
    }
}

/// Wind down both registrations a camera app runs on.
///
/// There are two: the application's own, which carries the video listener or
/// connection and the relay legs, and `isekai-p2p-core`'s shared one, which the
/// P2P control-plane transports open for themselves. Draining one and not the
/// other still hangs.
///
/// Returns whether both drained. A `false` means the caller should exit without
/// running destructors.
pub async fn shutdown_msquic_stack(app: Arc<Registration>, timeout: Duration) -> bool {
    // Order does not matter — they are independent — but both must happen.
    let core = isekai_p2p::agent::shutdown_msquic(timeout).await;
    let app = drain_registration(app, timeout).await;
    core && app
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn registration() -> Arc<Registration> {
        Arc::new(
            Registration::new(&msquic_async::msquic::RegistrationConfig::default())
                .expect("open a registration"),
        )
    }

    /// Nothing was ever opened, so there is nothing to wait for.
    #[tokio::test]
    async fn an_idle_registration_drains_immediately() {
        assert!(drain_registration(registration(), Duration::from_secs(5)).await);
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
        let (reg, listener, _bound) = crate::bind_video_listener(Some(reg), addr, None)
            .expect("bind the video listener");
        drop(listener);
        assert!(drain_registration(reg, Duration::from_secs(5)).await);
    }

}
