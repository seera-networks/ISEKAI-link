//! Leaving the process, which turns out not to be free.
//!
//! **Ctrl+C stopped working once traffic had started**, and the reason is in
//! `isekai_p2p_core::transport`'s own documentation, one function above the one
//! that was being called:
//!
//! > `shutdown_msquic` drops the registration once it drains, which runs
//! > `RegistrationClose`. That is still a *blocking* call, and `wait_idle()`
//! > does not cover application-owned client `Configuration`s — one outstanding
//! > anywhere and the close waits on its rundown reference, uninterruptibly and
//! > after the timeout has already been satisfied.
//!
//! A configuration's rundown reference outlives `ConfigurationClose`, so the
//! wait is not one a timeout can end. Before any traffic there is no
//! configuration to hold it, which is why Ctrl+C worked right up until the
//! moment it mattered.
//!
//! # So this does not close anything
//!
//! [`drain_msquic`] shuts the registration down, waits for connections and
//! listeners to let go — worth doing, because it is what sends CONNECTION_CLOSE
//! so peers learn immediately rather than timing out — and then **leaks** it
//! rather than dropping it.
//!
//! And then the process leaves through `_exit`, skipping every remaining
//! destructor. Returning from `main` would drop the tokio runtime and with it
//! the application's own registration, which is the same blocking close by
//! another route. `camera-core::shutdown` reached this conclusion first and for
//! the same reasons; this is that answer, for two binaries that do not depend
//! on it.
//!
//! There is nothing to gain from closing a registration in a process that is
//! about to stop existing.

use std::time::Duration;

/// How long to wait for connections and listeners to let go.
///
/// Generous next to what it is waiting for — cancelled tasks dropping a
/// connection — and short enough that Ctrl+C does not look ignored. Exceeding
/// it costs peers a timeout instead of a close, not correctness.
const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

/// Make the next Ctrl+C leave immediately, however the graceful close is going.
///
/// **Because the first one took the escape hatch away.** `tokio::signal::ctrl_c`
/// replaces SIGINT's default disposition process-wide the first time it is
/// called, so once a program has caught one interrupt, pressing it again does
/// nothing unless something is listening. If the graceful close then blocks —
/// which is the whole subject of this module — there is no way out but another
/// terminal and a `kill`.
///
/// So: call this at the moment the decision to stop is made, and the second
/// press is a hard exit. It does not replace understanding a hang; it stops one
/// from trapping whoever meets it.
pub fn hard_exit_on_second_interrupt() {
    tokio::spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            eprintln!("interrupted again; leaving without waiting");
            use std::io::Write as _;
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().flush();
            // 128 + SIGINT, which is what a shell reports for an interrupted
            // program.
            unsafe { libc_exit(130) }
        }
    });
}

/// Wind msquic down and leave with `code`. **Never returns.**
///
/// Call this instead of returning from `main`, and after whatever graceful close
/// the application has of its own — this drains the shared control-plane
/// registration, not the caller's connections.
pub async fn leave(code: i32) -> ! {
    if !isekai_p2p::agent::drain_msquic(DRAIN_TIMEOUT).await {
        tracing::debug!("msquic still had live handles; leaving anyway");
    }
    // Before `_exit`, which runs nothing: the ids and messages a person is
    // reading are the whole output of these programs.
    use std::io::Write as _;
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
    // SAFETY: `_exit` terminates the process. Nothing after it runs, which is
    // the point — every destructor left is one that can block.
    unsafe { libc_exit(code) }
}

unsafe extern "C" {
    #[link_name = "_exit"]
    fn libc_exit(code: i32) -> !;
}
