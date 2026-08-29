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
/// **Covers SIGTERM too, and arming late is required rather than tidy.**
///
/// A program that also waits on a signal asynchronously cannot arm this early.
/// `tokio::signal` goes through `signal_hook_registry`, whose handler calls the
/// *previous* disposition before running any registered action
/// (`slot.prev.execute(sig)`). So a raw handler installed first is chained to
/// and `_exit`s before tokio's wakeup runs; one installed afterwards simply
/// replaces tokio's, so the async side never hears the signal at all.
/// **Either order defeats the graceful path.**
///
/// That was measured rather than reasoned: both spellings exited 143 with the
/// async arm never reached, while arming on receipt stopped gracefully and left
/// immediately on a second signal. Which is why this is called at the moment
/// the decision to stop is made — for both signals, for one reason.
pub fn hard_exit_on_second_signal() {
    // SAFETY: `handler` is the address of an `extern "C"` function with the
    // signature `signal(2)` requires, and both are valid signal numbers.
    unsafe {
        signal(SIGINT, hard_exit as extern "C" fn(i32) as usize);
        #[cfg(unix)]
        signal(SIGTERM, hard_exit as extern "C" fn(i32) as usize);
    }
}

/// SIGINT's number on every platform this builds for.
const SIGINT: i32 = 2;

/// SIGTERM's number on the Unix platforms this builds for. Windows has none.
#[cfg(unix)]
const SIGTERM: i32 = 15;

/// **A raw handler, not a spawned task**, and the difference is the case this
/// exists for. A task needs a free worker to run on; the thing it is meant to
/// rescue somebody from is a close that has blocked a worker, and on a
/// single-core host `#[tokio::main]` gives exactly one. The hatch would then be
/// starved by precisely the hang it is there for.
///
/// A signal handler runs on whatever thread takes the signal, with no runtime
/// involved. `_exit` is async-signal-safe, which is the whole of what a handler
/// is allowed to do — no allocation, no locks, and no message, because printing
/// one is not.
extern "C" fn hard_exit(signal: i32) {
    // 128 + the signal, which is what a shell reports for a program killed by
    // one: 130 for an interrupt, 143 for a terminate.
    unsafe { libc_exit(128 + signal) }
}

unsafe extern "C" {
    fn signal(signum: i32, handler: usize) -> usize;
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
