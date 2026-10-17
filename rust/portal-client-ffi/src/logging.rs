//! Sends this library's `tracing` output to logcat.
//!
//! **Without this, nothing the Rust side says reaches anyone.** `tracing`
//! drops every event when no subscriber is installed, and an Android app has no
//! stderr to fall back on — so pairing, connect, relay and path-switch logs,
//! and every warning in `isekai_p2p`/`portal_core`, simply vanish while logcat
//! shows only the Kotlin side. That is the state this crate shipped in until
//! [`init_logging`] existed (ISK-24).
//!
//! Written straight to `liblog` rather than through a Kotlin callback the way
//! `isekai-client-ffi`'s bridge does: what has to be readable is the log of a
//! session that went wrong, and a path through the JVM is one more thing that
//! can be wedged or gone when it does. Off Android (host builds and tests) the
//! same lines go to stderr.

use std::sync::{Mutex, Once};

use tracing::Level;
use tracing_subscriber::fmt::MakeWriter;

/// The logcat tag. Distinct from the Kotlin side's `PortalFFI`, so
/// `adb logcat -s PortalRust` shows the Rust half on its own and
/// `adb logcat -s PortalFFI PortalRust` shows both.
const TAG: &str = "PortalRust";

/// What [`init_logging`] uses when given an empty filter.
pub const DEFAULT_FILTER: &str = "info";

/// logcat drops whatever is past roughly 4 KB of one entry; a line longer than
/// this is split rather than lost. Kept well under the limit, since the limit
/// counts the tag and header too.
const CHUNK: usize = 3000;

static INIT: Once = Once::new();
/// Applies a new filter to the installed subscriber — see [`init_logging`].
#[allow(clippy::type_complexity)]
static RELOAD: Mutex<Option<Box<dyn Fn(&str) -> Result<(), String> + Send>>> = Mutex::new(None);

/// Start sending Rust logs to logcat, with an `EnvFilter`-style `filter`
/// (e.g. `"info"`, `"info,isekai_p2p=debug"`). Empty means [`DEFAULT_FILTER`].
///
/// Safe to call more than once. The first call installs the subscriber and a
/// panic hook; later calls only change the filter, so the app can turn detail
/// up for one reproduction without being restarted. `tracing` allows a single
/// global subscriber per process, which is why the subscriber itself cannot be
/// replaced.
///
/// Returns an error only for a filter that does not parse; logging stays on
/// the previous filter in that case.
#[uniffi::export]
pub fn init_logging(filter: String) -> Result<(), crate::PortalError> {
    let filter = if filter.trim().is_empty() {
        DEFAULT_FILTER.to_owned()
    } else {
        filter
    };
    let parsed = tracing_subscriber::EnvFilter::try_new(&filter)
        .map_err(|e| crate::PortalError::Runtime(format!("bad log filter {filter:?}: {e}")))?;

    let mut first = false;
    INIT.call_once(|| {
        first = true;
        install(parsed);
    });
    if !first {
        if let Some(reload) = RELOAD.lock().expect("log reload mutex poisoned").as_ref() {
            reload(&filter).map_err(crate::PortalError::Runtime)?;
        }
    }
    tracing::info!(filter = %filter, "Rust logging to logcat");
    Ok(())
}

fn install(filter: tracing_subscriber::EnvFilter) {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    let (filter_layer, handle) = tracing_subscriber::reload::Layer::new(filter);
    // `try_init` also bridges the `log` crate into `tracing` (the
    // `tracing-log` feature), so dependencies that log through `log` show up
    // here too instead of going nowhere.
    let installed = tracing_subscriber::registry()
        .with(filter_layer)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(Logcat)
                .with_ansi(false)
                // logcat stamps every line itself, and its level column says
                // what the level would.
                .without_time()
                .with_level(false)
                .with_target(true),
        )
        .try_init();
    match installed {
        Ok(()) => {
            *RELOAD.lock().expect("log reload mutex poisoned") = Some(Box::new(move |f: &str| {
                let parsed = tracing_subscriber::EnvFilter::try_new(f)
                    .map_err(|e| format!("bad log filter {f:?}: {e}"))?;
                handle.reload(parsed).map_err(|e| e.to_string())
            }));
        }
        // Somebody else in the process got there first; their subscriber gets
        // the events. Say so where it can be seen.
        Err(e) => write_line(Priority::Warn, &format!("could not install the log bridge: {e}")),
    }

    // A panic on a background task would otherwise end the session with
    // nothing in logcat but the Kotlin side noticing it closed.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write_line(Priority::Error, &format!("panic: {info}"));
        previous(info);
    }));
}

/// logcat's priorities, as `android/log.h` numbers them.
#[derive(Clone, Copy)]
#[repr(i32)]
enum Priority {
    Verbose = 2,
    Debug = 3,
    Info = 4,
    Warn = 5,
    Error = 6,
}

impl From<&Level> for Priority {
    fn from(level: &Level) -> Self {
        match *level {
            Level::TRACE => Priority::Verbose,
            Level::DEBUG => Priority::Debug,
            Level::INFO => Priority::Info,
            Level::WARN => Priority::Warn,
            Level::ERROR => Priority::Error,
        }
    }
}

/// Hands out one [`LineWriter`] per event, at that event's priority.
struct Logcat;

impl<'a> MakeWriter<'a> for Logcat {
    type Writer = LineWriter;

    fn make_writer(&'a self) -> Self::Writer {
        LineWriter::new(Priority::Info)
    }

    fn make_writer_for(&'a self, meta: &tracing::Metadata<'_>) -> Self::Writer {
        LineWriter::new(meta.level().into())
    }
}

/// Collects one formatted event and writes it out when dropped.
///
/// `fmt` may write an event in several pieces; sending each piece as its own
/// logcat entry would split one line across several, so they are gathered
/// first.
struct LineWriter {
    priority: Priority,
    buf: Vec<u8>,
}

impl LineWriter {
    fn new(priority: Priority) -> Self {
        Self {
            priority,
            buf: Vec::new(),
        }
    }
}

impl std::io::Write for LineWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Drop for LineWriter {
    fn drop(&mut self) {
        let text = String::from_utf8_lossy(&self.buf);
        let text = text.trim_end();
        if !text.is_empty() {
            write_line(self.priority, text);
        }
    }
}

/// Write `text` as one or more logcat entries, splitting long ones on
/// character boundaries.
fn write_line(priority: Priority, text: &str) {
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(CHUNK);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (chunk, tail) = rest.split_at(end);
        sys::write(priority as i32, chunk);
        rest = tail;
    }
}

#[cfg(target_os = "android")]
mod sys {
    use std::ffi::{c_char, c_int, CString};

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    pub fn write(priority: i32, text: &str) {
        // An interior NUL would end the entry early in C; it cannot be a
        // character anyone meant, so it is shown rather than obeyed.
        let text = CString::new(text.replace('\0', "\\0")).expect("NULs were replaced");
        let tag = CString::new(super::TAG).expect("tag has no NUL");
        // SAFETY: both pointers are valid NUL-terminated strings for the
        // duration of the call, which is all liblog asks.
        unsafe {
            __android_log_write(priority, tag.as_ptr(), text.as_ptr());
        }
    }
}

#[cfg(not(target_os = "android"))]
mod sys {
    pub fn write(_priority: i32, text: &str) {
        eprintln!("{}: {text}", super::TAG);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_bad_filter_is_refused_and_a_good_one_can_follow_it() {
        assert!(init_logging("not a [valid filter".to_owned()).is_err());
        init_logging(String::new()).expect("the default filter parses");
        // Calling again only reloads the filter.
        init_logging("debug,portal_client_ffi=trace".to_owned()).expect("reload works");
        tracing::debug!("visible after the reload");
    }

    #[test]
    fn long_lines_split_on_character_boundaries() {
        // Three-byte characters straddling CHUNK must not panic.
        let line = "日".repeat(CHUNK);
        write_line(Priority::Info, &line);
    }
}
