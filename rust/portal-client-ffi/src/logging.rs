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

use std::sync::OnceLock;

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

/// What the first call settled, for every later call to report: the filter in
/// effect, or why no bridge could be installed.
static INSTALLED: OnceLock<Result<String, String>> = OnceLock::new();

/// Start sending Rust logs to logcat, with an `EnvFilter`-style `filter`
/// (e.g. `"info"`, `"info,isekai_p2p=debug"`). Empty means [`DEFAULT_FILTER`].
///
/// Call it once, before anything else calls into Rust. The first call installs
/// the subscriber and a panic hook, and **its filter holds for the life of the
/// process**: `tracing` allows one global subscriber, and nothing in the app
/// changes the filter while it runs, so there is no reload path to carry.
///
/// Errors, so that nothing is reported as working when it isn't:
/// - a filter that does not parse;
/// - a later call asking for a different filter than the one in effect (the
///   same filter again is fine and does nothing);
/// - a bridge that could not be installed because something else in the
///   process already owns the global subscriber. Every later call reports that
///   too, so a dead bridge is never mistaken for a working one.
#[uniffi::export]
pub fn init_logging(filter: String) -> Result<(), crate::PortalError> {
    let filter = if filter.trim().is_empty() {
        DEFAULT_FILTER.to_owned()
    } else {
        filter
    };
    let parsed = tracing_subscriber::EnvFilter::try_new(&filter)
        .map_err(|e| crate::PortalError::Runtime(format!("bad log filter {filter:?}: {e}")))?;

    match INSTALLED.get_or_init(|| install(parsed, &filter)) {
        Err(e) => Err(crate::PortalError::Runtime(format!(
            "Rust logs are not reaching logcat: {e}"
        ))),
        Ok(active) if *active != filter => Err(crate::PortalError::Runtime(format!(
            "the log filter is {active:?} for the life of this process; {filter:?} was not applied"
        ))),
        Ok(_) => Ok(()),
    }
}

/// Installs the subscriber and the panic hook. `Ok` holds the filter in effect.
fn install(filter: tracing_subscriber::EnvFilter, text: &str) -> Result<String, String> {
    use tracing_subscriber::layer::SubscriberExt as _;
    use tracing_subscriber::util::SubscriberInitExt as _;

    // `try_init` also bridges the `log` crate into `tracing` (the
    // `tracing-log` feature), so dependencies that log through `log` show up
    // here too instead of going nowhere.
    let installed = tracing_subscriber::registry()
        .with(filter)
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(Logcat)
                .with_ansi(false)
                // logcat stamps every line itself, and its level column says
                // what the level would (off Android, `sys::write` prefixes
                // the level instead).
                .without_time()
                .with_level(false)
                .with_target(true),
        )
        .try_init();
    // A panic on a background task would otherwise end the session with
    // nothing in logcat but the Kotlin side noticing it closed. Written
    // straight to logcat, so it is installed even if the subscriber wasn't.
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        write_line(Priority::Error, &format!("panic: {info}"));
        previous(info);
    }));

    match installed {
        Ok(()) => {
            tracing::info!(filter = %text, "Rust logging to logcat");
            Ok(text.to_owned())
        }
        // Somebody else in the process got there first; their subscriber gets
        // the events. Say so where it can be seen, and to every caller.
        Err(e) => {
            let msg = format!("could not install the log bridge: {e}");
            write_line(Priority::Warn, &msg);
            Err(msg)
        }
    }
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

/// Write `text` as one or more logcat entries.
fn write_line(priority: Priority, text: &str) {
    for chunk in chunks(text) {
        sys::write(priority, chunk);
    }
}

/// `text` in pieces of at most [`CHUNK`] bytes, each ending on a character
/// boundary: `split_at` panics anywhere else.
fn chunks(text: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(CHUNK);
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        let (chunk, tail) = rest.split_at(end);
        out.push(chunk);
        rest = tail;
    }
    out
}

#[cfg(target_os = "android")]
mod sys {
    use std::ffi::{c_char, c_int, CString};

    #[link(name = "log")]
    extern "C" {
        fn __android_log_write(prio: c_int, tag: *const c_char, text: *const c_char) -> c_int;
    }

    pub fn write(priority: super::Priority, text: &str) {
        // An interior NUL would end the entry early in C; it cannot be a
        // character anyone meant, so it is shown rather than obeyed.
        let text = CString::new(text.replace('\0', "\\0")).expect("NULs were replaced");
        let tag = CString::new(super::TAG).expect("tag has no NUL");
        // SAFETY: both pointers are valid NUL-terminated strings for the
        // duration of the call, which is all liblog asks.
        unsafe {
            __android_log_write(priority as c_int, tag.as_ptr(), text.as_ptr());
        }
    }
}

#[cfg(not(target_os = "android"))]
mod sys {
    use super::Priority;

    /// stderr has no level column, so the level goes in the line, the way
    /// `adb logcat -v brief` shows it (`W/PortalRust: ...`).
    pub fn write(priority: Priority, text: &str) {
        let level = match priority {
            Priority::Verbose => 'V',
            Priority::Debug => 'D',
            Priority::Info => 'I',
            Priority::Warn => 'W',
            Priority::Error => 'E',
        };
        eprintln!("{level}/{}: {text}", super::TAG);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_first_filter_holds_and_a_different_one_is_refused() {
        assert!(init_logging("not a [valid filter".to_owned()).is_err());
        init_logging(String::new()).expect("the default filter parses and installs");
        // The same filter again (empty means the default) does nothing.
        init_logging(DEFAULT_FILTER.to_owned()).expect("same filter again");
        // A different one is refused rather than reported as applied.
        let err = init_logging("debug".to_owned()).expect_err("a different filter");
        assert!(err.to_string().contains("was not applied"), "{err}");
    }

    /// A character that straddles CHUNK, for each UTF-8 width that can: the
    /// cut has to move back to where the character starts.
    #[test]
    fn long_lines_split_on_character_boundaries() {
        for ch in ["é", "日", "😀"] {
            let line = "a".repeat(CHUNK - 1) + &ch.repeat(10);
            let pieces = chunks(&line);
            assert_eq!(pieces[0].len(), CHUNK - 1, "cut before {ch:?}, not inside it");
            assert!(pieces.iter().all(|p| p.len() <= CHUNK));
            assert_eq!(pieces.concat(), line);
            write_line(Priority::Info, &line);
        }
    }
}
