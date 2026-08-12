//! Which camera to capture from, and the thread that does it.
//!
//! The device used to be `VideoCapture(0)`, opened once at startup and held for
//! the life of the process. A machine with more than one camera — a laptop's
//! built-in one next to the USB camera actually pointed at something — had no
//! way to say which.
//!
//! Two pieces: a best-effort list of what is attached ([`enumerate`]), and a
//! capture thread that reopens whenever the selection changes ([`run`]). The
//! list is a convenience and the selection is not limited to it; **the authority
//! on whether a device works is opening it**, which is what [`run`] does and
//! reports through [`Status`].

use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex};

use opencv::prelude::*;
use opencv::videoio;

/// The camera used when the operator has not chosen one — the first, which is
/// what this always captured from.
pub const DEFAULT_INDEX: i32 = 0;

/// The capture resolution, unchanged and still not selectable.
const FRAME_WIDTH: f64 = 640.0;
const FRAME_HEIGHT: f64 = 480.0;

/// How long to wait before trying a device that would not open again.
///
/// Long enough not to spin on a camera another application is holding, short
/// enough that unplugging and replugging one recovers without a restart. A
/// failed open is not fatal: the operator can pick a different device, and this
/// keeps the one they picked from needing a click to retry.
const REOPEN_DELAY: std::time::Duration = std::time::Duration::from_millis(500);

/// The frame interval, and the idle poll when nothing is being captured.
const FRAME_INTERVAL: std::time::Duration = std::time::Duration::from_millis(33);

/// How many indices to try on platforms with nothing better to go on.
///
/// Blind probing means opening devices that may not exist, which is slow and
/// makes the backend complain on stderr, so this is deliberately small. More
/// cameras than this on one machine is not the case being served — and the
/// operator can still type an index that is not on the list.
const PROBE_LIMIT: i32 = 5;

/// A camera the operator can choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Device {
    /// What `VideoCapture` takes.
    pub index: i32,
    /// What to show. The driver's name where there is one, else the index.
    pub name: String,
}

impl Device {
    fn new(index: i32) -> Self {
        Self {
            name: driver_name(index).unwrap_or_else(|| format!("Camera {index}")),
            index,
        }
    }
}

/// What the capture thread is doing, for the operator to see.
#[derive(Debug, Default, Clone)]
pub struct Status {
    /// The device currently open, if any.
    pub open: Option<i32>,
    /// Why the last attempt to open one failed, cleared once one does.
    ///
    /// Worth showing rather than only logging: choosing a camera that is
    /// unplugged or held by another application is an ordinary mistake, and
    /// without this the picture simply never arrives.
    pub error: Option<String>,
}

/// Which camera the capture thread should be using.
///
/// An index rather than a [`Device`], because it is also what an operator types
/// by hand for a camera the list did not find.
#[derive(Debug, Clone)]
pub struct Selection(Arc<AtomicI32>);

impl Selection {
    pub fn new(index: i32) -> Self {
        Self(Arc::new(AtomicI32::new(index)))
    }

    pub fn get(&self) -> i32 {
        self.0.load(Ordering::Relaxed)
    }

    /// Ask the capture thread to switch. It takes effect on its next pass,
    /// within a frame interval.
    pub fn set(&self, index: i32) {
        self.0.store(index, Ordering::Relaxed);
    }
}

/// What the window needs of the capture thread: what to ask it for, and what
/// it is making of that.
///
/// One value because the two are only ever useful together — a selection with
/// no way to see whether it took is a control with no feedback.
#[derive(Debug, Clone)]
pub struct Handle {
    pub selection: Selection,
    pub status: Arc<Mutex<Status>>,
}

impl Handle {
    pub fn new(index: i32) -> Self {
        Self {
            selection: Selection::new(index),
            status: Arc::new(Mutex::new(Status::default())),
        }
    }

    /// The device currently open, if any.
    pub fn open(&self) -> Option<i32> {
        self.status.lock().unwrap().open
    }
}

/// The cameras attached, as far as this can tell.
///
/// **Best effort, and not a limit on what can be selected.** There is no
/// portable way to ask; what this does is try to open a bounded set of
/// candidates and keep the ones that answer.
///
/// `in_use` is the index the capture thread already holds. It is reported
/// without being probed — a device open in this process generally will not open
/// a second time, so probing it would drop the one camera known to work.
pub fn enumerate(in_use: Option<i32>) -> Vec<Device> {
    let mut found = Vec::new();
    for index in candidates() {
        if Some(index) == in_use {
            found.push(Device::new(index));
            continue;
        }
        match videoio::VideoCapture::new(index, videoio::CAP_ANY) {
            Ok(cam) if cam.is_opened().unwrap_or(false) => found.push(Device::new(index)),
            _ => {}
        }
    }
    found
}

/// Indices worth trying.
///
/// On Linux the kernel already lists them, so nothing has to be guessed at and
/// nothing that cannot exist is opened. That matters because the list includes
/// nodes that are not capture devices — a camera commonly registers a metadata
/// node beside its video one — which is what the probe in [`enumerate`] is
/// for: the kernel says what exists, opening says what captures.
#[cfg(target_os = "linux")]
fn candidates() -> Vec<i32> {
    let Ok(entries) = std::fs::read_dir("/sys/class/video4linux") else {
        return (0..PROBE_LIMIT).collect();
    };
    let mut indices: Vec<i32> = entries
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_prefix("video"))
                .and_then(|n| n.parse().ok())
        })
        .collect();
    indices.sort_unstable();
    indices
}

#[cfg(not(target_os = "linux"))]
fn candidates() -> Vec<i32> {
    (0..PROBE_LIMIT).collect()
}

/// The name the driver gives this device, where the platform exposes one.
#[cfg(target_os = "linux")]
fn driver_name(index: i32) -> Option<String> {
    let name = std::fs::read_to_string(format!("/sys/class/video4linux/video{index}/name")).ok()?;
    let name = name.trim();
    (!name.is_empty()).then(|| name.to_owned())
}

#[cfg(not(target_os = "linux"))]
fn driver_name(_index: i32) -> Option<String> {
    None
}

/// Open `index` at the capture resolution.
fn open(index: i32) -> anyhow::Result<videoio::VideoCapture> {
    let mut cam = videoio::VideoCapture::new(index, videoio::CAP_ANY)?;
    if !cam.is_opened()? {
        anyhow::bail!("camera {index} could not be opened");
    }
    // Best effort, as it always was: a device that will not take this size
    // still delivers whatever it does deliver.
    cam.set(videoio::CAP_PROP_FRAME_WIDTH, FRAME_WIDTH)?;
    cam.set(videoio::CAP_PROP_FRAME_HEIGHT, FRAME_HEIGHT)?;
    Ok(cam)
}

/// The device the thread should be holding, opening or reopening as needed.
///
/// Returns `None` while the wanted device will not open, having said so in
/// `status`; the caller waits and asks again, so a camera that comes back —
/// replugged, or released by whatever had it — is picked up without the
/// operator doing anything.
fn current(
    held: &mut Option<(i32, videoio::VideoCapture)>,
    wanted: i32,
    status: &Mutex<Status>,
) -> bool {
    if held.as_ref().is_some_and(|(index, _)| *index == wanted) {
        return true;
    }
    // Dropped before opening the next one: the two may be the same device, and
    // holding it twice is what would stop it opening at all.
    *held = None;
    match open(wanted) {
        Ok(cam) => {
            tracing::info!(camera = wanted, "capturing");
            *held = Some((wanted, cam));
            *status.lock().unwrap() = Status {
                open: Some(wanted),
                error: None,
            };
            true
        }
        Err(e) => {
            let error = format!("could not open camera {wanted}: {e}");
            let mut status = status.lock().unwrap();
            // Said once per change, not once per retry.
            if status.error.as_deref() != Some(error.as_str()) {
                tracing::warn!("{error}");
                *status = Status {
                    open: None,
                    error: Some(error),
                };
            }
            false
        }
    }
}

/// Run the capture loop until `is_terminated`.
///
/// `for_each_frame` is handed every frame captured, as OpenCV delivers it
/// (BGR); everything the application does with a frame is that closure's
/// business, including what to make of a frame it cannot use. Returns when
/// asked to terminate, or when the closure breaks.
///
/// Nothing here is fallible on purpose. A device that will not open or will not
/// read is an ordinary condition handled by waiting and trying again, not an
/// error to return — the operator is watching a window, and the useful answer
/// is in [`Status`] rather than in an exit.
pub fn run(
    handle: Handle,
    is_streaming: Arc<std::sync::atomic::AtomicBool>,
    is_terminated: Arc<std::sync::atomic::AtomicBool>,
    mut for_each_frame: impl FnMut(&Mat) -> std::ops::ControlFlow<()>,
) {
    let Handle { selection, status } = handle;
    let mut held: Option<(i32, videoio::VideoCapture)> = None;
    loop {
        if is_terminated.load(Ordering::Relaxed) {
            tracing::debug!("camera task terminating");
            break;
        }
        if !is_streaming.load(Ordering::Relaxed) {
            // Nothing is being sent or shown, so nothing is captured — but the
            // device stays open, which is what makes Start immediate.
            std::thread::sleep(FRAME_INTERVAL);
            continue;
        }
        if !current(&mut held, selection.get(), &status) {
            std::thread::sleep(REOPEN_DELAY);
            continue;
        }
        let (_, cam) = held.as_mut().expect("held after a successful open");

        let mut frame = Mat::default();
        if cam.read(&mut frame).is_err() || frame.empty() {
            // A grab that fails is usually a device that has gone away — it was
            // unplugged, or something else took it. Let go of it, so the next
            // pass opens it again if it comes back rather than reading a handle
            // that will never produce another frame.
            tracing::debug!(camera = selection.get(), "no frame; reopening");
            held = None;
            std::thread::sleep(FRAME_INTERVAL);
            continue;
        }

        if for_each_frame(&frame).is_break() {
            break;
        }

        std::thread::sleep(FRAME_INTERVAL);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The device already open is reported without being probed. Probing it
    /// would fail — it cannot be opened twice — and would drop the one camera
    /// that is known to work from the list the operator picks from.
    #[test]
    fn the_camera_in_use_is_listed_without_being_opened() {
        // No real device is opened here: whatever `candidates` returns, an
        // index that is in use must appear, and one that is not must survive
        // only if it opened. On a machine with no cameras at all the second
        // half is vacuous, which is why the assertion is about the first.
        let in_use = candidates().first().copied();
        if let Some(index) = in_use {
            let listed = enumerate(Some(index));
            assert!(
                listed.iter().any(|d| d.index == index),
                "the camera being captured from must stay selectable",
            );
        }
    }

    /// A name is always shown, so a device is never an unlabelled number in a
    /// list of them.
    #[test]
    fn every_device_has_something_to_call_it() {
        let device = Device::new(3);
        assert!(!device.name.is_empty());
        assert_eq!(device.index, 3);
    }

    /// The selection is what the operator asked for, not what is open: those
    /// differ while a device is being switched to, or refusing to open.
    #[test]
    fn a_selection_is_a_request() {
        let selection = Selection::new(0);
        assert_eq!(selection.get(), 0);
        selection.set(2);
        assert_eq!(selection.get(), 2);
        assert_eq!(selection.clone().get(), 2, "the thread sees the same value");
    }
}
