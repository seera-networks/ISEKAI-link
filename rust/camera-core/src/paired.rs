//! The Endpoints this device has paired with, remembered locally.
//!
//! # What this is for
//!
//! Pinning the attested key (`video::AttestedPeer`) proves you are talking to
//! the Endpoint the connect response names. **It does not prove that Endpoint is
//! the camera the user meant**, because the response is the proxy's, and so is
//! the listing the camera was chosen from. A proxy that wanted to could point a
//! viewer at an Endpoint of its own, which would then attest quite honestly to
//! its own key.
//!
//! Closing that needs an Endpoint ID that did not come from the proxy. Pairing
//! is where one arrives: a code read off the camera's screen and typed in here.
//! What is remembered is what was learned then, and later connections are held
//! against it.
//!
//! # Only for cameras that were paired
//!
//! A capability entered by hand is a legitimate way to reach a camera and comes
//! with no pairing, so there is nothing to compare and the connection proceeds.
//! The check bites only where there is something to check with — which is also
//! why the file is a set of Endpoints rather than a policy: it records what
//! happened, not what is allowed.

use std::collections::BTreeSet;
use std::path::PathBuf;

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// What is on disk.
#[derive(Debug, Default, Serialize, Deserialize)]
struct Record {
    /// Endpoint IDs, sorted so the file does not churn between writes.
    #[serde(default)]
    endpoints: BTreeSet<String>,
}

fn path() -> anyhow::Result<PathBuf> {
    Ok(crate::privacy::config_dir()?.join("paired-endpoints.json"))
}

fn load() -> Record {
    // A file that is missing, unreadable or malformed leaves nothing to compare
    // against, which is the same position a viewer that has never paired is in.
    // Refusing to start over a file this owns would be worse than the check it
    // provides.
    path()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Remember that this device paired with `endpoint`.
///
/// Called on a successful pairing. Idempotent: pairing with the same camera
/// again records the same thing.
pub fn remember(endpoint: &str) -> anyhow::Result<()> {
    let mut record = load();
    if !record.endpoints.insert(endpoint.to_owned()) {
        return Ok(());
    }
    let path = path()?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(&record).context("failed to encode the paired list")?;
    std::fs::write(&path, json).with_context(|| format!("failed to write {}", path.display()))
}

/// Whether `endpoint` is one this device paired with.
pub fn is_paired(endpoint: &str) -> bool {
    load().endpoints.contains(endpoint)
}

/// Why a connection was refused before it was made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrongPeer {
    /// The Endpoint this device paired with.
    pub expected: String,
    /// The Endpoint the proxy answered with, or `None` when it named nobody.
    pub actual: Option<String>,
}

impl std::fmt::Display for WrongPeer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "this camera was paired as {}, but ", self.expected)?;
        match &self.actual {
            Some(actual) => write!(f, "the proxy answered with {actual}")?,
            None => f.write_str("the proxy named no endpoint at all")?,
        }
        f.write_str("; refusing to connect")
    }
}

impl std::error::Error for WrongPeer {}

/// Check who answered against who was meant.
///
/// `intended` is the Endpoint of the camera the viewer chose; `answered` is the
/// `peer_endpoint` of the connect response. They differ only if the proxy sent
/// the connection somewhere else.
///
/// Nothing is checked unless `intended` was paired — a camera reached by hand
/// has no out-of-band identity to hold the answer against, and inventing one
/// from the proxy's own listing would be checking the proxy against itself.
///
/// `answered` is `None` when the response named nobody. Only `POST
/// /v1/peer/connect` carries the field and it always does, so on a camera that
/// was paired this is a response that does not hold together rather than an
/// older proxy — and stripping the field is how the check would otherwise be
/// stepped around.
pub fn check(intended: &str, answered: Option<&str>) -> Result<(), WrongPeer> {
    decide(&load().endpoints, intended, answered)
}

/// The decision itself, apart from where the list is kept.
fn decide(
    paired: &BTreeSet<String>,
    intended: &str,
    answered: Option<&str>,
) -> Result<(), WrongPeer> {
    if !paired.contains(intended) || answered == Some(intended) {
        return Ok(());
    }
    Err(WrongPeer {
        expected: intended.to_owned(),
        actual: answered.map(str::to_owned),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paired(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The point of the whole module: the proxy sent the connection to an
    /// Endpoint other than the one the code was read off.
    #[test]
    fn a_paired_camera_answered_by_someone_else_is_refused() {
        let err = decide(&paired(&["ep:a"]), "ep:a", Some("ep:b")).unwrap_err();
        assert_eq!(err.expected, "ep:a");
        assert_eq!(err.actual.as_deref(), Some("ep:b"));
    }

    /// The ordinary case, and the one that must not become noisy.
    #[test]
    fn the_same_endpoint_is_fine() {
        assert!(decide(&paired(&["ep:a"]), "ep:a", Some("ep:a")).is_ok());
    }

    /// A capability entered by hand is a legitimate way in and brings no
    /// out-of-band Endpoint to hold the answer against.
    #[test]
    fn an_unpaired_camera_is_not_checked() {
        assert!(decide(
            &paired(&["ep:a"]),
            "ep:never-paired",
            Some("ep:someone-else")
        )
        .is_ok());
    }

    /// A response that names nobody is not a way around the check.
    #[test]
    fn a_paired_camera_answered_by_nobody_is_refused() {
        let err = decide(&paired(&["ep:a"]), "ep:a", None).unwrap_err();
        assert_eq!(err.actual, None);
        assert!(err.to_string().contains("no endpoint at all"), "{err}");
    }

    /// Pairing with a second camera must not turn the first into a mismatch:
    /// the answer is held against the camera being dialled, not the whole list.
    #[test]
    fn each_camera_is_checked_against_itself() {
        let known = paired(&["ep:a", "ep:b"]);
        assert!(decide(&known, "ep:b", Some("ep:b")).is_ok());
        assert!(decide(&known, "ep:a", Some("ep:b")).is_err());
    }
}
