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
    let Ok(path) = path() else {
        return Record::default();
    };
    let bytes = match std::fs::read(&path) {
        Ok(bytes) => bytes,
        // Nothing paired yet, which is where every device starts.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Record::default(),
        Err(e) => {
            // Refusing to start over a file this owns would be worse than the
            // check it provides — but a check that has quietly stopped running
            // is the one failure nobody would notice, so it is said out loud.
            tracing::error!(
                "cannot read {}: {e}; connections cannot be checked against the \
                 Endpoints this device paired with",
                path.display(),
            );
            return Record::default();
        }
    };
    serde_json::from_slice(&bytes).unwrap_or_else(|e| {
        tracing::error!(
            "{} does not parse: {e}; connections cannot be checked against the \
             Endpoints this device paired with, and pairing again will replace it",
            path.display(),
        );
        Record::default()
    })
}

/// Remember that this device paired with `endpoint`.
///
/// Called on a successful pairing. Idempotent: pairing with the same camera
/// again records the same thing.
pub fn remember(endpoint: &str) -> anyhow::Result<()> {
    // The Endpoint is the proxy's JSON. An empty one would go in as an entry
    // that matches the "nothing selected" case, and every hand-carried
    // connection — the ones this deliberately leaves alone — would be refused,
    // with nothing in any interface to clear it.
    if endpoint.is_empty() {
        anyhow::bail!("the grant named no endpoint, so there is nothing to remember");
    }
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
    tracing::info!(
        endpoint,
        "remembering a paired Endpoint in {}",
        path.display()
    );
    // Through a temporary and a rename, because this is read-modify-write: a
    // write interrupted halfway leaves a file that does not parse, and what
    // follows is not a loud failure but a check that silently passes
    // everything. `write_secret` is stricter than this needs (0600 on a list of
    // public identifiers) but it is the atomicity that is wanted, and writing
    // the dance out a second time is how the two come to differ.
    isekai_p2p::secret::write_secret(&path, &json)
        .with_context(|| format!("failed to write {}", path.display()))
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

/// What [`check`] found, when it did not refuse.
///
/// A connection that was held against a pairing and one that had nothing to be
/// held against both go on to stream, and **only one of them is protected**.
/// Told apart so an operator can see which they have.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Checked {
    /// The camera was paired with, and the Endpoint that answered is the one it
    /// was paired as.
    AgainstPairing,
    /// No camera was selected from a listing, so the caller named no Endpoint
    /// to check. The ordinary hand-carried case.
    NoSelection,
    /// A camera was selected, but its Endpoint is not one this device paired
    /// with. Ordinary for a listener reached by capability — and what a
    /// pairing that failed to be written down also looks like, which is why it
    /// is not folded in with [`Self::NoSelection`].
    NotPaired,
}

impl std::fmt::Display for Checked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AgainstPairing => {
                f.write_str("the camera answered as the Endpoint it was paired as")
            }
            Self::NoSelection => f.write_str(
                "no camera was selected from a listing, so the proxy is trusted about \
                 which Endpoint answered",
            ),
            Self::NotPaired => f.write_str(
                "this camera is not among the ones this device paired with, so the proxy \
                 is trusted about which Endpoint answered",
            ),
        }
    }
}

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
pub fn check(intended: &str, answered: Option<&str>) -> Result<Checked, WrongPeer> {
    decide(&load().endpoints, intended, answered)
}

/// The decision itself, apart from where the list is kept.
fn decide(
    paired: &BTreeSet<String>,
    intended: &str,
    answered: Option<&str>,
) -> Result<Checked, WrongPeer> {
    // An empty `intended` is "no camera was selected from a listing", which is
    // the hand-carried case and not something an entry could match — but a
    // stray empty entry would make it match everything.
    if intended.is_empty() {
        return Ok(Checked::NoSelection);
    }
    if !paired.contains(intended) {
        return Ok(Checked::NotPaired);
    }
    if answered == Some(intended) {
        return Ok(Checked::AgainstPairing);
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
        assert_eq!(
            decide(&paired(&["ep:a"]), "ep:a", Some("ep:a")),
            Ok(Checked::AgainstPairing),
        );
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

    /// An empty entry — which `remember` refuses to create — must not turn the
    /// hand-carried case into a refusal.
    #[test]
    fn an_empty_entry_does_not_refuse_everything() {
        assert_eq!(
            decide(&paired(&["", "ep:a"]), "", Some("ep:x")),
            Ok(Checked::NoSelection),
        );
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
        assert_eq!(
            decide(&known, "ep:b", Some("ep:b")),
            Ok(Checked::AgainstPairing)
        );
        assert!(decide(&known, "ep:a", Some("ep:b")).is_err());
    }
}
