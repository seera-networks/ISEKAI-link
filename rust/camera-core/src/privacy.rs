//! The privacy policy, and whether this user has agreed to it.
//!
//! Using ISEKAI link needs an account, and an account means personal
//! information — so every application asks for agreement before it does
//! anything, and remembers the answer.
//!
//! **One text, three applications.** `camera-server`, `camera-client` and the
//! iOS viewer all show what is in `docs/privacy-policy.*.md`, compiled in here
//! rather than copied into each. The iOS app reaches it through the FFI for the
//! same reason: three applications agreeing to three slightly different
//! documents is worse than having no document at all.
//!
//! **The agreement records a version.** Consent to one text is not consent to
//! the next one, so [`Consent`] stores which version was agreed and
//! [`needs_agreement`] compares it against [`VERSION`]. Revising the policy is
//! then a matter of editing the documents and bumping the constant; every
//! application asks again on its next start.

use std::path::{Path, PathBuf};

use anyhow::Context as _;
use serde::{Deserialize, Serialize};

/// Which version of the policy this build carries.
///
/// Bump it whenever the documents change in a way a person would want to know
/// about. A test keeps it in step with what the documents themselves say.
pub const VERSION: &str = "2026-08-05";

/// Where the authoritative, publishable copy lives.
///
/// Shown beside the bundled text: the bundled copy is what was agreed to and
/// works with no network, and this is the one that stays current.
pub const URL: &str = "https://isekai.tools/privacy";

/// The policy in Japanese.
pub const TEXT_JA: &str = include_str!("../../../docs/privacy-policy.ja.md");
/// The policy in English.
pub const TEXT_EN: &str = include_str!("../../../docs/privacy-policy.en.md");

/// Which rendering of the policy to show.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Language {
    Japanese,
    English,
}

impl Language {
    /// The text itself.
    pub fn text(self) -> &'static str {
        match self {
            Self::Japanese => TEXT_JA,
            Self::English => TEXT_EN,
        }
    }

    /// What to put on the control that switches to the *other* language.
    pub fn other_label(self) -> &'static str {
        match self {
            Self::Japanese => "English",
            Self::English => "日本語",
        }
    }

    pub fn toggled(self) -> Self {
        match self {
            Self::Japanese => Self::English,
            Self::English => Self::Japanese,
        }
    }

    /// The language to open with, from the environment's own preference.
    ///
    /// Japanese when the locale asks for it, English otherwise — the policy has
    /// to be readable before anyone has had a chance to set a preference,
    /// because agreeing to a document you cannot read is not agreement.
    pub fn preferred() -> Self {
        let locale = std::env::var("LC_ALL")
            .or_else(|_| std::env::var("LC_MESSAGES"))
            .or_else(|_| std::env::var("LANG"))
            .unwrap_or_default();
        if locale.to_ascii_lowercase().starts_with("ja") {
            Self::Japanese
        } else {
            Self::English
        }
    }
}

/// A recorded agreement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consent {
    /// The [`VERSION`] that was shown. Agreement is to a specific text.
    pub version: String,
    /// When, as an RFC 3339 timestamp — the evidence half of the record.
    pub accepted_at: String,
    /// Which rendering was on screen, so it is known what was actually read.
    pub language: String,
}

impl Consent {
    fn now(language: Language) -> Self {
        Self {
            version: VERSION.to_owned(),
            accepted_at: rfc3339_now(),
            language: match language {
                Language::Japanese => "ja",
                Language::English => "en",
            }
            .to_owned(),
        }
    }
}

/// Whether `consent` still covers the policy this build carries.
///
/// Separate from the IO so the decision can be tested on its own, and so a
/// caller that keeps consent somewhere else — the iOS app keeps it in
/// `UserDefaults` — can use the same rule.
pub fn needs_agreement(consent: Option<&Consent>) -> bool {
    match consent {
        Some(consent) => consent.version != VERSION,
        None => true,
    }
}

/// Read the recorded agreement for this user, if there is one.
///
/// A missing or unreadable record reads as "not agreed": the cost of asking
/// again is a dialog, and the cost of assuming agreement that cannot be shown
/// is that there is no record of it.
pub fn load(app: &str) -> Option<Consent> {
    let path = consent_path(app).ok()?;
    let raw = std::fs::read(path).ok()?;
    serde_json::from_slice(&raw).ok()
}

/// Record that this user agreed to the current policy.
pub fn save(app: &str, language: Language) -> anyhow::Result<Consent> {
    let consent = Consent::now(language);
    let path = consent_path(app)?;
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create {}", dir.display()))?;
    }
    let json = serde_json::to_vec_pretty(&consent)?;
    std::fs::write(&path, json)
        .with_context(|| format!("failed to record consent at {}", path.display()))?;
    Ok(consent)
}

/// Where this user's agreement is kept.
///
/// Deliberately **not** beside the working directory, unlike the Endpoint key
/// and the token store. Those are per-installation working files; an agreement
/// is a fact about a person, and one that appears or disappears depending on
/// which directory the application was started from is not a record of anything.
fn consent_path(app: &str) -> anyhow::Result<PathBuf> {
    Ok(config_dir()?.join(format!("{app}-privacy-consent.json")))
}

/// The per-user configuration directory, by each platform's own convention.
fn config_dir() -> anyhow::Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")
            .context("APPDATA is not set, so there is nowhere to record consent")?;
        return Ok(Path::new(&base).join("ISEKAI link"));
    }
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")
            .context("HOME is not set, so there is nowhere to record consent")?;
        return Ok(Path::new(&home)
            .join("Library/Application Support")
            .join("ISEKAI link"));
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        if let Some(base) = std::env::var_os("XDG_CONFIG_HOME").filter(|v| !v.is_empty()) {
            return Ok(Path::new(&base).join("isekai-link"));
        }
        let home = std::env::var_os("HOME").context(
            "neither XDG_CONFIG_HOME nor HOME is set, so there is nowhere to \
                      record consent",
        )?;
        Ok(Path::new(&home).join(".config").join("isekai-link"))
    }
}

fn rfc3339_now() -> String {
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn consent(version: &str) -> Consent {
        Consent {
            version: version.to_owned(),
            accepted_at: "2026-08-05T00:00:00Z".to_owned(),
            language: "ja".to_owned(),
        }
    }

    /// Nothing recorded means nobody has been asked yet.
    #[test]
    fn no_record_means_it_has_to_be_asked() {
        assert!(needs_agreement(None));
    }

    #[test]
    fn agreeing_to_this_version_is_enough() {
        assert!(!needs_agreement(Some(&consent(VERSION))));
    }

    /// The point of recording a version. Someone who agreed to last year's
    /// text has not agreed to this one, and a policy that can be revised
    /// without re-asking is a policy nobody has agreed to.
    #[test]
    fn agreeing_to_another_version_is_not() {
        assert!(needs_agreement(Some(&consent("2020-01-01"))));
        assert!(needs_agreement(Some(&consent(""))));
    }

    /// The documents state their own version, and this constant decides when
    /// everyone is asked again. If they drift, the applications would ask for
    /// agreement to a text that says it is something else.
    #[test]
    fn the_documents_and_the_constant_agree_on_the_version() {
        for (name, text) in [("ja", TEXT_JA), ("en", TEXT_EN)] {
            assert!(
                text.contains(VERSION),
                "privacy-policy.{name}.md does not state version {VERSION}",
            );
        }
    }

    /// Both renderings have to be real documents — an empty or stub one would
    /// mean somebody is agreeing to nothing.
    #[test]
    fn both_languages_are_present() {
        assert!(TEXT_JA.len() > 1000, "the Japanese text is missing");
        assert!(TEXT_EN.len() > 1000, "the English text is missing");
        assert!(TEXT_JA.contains("プライバシーポリシー"));
        assert!(TEXT_EN.contains("Privacy Policy"));
    }

    /// The thing the operator most needs to know before publishing: the draft
    /// still has fields only they can fill in.
    #[test]
    fn the_placeholders_are_findable() {
        assert!(
            TEXT_JA.contains("{{") && TEXT_EN.contains("{{"),
            "if the placeholders are gone the review note should be too",
        );
    }

    #[test]
    fn the_other_language_is_offered_by_name() {
        assert_eq!(Language::Japanese.other_label(), "English");
        assert_eq!(Language::English.other_label(), "日本語");
        assert_eq!(Language::Japanese.toggled(), Language::English);
    }
}
