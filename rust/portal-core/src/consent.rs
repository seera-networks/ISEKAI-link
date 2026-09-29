//! Refusing to run until the privacy policy has been agreed to.
//!
//! **Using ISEKAI link needs an account, and an account means personal
//! information.** The camera applications draw the policy and offer a button
//! (`camera-ui::ConsentGate`); these two have no window, so they print it and
//! stop. The text, the version and the record are the same ones — the crate
//! that holds them is [`isekai_privacy`], and an operator who has agreed in one
//! program has not thereby agreed in another: the record is per program, as it
//! is for the two camera applications on one machine.
//!
//! **Recorded, so it is asked once rather than every run.** A flag that had to
//! be repeated for ever would end up in a shell alias within the week, which is
//! a worse record of agreement than a file. The flag still works every time,
//! which is what an unattended job wants; the file is what stops a person being
//! asked twice.
//!
//! **And asked again when the policy changes**, because agreement to one text
//! is not agreement to the next one. That is the whole point of
//! [`isekai_privacy::VERSION`].

use isekai_privacy::{needs_agreement, Consent, Language};

/// What the two flags between them say to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Carry on with the run.
    Proceed,
    /// The policy was asked for and has been printed; exit successfully.
    Printed,
}

/// What [`decide`] says should happen, including the case [`Decision`] cannot
/// carry because the run does not continue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Nothing more to ask.
    Proceed,
    /// Agreed just now; record it, then proceed.
    Record,
    /// Print the policy and stop, successfully — it was asked for.
    Print,
    /// Print the policy and refuse the run.
    Refuse,
}

/// The whole of the decision, with the reading and writing left outside.
///
/// **Separated so it can be tested at all.** The record lives in the user's
/// configuration directory, which a test would have to move by environment
/// variable — and environment variables are process-wide, so two tests doing it
/// at once decide each other's outcome.
fn decide(accept: bool, show: bool, recorded: Option<&Consent>) -> Outcome {
    // **Showing wins.** Somebody who asked to read it gets to read it, and a
    // run that passed both would otherwise print nothing and carry on --
    // agreeing to a text it never put on screen.
    if show {
        return Outcome::Print;
    }
    if accept {
        return Outcome::Record;
    }
    // **The record, not a `bool` derived from it.** This took a `bool agreed`
    // and the caller computed it with `!needs_agreement(..)` -- a negation
    // outside every test, which cargo-mutants deleted without a single test
    // noticing. Taking what was read closes that, and stops the three states
    // (nothing recorded, an old version, this version) being flattened into
    // two on the way in.
    if needs_agreement(recorded) {
        return Outcome::Refuse;
    }
    Outcome::Proceed
}

/// Decide whether this run may go ahead, printing the policy when it may not.
///
/// **Before anything else**, which is why it takes no network and touches no
/// Endpoint key: a run that registered a device and *then* asked has already
/// done the thing it was asking about.
///
/// `accept` is `--accept-privacy-policy` and `show` is `--show-privacy-policy`.
/// Showing wins over accepting: somebody who asked to read it gets to read it,
/// and a run that did both would otherwise print nothing and carry on.
pub fn gate(app: &'static str, accept: bool, show: bool) -> anyhow::Result<Decision> {
    let language = Language::preferred();
    let recorded = isekai_privacy::load(app);
    match decide(accept, show, recorded.as_ref()) {
        Outcome::Proceed => Ok(Decision::Proceed),
        Outcome::Record => {
            // **Not fatal when it cannot be written.** The person has agreed;
            // the only cost of an unwritten record is being asked again, and
            // refusing the run over it would turn a read-only home directory
            // into an unusable installation.
            if let Err(e) = isekai_privacy::save(app, language) {
                tracing::warn!("could not record your agreement, so it will be asked again: {e:#}");
            }
            Ok(Decision::Proceed)
        }
        // **stdout, because here the policy *is* the answer.** Somebody who
        // asked for it is the one redirecting it into a file or a pager, and
        // `--show-privacy-policy > policy.txt` writing an empty file is the
        // whole command failing quietly.
        Outcome::Print => {
            println!("{}", rendered(language));
            Ok(Decision::Printed)
        }
        Outcome::Refuse => {
            // **stderr on this path**, where the answer is the refusal and
            // stdout carries what these programs are asked for -- an Endpoint
            // ID, a pairing code. `EP=$(portal-client --whoami)` would
            // otherwise capture a privacy policy.
            eprintln!("{}", rendered(language));
            anyhow::bail!(
                "{app} collects personal information, and has not been told you agree to the \
                 policy above (version {version}). Pass --accept-privacy-policy to agree and \
                 carry on; it is recorded, so it is asked once rather than every run. \
                 --show-privacy-policy prints the policy on its own.",
                version = isekai_privacy::VERSION,
            )
        }
    }
}

/// The policy as it is shown, with both links under it.
///
/// The other language is linked rather than printed as well: two full
/// renderings is four hundred lines, and the one that was read is the one
/// recorded with the agreement. Both labels are in the language they name.
fn rendered(language: Language) -> String {
    format!(
        "{}\n---\n{}: {}\n{}: {}",
        language.text(),
        language.this_label(),
        language.url(),
        language.other_label(),
        language.toggled().url(),
    )
}

/// Forget this program's recorded agreement, so it is asked again.
///
/// **There has to be a way back.** An agreement that cannot be withdrawn on the
/// machine that recorded it is a setting, not an agreement.
///
/// **Re-exported rather than wrapped.** The wrapper it replaces was one line
/// of delegation, and cargo-mutants could turn it into `Ok(())` -- a
/// withdrawal that reports success and removes nothing -- without a test
/// noticing. A test for a line that forwards is worth less than not having the
/// line: this way the only code is the one `isekai-privacy` tests.
pub use isekai_privacy::forget as withdraw;

#[cfg(test)]
mod tests {
    use super::*;

    fn agreed(version: &str) -> Consent {
        Consent {
            version: version.to_owned(),
            accepted_at: "2026-09-24T00:00:00Z".to_owned(),
            language: "en".to_owned(),
        }
    }

    /// **The refusal is the whole feature.** A run that has not been told the
    /// policy is agreed to must not start, and the text has to reach the person
    /// who has to answer -- which is what `Refuse` carries beside the error.
    #[test]
    fn a_run_that_has_not_agreed_is_refused() {
        assert_eq!(decide(false, false, None), Outcome::Refuse);
    }

    /// Asked once, not every run. A flag that had to be repeated for ever ends
    /// up in a shell alias, which records nothing about anybody agreeing.
    #[test]
    fn a_recorded_agreement_carries_the_run() {
        let this = agreed(isekai_privacy::VERSION);
        assert_eq!(decide(false, false, Some(&this)), Outcome::Proceed);
    }

    /// **The third state, which a `bool` could not carry.** An agreement to
    /// last year's text is not an agreement to this one, and it is the state
    /// every policy revision puts everybody into.
    #[test]
    fn an_agreement_to_another_version_is_refused() {
        let old = agreed("2020-01-01");
        assert_eq!(decide(false, false, Some(&old)), Outcome::Refuse);
    }

    /// Agreeing writes it down even when there is already a record: the record
    /// is per policy version, and the caller cannot know which version this
    /// one is for.
    #[test]
    fn agreeing_records_it() {
        let this = agreed(isekai_privacy::VERSION);
        assert_eq!(decide(true, false, None), Outcome::Record);
        assert_eq!(decide(true, false, Some(&this)), Outcome::Record);
    }

    /// **Reading it must be possible without agreeing to it**, which is the
    /// point of a separate flag -- and the run stops there rather than going on
    /// under an agreement nobody gave.
    #[test]
    fn asking_to_read_it_prints_it_and_stops() {
        let this = agreed(isekai_privacy::VERSION);
        assert_eq!(decide(false, true, None), Outcome::Print);
        assert_eq!(decide(false, true, Some(&this)), Outcome::Print);
    }

    /// **Both flags together shows the policy.** The other way round is a run
    /// that agrees to a text it never put on screen, and then carries on --
    /// so the answer is the same whether or not there is a record already.
    #[test]
    fn showing_wins_over_accepting() {
        let this = agreed(isekai_privacy::VERSION);
        assert_eq!(decide(true, true, None), Outcome::Print);
        assert_eq!(decide(true, true, Some(&this)), Outcome::Print);
    }

    /// **What is put on screen has to be the policy.** Nothing held `rendered`
    /// to returning it, so a version of this that printed nothing at all would
    /// have refused the run with a blank screen above the error and passed
    /// every test -- which is the whole feature failing quietly.
    #[test]
    fn what_is_shown_is_the_policy_and_the_way_to_both_renderings() {
        let english = rendered(Language::English);
        assert!(english.contains("ISEKAI link Privacy Policy"), "{english}");
        assert!(english.contains(isekai_privacy::VERSION), "{english}");
        // Both links, so the reader can reach the other language and the
        // current copy of this one.
        assert!(english.contains("privacy-policy.en.md"));
        assert!(english.contains("privacy-policy.ja.md"));
        // Each label in the language it names (`this_label` / `other_label`).
        assert!(english.contains("This text"));
        assert!(english.contains("日本語"));

        let japanese = rendered(Language::Japanese);
        assert!(japanese.contains("プライバシーポリシー"), "{japanese}");
        assert!(japanese.contains("この文書"));
        assert!(japanese.contains("English"));
        assert_ne!(english, japanese);
    }
}
