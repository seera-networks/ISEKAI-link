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

use anyhow::Context as _;
use isekai_privacy::{needs_agreement, Language};

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
fn decide(accept: bool, show: bool, agreed: bool) -> Outcome {
    // **Showing wins.** Somebody who asked to read it gets to read it, and a
    // run that passed both would otherwise print nothing and carry on --
    // agreeing to a text it never put on screen.
    if show {
        return Outcome::Print;
    }
    if accept {
        return Outcome::Record;
    }
    if agreed {
        return Outcome::Proceed;
    }
    Outcome::Refuse
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
    let agreed = !needs_agreement(isekai_privacy::load(app).as_ref());
    match decide(accept, show, agreed) {
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
        Outcome::Print => {
            print_policy(language);
            Ok(Decision::Printed)
        }
        Outcome::Refuse => {
            print_policy(language);
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

/// Put the policy where a person will see it.
///
/// **stderr, like every other word these programs say about themselves.**
/// stdout carries answers — an Endpoint ID, a pairing code, a key — and
/// `EP=$(portal-client --whoami)` would otherwise capture a privacy policy.
///
/// The other language is offered as a link rather than printed as well: two
/// full renderings is four hundred lines, and the one that was read is the one
/// recorded with the agreement.
fn print_policy(language: Language) {
    eprintln!("{}", language.text());
    eprintln!(
        "\n---\n{}: {}\n{}: {}",
        language.other_label(),
        language.toggled().url(),
        "This text",
        language.url(),
    );
}

/// Forget this program's recorded agreement.
///
/// **There has to be a way back.** An agreement that cannot be withdrawn on the
/// machine that recorded it is a setting, not an agreement.
pub fn withdraw(app: &str) -> anyhow::Result<()> {
    let path = isekai_privacy::config_dir()?.join(format!("{app}-privacy-consent.json"));
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        // Nothing recorded is the state this asks for, so it is not a failure.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("failed to remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The refusal is the whole feature.** A run that has not been told the
    /// policy is agreed to must not start, and the text has to reach the person
    /// who has to answer -- which is what `Refuse` carries beside the error.
    #[test]
    fn a_run_that_has_not_agreed_is_refused() {
        assert_eq!(decide(false, false, false), Outcome::Refuse);
    }

    /// Asked once, not every run. A flag that had to be repeated for ever ends
    /// up in a shell alias, which records nothing about anybody agreeing.
    #[test]
    fn a_recorded_agreement_carries_the_run() {
        assert_eq!(decide(false, false, true), Outcome::Proceed);
    }

    /// Agreeing writes it down even when there is already a record: the record
    /// is per policy version, and the caller cannot know which version this
    /// one is for.
    #[test]
    fn agreeing_records_it() {
        assert_eq!(decide(true, false, false), Outcome::Record);
        assert_eq!(decide(true, false, true), Outcome::Record);
    }

    /// **Reading it must be possible without agreeing to it**, which is the
    /// point of a separate flag -- and the run stops there rather than going on
    /// under an agreement nobody gave.
    #[test]
    fn asking_to_read_it_prints_it_and_stops() {
        assert_eq!(decide(false, true, false), Outcome::Print);
        assert_eq!(decide(false, true, true), Outcome::Print);
    }

    /// **Both flags together shows the policy.** The other way round is a run
    /// that agrees to a text it never put on screen, and then carries on --
    /// so the answer is the same whether or not there is a record already.
    #[test]
    fn showing_wins_over_accepting() {
        assert_eq!(decide(true, true, false), Outcome::Print);
        assert_eq!(decide(true, true, true), Outcome::Print);
    }
}
