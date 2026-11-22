//! Which of this host's own addresses the stack may use (feature `msquic`).
//!
//! `AUTO` — the mode every connection in this crate runs in — pairs every
//! address the host has with every remote the connection knows, and opens paths
//! from the top of that table. On a laptop that table includes the docker
//! bridge, a VPN the proxy cannot answer on, and whatever a container runtime
//! left behind. Those pairs become paths the stack opens and cannot validate:
//! each costs a UDP binding and a destination CID out of four, and msquic
//! rate-limits the churn rather than avoiding it.
//!
//! seera-msquic answers that with a per-connection policy, and this is where
//! the operator's list of them lives. **Process-wide**, like the registration
//! in [`crate::transport`], because what it describes is the host's network
//! rather than any one connection: the same addresses are unusable for the
//! control plane, for every relay leg, and for a published public address.
//!
//! The policies have to be in place *before* a connection starts —
//! `QuicConnAddLocalAddressPolicy` inserts the rule and queues nothing, so one
//! added later leaves the paths already opened where they are — which is why
//! [`set`] is called once from `main` and the connectors read it as they are
//! built.

use anyhow::Context;
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::str::FromStr;
use std::sync::Mutex;

/// How many policies one connection may carry.
///
/// `QUIC_MAX_LOCAL_ADDRESS_POLICIES`. The seventeenth is refused with
/// `QUIC_STATUS_PATH_LIMIT_REACHED`, which would surface as a connection that
/// cannot be opened — so the limit is checked here instead, where the list can
/// be named in the error.
pub const MAX_EXCLUDED_PREFIXES: usize = 16;

/// One rule: an address, and how much of it to match on.
///
/// `10.0.0.0/8` and `fd00::/8` are the ordinary forms. A bare address is the
/// whole of it — `10.1.2.3` is `10.1.2.3/32` — which is what an operator
/// excluding one interface writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct ExcludedPrefix {
    address: IpAddr,
    prefix_length: u8,
}

impl ExcludedPrefix {
    /// The longest prefix `address` can carry: 32 for IPv4, 128 for IPv6.
    fn host_length(address: IpAddr) -> u8 {
        match address {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        }
    }

    /// What `with_local_address_policies` takes.
    ///
    /// The port is ignored by msquic — a policy is about addresses — and it
    /// clears it before storing, so zero is what it would report back anyway.
    fn as_policy(self) -> (SocketAddr, u8) {
        (SocketAddr::new(self.address, 0), self.prefix_length)
    }
}

impl FromStr for ExcludedPrefix {
    type Err = anyhow::Error;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let (address, length) = match text.split_once('/') {
            Some((address, length)) => (address, Some(length)),
            None => (text, None),
        };
        let address: IpAddr = address.trim().parse().map_err(|_| {
            anyhow::anyhow!(
                "`{text}` does not name an address and prefix. Write one as \
                 `10.0.0.0/8` or `fd00::/8`, or a single address as `10.1.2.3`",
            )
        })?;
        // **IPv4-mapped is unmapped first, as msquic does it.** It validates
        // the prefix against the family it ends up with, so `::ffff:10.1.2.3`
        // is an IPv4 address and `/128` is refused rather than stored as a rule
        // that could never match. Doing it here means the length below is
        // checked against the same family, and that the error says so.
        let address = match address {
            IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
                Some(v4) => IpAddr::V4(v4),
                None => IpAddr::V6(v6),
            },
            v4 => v4,
        };
        let host_length = Self::host_length(address);
        let prefix_length = match length {
            None => host_length,
            Some(length) => {
                let length: u8 = length.trim().parse().map_err(|_| {
                    anyhow::anyhow!("`{text}` has a prefix length that is not a number")
                })?;
                anyhow::ensure!(
                    length <= host_length,
                    "`{text}` has a prefix length of {length}, and {address} is an \
                     {family} address, so the longest it can be is {host_length}",
                    family = if host_length == 32 { "IPv4" } else { "IPv6" },
                );
                length
            }
        };
        Ok(Self {
            address,
            prefix_length,
        })
    }
}

impl fmt::Display for ExcludedPrefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.address, self.prefix_length)
    }
}

/// The prefixes this process will not let `AUTO` pick from.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ExcludedPrefixes(Vec<ExcludedPrefix>);

impl ExcludedPrefixes {
    /// Everything the command line said and everything the configuration file
    /// said, which is **both** rather than one overriding the other.
    ///
    /// An operator keeping a host's own interfaces in a file and adding one for
    /// a single run should get both; making the flag replace the file would
    /// mean re-stating the file to add one line, and making the file win would
    /// mean the flag silently did nothing. Neither is a reading of "specify it
    /// in either place".
    ///
    /// The same prefix from both sources is one policy: msquic refuses an exact
    /// duplicate with `ADDRESS_IN_USE`, and an overlap between the two lists is
    /// the ordinary case rather than a mistake worth failing over. `10.0.0.0/8`
    /// and `10.1.0.0/16` are **not** duplicates — msquic compares address,
    /// prefix and action together — so both are kept.
    pub fn union(arguments: &[String], file: &[String]) -> anyhow::Result<Self> {
        let mut prefixes = Vec::new();
        for (text, source) in arguments
            .iter()
            .map(|text| (text, "the command line"))
            .chain(file.iter().map(|text| (text, "the configuration file")))
        {
            let prefix: ExcludedPrefix = text
                .parse()
                .with_context(|| format!("in the excluded prefix from {source}"))?;
            if !prefixes.contains(&prefix) {
                prefixes.push(prefix);
            }
        }
        anyhow::ensure!(
            prefixes.len() <= MAX_EXCLUDED_PREFIXES,
            "{} prefixes are excluded and msquic takes at most {MAX_EXCLUDED_PREFIXES}: {}",
            prefixes.len(),
            prefixes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        );
        Ok(Self(prefixes))
    }

    /// Whether these are the same prefixes, whatever order they were written
    /// in. See [`set`].
    fn same_set_as(&self, other: &Self) -> bool {
        let mut mine = self.0.clone();
        let mut theirs = other.0.clone();
        mine.sort();
        theirs.sort();
        mine == theirs
    }

    /// Nothing excluded, which is what every caller that says nothing gets.
    pub fn none() -> Self {
        Self(Vec::new())
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// For a log line, in the form they were written in.
    pub fn describe(&self) -> String {
        self.0
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// What the connector takes, with the action this crate always means.
    ///
    /// `Exclude` is the only action msquic accepts today, and the connector
    /// takes it per entry rather than assuming it so that a later one needs no
    /// new signature. This crate has nothing to say with a second action, so it
    /// names the one it means.
    pub(crate) fn as_policies(
        &self,
    ) -> Vec<(
        SocketAddr,
        u8,
        h3_util::msquic_async::LocalAddressPolicyAction,
    )> {
        self.0
            .iter()
            .map(|prefix| {
                let (address, length) = prefix.as_policy();
                (
                    address,
                    length,
                    h3_util::msquic_async::LocalAddressPolicyAction::Exclude,
                )
            })
            .collect()
    }
}

/// The process's list, read by every connector this crate builds.
static EXCLUDED: Mutex<Option<ExcludedPrefixes>> = Mutex::new(None);

/// Record what the operator excluded, before anything dials.
///
/// **Once**, from `main`. A second call with a different list is an error
/// rather than a replacement: connections already open keep the policies they
/// started with — the parameter has no effect on a path that exists — so a
/// process with two answers would behave differently per connection with
/// nothing saying which. Calling it twice with the *same* list is allowed,
/// because a binary that configures itself on more than one path should not
/// have to track whether it already did.
pub fn set(prefixes: ExcludedPrefixes) -> anyhow::Result<()> {
    let mut slot = EXCLUDED.lock().expect("excluded-prefix mutex poisoned");
    match slot.as_ref() {
        // **As a set, not in order.** The promise above is that a binary which
        // settles this on more than one path need not track whether it already
        // did, and two call sites that build the same prefixes from the file
        // and the flag in a different order would otherwise hit the refusal
        // below. What the policies do does not depend on their order, so
        // neither does this.
        Some(existing) if !existing.same_set_as(&prefixes) => anyhow::bail!(
            "the excluded local prefixes were already set to `{}` and cannot be changed to \
             `{}`: a connection keeps the policies it started with",
            existing.describe(),
            prefixes.describe(),
        ),
        _ => {
            // Said once, here, rather than per connection: every connector
            // this process builds reads the same list, and a line per leg
            // would say the same thing a dozen times.
            if prefixes.is_empty() {
                tracing::debug!("no local addresses are excluded");
            } else {
                tracing::info!(
                    count = prefixes.len(),
                    "excluding local addresses from automatic path selection: {}",
                    prefixes.describe(),
                );
            }
            *slot = Some(prefixes);
            Ok(())
        }
    }
}

/// What [`set`] recorded, or nothing.
pub(crate) fn current() -> ExcludedPrefixes {
    EXCLUDED
        .lock()
        .expect("excluded-prefix mutex poisoned")
        .clone()
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn prefix(text: &str) -> ExcludedPrefix {
        text.parse().expect(text)
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| (*s).to_owned()).collect()
    }

    /// The forms an operator writes, and the one that is a shorthand: a bare
    /// address is the whole of it, because excluding one interface is the
    /// commonest reason to write any of this.
    #[test]
    fn a_bare_address_is_the_whole_of_it() {
        assert_eq!(prefix("10.0.0.0/8").to_string(), "10.0.0.0/8");
        assert_eq!(prefix("fd00::/8").to_string(), "fd00::/8");
        assert_eq!(prefix("10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(prefix("fd00::1").to_string(), "fd00::1/128");
        // Whitespace around either half, which is what a hand-edited TOML
        // list and a shell quoting mistake both produce.
        assert_eq!(prefix(" 10.0.0.0 / 8 ").to_string(), "10.0.0.0/8");
    }

    /// **Unmapped before the length is judged, as msquic does it**, so the
    /// prefix is checked against the family the address ends up as. Without
    /// this `::ffff:10.1.2.3/128` would be stored as a rule that can never
    /// match, and `/32` would be refused for naming the whole of an address.
    #[test]
    fn an_ipv4_mapped_address_is_an_ipv4_address() {
        assert_eq!(prefix("::ffff:10.1.2.3").to_string(), "10.1.2.3/32");
        assert_eq!(prefix("::ffff:10.1.2.3/32").to_string(), "10.1.2.3/32");
        assert!("::ffff:10.1.2.3/128".parse::<ExcludedPrefix>().is_err());
    }

    /// Every refusal names the text it came from: these arrive from a file an
    /// operator wrote, and "invalid prefix" without the line is a hunt.
    #[test]
    fn what_cannot_be_a_prefix_says_so() {
        for bad in [
            "10.0.0.0/33",
            "fd00::/129",
            "10.0.0.0/eight",
            "not-an-address",
            "",
            "/8",
            "10.0.0.0/",
        ] {
            let error = format!("{:#}", bad.parse::<ExcludedPrefix>().unwrap_err());
            assert!(
                error.contains(bad) || bad.is_empty(),
                "the error for `{bad}` has to quote it, and said: {error}",
            );
        }
        // And the one that is easiest to get wrong says what the limit is.
        let error = format!("{:#}", "10.0.0.0/33".parse::<ExcludedPrefix>().unwrap_err());
        assert!(error.contains("32"), "{error}");
        assert!(error.contains("IPv4"), "{error}");
    }

    /// **Both sources, not one of them.** This is the behaviour asked for, and
    /// the two wrong answers are a flag that silently does nothing and a file
    /// that has to be restated to add one line for a single run.
    #[test]
    fn the_two_sources_are_added_together() {
        let both = ExcludedPrefixes::union(
            &strings(&["172.17.0.0/16"]),
            &strings(&["10.8.0.0/24", "fd00::/8"]),
        )
        .expect("a union of three");
        assert_eq!(both.len(), 3);
        assert_eq!(both.describe(), "172.17.0.0/16, 10.8.0.0/24, fd00::/8");
    }

    /// The same prefix from both is one policy — msquic refuses an exact
    /// duplicate — while two prefixes that merely overlap are two policies,
    /// because that is how msquic compares them.
    #[test]
    fn a_repeat_is_one_policy_and_an_overlap_is_two() {
        let same = ExcludedPrefixes::union(
            &strings(&["10.0.0.0/8"]),
            &strings(&["10.0.0.0/8", " 10.0.0.0/8 "]),
        )
        .expect("one policy");
        assert_eq!(same.describe(), "10.0.0.0/8");

        let overlapping =
            ExcludedPrefixes::union(&strings(&["10.0.0.0/8"]), &strings(&["10.1.0.0/16"]))
                .expect("two policies");
        assert_eq!(overlapping.len(), 2);
    }

    /// Checked here rather than at `connect`, where the seventeenth policy
    /// comes back as a connection that cannot be opened and nothing names the
    /// list.
    #[test]
    fn more_than_msquic_takes_is_refused_with_the_list() {
        let many: Vec<String> = (0..MAX_EXCLUDED_PREFIXES + 1)
            .map(|i| format!("10.{i}.0.0/16"))
            .collect();
        let error = format!("{:#}", ExcludedPrefixes::union(&many, &[]).unwrap_err());
        assert!(error.contains("17"), "{error}");
        assert!(
            error.contains(&MAX_EXCLUDED_PREFIXES.to_string()),
            "{error}"
        );
        assert!(error.contains("10.16.0.0/16"), "{error}");

        // And exactly the limit is fine, because an operator with sixteen
        // interfaces to exclude is not doing anything wrong.
        let at_the_limit = &many[..MAX_EXCLUDED_PREFIXES];
        assert_eq!(
            ExcludedPrefixes::union(at_the_limit, &[])
                .expect("sixteen")
                .len(),
            MAX_EXCLUDED_PREFIXES,
        );
    }

    /// The guarantee [`set`] documents: the same prefixes twice is allowed,
    /// **whatever order they were written in**, so a binary that settles this
    /// on two paths need not track whether it already did. A different set is
    /// still refused, because a connection keeps the policies it started with.
    #[test]
    fn the_same_prefixes_in_another_order_are_the_same_answer() {
        let one = ExcludedPrefixes::union(&strings(&["10.0.0.0/8"]), &strings(&["fd00::/8"]))
            .expect("two");
        let other = ExcludedPrefixes::union(&strings(&["fd00::/8"]), &strings(&["10.0.0.0/8"]))
            .expect("the same two");
        assert_ne!(one, other, "the written order is kept, which the log wants");
        assert!(one.same_set_as(&other), "but they are the same policies");

        let fewer = ExcludedPrefixes::union(&strings(&["10.0.0.0/8"]), &[]).expect("one");
        assert!(!one.same_set_as(&fewer));
    }

    /// Nothing said means nothing excluded, which has to stay the shape of the
    /// default: every binary that says nothing about this keeps `AUTO` whole.
    #[test]
    fn saying_nothing_excludes_nothing() {
        let empty = ExcludedPrefixes::union(&[], &[]).expect("an empty union");
        assert!(empty.is_empty());
        assert_eq!(empty, ExcludedPrefixes::none());
        assert_eq!(empty.describe(), "");
    }
}
