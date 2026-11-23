//! The `[network]` section: which of this host's own addresses the stack may
//! use.
//!
//! **One schema, two files.** `portal-server` carries it inside the service
//! catalogue it already reads, and `portal-client` has a file of its own that
//! holds nothing else. The section is the same in both because what it
//! describes is the same — the host's network, not the role the binary plays —
//! and an operator who has worked out which interfaces are unusable should be
//! able to write the same three lines on either side.
//!
//! What it is for is in [`isekai_p2p_core::local_address`]: `AUTO` pairs every
//! address the host has with every remote, so a docker bridge or a VPN the
//! proxy cannot answer on becomes a path the stack opens and cannot validate.

use std::path::Path;

use anyhow::Context;
use serde::Deserialize;

/// What `portal-client --example-config` writes.
///
/// Deliberately a file that does nothing: every prefix in it is commented out,
/// because the addresses worth excluding are the ones this host has and no
/// example can know them. A starter file that silently excluded something would
/// be worse than none.
pub const EXAMPLE: &str = r#"# Which of this host's own addresses may carry this client's connections.
#
# Nothing here is required. Left empty, every address the host has is available,
# which is the right answer on a machine with one network.
#
# It is worth filling in where the host has addresses the proxy and the relay
# cannot answer on -- a container bridge, a VPN that does not route to them, a
# management interface. Those are tried anyway, cost a socket and a connection
# ID each, and fail; naming them here takes them out of the running.
#
# Each entry is an address and a prefix length. A bare address means the whole
# of it, so `10.1.2.3` is `10.1.2.3/32`. At most 16 entries.
#
# `--exclude-local` adds to this list rather than replacing it, so a prefix that
# matters for one run does not have to be written here.

[network]
exclude_local = [
  # "172.17.0.0/16",   # the docker bridge
  # "10.8.0.0/24",     # a VPN the proxy cannot answer on
  # "fd00::/8",        # unique-local addresses that go nowhere useful
]
"#;

/// The `[network]` section of either file.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Network {
    /// Prefixes `AUTO` may not pick a local address from.
    ///
    /// Kept as written rather than parsed here: the parsing, and the error that
    /// names the offending text, belong to
    /// [`isekai_p2p_core::local_address::ExcludedPrefixes`], which also has to
    /// do it for the command line. Two parsers would be two sets of accepted
    /// spellings.
    #[serde(default)]
    pub exclude_local: Vec<String>,
}

/// The whole of `portal-client`'s configuration file.
///
/// `deny_unknown_fields` for the reason the catalogue's own `File` gives: a
/// mistyped `[netowrk]` would otherwise be discarded, the file would parse, and
/// the client would run with none of the exclusions the operator wrote.
#[derive(Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct File {
    #[serde(default)]
    network: Network,
}

/// Just the `[network]` section, out of a file that may hold anything else.
///
/// **For `portal-server`'s catalogue**, which has to be read for this section
/// before `--login` and the grant administration return — and those have never
/// needed a catalogue. [`crate::config::parse`]'s rules would make them need
/// one: at least one `[service.*]`, every target an address. So this applies
/// none of them and ignores what it does not recognise.
///
/// That leniency is why it is a second function rather than what [`parse`]
/// does. A client's file holds nothing but this section, so an unknown key
/// there is a typo worth refusing; the catalogue's own strict read still
/// happens when the server loads it for the services, so a `[netowrk]` in that
/// file is caught before anything is served.
pub fn section_of(text: &str) -> anyhow::Result<Network> {
    #[derive(Deserialize)]
    struct Section {
        #[serde(default)]
        network: Network,
    }
    let section: Section = toml::from_str(text).context("the file is not valid TOML")?;
    Ok(section.network)
}

/// [`section_of`] from a file.
pub fn load_section(path: &Path) -> anyhow::Result<Network> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;
    section_of(&text).with_context(|| format!("in {}", path.display()))
}

/// Read the configuration from `path`.
pub fn load(path: &Path) -> anyhow::Result<Network> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the configuration at {}", path.display()))?;
    parse(&text).with_context(|| format!("in {}", path.display()))
}

/// [`load`] from a string, which is what the tests use.
pub fn parse(text: &str) -> anyhow::Result<Network> {
    let file: File = toml::from_str(text).context("the configuration is not valid TOML")?;
    Ok(file.network)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example has to load, and has to exclude nothing: it is a file people
    /// copy, and an exclusion they did not mean is a path that silently stops
    /// being used.
    #[test]
    fn the_example_loads_and_excludes_nothing() {
        let network = parse(EXAMPLE).expect("--example-config must produce a file that loads");
        assert!(
            network.exclude_local.is_empty(),
            "the example must not exclude anything by itself",
        );
    }

    /// A file with the section filled in, which is the whole of the format.
    #[test]
    fn the_section_is_read_as_written() {
        let network = parse(
            r#"
            [network]
            exclude_local = ["172.17.0.0/16", "fd00::/8"]
            "#,
        )
        .expect("a filled-in section");
        assert_eq!(network.exclude_local, ["172.17.0.0/16", "fd00::/8"]);
    }

    /// Empty and absent are the same answer, so a file that holds only comments
    /// is as good as no file.
    #[test]
    fn an_empty_file_excludes_nothing() {
        assert_eq!(parse("").expect("empty"), Network::default());
        assert_eq!(
            parse("[network]\n").expect("bare section"),
            Network::default()
        );
    }

    /// **The lenient reader ignores what it does not know**, which is the one
    /// thing it must do differently from [`parse`]: it reads the server's
    /// catalogue, and a catalogue is full of sections this type knows nothing
    /// about.
    #[test]
    fn the_section_can_be_read_out_of_a_catalogue() {
        let network = section_of(
            r#"[service.db]
               protocol = "tcp"
               target = "nonsense-that-parse-would-refuse"

               [network]
               exclude_local = ["172.17.0.0/16"]"#,
        )
        .expect("a catalogue's network section");
        assert_eq!(network.exclude_local, ["172.17.0.0/16"]);

        // And a file with no section at all, which is every catalogue written
        // before this existed.
        assert_eq!(
            section_of("[service.db]\nprotocol = \"tcp\"\ntarget = \"10.0.0.5:5432\"\n")
                .expect("no section"),
            Network::default(),
        );
        // Still TOML, though.
        assert!(section_of("[network").is_err());
    }

    /// **A mistyped key is refused rather than ignored**, which is the whole
    /// reason for `deny_unknown_fields`: the other behaviour is a client that
    /// runs with none of the exclusions and says nothing.
    #[test]
    fn a_mistyped_key_is_refused() {
        for bad in [
            "[netowrk]\nexclude_local = []\n",
            "[network]\nexclude_locals = []\n",
            "[network]\nexclude_local = \"10.0.0.0/8\"\n",
        ] {
            assert!(parse(bad).is_err(), "`{bad}` must not load");
        }
    }
}
