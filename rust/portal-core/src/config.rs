//! The file that says what may be reached.
//!
//! **Phase 2 of `docs/portal_plan.md`**, and the security-relevant half of this
//! crate. §4.3 is the argument: the initiator asks for `db` and never for a
//! host and port, because a caller that could name an address turns the server
//! into an open proxy onto whatever network it can see — every device on that
//! LAN, every link-local metadata endpoint, every `127.0.0.1` service the
//! operator never meant to expose. A Grant says two Endpoints may talk; it says
//! nothing about what may be reached.
//!
//! So this file is the whole of what is reachable, and nothing in it crosses
//! the wire.
//!
//! ```toml
//! [service.db]
//! protocol = "tcp"
//! target   = "10.0.0.5:5432"
//!
//! [service.dns]
//! protocol = "udp"
//! target   = "10.0.0.1:53"
//! ```
//!
//! # Targets are addresses, not names
//!
//! `target` is parsed as a `host:port` literal. A hostname would mean resolving
//! it, which puts a DNS lookup on the path of every forwarded connection and a
//! resolver's answer in charge of where traffic goes — a different decision
//! from this one, and not one to make by accepting a string that happens to
//! parse either way.
//!
//! # UDP is served as of phase 3b
//!
//! `protocol = "udp"` was accepted and refused from phase 2, so that the file
//! format would not change under anyone when phase 3 landed. It has, and it did
//! not: a file written for phase 2 means today what it meant then, and a
//! catalogue of nothing but UDP services is now a server with work to do rather
//! than one that would refuse everything.
//!
//! What has not changed is that asking for a service over the protocol it is
//! *not* offered under is refused, with the same answer as a name that does not
//! exist — see [`crate::server::Lookup`].
//!
//! **One thing the file does not say is how large a datagram may be.** UDP
//! services are forwarded up to [`crate::datagram::MAX_PAYLOAD`] and anything
//! over that is dropped, which no entry here can raise; the constant's own
//! documentation says why, and DNS is the case to know about.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::Path;

use anyhow::Context as _;
use serde::Deserialize;

use crate::server::{Catalogue, Protocol};

/// A catalogue to start from, which `portal-server --example-config` prints.
///
/// **The targets are RFC 5737 documentation addresses**, and that is the
/// security-relevant part of this constant rather than a stylistic one. This is
/// a file people copy and edit, and an example left in among their own entries
/// is an entry they did not mean to offer. `10.0.0.1:53` reads as a plausible
/// placeholder and is the commonest LAN gateway there is — on exactly the
/// networks portal is pointed at — so leaving it in would quietly publish the
/// operator's own resolver, and it would *work*, which is what makes it worse
/// than a typo. `192.0.2.0/24` is routed nowhere by definition, so the same
/// mistake costs an `Unreachable` and a log line naming the service.
///
/// The commentary is the half of the format that a schema cannot carry — what
/// may be reached is decided here and only here.
pub const EXAMPLE: &str = r#"# What this portal server offers, and nothing else.
#
# A peer asks for a service by NAME. The target below never crosses the wire, so
# a peer cannot reach anything that is not listed here -- which is the whole
# point: a Grant says two Endpoints may talk, not what may be reached.
#
# Targets are addresses, never hostnames. Resolving one would put a DNS answer
# in charge of where forwarded traffic goes, which is a different decision from
# this one.
#
# The forward carries whatever the service speaks. If that is plaintext, it is
# plaintext to the peer that reached it -- a tunnel does not authenticate the
# service at the far end of it.

# The addresses below are RFC 5737 documentation addresses, routed nowhere.
# Replace them: an example left in among your own entries is a service you did
# not mean to offer.

[service.db]
protocol = "tcp"
target   = "192.0.2.10:5432"

# UDP is forwarded up to 1163 bytes per datagram; anything larger is
# dropped and counted rather than split. A large DNS response can exceed it.
[service.dns]
protocol = "udp"
target   = "192.0.2.1:53"
"#;

/// Read the catalogue from `path`.
pub fn load(path: &Path) -> anyhow::Result<Catalogue> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read the service catalogue at {}", path.display()))?;
    parse(&text).with_context(|| format!("in {}", path.display()))
}

/// [`load`] from a string, which is what the tests use.
pub fn parse(text: &str) -> anyhow::Result<Catalogue> {
    let file: File = toml::from_str(text).context("the service catalogue is not valid TOML")?;
    anyhow::ensure!(
        !file.service.is_empty(),
        "the service catalogue offers nothing; add a [service.<name>] section",
    );
    let mut catalogue = Catalogue::new();
    for (name, entry) in file.service {
        let protocol = match entry.protocol.as_str() {
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            other => anyhow::bail!(
                "service `{name}` has protocol `{other}`; it must be \"tcp\" or \"udp\"",
            ),
        };
        let target: SocketAddr = entry.target.parse().with_context(|| {
            format!(
                "service `{name}` has target `{}`, which is not a host:port address. \
                 A name would have to be resolved, and this file decides where traffic \
                 goes rather than delegating that to a resolver",
                entry.target,
            )
        })?;
        catalogue = catalogue
            .try_with(&name, protocol, target)
            .with_context(|| format!("service `{name}`"))?;
    }
    Ok(catalogue)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    /// `#[serde(default)]` so an empty file reaches the message above rather
    /// than a missing-field error about a table nobody wrote.
    ///
    /// And `deny_unknown_fields` above it, because without that `[services.db]`
    /// or `[srevice.db]` is *discarded*: the file parses, the remaining
    /// sections load, and the server offers a subset of what the operator
    /// wrote with nothing said. A catalogue that silently offers less is the
    /// benign direction of a mistake whose other direction is offering more,
    /// and neither should be silent.
    #[serde(default)]
    service: BTreeMap<String, ServiceEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceEntry {
    /// Not an enum with `#[serde(rename_all)]`: serde's own message for a bad
    /// variant names the field and the expected values, and this one names the
    /// *service* — which is what an operator with a dozen of them needs.
    protocol: String,
    target: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::Lookup;

    const BOTH: &str = r#"
        [service.db]
        protocol = "tcp"
        target   = "10.0.0.5:5432"

        [service.dns]
        protocol = "udp"
        target   = "10.0.0.1:53"
    "#;

    #[test]
    fn the_example_from_the_plan_loads() {
        let catalogue = parse(BOTH).expect("the plan's own example");
        assert_eq!(catalogue.len(), 2);
        assert_eq!(
            catalogue.look_up("db", Protocol::Tcp),
            Lookup::Found("10.0.0.5:5432".parse().unwrap()),
        );
    }

    /// **The property §4.3 is about.** A name offered over the other protocol
    /// and a name that does not exist are different things to the operator and
    /// must be the same thing to the caller — `forward_one` turns both of these
    /// into one `Refused`, and it can only do that because both arrive here.
    #[test]
    fn a_udp_service_is_not_reachable_over_tcp() {
        let catalogue = parse(BOTH).expect("parse");
        assert_eq!(
            catalogue.look_up("dns", Protocol::Tcp),
            Lookup::WrongProtocol(Protocol::Udp),
            "asking for a UDP service over TCP must not find it",
        );
        assert_eq!(catalogue.look_up("nothing", Protocol::Tcp), Lookup::Unknown);
    }

    /// **The example is a file, and files get typos.** `--example-config` is
    /// the first thing somebody runs, so one that does not parse is worse than
    /// no example at all — they would go looking for what *they* did wrong.
    /// Here rather than in the binary because this is where `parse` lives, and
    /// an example that drifts from its parser is the same failure a step later.
    #[test]
    fn the_example_catalogue_is_one_this_would_accept() {
        let catalogue = parse(EXAMPLE).expect("--example-config must produce a file that loads");
        assert_eq!(
            catalogue.look_up("db", Protocol::Tcp),
            Lookup::Found("192.0.2.10:5432".parse().unwrap()),
        );
        assert_eq!(
            catalogue.look_up("dns", Protocol::Udp),
            Lookup::Found("192.0.2.1:53".parse().unwrap()),
            "and the targets stay inside RFC 5737, for the reason `EXAMPLE` gives",
        );
    }

    /// **Phase 2 rejected this file outright**, because a server offering only
    /// UDP would have registered an Endpoint, opened a listener and refused
    /// every request. 3b serves them, so the rejection went — and a file written
    /// under the old rule still means exactly what it meant then.
    #[test]
    fn a_catalogue_of_nothing_but_udp_is_a_server_with_work_to_do() {
        let catalogue = parse(
            r#"[service.dns]
               protocol = "udp"
               target = "10.0.0.1:53""#,
        )
        .expect("a UDP-only catalogue is served as of phase 3b");
        assert_eq!(
            catalogue.look_up("dns", Protocol::Udp),
            Lookup::Found("10.0.0.1:53".parse().unwrap()),
        );
        assert_eq!(
            catalogue.look_up("dns", Protocol::Tcp),
            Lookup::WrongProtocol(Protocol::Udp),
            "and it is still not reachable over the other protocol",
        );
    }

    /// A file is written by hand, so every way of getting it wrong is a message
    /// naming the service rather than a panic or a silent omission.
    #[test]
    fn what_is_wrong_with_it_is_said_out_loud() {
        for (bad, expected) in [
            (
                r#"[service.db]
                   protocol = "sctp"
                   target = "10.0.0.5:5432""#,
                "protocol `sctp`",
            ),
            (
                r#"[service.db]
                   protocol = "tcp"
                   target = "db.internal:5432""#,
                "not a host:port",
            ),
            (
                r#"[service.db]
                   protocol = "tcp""#,
                "target",
            ),
            (
                r#"[srevice.db]
                   protocol = "tcp"
                   target = "10.0.0.5:5432""#,
                "srevice",
            ),
            (
                r#"[service.db]
                   protocol = "tcp"
                   target = "10.0.0.5:5432"
                   allow = "everyone""#,
                "allow",
            ),
            ("", "offers nothing"),
        ] {
            let err = format!("{:#}", parse(bad).expect_err("must not load"));
            assert!(
                err.contains(expected),
                "the error should mention {expected:?}, and says: {err}",
            );
        }
    }

    /// The name is what crosses the wire, and `write_open` refuses to send one
    /// that is too long — so a catalogue holding one would offer something
    /// nothing could ask for.
    #[test]
    fn a_name_that_could_never_be_asked_for_is_refused_here() {
        let long = "a".repeat(crate::frame::MAX_NAME + 1);
        let err = format!(
            "{:#}",
            parse(&format!(
                "[service.{long}]\nprotocol = \"tcp\"\ntarget = \"10.0.0.5:5432\""
            ))
            .expect_err("must not load"),
        );
        assert!(err.contains("service name must be"), "says: {err}");
    }
}
