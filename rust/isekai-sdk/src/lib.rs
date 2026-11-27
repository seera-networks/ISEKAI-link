//! The ISEKAI link SDK — one entry point for the seven groups of surface
//! `docs/p2p_sdk_surface_from_portal.md` §7 arrived at.
//!
//! **This crate is a facade and nothing else.** Every type it offers comes from
//! `isekai-p2p`, which is where the orchestration lives; what this adds is a
//! handle to hang the groups off, a place to promise semver, and the two or
//! three things the layers below do not have (`docs/p2p_sdk_design.md` §3).
//! Deleting a function here must never delete behaviour — if it would, the
//! function belongs below.
//!
//! # What is settled, and where it is written down
//!
//! The design document records eleven decisions. The four that shape this file:
//!
//! - **The handle is the entry point, and the stack under it is shared**
//!   (D1 = C). msquic's registration is one per process, so two [`Sdk`] values
//!   are two configurations over one stack rather than two independent stacks.
//!   That is why [`Sdk::close`] cannot shut msquic down, and why [`shutdown`]
//!   and [`drain`] are free functions: the process's lifetime is the process's.
//! - **The facade is where semver is promised** (D2 = B). The crates behind it
//!   carry the workspace version and promise nothing; this one carries its own.
//! - **Async, for what touches the network** (D3 = A). A read of local state
//!   stays synchronous — a deadline on it would be a deadline on a memory load.
//! - **The low-level surface is not here** (D9 = A). `DatapathHook`,
//!   `BindSession` and the rest stay in `isekai_p2p::agent`; a caller that
//!   needs them depends on that crate directly, which keeps the promise this
//!   crate makes the same size as the surface it offers.
//!
//! # What is not here yet
//!
//! The group accessors (§7's stage 2 onwards): `endpoints()`, `grants()`,
//! `tickets()`, `provisioning_keys()`, `redeem()`, `connect()`, `listen()`,
//! `inspect()`. This stage fixes the shape of the entry — the handle, the
//! deadlines, the credential seams, the lifetime — because every one of those
//! hangs off it and because adding any of this later would break a crate that
//! promises semver.

use std::time::Duration;

// **Re-exported rather than wrapped.** A second name for `P2pConfig` would be
// a second thing to keep in step with it, and `docs/p2p_sdk_design.md` §3.2
// says the facade adds grouping and not semantics.
pub use isekai_p2p::{
    AssertionSource, Auth0TokenSource, Credential, Enrollment, Narrowing, P2pConfig,
    StaticAuth0Token,
};
// **The key has to be loadable, not just generatable.** Without this a caller
// that depends on the facade alone reaches only `EndpointKey::generate()` — a
// fresh Endpoint identity, and therefore a fresh registration, on every start —
// or `from_pkcs8_pem`, whose error type is re-exported nowhere. A facade that
// forces a second dependency for one function is not the facade D2 = B chose.
pub use isekai_p2p::load_or_generate_key;
// **Both credential seams go out, and both are traits** (D4 = A). `Auth0` is
// the path a person signs in on and `AssertionSource` the one an unattended
// workload proves itself on; exporting only one of them would leave a caller
// with the other kind of credential unable to bring its own token source,
// which is the case A was chosen for.
pub use isekai_p2p::agent::{
    EndpointKey, Missing, Outcome, Problem, ProxyError, Reading, Unreachable,
};

/// How long a call waits before giving up, when the caller does not say.
///
/// **These two numbers are the only measured ones there are.** Nothing below
/// this crate has a request timeout: `p2p_sdk_api_review.md` §5.3 found none,
/// and the two FFIs each put their own on top — 30 seconds for a pairing
/// redemption and 60 for a connect (`portal-client-ffi/src/lib.rs:165`,
/// `:268`), chosen from how long a person will hold a phone and wait. They are
/// carried here rather than re-derived (D7 = C).
///
/// **A deadline covers a request and its answer, not the life of a session.**
/// A session ends through [`Sdk::close`] or cancellation; a deadline on one
/// would read as "this SDK drops a connection after sixty seconds".
/// **Not exhaustively constructible, deliberately.** §7's later stages add
/// surface — listening, inspection — and a third deadline with it. With a
/// struct literal reachable from outside, that addition would break every
/// caller that wrote `Deadlines { redeem, connect }` and force a major bump on
/// the crate that exists to avoid exactly that. Build from
/// [`Deadlines::default`] and the setters below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Deadlines {
    /// Redeeming a pairing code, a ticket or a provisioning key.
    pub redeem: Duration,
    /// Reaching a peer, from the first request to a path that carries traffic.
    pub connect: Duration,
}

impl Default for Deadlines {
    fn default() -> Self {
        Self {
            redeem: Duration::from_secs(30),
            connect: Duration::from_secs(60),
        }
    }
}

impl Deadlines {
    /// How long to wait for a redemption.
    pub fn with_redeem(mut self, redeem: Duration) -> Self {
        self.redeem = redeem;
        self
    }

    /// How long to wait for a peer.
    pub fn with_connect(mut self, connect: Duration) -> Self {
        self.connect = connect;
        self
    }
}

/// An open SDK: the configuration, the defaults, and the entry point for every
/// group of surface.
///
/// **Opening one reaches nothing.** No network, no registration, no key read:
/// the first call that needs the stack opens it, which is what the layers below
/// have always done. So this cannot fail, and a configuration that names an
/// unreachable control plane is reported by the first call rather than here —
/// where a caller has nothing to retry yet.
#[derive(Clone)]
pub struct Sdk {
    config: P2pConfig,
    deadlines: Deadlines,
}

// **`P2pConfig` has no `Debug` on purpose** — it holds the credential, and the
// crates below use `redacted_debug!` wherever a secret would otherwise be
// printed. The handle cannot derive one either, so it names what is safe and
// says the rest is there rather than leaving the type unprintable: a handle
// that cannot appear in a log line is a handle whose misconfiguration is
// hard to report.
impl std::fmt::Debug for Sdk {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sdk")
            .field("identity_url", &self.config.identity_url)
            // Printed because it is the misconfiguration a `{:?}` is for:
            // `true` against an Identity API serving only h1/h2 fails in a way
            // the URL alone cannot explain.
            .field("identity_http3", &self.config.identity_http3)
            .field("proxy_url", &self.config.proxy_url)
            .field("protocol", &self.config.protocol)
            .field("device_name", &self.config.device_name)
            .field("token_ttl", &self.config.token_ttl)
            .field("narrowing", &self.config.narrowing)
            .field("credential", &format_args!("<redacted>"))
            .field("key", &format_args!("<redacted>"))
            .field("deadlines", &self.deadlines)
            .finish()
    }
}

impl Sdk {
    /// Open the SDK over a configuration.
    ///
    /// The configuration carries the credential, the key, the device name and
    /// the narrowing (`isekai_p2p::P2pConfig`), so there is nothing to pass
    /// beside it. **That is also where the two values the phone app used to
    /// nail shut belong** (D6 = A): both are read before any connect — at
    /// registration, at enrolment and when a token is issued — so a per-call
    /// argument would have meant re-issuing a token per call.
    pub fn open(config: P2pConfig) -> Self {
        Self {
            config,
            deadlines: Deadlines::default(),
        }
    }

    /// Replace the deadlines this handle applies when a call does not name one.
    pub fn with_deadlines(mut self, deadlines: Deadlines) -> Self {
        self.deadlines = deadlines;
        self
    }

    /// What this handle applies when a call does not name a deadline.
    pub fn deadlines(&self) -> Deadlines {
        self.deadlines
    }

    /// The configuration this handle was opened over.
    pub fn config(&self) -> &P2pConfig {
        &self.config
    }

    /// Close what this handle owns, and nothing else.
    ///
    /// **It does not close msquic** (D8 = C1). The registration is one per
    /// process and this handle is not necessarily the only one over it, so
    /// closing it here would pull the ground out from under another handle.
    /// Ending the process's use of the stack is [`shutdown`] or [`drain`], and
    /// that judgement belongs to whoever owns the process.
    ///
    /// `true` if everything this handle owned finished within `timeout`.
    /// **The answer is the point**: its siblings [`shutdown`] and [`drain`]
    /// return one because "did it finish?" is the caller's decision, and a
    /// relay lease left reserved because a drain did not complete is a failure
    /// nobody would otherwise hear about. Returning `()` here and adding the
    /// answer later would break the callers who wrote `sdk.close(t).await;`.
    ///
    /// **Idempotent, and shared between clones.** [`Sdk`] is `Clone`, and what
    /// a handle owns is owned by all of its clones — so closing one closes it
    /// for every clone, and closing twice is not an error.
    ///
    /// **Today it owns nothing**, because the sessions arrive with §7's later
    /// stages, so it returns `true` at once: everything it owned — nothing —
    /// finished.
    pub async fn close(&self, _timeout: Duration) -> bool {
        true
    }
}

/// Drain the process's msquic registration and close it.
///
/// `true` if it drained within `timeout`, **and closing only happens then**:
/// on timeout it logs that live handles remain, skips `RegistrationClose` and
/// leaks the registration on purpose, so nothing below can block an exit
/// (`isekai-p2p-core/src/transport.rs:500`). So `false` does not mean "closed
/// anyway" — it means the stack is still live, and a caller that has to be
/// certain nothing is running should not return from `main` normally on it.
///
/// The caller that owns the process calls this on the way out, after the last
/// [`Sdk`] is done with (`p2p_sdk_api_review.md` §5.2).
pub async fn shutdown(timeout: Duration) -> bool {
    isekai_p2p::agent::shutdown_msquic(timeout).await
}

/// Drain the process's msquic registration **without** closing it.
///
/// For the path that leaves the process without running destructors: the
/// registration is deliberately leaked whether the drain succeeded or not, so
/// nothing below can block an exit. `true` if it drained within `timeout`.
/// Prefer [`shutdown`] where the process carries on — the difference between
/// the two is only whether a *successful* drain is followed by
/// `RegistrationClose`.
pub async fn drain(timeout: Duration) -> bool {
    isekai_p2p::agent::drain_msquic(timeout).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The two numbers are the measured ones**, and a test says so because
    /// the only thing that makes them right is where they came from: the FFIs
    /// chose them from how long a person will wait, and nothing below this
    /// crate has an opinion at all.
    #[test]
    fn the_defaults_are_the_two_the_ffis_measured() {
        let deadlines = Deadlines::default();
        assert_eq!(deadlines.redeem, Duration::from_secs(30));
        assert_eq!(deadlines.connect, Duration::from_secs(60));
    }

    /// A handle applies its own deadlines, and `with_deadlines` is how a caller
    /// that knows better says so without passing one to every call.
    #[test]
    fn a_handle_carries_the_deadlines_it_was_given() {
        let config = config();
        let sdk = Sdk::open(config.clone());
        assert_eq!(sdk.deadlines(), Deadlines::default());

        // Built the way a caller outside this crate has to: `Deadlines` is
        // `#[non_exhaustive]`, so there is no struct literal to write.
        let patient = Deadlines::default()
            .with_redeem(Duration::from_secs(5))
            .with_connect(Duration::from_secs(600));
        let sdk = sdk.with_deadlines(patient);
        assert_eq!(sdk.deadlines(), patient);
        assert_eq!(sdk.config().proxy_url, config.proxy_url);
    }

    /// **The setters are the only way in from outside**, so they have to leave
    /// the other field alone — a `with_redeem` that reset `connect` to the
    /// default would be silently wrong for every caller that set both.
    #[test]
    fn a_setter_changes_one_deadline_and_leaves_the_other() {
        let short = Deadlines::default().with_redeem(Duration::from_secs(1));
        assert_eq!(short.redeem, Duration::from_secs(1));
        assert_eq!(short.connect, Deadlines::default().connect);

        let both = short.with_connect(Duration::from_secs(2));
        assert_eq!(both.redeem, Duration::from_secs(1));
        assert_eq!(both.connect, Duration::from_secs(2));
    }

    /// Closing a handle that owns nothing answers `true`, and twice is not an
    /// error — the contract the doc comment states.
    #[tokio::test]
    async fn closing_an_idle_handle_answers_true_and_is_idempotent() {
        let sdk = Sdk::open(config());
        assert!(sdk.close(Duration::from_secs(1)).await);
        assert!(sdk.close(Duration::from_secs(1)).await);
    }

    /// **The handle prints without printing the token.** `P2pConfig` has no
    /// `Debug` precisely because it holds one, so the hand-written impl is the
    /// place that could leak it — and a `{:?}` on a handle is exactly what ends
    /// up in a log line when a configuration is wrong.
    #[test]
    fn the_handle_prints_what_is_safe_and_redacts_the_rest() {
        let printed = format!("{:?}", Sdk::open(config()));

        assert!(printed.contains("link.example:6443"), "{printed}");
        assert!(printed.contains("identity.example:9443"), "{printed}");
        assert!(printed.contains("identity_http3"), "{printed}");
        assert!(printed.contains("narrowing"), "{printed}");
        assert!(printed.contains("deadlines"), "{printed}");
        assert!(
            !printed.contains(THE_TOKEN),
            "the token must not be printable: {printed}",
        );
        assert_eq!(printed.matches("<redacted>").count(), 2, "{printed}");
    }

    const THE_TOKEN: &str = "a-token-that-must-not-be-printed";

    /// **Built through `Credential::auth0`, not by naming the variant.** Two of
    /// its five fields are the registration's own state (`registered`,
    /// `attempted`), which a caller has no business setting — and the fact that
    /// the constructor exists is why §3.1's sketch takes a credential at all.
    fn config() -> P2pConfig {
        P2pConfig {
            identity_url: "https://identity.example:9443".to_owned(),
            identity_http3: false,
            proxy_url: "https://link.example:6443".to_owned(),
            credential: Credential::auth0(THE_TOKEN, None, false),
            protocol: "mjpeg".to_owned(),
            device_name: None,
            token_ttl: None,
            key: EndpointKey::generate(),
            narrowing: Narrowing::default(),
        }
    }
}
