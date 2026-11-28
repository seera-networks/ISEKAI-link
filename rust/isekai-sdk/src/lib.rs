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

use std::fmt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

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
// Named in the signatures of the control-plane plumbing, not re-exported for
// their own sake: a caller reaches the accessors and never holds the client.
use isekai_p2p::agent::{MasqueH3Transport, ProxyClient};
// **The failure of the call every accessor is built on** (D14). Each group in
// §3.3 needs an Endpoint Token before it can ask anything, so this is the error
// a caller of the facade meets first — and reading it takes
// [`TokenError::outcome`], which is the same `Outcome` vocabulary as the rest.
pub use isekai_p2p::TokenError;
// **What the accessors answer with has to be nameable.** A caller that depends
// on the facade alone would otherwise be unable to write the type of a `Grant`
// it just made, or to match on `Made`. `reading` goes out for the same reason
// one layer along: a caller holding a [`SdkError`] can ask how the route it
// came from reads its answers, and compare it with its own.
pub use isekai_p2p::agent::{
    reading, Grant, Made, ProvisioningBinding, ProvisioningBounds, ProvisioningKey,
    ProvisioningKeyRecord, ProvisioningRedemption, Ticket, TicketBounds, TicketRecord,
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
    /// The control-plane client, once something has needed one.
    ///
    /// **Shared between clones, deliberately.** [`Sdk::close`] already says
    /// what a handle owns is owned by all of its clones; the same has to be
    /// true of the token, or two clones would mint one each and the second
    /// would spend a round trip replacing a token that was fine.
    ///
    /// `std::sync::Mutex` and not `tokio`'s: the facade has one dependency and
    /// no runtime of its own, and nothing is awaited while this is held — see
    /// [`Sdk::control`].
    control: Arc<Mutex<Option<Control>>>,
}

/// The control-plane client a handle lends to its accessors, and how long the
/// token it carries is good for.
struct Control {
    client: ProxyClient<MasqueH3Transport>,
    /// When the token stops being good for a whole call, not when it expires:
    /// [`renew_delay`] keeps the margin that `isekai-p2p` renews on.
    stale_at: Instant,
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
            control: Arc::new(Mutex::new(None)),
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

    /// Everyone this Endpoint has let in (§3.3).
    pub fn grants(&self) -> Grants<'_> {
        Grants(self)
    }

    /// The Tickets this Endpoint has handed out (§3.3).
    pub fn tickets(&self) -> Tickets<'_> {
        Tickets(self)
    }

    /// The Provisioning Keys this Endpoint has issued (§3.3).
    pub fn provisioning_keys(&self) -> ProvisioningKeys<'_> {
        ProvisioningKeys(self)
    }

    /// A control-plane client whose token is good for a whole call.
    ///
    /// **The token is cached, and the client with it** (D13 = B). An Endpoint
    /// Token lasts minutes and the MASQUE tunnel under the client outlives it
    /// by hours, so the token is replaced *in place*
    /// (`ProxyClient::set_endpoint_token`) rather than by rebuilding the
    /// client — rebuilding it would tear down the tunnel every relay leg is
    /// running over. Without the cache every accessor call would be a token
    /// issue, a QUIC handshake, and a round trip.
    ///
    /// **Nothing is awaited while the lock is held.** The lock is taken to
    /// read, dropped, and taken again to store; so two callers arriving
    /// together on a cold handle can both issue a token, and the second simply
    /// replaces the first's under a client they share. That costs one round
    /// trip and cannot leave the two disagreeing — which is the trade a
    /// `std::sync::Mutex` asks for, and the reason the alternative (holding a
    /// `tokio::sync::Mutex` across the issue) would put a runtime in the
    /// facade's dependencies for a saving of one request.
    ///
    /// `reading` is the route the client is being fetched *for*: a control
    /// plane that cannot be opened at all is a `ProxyError::Transport`, which
    /// every reading reports the same way (`Outcome::of_proxy` answers
    /// `Unreachable` before it consults one), and carrying the caller's route
    /// keeps the error saying which call never happened.
    async fn control(
        &self,
        reading: &'static Reading,
    ) -> Result<ProxyClient<MasqueH3Transport>, SdkError> {
        if let Some(client) = self.unexpired() {
            return Ok(client);
        }
        let token = isekai_p2p::issue_endpoint_token(&self.config).await?;
        let stale_at = Instant::now() + isekai_p2p::config::renew_delay(Some(token.expires_in));
        let mut held = self
            .control
            .lock()
            .expect("the control-plane lock is poisoned");
        match held.as_mut() {
            Some(control) => {
                control.client.set_endpoint_token(&token.endpoint_token);
                control.stale_at = stale_at;
                Ok(control.client.clone())
            }
            None => {
                let client = isekai_p2p::proxy_client(&self.config, &token.endpoint_token)
                    .map_err(|e| SdkError::proxy(ProxyError::Transport(e), reading))?;
                *held = Some(Control {
                    client: client.clone(),
                    stale_at,
                });
                Ok(client)
            }
        }
    }

    /// The cached client, while its token is still good for a whole call.
    fn unexpired(&self) -> Option<ProxyClient<MasqueH3Transport>> {
        let held = self
            .control
            .lock()
            .expect("the control-plane lock is poisoned");
        let control = held.as_ref()?;
        (Instant::now() < control.stale_at).then(|| control.client.clone())
    }
}

/// Why a control-plane call did not answer (D15 = B).
///
/// **Two layers, neither folded into the other.** A call needs an Endpoint
/// Token before it can be made, and that is a different failure with a
/// different remedy: `Token` carries [`TokenError`], whose credential arm says
/// "get another credential", and `Proxy` carries what the proxy itself said.
/// Folding the first into [`ProxyError::Transport`] would put it back where
/// D14 found it — read as a network failure to wait out.
///
/// **Read it with [`SdkError::outcome`]**, which answers in the same [`Outcome`]
/// vocabulary for both: the arms say which layer failed, and the outcome says
/// what to do about it.
///
/// **It adds no words of its own**, and so adds no line to the cause chain
/// either — see its `Error::source`.
#[derive(Debug)]
#[non_exhaustive]
pub enum SdkError {
    /// No Endpoint Token, so the call was never made.
    Token(TokenError),
    /// The proxy refused the call, or could not be reached.
    #[non_exhaustive]
    Proxy {
        /// What the proxy said.
        source: ProxyError,
        /// How the route this came from reads its answers — stated beside the
        /// route itself, in [`reading`].
        reading: &'static Reading,
    },
}

impl SdkError {
    /// What the caller can do about it.
    pub fn outcome(&self) -> Outcome {
        match self {
            SdkError::Token(error) => error.outcome(),
            SdkError::Proxy { source, reading } => Outcome::of_proxy(source, reading),
        }
    }

    fn proxy(source: ProxyError, reading: &'static Reading) -> Self {
        SdkError::Proxy { source, reading }
    }
}

impl From<TokenError> for SdkError {
    fn from(error: TokenError) -> Self {
        SdkError::Token(error)
    }
}

impl fmt::Display for SdkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SdkError::Token(error) => write!(f, "{error}"),
            SdkError::Proxy { source, .. } => write!(f, "{source}"),
        }
    }
}

impl std::error::Error for SdkError {
    /// **Transparent, by hand.** This type says which layer failed, which its
    /// arms already say, and adds no sentence of its own — so it must not add a
    /// line to the chain either, or `{:#}` through `anyhow` would print the
    /// same words twice (`IdentityError::Transport` does exactly that, as
    /// #386 measured). `#[error(transparent)]` cannot express it: that needs a
    /// variant with exactly one field, and the proxy arm also carries its
    /// route's reading.
    ///
    /// **How far the chain reaches is the arm's own business.** `TokenError`
    /// links its cause, so a report walks into the Identity answer and the
    /// transport failure under it. `ProxyError::Transport` does not — it holds
    /// an `anyhow::Error` that is not marked a source — so for that arm the
    /// chain stops at the proxy's own sentence, and the cause is in
    /// [`SdkError::outcome`], which `Outcome::of_proxy` fills in with the whole
    /// chain on purpose.
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SdkError::Token(error) => error.source(),
            SdkError::Proxy { source, .. } => source.source(),
        }
    }
}

/// Everyone this Endpoint has let in (spec §8.8).
///
/// **The facade is the only name for `list` and `revoke`** (D10 = A): the two
/// on `ListenerSession` are plumbing for a running listener and answer with
/// `anyhow::Result`, and a second public name with a different reading is what
/// `p2p_sdk_surface_from_portal.md` §4.3 warned about.
pub struct Grants<'a>(&'a Sdk);

impl Grants<'_> {
    /// Let one Endpoint reach this one over one protocol.
    ///
    /// **An upsert**: a pair that already has a grant for this protocol gets
    /// the existing id back, and [`Made`] says which happened — which matters
    /// to a caller keeping a ledger, since adopting somebody else's grant means
    /// revoking it later.
    ///
    /// `expires_in` omitted means it stands until revoked, which is the usual
    /// case.
    pub async fn create(
        &self,
        allowed_endpoint: &str,
        protocol: &str,
        expires_in: Option<u64>,
        label: Option<&str>,
    ) -> Result<(Grant, Made), SdkError> {
        let proxy = self.0.control(&reading::GRANT_CREATE).await?;
        proxy
            .create_grant(allowed_endpoint, protocol, expires_in, label)
            .await
            .map_err(|e| SdkError::proxy(e, &reading::GRANT_CREATE))
    }

    /// Everyone this Endpoint has let in, including grants it did not make.
    pub async fn list(&self) -> Result<Vec<Grant>, SdkError> {
        let proxy = self.0.control(&reading::GRANT_LIST).await?;
        proxy
            .list_grants()
            .await
            .map_err(|e| SdkError::proxy(e, &reading::GRANT_LIST))
    }
}

/// The Tickets this Endpoint has handed out (spec §8.12).
pub struct Tickets<'a>(&'a Sdk);

impl Tickets<'_> {
    /// Issue a Ticket for one protocol.
    ///
    /// **Several may be live for the same protocol**, unlike a pairing code —
    /// so three CI jobs can each have their own. [`TicketBounds`] is where the
    /// two lifetimes are written down: they are different quantities, and the
    /// Grant's is not capped by the Ticket's.
    pub async fn create(
        &self,
        protocol: &str,
        bounds: TicketBounds,
        label: Option<&str>,
    ) -> Result<Ticket, SdkError> {
        let proxy = self.0.control(&reading::TICKET_CREATE).await?;
        proxy
            .create_ticket(protocol, bounds, label)
            .await
            .map_err(|e| SdkError::proxy(e, &reading::TICKET_CREATE))
    }

    /// The Tickets this Endpoint has issued, spent ones included.
    pub async fn list(&self) -> Result<Vec<TicketRecord>, SdkError> {
        let proxy = self.0.control(&reading::TICKET_LIST).await?;
        proxy
            .list_tickets()
            .await
            .map_err(|e| SdkError::proxy(e, &reading::TICKET_LIST))
    }
}

/// The Provisioning Keys this Endpoint has issued (spec §8.13).
pub struct ProvisioningKeys<'a>(&'a Sdk);

impl ProvisioningKeys<'_> {
    /// Issue a Provisioning Key.
    ///
    /// [`ProvisioningBounds`] carries the ceilings a key is issued under and
    /// [`ProvisioningBinding`] the workload identity it is tied to, when it is
    /// tied to one — which is what makes a key usable in a public repository's
    /// CI.
    pub async fn create(
        &self,
        protocol: &str,
        bounds: ProvisioningBounds,
        binding: Option<&ProvisioningBinding>,
        label: Option<&str>,
    ) -> Result<ProvisioningKey, SdkError> {
        let proxy = self.0.control(&reading::KEY_CREATE).await?;
        proxy
            .create_provisioning_key(protocol, bounds, binding, label)
            .await
            .map_err(|e| SdkError::proxy(e, &reading::KEY_CREATE))
    }

    /// The keys this Endpoint has issued, with how many Grants each is holding
    /// against its ceiling.
    pub async fn list(&self) -> Result<Vec<ProvisioningKeyRecord>, SdkError> {
        let proxy = self.0.control(&reading::KEY_LIST).await?;
        proxy
            .list_provisioning_keys()
            .await
            .map_err(|e| SdkError::proxy(e, &reading::KEY_LIST))
    }

    /// Who came in on one key.
    ///
    /// **Outlives the key**: revoking or expiring one does not erase this, and
    /// a key is stopped because of a leak or somebody leaving — the moment the
    /// answer matters most. A `404` here is therefore an id this Endpoint never
    /// had, which [`reading::KEY_REDEMPTIONS`] reads as
    /// [`Outcome::Vanished`].
    pub async fn redemptions(&self, key_id: &str) -> Result<Vec<ProvisioningRedemption>, SdkError> {
        let proxy = self.0.control(&reading::KEY_REDEMPTIONS).await?;
        proxy
            .provisioning_redemptions(key_id)
            .await
            .map_err(|e| SdkError::proxy(e, &reading::KEY_REDEMPTIONS))
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

    /// A refusal with no problem document, which is all these readings need:
    /// none of the seven sanctions a `kind`, so every one of them answers by
    /// status alone.
    fn problem(status: u16) -> ProxyError {
        ProxyError::Problem {
            status,
            problem: None,
            retry_after: None,
        }
    }

    /// **The route's own reading is the one that is applied**, which is the
    /// whole reason the error carries it. The same `404` means "that key is not
    /// here" where a key was named, and nothing in particular on a collection —
    /// so a caller branching on the outcome gets a different answer for the two
    /// without having to know which route it called.
    #[test]
    fn a_404_reads_by_the_route_it_came_from() {
        let named = SdkError::proxy(problem(404), &reading::KEY_REDEMPTIONS);
        assert!(
            matches!(named.outcome(), Outcome::Vanished { .. }),
            "{:?}",
            named.outcome()
        );

        let collection = SdkError::proxy(problem(404), &reading::TICKET_LIST);
        assert!(
            !matches!(collection.outcome(), Outcome::Vanished { .. }),
            "{:?}",
            collection.outcome()
        );
    }

    /// **The two layers keep their own remedies** (D15 = B). A credential that
    /// cannot be minted asks for another credential; a proxy that refused is a
    /// refusal. Folding the first into `ProxyError::Transport` — the shape A
    /// would have taken — would have made it a network failure to wait out,
    /// which is what D14 had just finished removing one layer down.
    #[test]
    fn the_token_layer_and_the_proxy_layer_read_differently() {
        let refused = SdkError::proxy(problem(403), &reading::GRANT_LIST);
        assert!(matches!(refused.outcome(), Outcome::Refused { .. }));

        // Built the way a caller outside `isekai-p2p` has to: the arm's fields
        // are public, its constructor is not.
        let credential: SdkError = TokenError::Credential {
            explain: "could not obtain a current Auth0 token",
            source: anyhow::anyhow!("the refresh token has expired"),
        }
        .into();
        match credential.outcome() {
            Outcome::Reauthenticate { explain } => {
                assert!(explain.contains("Auth0 token"), "{explain}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// **No layer, no line**: this type adds no words, so a report must not
    /// show the same sentence twice.
    ///
    /// **And for a transport failure the words are in the outcome, not in the
    /// chain.** `ProxyError::Transport` holds an `anyhow::Error` without
    /// marking it a source — unlike `IdentityError::Transport`, which takes one
    /// by `#[from]` — so nothing downstream can walk into it. That is why
    /// `Outcome::of_proxy` formats the whole chain into `explain` itself, and
    /// why a caller that wants to know *which* transport failure this was reads
    /// the outcome rather than the report. Both halves are checked here,
    /// because a reader of `SdkError::source` would otherwise reasonably assume
    /// the chain goes all the way down.
    #[test]
    fn the_report_names_the_cause_once_and_the_outcome_carries_it() {
        let error = SdkError::proxy(
            ProxyError::Transport(anyhow::anyhow!("HTTPS request failed").context("dialling")),
            &reading::GRANT_LIST,
        );
        // The outcome first: the report below takes the error by value.
        let outcome = error.outcome();
        let reported = format!("{:#}", anyhow::Error::from(error));
        assert_eq!(reported.matches("dialling").count(), 1, "{reported}");

        match outcome {
            Outcome::Unreachable(Unreachable::Transport { explain }) => {
                assert!(explain.contains("dialling"), "{explain}");
                assert!(explain.contains("HTTPS request failed"), "{explain}");
            }
            other => panic!("{other:?}"),
        }
    }

    /// The groups are reachable from a handle that has opened nothing, because
    /// opening reaches nothing: the first call that needs a token takes one.
    #[test]
    fn a_cold_handle_hands_out_groups_and_holds_no_client() {
        let sdk = Sdk::open(config());
        let _ = (sdk.grants(), sdk.tickets(), sdk.provisioning_keys());
        assert!(sdk.unexpired().is_none());
    }

    /// **Clones share the control plane.** Two handles of the same session
    /// minting a token each would spend a round trip replacing a token that was
    /// fine, and `close`'s documented contract — what one owns, all own —
    /// would not hold.
    #[test]
    fn a_clone_shares_the_cached_client() {
        let sdk = Sdk::open(config());
        let twin = sdk.clone();
        assert!(Arc::ptr_eq(&sdk.control, &twin.control));
    }

    /// **One margin for the project** (D13 = B). The cache asks
    /// `isekai-p2p` how long a token is good for rather than keeping a second
    /// number beside it; this says so, so that tuning the renewal margin is
    /// visibly tuning this too.
    #[test]
    fn the_cache_leans_on_the_renewal_margin() {
        assert_eq!(
            isekai_p2p::config::renew_delay(Some(300)),
            Duration::from_secs(240),
        );
    }

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
