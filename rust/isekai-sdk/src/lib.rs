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
//! The design document records fifteen decisions. The six that shape this
//! file:
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
//! - **The token is this handle's to keep** (D13 = B). One Endpoint Token and
//!   one control-plane client are cached and shared by every clone, because an
//!   accessor that minted a token and built a MASQUE tunnel per call would pay
//!   two round trips for a list.
//! - **A failure says which layer it came from** (D15 = B). [`SdkError`] has an
//!   arm for the token and an arm for the proxy, and both are read through
//!   [`SdkError::outcome`]; the `Reading` each route is read under lives beside
//!   the route, in [`reading`], so grouping the routes here adds no semantics.
//!
//! # What is not here yet
//!
//! `grants().revoke()`, `tickets().revoke()` and
//! `provisioning_keys().revoke()` — the three wait on D5, which settles how a
//! `409` is read on those routes before a `Reading` is written for them. Then
//! §7's later stages: `endpoints()`, `redeem()`, `connect()`, `listen()`,
//! `inspect()`.

use std::fmt;
use std::future::Future;
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
    /// [`good_for`] keeps the margin `isekai-p2p` renews on, under a ceiling of
    /// the token's own lifetime.
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
    ///
    /// **The issuer accessors apply neither of them**, and neither does
    /// anything below this crate (`p2p_sdk_api_review.md` §5.3 found no request
    /// timeout at all). The two numbers here are a redemption and a connect,
    /// measured for those two waits by the FFIs; a control-plane request is a
    /// third quantity nobody has measured, and inventing a default for it here
    /// would be the one thing D7 = C set out to avoid. So a caller that needs
    /// one wraps the call — `tokio::time::timeout(d, sdk.tickets().list())` —
    /// and a `Deadlines` with a third field stays an addition this crate can
    /// make without breaking anyone, which is what `#[non_exhaustive]` is for.
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
    /// **What it owns today is the control-plane client** — a MASQUE tunnel on
    /// msquic, kept by the handle so that every accessor does not build one.
    /// Dropping it is the whole of the work and does not wait, so the timeout
    /// is not consulted and the answer is always `true`.
    ///
    /// **It has to be dropped for [`shutdown`] to close anything.**
    /// `shutdown_msquic` waits for the registration to go idle and, when
    /// something still holds a handle, logs "still has live handles", skips
    /// `RegistrationClose` and answers `false`. A handle left in scope with a
    /// cached tunnel under it is such a holder — so the documented order,
    /// close the handles and then shut the stack down, is what lets
    /// [`shutdown`] answer `true` at all.
    pub async fn close(&self, _timeout: Duration) -> bool {
        self.forget();
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
    ///
    /// The flag says whether *this* call minted the token, which is what tells
    /// a refusal of a cached token from a refusal of a fresh one — see
    /// [`Sdk::call`].
    async fn control(
        &self,
        reading: &'static Reading,
    ) -> Result<(ProxyClient<MasqueH3Transport>, Minted), SdkError> {
        if let Some(client) = self.unexpired() {
            return Ok((client, Minted::No));
        }
        let token = isekai_p2p::issue_endpoint_token(&self.config).await?;
        let stale_at = Instant::now() + good_for(token.expires_in);
        let mut held = self
            .control
            .lock()
            .expect("the control-plane lock is poisoned");
        let client = match held.as_mut() {
            Some(control) => {
                control.client.set_endpoint_token(&token.endpoint_token);
                control.stale_at = stale_at;
                control.client.clone()
            }
            None => {
                let client = isekai_p2p::proxy_client(&self.config, &token.endpoint_token)
                    .map_err(|e| SdkError::proxy(ProxyError::Transport(e), reading))?;
                *held = Some(Control {
                    client: client.clone(),
                    stale_at,
                });
                client
            }
        };
        Ok((client, Minted::Yes))
    }

    /// Make one control-plane call with the client this handle keeps.
    ///
    /// **The cache is dropped when the answer says it is spent**, which two
    /// answers do.
    ///
    /// A `ProxyError::Transport` means the request did not get out, and the
    /// client may be unusable for good: the MASQUE channel is a tower
    /// `Buffer`, whose worker stores the first `poll_ready` error "so that
    /// subsequent requests will also fail with the same error" and then closes
    /// the queue (tower 0.5.3, `buffer/worker.rs`). Building the client reaches
    /// nothing, so a handle that made its first call while the proxy was away
    /// would otherwise keep that dead client — and every clone with it, since
    /// the cache is shared — answering `Unreachable` with the same stale
    /// message for the life of the process, long after the proxy came back.
    ///
    /// A `401` means the token is no longer accepted, which the margin did not
    /// predict: a clock out by more than a minute, a host suspended between two
    /// calls, a lifetime shorter than anything [`good_for`] can stay ahead of.
    ///
    /// **A `401` on a cached token is retried once.** The caller cannot mint
    /// this handle's token for it, so answering `Reauthenticate` — "get another
    /// credential" — for a credential that is fine would be this cache's
    /// bookkeeping leaking out as advice. One fresh token, one retry; if that
    /// is refused too, the refusal is the Endpoint's own and is reported as it
    /// came.
    async fn call<T, F, Fut>(&self, reading: &'static Reading, call: F) -> Result<T, SdkError>
    where
        F: Fn(ProxyClient<MasqueH3Transport>) -> Fut,
        Fut: Future<Output = Result<T, ProxyError>>,
    {
        let (client, minted) = self.control(reading).await?;
        let error = match call(client).await {
            Ok(answer) => return Ok(answer),
            Err(error) => error,
        };
        let worth_retrying = minted == Minted::No && token_refused(&error);
        self.forget_if_spent(&error);
        if !worth_retrying {
            return Err(SdkError::proxy(error, reading));
        }
        let (client, _) = self.control(reading).await?;
        call(client).await.map_err(|again| {
            self.forget_if_spent(&again);
            SdkError::proxy(again, reading)
        })
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

    /// Drop the cached client if this answer says it is spent.
    fn forget_if_spent(&self, error: &ProxyError) {
        if spent(error) {
            self.forget();
        }
    }

    /// Drop the cached client, so that the next call builds one.
    fn forget(&self) {
        *self
            .control
            .lock()
            .expect("the control-plane lock is poisoned") = None;
    }
}

/// Whether this handle minted the token the call is about to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Minted {
    Yes,
    No,
}

/// Whether this answer says the cached client is of no further use.
///
/// The two that do, for the reasons [`Sdk::call`] gives: a request that did not
/// get out may have poisoned the channel under it, and a refused token is one
/// this handle can replace. Everything else — a `403`, a `404`, a malformed
/// body — is an answer about the *request*, and throwing the client away over
/// it would turn one refusal into a new tunnel per call.
fn spent(error: &ProxyError) -> bool {
    matches!(error, ProxyError::Transport(_)) || token_refused(error)
}

/// Whether the proxy refused the Endpoint Token itself.
///
/// By status: the control plane answers `401` when the token is missing,
/// expired or not accepted, and a cached one being past its use is the only
/// case of the three this handle can do something about on its own.
fn token_refused(error: &ProxyError) -> bool {
    matches!(error, ProxyError::Problem { status: 401, .. })
}

/// How long a token this handle just issued can be relied on.
///
/// [`renew_delay`](isekai_p2p::config::renew_delay) answers the renewal loop's
/// question and keeps a floor under its answer — `RENEW_MIN`, so that a loop
/// cannot busy-spin — and that floor is not an answer to *this* question. A
/// `token_ttl` the caller set low, or one a server clamped, can expire inside
/// it; so the token's own lifetime is the ceiling here, and the margin only
/// ever makes the window shorter.
fn good_for(expires_in: i64) -> Duration {
    let lifetime = Duration::from_secs(expires_in.max(0) as u64);
    isekai_p2p::config::renew_delay(Some(expires_in)).min(lifetime)
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
/// **The facade is the only name for these** (D10 = A): the two on
/// `ListenerSession` are plumbing for a running listener and answer with
/// `anyhow::Result`, and a second public name with a different reading is what
/// `p2p_sdk_surface_from_portal.md` §4.3 warned about. `revoke` joins them once
/// D5 has established how the three revoke routes read a `409`.
///
/// **By value, and `Copy`.** The group is one reference, and a method taking
/// `&self` would make every future borrow the temporary the group is — so
/// `let pending = sdk.grants().list();` would not compile, and neither would a
/// fan-out like `ids.iter().map(|id| sdk.provisioning_keys().redemptions(id))`.
#[derive(Debug, Clone, Copy)]
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
        self,
        allowed_endpoint: &str,
        protocol: &str,
        expires_in: Option<u64>,
        label: Option<&str>,
    ) -> Result<(Grant, Made), SdkError> {
        self.0
            .call(&reading::GRANT_CREATE, |proxy| async move {
                proxy
                    .create_grant(allowed_endpoint, protocol, expires_in, label)
                    .await
            })
            .await
    }

    /// Everyone this Endpoint has let in, including grants it did not make.
    pub async fn list(self) -> Result<Vec<Grant>, SdkError> {
        self.0
            .call(&reading::GRANT_LIST, |proxy| async move {
                proxy.list_grants().await
            })
            .await
    }
}

/// The Tickets this Endpoint has handed out (spec §8.12).
///
/// `Copy` and taken by value, for the reason [`Grants`] gives.
#[derive(Debug, Clone, Copy)]
pub struct Tickets<'a>(&'a Sdk);

impl Tickets<'_> {
    /// Issue a Ticket for one protocol.
    ///
    /// **Several may be live for the same protocol**, unlike a pairing code —
    /// so three CI jobs can each have their own. [`TicketBounds`] is where the
    /// two lifetimes are written down: they are different quantities, and the
    /// Grant's is not capped by the Ticket's.
    pub async fn create(
        self,
        protocol: &str,
        bounds: TicketBounds,
        label: Option<&str>,
    ) -> Result<Ticket, SdkError> {
        self.0
            .call(&reading::TICKET_CREATE, |proxy| async move {
                proxy.create_ticket(protocol, bounds, label).await
            })
            .await
    }

    /// The Tickets this Endpoint has issued, spent ones included.
    pub async fn list(self) -> Result<Vec<TicketRecord>, SdkError> {
        self.0
            .call(&reading::TICKET_LIST, |proxy| async move {
                proxy.list_tickets().await
            })
            .await
    }
}

/// The Provisioning Keys this Endpoint has issued (spec §8.13).
///
/// `Copy` and taken by value, for the reason [`Grants`] gives.
#[derive(Debug, Clone, Copy)]
pub struct ProvisioningKeys<'a>(&'a Sdk);

impl ProvisioningKeys<'_> {
    /// Issue a Provisioning Key.
    ///
    /// [`ProvisioningBounds`] carries the ceilings a key is issued under and
    /// [`ProvisioningBinding`] the workload identity it is tied to, when it is
    /// tied to one — which is what makes a key usable in a public repository's
    /// CI.
    pub async fn create(
        self,
        protocol: &str,
        bounds: ProvisioningBounds,
        binding: Option<&ProvisioningBinding>,
        label: Option<&str>,
    ) -> Result<ProvisioningKey, SdkError> {
        self.0
            .call(&reading::KEY_CREATE, |proxy| async move {
                proxy
                    .create_provisioning_key(protocol, bounds, binding, label)
                    .await
            })
            .await
    }

    /// The keys this Endpoint has issued, with how many Grants each is holding
    /// against its ceiling.
    pub async fn list(self) -> Result<Vec<ProvisioningKeyRecord>, SdkError> {
        self.0
            .call(&reading::KEY_LIST, |proxy| async move {
                proxy.list_provisioning_keys().await
            })
            .await
    }

    /// Who came in on one key.
    ///
    /// **Outlives the key**: revoking or expiring one does not erase this, and
    /// a key is stopped because of a leak or somebody leaving — the moment the
    /// answer matters most.
    pub async fn redemptions(self, key_id: &str) -> Result<Vec<ProvisioningRedemption>, SdkError> {
        self.0
            .call(&reading::KEY_REDEMPTIONS, |proxy| async move {
                proxy.provisioning_redemptions(key_id).await
            })
            .await
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

    /// **The failure carries the route it came from**, which is what lets the
    /// reading be the route's rather than the facade's. The seven readings
    /// agree today — none of these routes assigns a meaning to a `404` or a
    /// `409` — so this checks the wiring rather than a difference in outcome:
    /// the first route whose answers stop agreeing is a revoke, and D5 settles
    /// those before they are written.
    #[test]
    fn the_failure_carries_the_route_it_came_from() {
        let error = SdkError::proxy(problem(404), &reading::KEY_REDEMPTIONS);
        let SdkError::Proxy { reading, .. } = &error else {
            panic!("the proxy arm");
        };
        assert!(std::ptr::eq(*reading, &reading::KEY_REDEMPTIONS));

        // **And a bodiless `404` stays a failure.** `Reading::gone_kinds`
        // argues why: an intermediary's page, a wrong base path or a proxy
        // built without the route all arrive as a `404` with no problem
        // document, and reading that by status would answer "that key is not
        // here" for a deployment that cannot answer at all.
        assert!(
            !matches!(error.outcome(), Outcome::Vanished { .. }),
            "{:?}",
            error.outcome()
        );
    }

    /// **Two answers end the cached client's usefulness, and only two.** A
    /// request that never got out may have left the channel under it poisoned
    /// for good — tower's `Buffer` hands every later request a clone of the
    /// first `poll_ready` error — and a refused token is one this handle can
    /// replace. A `403` is an answer about the request, and dropping the
    /// tunnel over it would build a new one for every refusal.
    #[test]
    fn only_a_dead_channel_or_a_refused_token_spends_the_client() {
        assert!(spent(&ProxyError::Transport(anyhow::anyhow!(
            "connection refused"
        ))));
        assert!(spent(&problem(401)));
        assert!(!spent(&problem(403)));
        assert!(!spent(&problem(404)));
        assert!(!spent(&problem(429)));
    }

    /// **The renewal margin's floor is not an answer to "is this token still
    /// good".** `renew_delay` keeps `RENEW_MIN` under its answer so a renewal
    /// loop cannot busy-spin; a `token_ttl` the caller set low — or one a
    /// server clamped — would otherwise be treated as fresh for thirty seconds
    /// after it had expired, and every call in that window would take a `401`.
    #[test]
    fn a_short_lived_token_is_never_called_fresh_past_its_end() {
        assert_eq!(good_for(300), Duration::from_secs(240));
        assert_eq!(good_for(10), Duration::from_secs(10));
        assert_eq!(good_for(0), Duration::ZERO);
        assert_eq!(good_for(-5), Duration::ZERO);
    }

    /// **A call can be held before it is awaited**, which is what taking the
    /// group by value buys: with `&self` the future borrowed the temporary the
    /// group is, so this line was `E0716` and so was every `map` over ids.
    #[test]
    fn a_group_call_can_be_held_before_it_is_awaited() {
        let sdk = Sdk::open(config());
        let pending = sdk.grants().list();
        let fanned: Vec<_> = ["k1", "k2"]
            .iter()
            .map(|id| sdk.provisioning_keys().redemptions(id))
            .collect();
        drop((pending, fanned));
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
    /// error — the contract the doc comment states. **And it leaves the cache
    /// empty**, which is what `shutdown` needs: a tunnel still held is a live
    /// msquic handle, and `shutdown_msquic` answers `false` and skips
    /// `RegistrationClose` while one exists.
    #[tokio::test]
    async fn closing_an_idle_handle_answers_true_and_is_idempotent() {
        let sdk = Sdk::open(config());
        assert!(sdk.close(Duration::from_secs(1)).await);
        assert!(sdk.close(Duration::from_secs(1)).await);
        assert!(sdk.unexpired().is_none());
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
