//! Where a *current* Auth0 token comes from.
//!
//! An Endpoint Token lasts minutes — the spec recommends 5–15 (§5.3) — so a
//! session that runs for hours has to keep issuing new ones. Issuing requires an
//! Auth0 token every time: §5.3 requires "Auth0 authentication state plus
//! possession of the Endpoint private key" and forbids renewing from the old
//! Endpoint Token alone.
//!
//! So a token captured once at startup is not enough to keep a session alive
//! past the Auth0 token's own lifetime, and the caller is the only one that
//! knows how to get a fresh one — an iOS app refreshes it against Auth0, a
//! desktop app may have to ask a human. [`Auth0TokenSource`] is that seam.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::OnceCell;

/// A source of Auth0 access tokens that are valid *now*.
///
/// Called each time an Endpoint Token is issued, which is every few minutes for
/// the life of a session — so an implementation should return a cached token
/// while it is still good and refresh only when it is not.
pub trait Auth0TokenSource: Send + Sync {
    /// A token valid now, refreshed if the previous one has expired.
    ///
    /// An error ends that renewal attempt, not the session: the current Endpoint
    /// Token keeps working until it expires, and the next attempt tries again.
    /// Returning an error is therefore the right answer to "the user has to log
    /// in again" — the caller reports it and the video keeps flowing meanwhile.
    fn auth0_token(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>>;
}

/// A source of workload identity assertions, one per audience.
///
/// The unattended counterpart of [`Auth0TokenSource`], and it takes the
/// audience as an argument for a reason that is worth stating: **Identity and
/// the proxy deliberately want different ones** (`isekai-identity` and
/// `isekai-proxy`), so that a token minted for one is refused by the other.
/// Passing the audience in is what makes reusing a single token for both
/// inexpressible rather than merely discouraged.
///
/// # Called for every request that needs one
///
/// Not once per job. §8.8.7 verifies `binding` on **every** renewal — that is
/// the brake that stops an `oidc` key outliving the job it was issued for — and
/// a GitHub ID token lives 5–15 minutes against a renewal interval that is
/// longer than that. So an implementation mints or re-reads; there is nothing
/// worth caching, and a cache that never hits is only one more way to hold an
/// expired token.
pub trait AssertionSource: Send + Sync {
    /// A workload identity token for `audience`, valid now.
    fn assertion<'a>(
        &'a self,
        audience: &'a str,
    ) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>>;
}

/// How a session proves who it is to the Identity API.
///
/// **An enum rather than a set of optional fields.** The alternative — leaving
/// the Auth0 fields in place and adding an enrolment one beside them — makes "a
/// config whose Auth0 token is silently ignored" representable, and that turns
/// up as a `401` several steps later with nothing pointing back at the config
/// that caused it.
#[derive(Clone)]
pub enum Credential {
    /// Route A: a person signed in to Auth0.
    Auth0 {
        /// The token to start with. An Endpoint Token lasts minutes and is
        /// reissued for the life of the session, so once this one expires
        /// renewal needs a fresh one from `source`.
        token: String,
        /// Where a *current* token comes from. `None` keeps using `token`,
        /// which works until it expires and then stops.
        source: Option<Arc<dyn Auth0TokenSource>>,
        /// Register the Endpoint before issuing a token (§8.1), needed on
        /// first use of a freshly generated key.
        ///
        /// **Inside this arm and not beside it.** §8.1 registration requires
        /// Auth0 authentication state, so it is not a choice the unattended
        /// route has; leaving it at the top level would make a field that is
        /// silently ignored there — the same defect this enum removes.
        register: bool,
    },
    /// §8.8: an Enrollment Key, for a job with nobody at the keyboard.
    Enrollment(Enrollment),
}

impl Credential {
    /// The ordinary attended credential.
    pub fn auth0(
        token: impl Into<String>,
        source: Option<Arc<dyn Auth0TokenSource>>,
        register: bool,
    ) -> Self {
        Credential::Auth0 {
            token: token.into(),
            source,
            register,
        }
    }

    /// An Enrollment Key with no additional evidence — the `binding: none`
    /// case.
    ///
    /// For an `oidc` binding, add an assertion source; for `sub` or `tenant`,
    /// an Auth0 one (§8.8.3):
    ///
    /// ```no_run
    /// # use std::sync::Arc;
    /// # use isekai_p2p::{AssertionSource, Credential, Enrollment};
    /// # fn example(source: Arc<dyn AssertionSource>) -> Credential {
    /// Enrollment::new("enr1_…").with_assertions(source).into()
    /// # }
    /// ```
    pub fn enrollment(key: impl Into<String>) -> Self {
        Enrollment::new(key).into()
    }
}

impl From<Enrollment> for Credential {
    fn from(enrollment: Enrollment) -> Self {
        Credential::Enrollment(enrollment)
    }
}

/// An Enrollment Key and whatever its `binding` additionally requires.
#[derive(Clone)]
pub struct Enrollment {
    /// The `enr1_` secret.
    pub key: String,
    /// Where to mint the workload identity token an `oidc` binding wants.
    pub assertion: Option<Arc<dyn AssertionSource>>,
    /// An Auth0 token, for the `sub` and `tenant` bindings that compare
    /// against a principal (§8.8.3). Those two are the attended case and
    /// cannot be used by a job on its own.
    pub auth0: Option<Arc<dyn Auth0TokenSource>>,
    /// Which Endpoint this credential has already grown, if any.
    ///
    /// **Shared across clones, and it has to be.** [`crate::P2pConfig`] is
    /// `Clone` and the renewal task holds one while other callers hold others.
    /// A second enrolment would present the same keypair and take
    /// `409 endpoint-already-registered`, which does not even free the slot it
    /// spent.
    ///
    /// **One Enrollment Key can grow several Endpoints** — that is what
    /// `max_live_endpoints` counts — so this records *which*, and the caller
    /// checks it against the keypair in hand. A credential shared between two
    /// configs with different keys would otherwise let the second skip
    /// enrolment and renew an Endpoint that was never registered.
    ///
    /// **`tokio`'s `OnceCell` and not `std`'s.** The initializer is async, and
    /// `std::sync::OnceLock` has no way to hold one: "check, then enrol" across
    /// an `.await` is a race two concurrent callers both win.
    enrolled: Arc<OnceCell<Registered>>,
}

/// What an enrolment attempt settled, once.
///
/// **`by_us` is the part that matters on the way out.** A slot is spent by the
/// process that *registered*, and a run that found the Endpoint already there —
/// `409`, which this treats as success — spent nothing. Revoking on its way out
/// would destroy an Endpoint somebody else is still using, which is exactly
/// what a key-issuing invocation beside a running server does.
#[derive(Debug, Clone)]
pub(crate) struct Registered {
    pub(crate) endpoint_id: String,
    pub(crate) by_us: bool,
}

impl Enrollment {
    /// An Enrollment Key on its own.
    ///
    /// **Public, so the builders below can be reached without destructuring.**
    /// They live here rather than on [`Credential`] because they are only
    /// meaningful on this arm; without a constructor a caller had to `match` an
    /// enum on an arm that cannot occur, which is worse than either.
    pub fn new(key: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            assertion: None,
            auth0: None,
            enrolled: Arc::new(OnceCell::new()),
        }
    }

    /// Mint assertions for the `oidc` binding from `source`.
    pub fn with_assertions(mut self, source: Arc<dyn AssertionSource>) -> Self {
        self.assertion = Some(source);
        self
    }

    /// Present an Auth0 token as well, for a `sub` or `tenant` binding.
    pub fn with_auth0(mut self, source: Arc<dyn Auth0TokenSource>) -> Self {
        self.auth0 = Some(source);
        self
    }

    /// The Endpoint this key grew, once it has.
    pub fn endpoint_id(&self) -> Option<&str> {
        self.enrolled.get().map(|r| r.endpoint_id.as_str())
    }

    /// Whether *this process* registered it, and so owes the slot back.
    pub fn registered_here(&self) -> bool {
        self.enrolled.get().is_some_and(|r| r.by_us)
    }

    /// The cell the enrolment writes to. See its documentation.
    pub(crate) fn cell(&self) -> &OnceCell<Registered> {
        &self.enrolled
    }
}

/// The one token the caller had, and no way to get another.
///
/// What every caller did before this trait existed, kept as the default so
/// behaviour does not change by accident. It works until the Auth0 token
/// expires, and then renewal starts failing — which is a real limit, not a
/// placeholder to be ignored: see [`Auth0TokenSource`] for the way out.
pub struct StaticAuth0Token(pub String);

impl Auth0TokenSource for StaticAuth0Token {
    fn auth0_token(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
        let token = self.0.clone();
        Box::pin(async move { Ok(token) })
    }
}

/// Wrap a closure that already has a token to hand.
pub fn from_fn<F, Fut>(f: F) -> Arc<dyn Auth0TokenSource>
where
    F: Fn() -> Fut + Send + Sync + 'static,
    Fut: Future<Output = anyhow::Result<String>> + Send + 'static,
{
    struct FromFn<F>(F);
    impl<F, Fut> Auth0TokenSource for FromFn<F>
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: Future<Output = anyhow::Result<String>> + Send + 'static,
    {
        fn auth0_token(&self) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + '_>> {
            Box::pin((self.0)())
        }
    }
    Arc::new(FromFn(f))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_static_token_is_returned_as_is() {
        let source = StaticAuth0Token("header.payload.signature".to_owned());
        assert_eq!(
            source.auth0_token().await.unwrap(),
            "header.payload.signature"
        );
    }

    /// The point of the seam: the second call can answer differently from the
    /// first, which is what a refresh looks like from here.
    #[tokio::test]
    async fn a_source_can_answer_differently_each_time() {
        let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let seen = calls.clone();
        let source = from_fn(move || {
            let n = seen.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            async move { Ok(format!("token-{n}")) }
        });
        assert_eq!(source.auth0_token().await.unwrap(), "token-0");
        assert_eq!(source.auth0_token().await.unwrap(), "token-1");
    }
}
