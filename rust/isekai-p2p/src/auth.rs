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
