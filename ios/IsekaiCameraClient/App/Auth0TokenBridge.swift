import Foundation

/// Hands the Rust core a current Auth0 access token, for as long as a session
/// runs.
///
/// The token passed to `connect` is a snapshot and lasts hours. The Endpoint
/// Token behind every proxy call lasts *minutes* and is reissued for the life of
/// the session, and the Identity API wants Auth0 authentication state on each
/// issue — so once the snapshot lapses the renewals stop, and the session can no
/// longer open anything new. This is what the core asks instead.
///
/// **It answers from a cache and never blocks.** The core calls this from one of
/// its worker threads, and `AuthStore` is `@MainActor` with an async refresh, so
/// waiting here would mean parking a core thread on the main queue — a deadlock
/// waiting to happen while video is flowing. Returning a slightly stale token
/// instead costs one failed renewal, which the core retries within the minute,
/// by which time the refresh started here has landed.
final class Auth0TokenBridge: Auth0TokenProvider, @unchecked Sendable {
    private let auth: AuthStore
    private let lock = NSLock()
    private var cached: String
    /// Set while a refresh is in flight, so a burst of calls starts one refresh
    /// rather than one each.
    private var refreshing = false

    /// `initial` is the token the connect itself used, so the first renewal has
    /// something to work with before any refresh has run.
    init(auth: AuthStore, initial: String) {
        self.auth = auth
        cached = initial
    }

    func currentToken() -> String {
        lock.lock()
        let token = cached
        let alreadyRefreshing = refreshing
        if !alreadyRefreshing {
            refreshing = true
        }
        lock.unlock()

        if !alreadyRefreshing {
            Task { [weak self] in
                guard let self else { return }
                // `accessToken()` returns the held token when it is still good,
                // so this is cheap in the common case and only reaches Auth0
                // when the token has actually gone stale.
                let renewed = try? await self.auth.accessToken()
                self.lock.lock()
                if let renewed, !renewed.isEmpty {
                    self.cached = renewed
                }
                self.refreshing = false
                self.lock.unlock()
            }
        }
        return token
    }
}
