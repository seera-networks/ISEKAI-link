import Foundation

enum AuthError: LocalizedError {
    case notSignedIn
    case sessionExpired

    var errorDescription: String? {
        switch self {
        case .notSignedIn: return "Sign in to Auth0 first"
        case .sessionExpired: return "The session expired — sign in again"
        }
    }
}

/// The signed-in session: tokens in the keychain, renewed when they go stale.
@MainActor
final class AuthStore: ObservableObject {
    @Published private(set) var tokens: Auth0Tokens?
    @Published private(set) var isWorking = false

    var isSignedIn: Bool { tokens != nil }
    var expiresAt: Date? { tokens?.expiresAt }

    private let config: Auth0Config
    private let client: Auth0Client

    init(config: Auth0Config = Auth0Config()) {
        self.config = config
        client = Auth0Client(config: config)
        tokens = Self.loadFromKeychain()
    }

    func signIn() async throws {
        isWorking = true
        defer { isWorking = false }
        store(try await client.logIn())
    }

    func signOut() {
        tokens = nil
        try? KeychainStore.delete(for: KeychainStore.auth0SessionAccount)
    }

    /// An access token good for the request about to be made, renewed first if
    /// the one held has expired.
    func accessToken() async throws -> String {
        guard let current = tokens else { throw AuthError.notSignedIn }
        guard current.isExpired() else { return current.accessToken }
        guard let refreshToken = current.refreshToken else {
            // No `offline_access`, so there is nothing to renew with.
            signOut()
            throw AuthError.sessionExpired
        }

        isWorking = true
        defer { isWorking = false }
        do {
            var renewed = try await client.refresh(using: refreshToken)
            // Auth0 only returns a new refresh token when rotation is enabled;
            // otherwise the existing one stays valid.
            if renewed.refreshToken == nil {
                renewed.refreshToken = refreshToken
            }
            store(renewed)
            return renewed.accessToken
        } catch let failure as Auth0Client.Failure {
            // Auth0 rejected the refresh token: it is spent or revoked, so the
            // session really is over. A transport error is not, and propagates
            // without signing out.
            signOut()
            throw failure
        }
    }

    private func store(_ tokens: Auth0Tokens) {
        self.tokens = tokens
        guard let data = try? JSONEncoder().encode(tokens),
              let json = String(data: data, encoding: .utf8)
        else { return }
        try? KeychainStore.set(json, for: KeychainStore.auth0SessionAccount)
    }

    private static func loadFromKeychain() -> Auth0Tokens? {
        // `try?` flattens the throwing call's optional result, so this binds
        // only when a session was actually stored.
        guard let json = try? KeychainStore.string(for: KeychainStore.auth0SessionAccount),
              let data = json.data(using: .utf8)
        else { return nil }
        return try? JSONDecoder().decode(Auth0Tokens.self, from: data)
    }
}
