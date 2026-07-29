import Foundation

/// Where the app logs in, and what it asks a token for.
///
/// None of this is secret. A native OAuth client has no client secret — that is
/// the reason it uses PKCE — and the client id travels in the authorize URL of
/// every login, so it is a public identifier like the domain beside it.
///
/// `issuer` and `audience` have to match the Identity API's `AUTH0_ISSUER` and
/// `AUTH0_AUDIENCE`, or the token it receives is rejected.
struct Auth0Config: Equatable {
    var domain = "seera-networks.jp.auth0.com"
    var clientID = "FeDSXYhJsfV1d9v6JyBte874R6En4tok"
    var audience = "https://masque.seera-networks.com/"

    /// `offline_access` is what makes Auth0 return a refresh token, so a session
    /// outlives the access token's few hours. It requires "Allow Offline Access"
    /// on the API in the Auth0 dashboard; without it the login still works and
    /// the app simply asks again when the token expires.
    var scope = "openid profile email offline_access"

    /// Auth0's documented callback shape for a native app. The scheme is the
    /// bundle identifier, which the app registers in its Info.plist, so no other
    /// app on the device can claim the redirect.
    var redirectURI: String {
        "\(Self.bundleID)://\(domain)/ios/\(Self.bundleID)/callback"
    }

    /// The scheme half of `redirectURI`, which is all
    /// `ASWebAuthenticationSession` matches on.
    var callbackScheme: String { Self.bundleID }

    var isConfigured: Bool {
        !domain.isEmpty && !clientID.isEmpty && !audience.isEmpty
    }

    private static let bundleID = Bundle.main.bundleIdentifier ?? "tools.isekai.viewer"
}
