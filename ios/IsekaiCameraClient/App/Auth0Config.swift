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

    /// Where Auth0 sends the browser back to. Must be listed verbatim in the
    /// Auth0 application's **Allowed Callback URLs**.
    var redirectURI: String { "\(callbackScheme)://callback" }

    /// The scheme half of `redirectURI`, which is all
    /// `ASWebAuthenticationSession` matches on. It must also appear in
    /// `CFBundleURLSchemes` — see ios/project.yml.
    ///
    /// Deliberately a constant rather than the bundle identifier, which is
    /// Auth0's usual suggestion for a native app: sideloading rewrites the
    /// bundle identifier to append the signing team (`…viewer.KJ6DNKW8B9`), so
    /// deriving the scheme from it produces a different redirect on every
    /// machine that installs the app — and one that no longer matches the
    /// scheme baked into Info.plist at build time.
    let callbackScheme = "isekaiviewer"

    var isConfigured: Bool {
        !domain.isEmpty && !clientID.isEmpty && !audience.isEmpty
    }
}
