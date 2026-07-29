import AuthenticationServices
import CryptoKit
import Foundation
import UIKit

/// The tokens a login (or a refresh) produced.
struct Auth0Tokens: Codable, Equatable {
    var accessToken: String
    var refreshToken: String?
    var expiresAt: Date

    /// Treats a token about to expire as expired: the Identity API checks `exp`
    /// when the request lands, not when it was sent.
    func isExpired(now: Date = Date(), margin: TimeInterval = 60) -> Bool {
        expiresAt.addingTimeInterval(-margin) <= now
    }
}

/// Auth0 Authorization Code flow with PKCE, through `ASWebAuthenticationSession`.
///
/// Hand-rolled rather than pulled from Auth0.swift: it is three requests and a
/// hash, and the project has no package dependencies to weigh that against.
/// `ASWebAuthenticationSession` is what the SDK would use underneath anyway, and
/// it is what keeps the credentials in Safari rather than in a web view this app
/// could read.
@MainActor
final class Auth0Client {
    enum Failure: LocalizedError, Equatable {
        case notConfigured
        case cancelled
        case couldNotStart
        case badCallback(String)
        case stateMismatch
        case server(String)

        var errorDescription: String? {
            switch self {
            case .notConfigured: return "Auth0 is not configured"
            case .cancelled: return "Sign-in was cancelled"
            case .couldNotStart: return "Could not open the sign-in page"
            case .badCallback(let detail): return "Unexpected sign-in response: \(detail)"
            case .stateMismatch: return "Sign-in response did not match the request"
            case .server(let detail): return detail
            }
        }
    }

    private let config: Auth0Config
    private let anchor = PresentationAnchor()
    /// `ASWebAuthenticationSession` does nothing if it is deallocated before the
    /// user finishes, so it is held for the duration.
    private var session: ASWebAuthenticationSession?

    init(config: Auth0Config) {
        self.config = config
    }

    func logIn() async throws -> Auth0Tokens {
        guard config.isConfigured else { throw Failure.notConfigured }

        let verifier = Self.randomURLSafeString()
        let state = Self.randomURLSafeString(byteCount: 16)
        let callback = try await authorize(
            url: authorizeURL(challenge: Self.challenge(for: verifier), state: state)
        )

        let items = URLComponents(url: callback, resolvingAgainstBaseURL: false)?.queryItems ?? []
        func value(_ name: String) -> String? {
            items.first { $0.name == name }?.value
        }
        if let error = value("error") {
            throw Failure.server(value("error_description") ?? error)
        }
        guard value("state") == state else { throw Failure.stateMismatch }
        guard let code = value("code") else { throw Failure.badCallback("no authorization code") }

        return try await requestTokens([
            "grant_type": "authorization_code",
            "client_id": config.clientID,
            "code": code,
            "code_verifier": verifier,
            "redirect_uri": config.redirectURI,
        ])
    }

    /// Exchange a refresh token for a fresh access token.
    ///
    /// Auth0 may or may not return a new refresh token depending on whether
    /// rotation is enabled, so the caller keeps the old one when it does not.
    func refresh(using refreshToken: String) async throws -> Auth0Tokens {
        guard config.isConfigured else { throw Failure.notConfigured }
        return try await requestTokens([
            "grant_type": "refresh_token",
            "client_id": config.clientID,
            "refresh_token": refreshToken,
        ])
    }

    // MARK: -

    private func authorizeURL(challenge: String, state: String) -> URL {
        var components = URLComponents()
        components.scheme = "https"
        components.host = config.domain
        components.path = "/authorize"
        components.queryItems = [
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "client_id", value: config.clientID),
            URLQueryItem(name: "redirect_uri", value: config.redirectURI),
            URLQueryItem(name: "scope", value: config.scope),
            URLQueryItem(name: "audience", value: config.audience),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: challenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
        ]
        // The components are all built from fixed parts and generated values.
        return components.url!
    }

    private func authorize(url: URL) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: url,
                callbackURLScheme: config.callbackScheme
            ) { callbackURL, error in
                if let callbackURL {
                    continuation.resume(returning: callbackURL)
                } else if let error = error as? ASWebAuthenticationSessionError,
                          error.code == .canceledLogin {
                    continuation.resume(throwing: Failure.cancelled)
                } else if let error {
                    continuation.resume(throwing: Failure.badCallback(error.localizedDescription))
                } else {
                    continuation.resume(throwing: Failure.cancelled)
                }
            }
            session.presentationContextProvider = anchor
            self.session = session
            // `start()` returning false means the handler will never run, so
            // resuming here cannot race it.
            if !session.start() {
                self.session = nil
                continuation.resume(throwing: Failure.couldNotStart)
            }
        }
    }

    private func requestTokens(_ parameters: [String: String]) async throws -> Auth0Tokens {
        var request = URLRequest(url: URL(string: "https://\(config.domain)/oauth/token")!)
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.httpBody = Data(Self.formEncoded(parameters).utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0

        let decoder = JSONDecoder()
        decoder.keyDecodingStrategy = .convertFromSnakeCase
        guard (200 ..< 300).contains(status) else {
            let detail = (try? decoder.decode(ErrorResponse.self, from: data))
                .map { $0.errorDescription ?? $0.error }
                ?? "Auth0 returned HTTP \(status)"
            throw Failure.server(detail)
        }
        guard let body = try? decoder.decode(TokenResponse.self, from: data) else {
            throw Failure.badCallback("could not read the token response")
        }
        return Auth0Tokens(
            accessToken: body.accessToken,
            refreshToken: body.refreshToken,
            expiresAt: Date().addingTimeInterval(TimeInterval(body.expiresIn))
        )
    }

    private struct TokenResponse: Decodable {
        let accessToken: String
        let refreshToken: String?
        let expiresIn: Int
    }

    private struct ErrorResponse: Decodable {
        let error: String
        let errorDescription: String?
    }

    private static func formEncoded(_ parameters: [String: String]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return parameters
            .map { key, value in
                let encoded = value.addingPercentEncoding(withAllowedCharacters: allowed) ?? value
                return "\(key)=\(encoded)"
            }
            .joined(separator: "&")
    }

    private static func randomURLSafeString(byteCount: Int = 32) -> String {
        var bytes = [UInt8](repeating: 0, count: byteCount)
        if SecRandomCopyBytes(kSecRandomDefault, byteCount, &bytes) != errSecSuccess {
            // The system RNG does not fail in practice, and a predictable
            // verifier would defeat PKCE, so refuse rather than carry on.
            preconditionFailure("SecRandomCopyBytes failed")
        }
        return Data(bytes).base64URLEncodedString()
    }

    private static func challenge(for verifier: String) -> String {
        Data(SHA256.hash(data: Data(verifier.utf8))).base64URLEncodedString()
    }
}

/// `ASWebAuthenticationSession` asks what to present over.
private final class PresentationAnchor: NSObject, ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { $0 as? UIWindowScene }
            .flatMap(\.windows)
            .first { $0.isKeyWindow }
            ?? ASPresentationAnchor()
    }
}

private extension Data {
    /// base64url per RFC 4648 §5, which is what PKCE and JWTs use.
    func base64URLEncodedString() -> String {
        base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}
