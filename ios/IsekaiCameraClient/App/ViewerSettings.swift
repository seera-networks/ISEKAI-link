import Foundation

/// Everything the connect screen collects apart from the secrets, which live in
/// the keychain. Persisted so a dev round-trip does not mean retyping five
/// fields; the defaults match the desktop `camera-client`.
struct ViewerSettings: Codable, Equatable {
    var identityURL = "https://identity.isekai.tools:9443"
    var proxyURL = "https://tokyo.link.isekai.tools:8443"
    var protocolName = "isekai-validator-v1"
    /// Issued by the camera server for this viewer's Endpoint ID.
    var capability = ""
    /// The camera server's "Listener ID".
    var listenerID = ""
    /// Register the Endpoint with the Identity API before a token is issued.
    var register = true
    /// **Dev only.** Accepts self-signed proxy/Identity certificates; Phase 4 of
    /// the plan turns real validation back on.
    var insecureSkipVerify = false
    /// Offer a direct path and allow migrating off the relay. Off makes the
    /// session relay-only, which is also how to tell a migration problem apart
    /// from a relay one.
    var enableMigration = true
    /// `RUST_LOG`-style filter for the core's logging. Empty disables it.
    /// There is no console on a phone, so this is the only way to see what the
    /// core is doing.
    var logFilter = ""
}

extension ViewerSettings {
    private static let defaultsKey = "viewer.settings"

    /// The saved settings, or fresh defaults. A blob written by an older build
    /// that lacks a field added since decodes as nil and falls back to defaults
    /// wholesale — acceptable while the shape is still moving.
    static func load() -> ViewerSettings {
        guard let data = UserDefaults.standard.data(forKey: defaultsKey),
              let decoded = try? JSONDecoder().decode(ViewerSettings.self, from: data)
        else { return ViewerSettings() }
        return decoded
    }

    func save() {
        guard let data = try? JSONEncoder().encode(self) else { return }
        UserDefaults.standard.set(data, forKey: Self.defaultsKey)
    }
}
