import Foundation

/// Everything the connect screen collects apart from the secrets, which live in
/// the keychain. Persisted so a dev round-trip does not mean retyping five
/// fields; the defaults match the desktop `camera-client`.
struct ViewerSettings: Codable, Equatable {
    /// The protocol identifier this app used to ask for. See `init(from:)`.
    static let retiredProtocolName = "isekai-validator-v1"

    var identityURL = "https://identity.isekai.tools:9443"
    var proxyURL = "https://link.isekai.tools:6443"
    var protocolName = "isekai-camera-v1"
    /// Issued by the camera server for this viewer's Endpoint ID.
    var capability = ""
    /// The camera server's "Listener ID".
    var listenerID = ""
    /// The Endpoint that camera is expected to be, kept beside the listener it
    /// is running. Saved rather than re-read because the check it feeds is
    /// against the proxy, and a relaunch must not quietly drop it. Empty for a
    /// camera reached by a hand-carried capability.
    var expectedEndpoint = ""
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
    private enum CodingKeys: String, CodingKey {
        case identityURL, proxyURL, protocolName, capability, listenerID
        case expectedEndpoint, register, insecureSkipVerify, enableMigration, logFilter
    }

    /// Decoded a field at a time, so a blob written by an older build keeps
    /// what it does have.
    ///
    /// A property's default value does not cover it: the synthesized decoder
    /// throws `keyNotFound` for a field added since, and `load()` falls back to
    /// defaults **wholesale** — so adding one field would have reset every
    /// server URL and dropped the selected camera on every installed app.
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let d = ViewerSettings()
        identityURL = try c.decodeIfPresent(String.self, forKey: .identityURL) ?? d.identityURL
        proxyURL = try c.decodeIfPresent(String.self, forKey: .proxyURL) ?? d.proxyURL
        // **The one field a blob is not allowed to keep.** The decoder below
        // preserves whatever an older build wrote, which is right for every
        // other field and wrong for this one: an upgraded viewer would go on
        // asking for the retired protocol while cameras register under the new
        // one, and the camera would never be listed, since the listener's
        // protocol is what identifies it.
        let storedProtocol =
            try c.decodeIfPresent(String.self, forKey: .protocolName) ?? d.protocolName
        protocolName = storedProtocol == Self.retiredProtocolName ? d.protocolName : storedProtocol
        capability = try c.decodeIfPresent(String.self, forKey: .capability) ?? d.capability
        listenerID = try c.decodeIfPresent(String.self, forKey: .listenerID) ?? d.listenerID
        expectedEndpoint =
            try c.decodeIfPresent(String.self, forKey: .expectedEndpoint) ?? d.expectedEndpoint
        register = try c.decodeIfPresent(Bool.self, forKey: .register) ?? d.register
        insecureSkipVerify =
            try c.decodeIfPresent(Bool.self, forKey: .insecureSkipVerify) ?? d.insecureSkipVerify
        enableMigration =
            try c.decodeIfPresent(Bool.self, forKey: .enableMigration) ?? d.enableMigration
        logFilter = try c.decodeIfPresent(String.self, forKey: .logFilter) ?? d.logFilter
    }

    /// The server fields are left out while they still equal the default.
    /// Stored, a default outlives the build it came from: `init(from:)` keeps a
    /// stored value, so an install that once connected would keep dialing the
    /// old address after the default moves (#325). Left out, decoding falls
    /// back to whatever the default is then. One typed by hand is kept.
    func encode(to encoder: Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        let d = ViewerSettings()
        if identityURL != d.identityURL { try c.encode(identityURL, forKey: .identityURL) }
        if proxyURL != d.proxyURL { try c.encode(proxyURL, forKey: .proxyURL) }
        if protocolName != d.protocolName { try c.encode(protocolName, forKey: .protocolName) }
        try c.encode(capability, forKey: .capability)
        try c.encode(listenerID, forKey: .listenerID)
        try c.encode(expectedEndpoint, forKey: .expectedEndpoint)
        try c.encode(register, forKey: .register)
        try c.encode(insecureSkipVerify, forKey: .insecureSkipVerify)
        try c.encode(enableMigration, forKey: .enableMigration)
        try c.encode(logFilter, forKey: .logFilter)
    }

    private static let defaultsKey = "viewer.settings"

    /// The saved settings, or fresh defaults.
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
