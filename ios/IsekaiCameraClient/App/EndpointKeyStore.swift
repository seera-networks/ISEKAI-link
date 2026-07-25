import Foundation

/// The device's long-lived Endpoint key (ECDSA P-256, PKCS#8 PEM).
///
/// The Rust core generates it; the keychain keeps it, so the Endpoint ID a
/// camera server authorises stays the same across launches. Moving to a Secure
/// Enclave key is a later step and needs the FFI to accept a signer rather than
/// a PEM, since `p256` cannot sign with an Enclave key (plan R7).
enum EndpointKeyStore {
    /// The stored key, generating and persisting one on first use.
    static func loadOrCreate() throws -> String {
        if let existing = try KeychainStore.string(for: KeychainStore.endpointKeyAccount) {
            return existing
        }
        let pem = try generateEndpointKeyPem()
        try KeychainStore.set(pem, for: KeychainStore.endpointKeyAccount)
        return pem
    }

    /// Forget the key, so the next connect mints a new identity. The camera
    /// server's capability is bound to the old Endpoint ID and stops matching.
    static func reset() throws {
        try KeychainStore.delete(for: KeychainStore.endpointKeyAccount)
    }
}
