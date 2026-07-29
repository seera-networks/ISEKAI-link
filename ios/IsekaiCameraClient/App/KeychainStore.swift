import Foundation
import Security

/// Keychain storage for the two secrets the viewer holds: the Endpoint private
/// key and the Auth0 access token.
///
/// Items are stored `AfterFirstUnlockThisDeviceOnly` — the Endpoint key must
/// never leave the device or sync to another one (plan R5), and the viewer needs
/// to read it without the screen being unlocked first.
enum KeychainStore {
    enum Failure: Error {
        case unexpectedStatus(OSStatus)
        case malformedValue
    }

    static let endpointKeyAccount = "endpoint-key-pem"
    /// The whole `Auth0Tokens` blob from a login, as JSON.
    static let auth0SessionAccount = "auth0-session"
    /// A token pasted by hand, the fallback for when Auth0 is unreachable.
    static let auth0TokenAccount = "auth0-access-token"

    /// The stored value, or nil if nothing has been stored under `account`.
    static func string(for account: String) throws -> String? {
        var query = baseQuery(account: account)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let data = item as? Data, let value = String(data: data, encoding: .utf8) else {
                throw Failure.malformedValue
            }
            return value
        case errSecItemNotFound:
            return nil
        default:
            throw Failure.unexpectedStatus(status)
        }
    }

    static func set(_ value: String, for account: String) throws {
        let data = Data(value.utf8)
        let query = baseQuery(account: account)

        let status = SecItemUpdate(query as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        switch status {
        case errSecSuccess:
            return
        case errSecItemNotFound:
            var insert = query
            insert[kSecValueData as String] = data
            insert[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            let addStatus = SecItemAdd(insert as CFDictionary, nil)
            guard addStatus == errSecSuccess else { throw Failure.unexpectedStatus(addStatus) }
        default:
            throw Failure.unexpectedStatus(status)
        }
    }

    static func delete(for account: String) throws {
        let status = SecItemDelete(baseQuery(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw Failure.unexpectedStatus(status)
        }
    }

    private static func baseQuery(account: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: "tools.isekai.viewer",
            kSecAttrAccount as String: account,
        ]
    }
}

extension KeychainStore.Failure: LocalizedError {
    var errorDescription: String? {
        switch self {
        case .unexpectedStatus(let status):
            let detail = SecCopyErrorMessageString(status, nil) as String? ?? "OSStatus \(status)"
            return "keychain error: \(detail)"
        case .malformedValue:
            return "keychain item was not valid UTF-8"
        }
    }
}
