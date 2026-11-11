//
//  AiDexPairingStore.swift
//  xdrip
//
//  Keychain storage for the AiDex PAIR key, one record per sensor serial.
//
//  The PAIR key is the credential the sensor hands out over F001 during the first pairing. It is
//  needed on every later connection to decrypt the BOND vector, so losing it means pairing again.
//  Pairing again only works while the sensor still accepts this phone (see AiDex notes in
//  CGMAiDexTransmitter). JugglucoNG keeps the same key in AiDexPairKeyVault.kt.
//

import Foundation
import Security

struct AiDexPairingRecord: Codable, Equatable {
    var serial: String
    /// 16-byte PAIR key from F001; saved only after the first valid, CRC-checked live frame.
    var pairKey: Data
    /// True once this phone completed an F001 write, which needs an encrypted link. iOS keeps the
    /// link key from that pairing, so later F001 writes (post-BOND config) work without a prompt.
    /// Set back to false when an F001 write fails with an ATT authentication/encryption error.
    var linkPaired: Bool
    var savedAt: Date
}

final class AiDexPairingStore {

    static let shared = AiDexPairingStore()

    private let service: String

    init(service: String = (Bundle.main.bundleIdentifier ?? "xdrip") + ".aidex") {
        self.service = service
    }

    func load(serial: String) -> AiDexPairingRecord? {
        guard let data = read(account(serial)),
              let record = try? JSONDecoder().decode(AiDexPairingRecord.self, from: data),
              record.pairKey.count == 16 else { return nil }
        return record
    }

    @discardableResult
    func save(_ record: AiDexPairingRecord) -> Bool {
        guard record.pairKey.count == 16, let data = try? JSONEncoder().encode(record) else { return false }
        return write(data, account: account(record.serial))
    }

    @discardableResult
    func delete(serial: String) -> Bool {
        let status = SecItemDelete(query(account(serial)) as CFDictionary)
        return status == errSecSuccess || status == errSecItemNotFound
    }

    private func account(_ serial: String) -> String {
        "sensor." + serial.uppercased()
    }

    private func query(_ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrSynchronizable as String: false]
    }

    private func read(_ account: String) -> Data? {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &result) == errSecSuccess else { return nil }
        return result as? Data
    }

    private func write(_ data: Data, account: String) -> Bool {
        // Readable after first unlock so a locked phone can still reconnect in the background.
        let attributes: [String: Any] = [kSecValueData as String: data,
                                         kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly]
        let q = query(account)
        let status = SecItemUpdate(q as CFDictionary, attributes as CFDictionary)
        if status == errSecItemNotFound {
            return SecItemAdd(q.merging(attributes) { _, new in new } as CFDictionary, nil) == errSecSuccess
        }
        return status == errSecSuccess
    }
}
