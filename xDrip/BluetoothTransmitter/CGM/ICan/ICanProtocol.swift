//
//  ICanProtocol.swift
//  xdrip
//
//  Sinocare iCan i3/i6 (iCGM-t3/t6, H3/H6, o3, i7) Bluetooth protocol: bundled AES keys,
//  challenge-derived CBC IV, vendor authentication, live frames, SN history batches.
//
//  Ported from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG, a fork of Juggluco by
//  Jaap Korthals Altes), Common/src/main/java/tk/glucodata/drivers/icanhealth/
//  ICanHealthConstants.kt, ICanHealthParser.kt, ICanHealthCrypto.kt, ICanHealthProfile.kt and
//  docs/ican-cgm-protocol.md. Not ported: the correctCode provisioning of fresh sensors (needs
//  the Sinocare cloud), user calibration (vendor libAlg port) and the sensor start command.
//

import Foundation
import CommonCrypto

enum ICanProtocol {

    // MARK: - identity

    /// Advertised-name prefixes JugglucoNG accepts (ICanHealthConstants.KNOWN_PREFIXES).
    static let knownNamePrefixes = ["iCGM-", "Sinocare CGM", "Sinocare ", "LT"]

    static func isICanDeviceName(_ name: String?) -> Bool {
        guard let name = name?.trimmingCharacters(in: .whitespaces), !name.isEmpty else { return false }
        return knownNamePrefixes.contains { name.hasPrefix($0) }
    }

    // MARK: - keys (vendor SDK values bundled by JugglucoNG)

    static let oldGlucoseKey = Array("4&13E6G24w6ZL3rF".utf8)
    static let newGlucoseKey = Array("y67BbdK!3qN?75t8".utf8)
    static let oldAuthKey = Array("92AFQU*u9c695826".utf8)
    static let newAuthKey = Array("px@9k5K*23cV%YDc".utf8)

    /// Key family: characters 10..<12 of the DIS serial (or else the software version), read as
    /// hex; 0x04...0x07 selects the new family.
    static func usesNewKeyFamily(serial: String?, softwareVersion: String?) -> Bool {
        func selector(_ source: String?) -> Int? {
            guard let trimmed = source?.trimmingCharacters(in: .whitespaces), trimmed.count >= 12 else { return nil }
            let start = trimmed.index(trimmed.startIndex, offsetBy: 10)
            let end = trimmed.index(start, offsetBy: 2)
            return Int(trimmed[start..<end], radix: 16)
        }
        guard let value = selector(serial) ?? selector(softwareVersion) else { return false }
        return (0x04...0x07).contains(value)
    }

    static func glucoseKey(newFamily: Bool) -> [UInt8] { newFamily ? newGlucoseKey : oldGlucoseKey }

    static func authKey(newFamily: Bool) -> [UInt8] { newFamily ? newAuthKey : oldAuthKey }

    // MARK: - warm-up XOR tables

    static let warmupXorTableOld: [UInt8] = [
        0x6D, 0x29, 0x8B, 0x2D, 0x24, 0xA7, 0x53, 0xF3, 0xC8, 0xB8, 0x7F, 0x2D, 0x85, 0x4D, 0x43, 0xF1,
        0x8A, 0xA2, 0x46, 0xAD, 0x8C, 0x77, 0xD4, 0x2D, 0xBE, 0x60, 0xFE, 0x07, 0xF2, 0xFE, 0x52, 0x77,
        0xAC, 0x8F, 0x7D, 0x1D, 0xED, 0x38, 0xBE, 0xEC, 0xDF, 0x78, 0x5D, 0x41, 0x9B, 0x68, 0x7F, 0x28,
        0xC4, 0xF2, 0x78, 0xF4, 0xF6, 0x47, 0x54, 0xD5, 0x0F, 0xAE, 0x5B, 0x27, 0xCB, 0x41, 0x21, 0x82,
    ]

    static let warmupXorTableNew: [UInt8] = [
        0xBF, 0x2D, 0x98, 0x23, 0xD2, 0xA3, 0x75, 0x4F, 0xF8, 0xB8, 0x87, 0x21, 0xD8, 0x43, 0xD4, 0x5F,
        0x62, 0xAA, 0x24, 0xAD, 0xE8, 0x74, 0x7D, 0xC2, 0xEE, 0x6E, 0x5F, 0x27, 0x7F, 0xF2, 0xE5, 0x27,
        0xD8, 0x8C, 0xF7, 0x1C, 0xDE, 0x3E, 0x8B, 0xDE, 0xDF, 0x7F, 0x85, 0x48, 0x39, 0x6F, 0xC7, 0xB2,
        0x8E, 0xF4, 0x27, 0xF5, 0x4F, 0x44, 0x75, 0x6D, 0xB9, 0xAF, 0xE5, 0x22, 0x7C, 0x41, 0x12, 0xB8,
    ]

    // MARK: - commands (written to 0x2AAC, vendor opcodes)

    static let requestChallenge: [UInt8] = [0xF3]
    static let requestSensorInfo: [UInt8] = [0xF6]

    /// RACP glucose history from a sequence number: `F1|01 03 02 01 <seq u16>`.
    /// The F1 family needs an MTU of at least 247 (JugglucoNG MIN_VENDOR_HISTORY_MTU).
    static func reportGlucoseHistory(fromSequence sequence: Int, modern: Bool) -> [UInt8] {
        let safe = max(1, min(0xFFFF, sequence))
        return [modern ? 0xF1 : 0x01, 0x03, 0x02, 0x01, UInt8(safe & 0xFF), UInt8(safe >> 8)]
    }

    // MARK: - profile

    struct Profile: Equatable {
        let family: String
        let readingIntervalMinutes: Int
        let warmupMinutes: Int
        let ratedLifetimeDays: Int
    }

    /// ICanHealthProfileResolver.resolve
    static func profile(model: String?, serial: String?, softwareVersion: String?) -> Profile {
        func normalize(_ value: String?) -> String {
            (value ?? "").trimmingCharacters(in: .whitespaces).lowercased()
                .replacingOccurrences(of: "_", with: " ").replacingOccurrences(of: "-", with: " ")
        }
        let combined = [normalize(model), normalize(serial), normalize(softwareVersion)].filter { !$0.isEmpty }.joined(separator: " ")
        func has(_ part: String) -> Bool { combined.contains(part) }

        if has("i7e") { return Profile(family: "i7e", readingIntervalMinutes: 1, warmupMinutes: 30, ratedLifetimeDays: 9) }
        if has("i7pro") || has("h7pro") || has("i7s") || has(" i7") || combined.hasPrefix("i7") {
            return Profile(family: "i7", readingIntervalMinutes: 1, warmupMinutes: 30, ratedLifetimeDays: 15)
        }
        if has("h6 14") { return Profile(family: "H6-14", readingIntervalMinutes: 3, warmupMinutes: 120, ratedLifetimeDays: 14) }
        if has("h6 15s") || has("h6 15") || (has("h6") && (has(" yk") || has(" zz") || has(" zb"))) {
            return Profile(family: "H6-15", readingIntervalMinutes: 3, warmupMinutes: 30, ratedLifetimeDays: 15)
        }
        if has("h6 7") || (has(" h6") && !has("h6 14") && !has("h6 15")) {
            return Profile(family: "H6", readingIntervalMinutes: 3, warmupMinutes: has(" yk") ? 30 : 120, ratedLifetimeDays: 7)
        }
        if has("h3") { return Profile(family: "H3", readingIntervalMinutes: 3, warmupMinutes: 120, ratedLifetimeDays: 8) }
        if has("i6pro") || has("i6s") || has(" i6") || combined.hasPrefix("i6") || has("t6") {
            return Profile(family: "i6", readingIntervalMinutes: 3, warmupMinutes: 30, ratedLifetimeDays: 15)
        }
        if has("o3") { return Profile(family: "o3", readingIntervalMinutes: 3, warmupMinutes: 120, ratedLifetimeDays: 15) }
        return Profile(family: "i3", readingIntervalMinutes: 3, warmupMinutes: 120, ratedLifetimeDays: 15)
    }

    // MARK: - crypto

    /// 16-byte IV with the four challenge bytes at positions 1, 6, 10 and 15.
    static func iv(challenge: [UInt8]) -> [UInt8]? {
        guard challenge.count == 4 else { return nil }
        var iv = [UInt8](repeating: 0, count: 16)
        iv[1] = challenge[0]
        iv[6] = challenge[1]
        iv[10] = challenge[2]
        iv[15] = challenge[3]
        return iv
    }

    static func cbcEncrypt(_ plaintext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        cbc(CCOperation(kCCEncrypt), plaintext, key: key, iv: iv)
    }

    static func cbcDecrypt(_ ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        guard !ciphertext.isEmpty, ciphertext.count % 16 == 0 else { return nil }
        return cbc(CCOperation(kCCDecrypt), ciphertext, key: key, iv: iv)
    }

    /// AES-128-CBC with PKCS7 padding.
    private static func cbc(_ operation: CCOperation, _ input: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        guard key.count == kCCKeySizeAES128, iv.count == kCCBlockSizeAES128 else { return nil }
        var output = [UInt8](repeating: 0, count: input.count + kCCBlockSizeAES128)
        let outputCount = output.count
        var moved = 0
        let status = key.withUnsafeBytes { keyBytes in
            iv.withUnsafeBytes { ivBytes in
                input.withUnsafeBytes { inputBytes in
                    CCCrypt(operation, CCAlgorithm(kCCAlgorithmAES), CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress, key.count, ivBytes.baseAddress,
                            inputBytes.baseAddress, input.count,
                            &output, outputCount, &moved)
                }
            }
        }
        guard status == CCCryptorStatus(kCCSuccess) else { return nil }
        return Array(output[0..<moved])
    }

    // MARK: - authentication

    /// User id as the vendor normalises it: last 12 printable characters, padded with '0'.
    static func normalizedUserId(_ source: String?) -> String {
        let printable = (source ?? "").unicodeScalars.filter { $0.value >= 0x21 && $0.value <= 0x7E }
        let trimmed = String(printable)
        if trimmed.count >= 12 { return String(trimmed.suffix(12)) }
        if trimmed.isEmpty { return String(repeating: "0", count: 12) }
        return trimmed + String(repeating: "0", count: 12 - trimmed.count)
    }

    /// `06 F3 01 <challenge 4>` -> challenge
    static func challenge(fromResponse bytes: [UInt8]) -> [UInt8]? {
        guard bytes.count >= 7, bytes[0] == 0x06, bytes[1] == 0xF3, bytes[2] == 0x01 else { return nil }
        return Array(bytes[3..<7])
    }

    /// `F4 10 <AES-CBC/PKCS7(F4 0C <userId 12>)>`
    static func authTokenPacket(challenge: [UInt8], userId: String, authKey: [UInt8]) -> [UInt8]? {
        guard let cbcIv = iv(challenge: challenge) else { return nil }
        let id = Array(normalizedUserId(userId).utf8)
        guard let token = cbcEncrypt([0xF4, UInt8(id.count)] + id, key: authKey, iv: cbcIv), token.count == 16 else { return nil }
        return [0xF4, 0x10] + token
    }

    /// Result byte of `xx F4 <result>`: 0x01 accepted, 0x02 rejected.
    static func authResult(_ bytes: [UInt8]) -> UInt8? {
        guard bytes.count >= 3, bytes[1] == 0xF4 else { return nil }
        return bytes[2]
    }

    /// A rejection `xx F4 02 <16 encrypted> <non-zero>` carries the user id the sensor expects.
    static func recoverUserId(fromReject bytes: [UInt8], challenge: [UInt8], authKey: [UInt8]) -> String? {
        guard bytes.count >= 20, bytes[1] == 0xF4, bytes[2] == 0x02, bytes[bytes.count - 1] != 0,
              let cbcIv = iv(challenge: challenge),
              let plaintext = cbcDecrypt(Array(bytes[3..<19]), key: authKey, iv: cbcIv) else { return nil }
        let text = String(decoding: plaintext, as: UTF8.self)
        // like the vendor SDK: keep ASCII letters, digits and whitespace
        let kept = text.unicodeScalars.filter { ($0.isASCII && CharacterSet.alphanumerics.contains($0)) || CharacterSet.whitespaces.contains($0) }
        let cleaned = String(kept)
            .trimmingCharacters(in: .whitespaces)
        return cleaned.isEmpty ? nil : cleaned
    }

    /// `1C F6 01 <lo> <hi>`: calibration table marker, 0xFFFF = no vendor code written.
    static func sensorInfoMarker(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 5, bytes[0] == 0x1C, bytes[1] == 0xF6, bytes[2] == 0x01 else { return nil }
        return Int(bytes[3]) | (Int(bytes[4]) << 8)
    }

    /// RACP indication `06 00 F1|01 <result>`: 0x01 done, 0x02 not supported, 0x06 no data, 0x0A failed.
    static func racpResult(_ bytes: [UInt8]) -> UInt8? {
        guard bytes.count >= 4, bytes[0] == 0x06, bytes[1] == 0x00, bytes[2] == 0xF1 || bytes[2] == 0x01 else { return nil }
        return bytes[3]
    }

    // MARK: - glucose decoding

    /// 12 bits of hundredths of mmol/L; the high nibble is a per-sensor constant of unknown use.
    static func glucoseMmol(low: UInt8, high: UInt8) -> Double {
        Double(Int(low) | (Int(high & 0x0F) << 8)) / 100
    }

    static let mmolToMgDl = 18.0182

    /// During warm-up the live/16-byte record value is XORed with two table bytes at
    /// `challenge[0] % 62`.
    static func undoWarmupXor(low: UInt8, high: UInt8, sequence: Int, warmupMinutes: Int, challenge: [UInt8], newFamily: Bool) -> (UInt8, UInt8)? {
        if sequence >= warmupMinutes { return (low, high) }
        guard challenge.count == 4 else { return nil }
        let table = newFamily ? warmupXorTableNew : warmupXorTableOld
        let offset = Int(challenge[0]) % (table.count - 2)
        return (low ^ table[offset], high ^ table[offset + 1])
    }

    struct Reading: Equatable {
        let sequence: Int
        let glucoseMmol: Double
        let launcherState: UInt8
        var glucoseMgDl: Double { glucoseMmol * mmolToMgDl }
    }

    /// 19-byte live frame: `<seq u16> 02 <16-byte AES-CBC/PKCS7>`; plaintext
    /// `0D <state> <value u16> <seq u16> 01 00×6`.
    static func parseLiveFrame(_ bytes: [UInt8], key: [UInt8], challenge: [UInt8], warmupMinutes: Int, newFamily: Bool) -> Reading? {
        guard bytes.count == 19, let cbcIv = iv(challenge: challenge),
              let plain = cbcDecrypt(Array(bytes[3..<19]), key: key, iv: cbcIv),
              plain.count == 13, plain[0] == 0x0D else { return nil }
        let sequence = Int(bytes[0]) | (Int(bytes[1]) << 8)
        guard Int(plain[4]) | (Int(plain[5]) << 8) == sequence,
              let value = undoWarmupXor(low: plain[2], high: plain[3], sequence: sequence, warmupMinutes: warmupMinutes, challenge: challenge, newFamily: newFamily) else { return nil }
        return Reading(sequence: sequence, glucoseMmol: glucoseMmol(low: value.0, high: value.1), launcherState: plain[1])
    }

    /// Single 16-byte encrypted history record (seq at [4..5], value at [2..3]).
    static func parseHistoryRecord(_ bytes: [UInt8], key: [UInt8], challenge: [UInt8], warmupMinutes: Int, newFamily: Bool) -> Reading? {
        guard bytes.count == 16, let cbcIv = iv(challenge: challenge),
              let plain = cbcDecrypt(bytes, key: key, iv: cbcIv), plain.count >= 13 else { return nil }
        let sequence = Int(plain[4]) | (Int(plain[5]) << 8)
        guard let value = undoWarmupXor(low: plain[2], high: plain[3], sequence: sequence, warmupMinutes: warmupMinutes, challenge: challenge, newFamily: newFamily) else { return nil }
        return Reading(sequence: sequence, glucoseMmol: glucoseMmol(low: value.0, high: value.1), launcherState: plain[1])
    }

    static func isSnBatch(_ bytes: [UInt8]) -> Bool {
        bytes.count >= 2 && bytes[0] == 0x53 && bytes[1] == 0x4E
    }

    /// Glucose SN batch `53 4E <len> 2A 52 02 <ciphertext> <trailer>`; plaintext
    /// `55 <baseSeq u16> <2-byte records> AA`. Records step by the reading interval and are not
    /// warm-up obfuscated. Original-history batches (subtype 01) return nil.
    static func parseGlucoseSnBatch(_ bytes: [UInt8], key: [UInt8], challenge: [UInt8], readingIntervalMinutes: Int) -> [Reading]? {
        guard bytes.count >= 8, isSnBatch(bytes), bytes[3] == 0x2A, bytes[4] == 0x52, bytes[5] == 0x02,
              let cbcIv = iv(challenge: challenge) else { return nil }
        let ciphertext = Array(bytes[6..<(bytes.count - 1)])
        guard let plain = cbcDecrypt(ciphertext, key: key, iv: cbcIv), plain.count >= 4,
              plain.first == 0x55, plain.last == 0xAA else { return nil }
        var sequence = Int(plain[1]) | (Int(plain[2]) << 8)
        var readings: [Reading] = []
        var offset = 3
        while offset + 2 <= plain.count - 1 {
            readings.append(Reading(sequence: sequence, glucoseMmol: glucoseMmol(low: plain[offset], high: plain[offset + 1]), launcherState: 0x80))
            sequence += readingIntervalMinutes
            offset += 2
        }
        return readings
    }

    // MARK: - CGM Status (0x2AA9)

    /// `[seq u16, launcher state, ...]`: minutes since session start and 0x00 idle / 0x01 warm-up /
    /// 0x40 ended / 0x80 running.
    static func status(_ bytes: [UInt8]) -> (sequence: Int, launcherState: UInt8)? {
        guard bytes.count >= 2 else { return nil }
        return (Int(bytes[0]) | (Int(bytes[1]) << 8), bytes.count > 2 ? bytes[2] : 0)
    }
}
