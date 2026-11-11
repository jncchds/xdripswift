//
//  AiDexProtocol.swift
//  xdrip
//
//  AiDex X / LinX (MicroTech Medical GX series) Bluetooth protocol: identity, key exchange,
//  F002 command construction and frame parsing.
//
//  Ported from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG, a fork of Juggluco by
//  Jaap Korthals Altes), files under Common/src/main/java/tk/glucodata/drivers/aidex/:
//  AiDexSerialIdentity.kt, native/protocol/AiDexOpcodes.kt, AiDexKeyExchange.kt,
//  AiDexCommandBuilder.kt, AiDexParser.kt and native/data/DataClasses.kt.
//

import Foundation

// MARK: - constants

enum AiDexOpcodes {
    static let getStartupDeviceInfo: UInt8 = 0x10
    static let getBroadcastData: UInt8 = 0x11
    static let setNewSensor: UInt8 = 0x20
    static let getStartTime: UInt8 = 0x21
    static let getHistoryRange: UInt8 = 0x22
    static let getHistoriesRaw: UInt8 = 0x23
    static let getHistories: UInt8 = 0x24
    static let setCalibration: UInt8 = 0x25
    static let setAutoUpdateStatus: UInt8 = 0x34
    static let deleteBond: UInt8 = 0xF2

    /// Opcodes whose responses always carry a CRC-16 trailer. A CRC mismatch rejects them.
    static let dataOpcodes: Set<UInt8> = [0x21, 0x22, 0x23, 0x24, 0x26, 0x27]

    static let dataFrameLength = 17
    static let statusFrameLength = 5

    static let glucoseMask: UInt16 = 0x03FF
    static let sentinelGlucose = 1023
    static let minValidGlucose = 20
    static let maxValidGlucose = 500

    /// Live frame opcodes whose glucose value is already mg/dL.
    static let directOpcodes: Set<UInt8> = [0xA1, 0xA4, 0x5B, 0xD7]
    /// Live frame opcodes whose glucose value is in 0.5 mg/dL units.
    static let halfScaleOpcodes: Set<UInt8> = [0xD2]

    static func scalingFactor(opcode: UInt8) -> Double? {
        if directOpcodes.contains(opcode) { return 1.0 }
        if halfScaleOpcodes.contains(opcode) { return 0.5 }
        return nil
    }

    /// Advertised-name prefixes JugglucoNG accepts as AiDex sensors.
    static let knownNamePrefixes = ["AiDex", "AiDEX", "AIDEX", "Linx", "LINX", "CGM", "Smart-", "IndiaX-", "VitaTok-"]

    static func isAiDexDeviceName(_ name: String?) -> Bool {
        guard let name else { return false }
        return knownNamePrefixes.contains { name.hasPrefix($0) }
    }
}

// MARK: - identity

/// Extracts the sensor serial from the advertised Bluetooth name.
///
/// The prefix in front of the serial ("AiDEX X-", "LinX", "Smart-", "IndiaX-", …) is a marketing
/// label that changes between hardware batches. Only the serial feeds the key derivation.
enum AiDexSerialIdentity {

    private static let minLength = 8
    private static let maxLength = 14

    private static let generationPrefixed = try! NSRegularExpression(
        pattern: "(?:^|\\s)(?:AIDEX\\s+)?[A-Z]\\s*-\\s*([A-Z0-9]{8,14})(?=$|\\s)",
        options: [.caseInsensitive]
    )

    private static let familyPrefixed = try! NSRegularExpression(
        pattern: "(?:^|\\s)(?:AIDEX|LINX|LUMI|VISTA|SMART|INDIA|VITATOK)\\s*(?:[A-Z]\\s*-|[-_])?\\s*([A-Z0-9]{8,14})(?=$|\\s)",
        options: [.caseInsensitive]
    )

    /// Bare upper-case serial (for example "2222267V4E") or nil if the name carries none.
    static func serial(fromAdvertisedName rawName: String) -> String? {
        let trimmed = rawName.trimmingCharacters(in: .whitespaces)
        for regex in [generationPrefixed, familyPrefixed] {
            let range = NSRange(trimmed.startIndex..., in: trimmed)
            if let match = regex.firstMatch(in: trimmed, options: [], range: range),
               let serialRange = Range(match.range(at: 1), in: trimmed) {
                return String(trimmed[serialRange]).uppercased()
            }
        }
        // Narrow compatibility with older bare 11-character names.
        let cleaned = trimmed.replacingOccurrences(of: " ", with: "")
        if cleaned.count == 11, cleaned.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
            return cleaned.uppercased()
        }
        return nil
    }

    /// Serial used for key derivation: the parsed serial, or the input itself if it already is one.
    static func bareSerial(_ serialOrName: String) -> String {
        if let serial = serial(fromAdvertisedName: serialOrName) { return serial }
        let trimmed = serialOrName.trimmingCharacters(in: .whitespaces)
        if (minLength...maxLength).contains(trimmed.count),
           trimmed.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) {
            return trimmed.uppercased()
        }
        return trimmed
    }
}

// MARK: - key exchange

/// Vendor key exchange state for one connection.
///
/// 1. write the serial-derived challenge to F001 (needs an encrypted link: iOS pairs here)
/// 2. F001 notifies the 16-byte PAIR key (stable until the sensor deletes its bond)
/// 3. read 17 bytes of BOND data from F002
/// 4. AES-CFB decrypt BOND with PAIR key + serial IV, check CRC-8 -> 16-byte session key
/// 5. F002 commands, F002 responses and F003 frames use session key + serial IV
struct AiDexKeyExchange {

    let bareSerial: String
    let challenge: [UInt8]
    let iv: [UInt8]

    private(set) var pairKey: [UInt8]?
    private(set) var sessionKey: [UInt8]?

    var isComplete: Bool { sessionKey != nil }

    init(serial: String) {
        bareSerial = AiDexSerialIdentity.bareSerial(serial)
        challenge = AiDexSerialCrypto.deriveSecret(bareSerial: bareSerial)
        iv = AiDexSerialCrypto.deriveIv(bareSerial: bareSerial)
    }

    mutating func setPairKey(_ key: [UInt8]) {
        pairKey = key
    }

    /// Returns true when BOND decrypts and its CRC-8 matches.
    mutating func decryptBond(_ bondData: [UInt8]) -> Bool {
        guard let pairKey, let key = AiDexAesCfb128.decryptBondData(bondData, pairKey: pairKey, iv: iv) else { return false }
        sessionKey = key
        return true
    }

    /// Encrypted post-BOND configuration written to F001: plaintext `10 C1 F3`.
    func postBondConfig() -> [UInt8]? {
        encrypt([0x10, 0xC1, 0xF3])
    }

    func encrypt(_ plaintext: [UInt8]) -> [UInt8]? {
        guard let sessionKey else { return nil }
        return AiDexAesCfb128.encrypt(plaintext, key: sessionKey, iv: iv)
    }

    func decrypt(_ ciphertext: [UInt8]) -> [UInt8]? {
        guard let sessionKey else { return nil }
        return AiDexAesCfb128.decrypt(ciphertext, key: sessionKey, iv: iv)
    }

    mutating func reset() {
        pairKey = nil
        sessionKey = nil
    }
}

// MARK: - commands

/// Builds encrypted F002 commands: `[opcode, params..., crcLo, crcHi]`, then AES-CFB.
enum AiDexCommandBuilder {

    static func plain(_ opcode: UInt8, _ params: [UInt8] = []) -> [UInt8] {
        AiDexCrc16CcittFalse.makeCommand(opcode: opcode, params: params)
    }

    static func encrypted(_ opcode: UInt8, _ params: [UInt8] = [], keyExchange: AiDexKeyExchange) -> [UInt8]? {
        keyExchange.encrypt(plain(opcode, params))
    }

    static func u16(_ value: Int) -> [UInt8] {
        [UInt8(truncatingIfNeeded: value), UInt8(truncatingIfNeeded: value >> 8)]
    }

    /// SET_NEW_SENSOR payload: `[yearLo, yearHi, month, day, hour, minute, second, tzQuarters, dstQuarters]`
    /// in the phone's local time. tzQuarters is the standard UTC offset in 15-minute units (signed),
    /// dstQuarters the daylight-saving offset in 15-minute units.
    static func newSensorParams(date: Date, timeZone: TimeZone) -> [UInt8] {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = timeZone
        let c = calendar.dateComponents([.year, .month, .day, .hour, .minute, .second], from: date)
        let quarter = 15 * 60
        let dstSeconds = Int(timeZone.daylightSavingTimeOffset(for: date))
        let standardSeconds = timeZone.secondsFromGMT(for: date) - dstSeconds
        let tzQuarters = Int8(truncatingIfNeeded: standardSeconds / quarter)
        let dstQuarters = UInt8(truncatingIfNeeded: dstSeconds / quarter)
        return u16(c.year ?? 0) + [
            UInt8(truncatingIfNeeded: c.month ?? 0),
            UInt8(truncatingIfNeeded: c.day ?? 0),
            UInt8(truncatingIfNeeded: c.hour ?? 0),
            UInt8(truncatingIfNeeded: c.minute ?? 0),
            UInt8(truncatingIfNeeded: c.second ?? 0),
            UInt8(bitPattern: tzQuarters),
            dstQuarters,
        ]
    }
}

// MARK: - parsed values

struct AiDexGlucoseFrame: Equatable {
    let opcode: UInt8
    /// minutes since sensor start
    let timeOffsetMinutes: Int
    /// factory-calibrated glucose, mg/dL, after opcode scaling
    let glucoseMgDl: Double
    let rawGlucosePacked: UInt16
    /// raw current channel (u16 / 100)
    let i1: Double
    /// skin temperature in °C according to JugglucoNG (u16 / 100)
    let i2: Double
    let crc16: UInt16
    /// not the 1023 sentinel and within 20...500
    let isValid: Bool
}

struct AiDexHistoryEntry: Equatable {
    let timeOffsetMinutes: Int
    let glucoseMgDl: Int
    let statusBit: Bool
    let isSentinel: Bool
}

struct AiDexHistoryRange: Equatable {
    /// first offset available for 0x24 (raw ADC) pages
    let briefStart: Int
    /// first offset available for 0x23 (calibrated) pages
    let rawStart: Int
    /// newest offset stored by the sensor
    let newest: Int
}

struct AiDexStartupDeviceInfo: Equatable {
    let firmwareVersion: String
    let hardwareVersion: String
    let wearDays: Int
    let modelName: String
}

struct AiDexLocalStartTime: Equatable {
    let year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int
    /// signed UTC offset in 15-minute units
    let tzQuarters: Int
    /// 4 means one hour of daylight saving time
    let dstQuarters: Int

    var isAllZeros: Bool {
        year == 0 && month == 0 && day == 0 && hour == 0 && minute == 0 && second == 0
    }

    /// Converts the sensor-local start to an absolute date (JugglucoNG: applyParsedSessionStartTime).
    var date: Date? {
        guard !isAllZeros else { return nil }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        guard let utcWallClock = calendar.date(from: DateComponents(year: year, month: month, day: day, hour: hour, minute: minute, second: second)) else { return nil }
        let offsetSeconds = tzQuarters * 15 * 60 + (dstQuarters == 4 ? 3600 : 0)
        return utcWallClock.addingTimeInterval(TimeInterval(-offsetSeconds))
    }
}

// MARK: - parser

enum AiDexParser {

    static func u16LE(_ bytes: [UInt8], _ offset: Int) -> Int {
        Int(bytes[offset]) | (Int(bytes[offset + 1]) << 8)
    }

    static func s16LE(_ bytes: [UInt8], _ offset: Int) -> Int {
        Int(Int16(bitPattern: UInt16(u16LE(bytes, offset))))
    }

    /// Parses a decrypted 17-byte F003 frame.
    ///
    /// `[0] opcode, [1..3] unknown, [4..5] offset minutes, [6..7] glucose (10 bits),
    ///  [8..9] i1, [10..11] i2, [12..14] unknown, [15..16] CRC-16 of [0..14]`
    static func parseDataFrame(_ bytes: [UInt8]) -> AiDexGlucoseFrame? {
        guard bytes.count == AiDexOpcodes.dataFrameLength else { return nil }
        let opcode = bytes[0]
        let packed = UInt16(u16LE(bytes, 6))
        let raw = Int(packed & AiDexOpcodes.glucoseMask)
        let scaling = AiDexOpcodes.scalingFactor(opcode: opcode) ?? 1.0
        let isValid = raw != AiDexOpcodes.sentinelGlucose
            && raw >= AiDexOpcodes.minValidGlucose
            && raw <= AiDexOpcodes.maxValidGlucose
        return AiDexGlucoseFrame(
            opcode: opcode,
            timeOffsetMinutes: u16LE(bytes, 4),
            glucoseMgDl: Double(raw) * scaling,
            rawGlucosePacked: packed,
            i1: Double(u16LE(bytes, 8)) / 100,
            i2: Double(u16LE(bytes, 10)) / 100,
            crc16: UInt16(u16LE(bytes, 15)),
            isValid: isValid
        )
    }

    /// True if bytes 15...16 are the CRC-16 of bytes 0...14.
    static func dataFrameCrcIsValid(_ bytes: [UInt8]) -> Bool {
        guard bytes.count == AiDexOpcodes.dataFrameLength else { return false }
        return AiDexCrc16CcittFalse.checksum(bytes[0..<15]) == UInt16(u16LE(bytes, 15))
    }

    /// Battery voltage in mV from a decrypted 5-byte status frame (bytes 1...2), when plausible.
    static func batteryMillivolts(fromStatusFrame bytes: [UInt8]) -> Int? {
        guard bytes.count >= 3 else { return nil }
        let candidate = u16LE(bytes, 1)
        return (500...3500).contains(candidate) ? candidate : nil
    }

    /// Strips opcode + status and, when the response has a valid CRC trailer, the trailer too.
    static func responsePayload(_ response: [UInt8]) -> [UInt8] {
        guard response.count > 2 else { return [] }
        let end = (response.count >= 4 && AiDexCrc16CcittFalse.isValidTrailer(response)) ? response.count - 2 : response.count
        guard end > 2 else { return [] }
        return Array(response[2..<end])
    }

    /// 0x22 response: `[0x22, status, briefStart u16, rawStart u16, newest u16, crc]`
    static func parseHistoryRange(_ response: [UInt8]) -> AiDexHistoryRange? {
        guard response.count >= 8 else { return nil }
        return AiDexHistoryRange(briefStart: u16LE(response, 2), rawStart: u16LE(response, 4), newest: u16LE(response, 6))
    }

    /// 0x23 payload (after opcode, status and CRC are removed): `startOffset u16, N × 2-byte rows`.
    /// Row: glucose = b0 | (b1 & 0x03) << 8, status bit = b1 & 0x04.
    static func parseCalibratedHistory(_ payload: [UInt8]) -> [AiDexHistoryEntry] {
        guard payload.count >= 4 else { return [] }
        let start = u16LE(payload, 0)
        let rows = (payload.count - 2) / 2
        return (0..<rows).map { i in
            let b0 = Int(payload[2 + i * 2])
            let b1 = Int(payload[3 + i * 2])
            let glucose = b0 | ((b1 & 0x03) << 8)
            return AiDexHistoryEntry(
                timeOffsetMinutes: start + i,
                glucoseMgDl: glucose,
                statusBit: (b1 & 0x04) != 0,
                isSentinel: glucose == AiDexOpcodes.sentinelGlucose
            )
        }
    }

    /// 0x10 response payload: `[status u16 (or model code), fwMaj, fwMin, hwMaj, hwMin, wearDays, modelCode, modelAscii...]`
    static func parseStartupDeviceInfo(response: [UInt8]) -> AiDexStartupDeviceInfo? {
        let end = (response.count >= 4 && AiDexCrc16CcittFalse.isValidTrailer(response)) ? response.count - 2 : response.count
        guard end > 1 else { return nil }
        if let info = parseDeviceInfoPayload(Array(response[1..<end]), requireZeroStatus: true) { return info }
        guard end > 2 else { return nil }
        let body = Array(response[2..<end])
        if let info = parseDeviceInfoPayload(body, requireZeroStatus: true) { return info }
        // Live sensors answer [0x10, 0x01 (ACK), ...] where the next u16 is a model code, not a status.
        guard response[1] == 0x01, let info = parseDeviceInfoPayload(body, requireZeroStatus: false) else { return nil }
        return info.modelName.unicodeScalars.allSatisfy({ $0.value >= 0x20 && $0.value <= 0x7E }) ? info : nil
    }

    private static func parseDeviceInfoPayload(_ payload: [UInt8], requireZeroStatus: Bool) -> AiDexStartupDeviceInfo? {
        guard payload.count >= 16 else { return nil }
        if requireZeroStatus && u16LE(payload, 0) != 0 { return nil }
        var modelBytes = Array(payload[8...])
        if let nul = modelBytes.firstIndex(of: 0) { modelBytes = Array(modelBytes[..<nul]) }
        let model = (String(bytes: modelBytes, encoding: .ascii) ?? "").trimmingCharacters(in: .whitespaces)
        guard !model.isEmpty else { return nil }
        return AiDexStartupDeviceInfo(
            firmwareVersion: "\(payload[2]).\(payload[3])",
            hardwareVersion: "\(payload[4]).\(payload[5])",
            wearDays: Int(payload[6]),
            modelName: model
        )
    }

    /// Start-time payload shared by CGM Session Start Time (0x2AAA) and the 0x21 response payload:
    /// `year u16, month, day, hour, minute, second, tz (s8, quarters), dst (u8, quarters)`.
    /// Returns nil unless all zeros (= not activated) or a plausible timestamp.
    static func parseLocalStartTime(_ payload: [UInt8]) -> AiDexLocalStartTime? {
        guard payload.count >= 7 else { return nil }
        let parsed = AiDexLocalStartTime(
            year: u16LE(payload, 0),
            month: Int(payload[2]),
            day: Int(payload[3]),
            hour: Int(payload[4]),
            minute: Int(payload[5]),
            second: Int(payload[6]),
            tzQuarters: payload.count >= 8 ? Int(Int8(bitPattern: payload[7])) : 0,
            dstQuarters: payload.count >= 9 ? Int(payload[8]) : 0
        )
        if parsed.isAllZeros { return parsed }
        let plausible = (2020...2040).contains(parsed.year) && (1...12).contains(parsed.month)
            && (1...31).contains(parsed.day) && (0...23).contains(parsed.hour)
            && (0...59).contains(parsed.minute) && (0...59).contains(parsed.second)
        return plausible ? parsed : nil
    }
}
