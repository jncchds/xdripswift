//
//  AccuChekSmartGuideProtocol.swift
//  xdrip
//
//  Accu-Chek SmartGuide: Bluetooth SIG Continuous Glucose Monitoring profile (service 0x181F).
//
//  Ported from Juggluco / JugglucoNG (GPL-3.0, Jaap Korthals Altes,
//  https://github.com/j-kaltes/Juggluco and https://github.com/ctqvva/JugglucoNG):
//  Common/src/dex/java/tk/glucodata/AccuGattCallback.java and
//  Common/src/main/cpp/accu/java.cpp, shortfloat.hpp.
//  The sensor computes glucose itself; no vendor algorithm is involved.
//

import Foundation

enum AccuChekSmartGuideProtocol {

    /// Bluetooth names are "AC-" followed by the sensor serial.
    static let namePrefix = "AC-"

    /// minutes between records (CGM Communication Interval response `03 05 …`)
    static let recordIntervalMinutes = 5

    /// first records are not requested: the sensor warms up for one hour
    static let warmupMinutes = 60

    static func serial(fromAdvertisedName name: String?) -> String? {
        guard let name, name.hasPrefix(namePrefix) else { return nil }
        let serial = String(name.dropFirst(namePrefix.count)).trimmingCharacters(in: .whitespaces)
        return serial.isEmpty ? nil : serial
    }

    // MARK: - E2E-CRC

    /// CGM profile E2E-CRC: CRC-16/MCRF4XX (poly 0x1021 reflected, init 0xFFFF), little endian.
    static func e2eCrc<S: Sequence>(_ bytes: S) -> UInt16 where S.Element == UInt8 {
        var crc: UInt16 = 0xFFFF
        for byte in bytes {
            crc ^= UInt16(byte)
            for _ in 0..<8 {
                crc = (crc & 0x0001) != 0 ? (crc >> 1) ^ 0x8408 : crc >> 1
            }
        }
        return crc
    }

    /// True if the last two bytes are the E2E-CRC of the bytes before them.
    static func hasValidE2eCrc(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 3 else { return false }
        let expected = e2eCrc(bytes[0..<(bytes.count - 2)])
        return expected == UInt16(bytes[bytes.count - 2]) | (UInt16(bytes[bytes.count - 1]) << 8)
    }

    static func withE2eCrc(_ bytes: [UInt8]) -> [UInt8] {
        let crc = e2eCrc(bytes)
        return bytes + [UInt8(crc & 0xFF), UInt8(crc >> 8)]
    }

    // MARK: - commands (same bytes as Juggluco)

    /// SOCP "Get CGM Communication Interval" (0x02) with E2E-CRC: `02 95 2C`
    static let getCommunicationInterval: [UInt8] = withE2eCrc([0x02])

    /// SOCP "Get Glucose Calibration Value" (0x05), record 0: `05 00 00 8E 00`
    static let getFirstCalibrationValue: [UInt8] = withE2eCrc([0x05, 0x00, 0x00])

    /// SOCP "Get Glucose Calibration Value" (0x05), last record (0xFFFF): `05 FF FF 36 F0`
    static let getLastCalibrationValue: [UInt8] = withE2eCrc([0x05, 0xFF, 0xFF])

    /// RACP "Report stored records" (0x01), operator "greater than or equal" (0x03),
    /// filter type time offset (0x01), offset in minutes. Juggluco sends it without CRC.
    static func reportRecords(fromTimeOffset minutes: Int) -> [UInt8] {
        let clamped = max(0, min(Int(UInt16.max), minutes))
        return [0x01, 0x03, 0x01, UInt8(clamped & 0xFF), UInt8(clamped >> 8)]
    }

    // MARK: - SFLOAT

    /// IEEE-11073 16-bit SFLOAT: 12-bit signed mantissa, 4-bit signed exponent.
    /// NaN, NRes and reserved map to .nan, +INF/-INF to ±.infinity.
    static func sfloat(_ raw: UInt16) -> Double {
        switch raw {
        case 0x07FE: return .infinity
        case 0x0802: return -.infinity
        case 0x07FF, 0x0800, 0x0801: return .nan
        default:
            var mantissa = Int(raw & 0x0FFF)
            if mantissa >= 0x0800 { mantissa -= 0x1000 }
            var exponent = Int(raw >> 12)
            if exponent >= 0x8 { exponent -= 0x10 }
            return Double(mantissa) * pow(10, Double(exponent))
        }
    }

    // MARK: - CGM Measurement (0x2AA7)

    struct Measurement: Equatable {
        let flags: UInt8
        /// mg/dL; ±infinity for HI/LO, nan for "no value"
        let glucoseMgDl: Double
        /// minutes since session start
        let timeOffsetMinutes: Int
        let annunciation: [UInt8]
        let trendMgDlPerMinute: Double?
        let quality: Double?
        /// nil when the record carries no E2E-CRC
        let crcValid: Bool?

        /// Juggluco only accepts records without Warning- and Status-octet (flags 0x43).
        var hasWarningOrStatus: Bool { flags & 0xA0 != 0 }

        var isUsableReading: Bool {
            glucoseMgDl.isFinite && !hasWarningOrStatus && crcValid != false
        }

        /// The sensor's "below measurement range" record (Juggluco: `0F E3 02 08 …`).
        var isBelowRange: Bool { glucoseMgDl == -.infinity && crcValid != false }
    }

    /// Splits one notification into records (each starts with its own size byte) and parses them.
    static func parseMeasurements(_ bytes: [UInt8]) -> [Measurement] {
        var result: [Measurement] = []
        var offset = 0
        while offset < bytes.count {
            let size = Int(bytes[offset])
            guard size >= 6, offset + size <= bytes.count else { break }
            if let measurement = parseMeasurement(Array(bytes[offset..<(offset + size)])) {
                result.append(measurement)
            }
            offset += size
        }
        return result
    }

    /// Parses a single record `[size, flags, glucose SFLOAT, timeOffset u16, annunciation 0–3,
    /// trend SFLOAT?, quality SFLOAT?, E2E-CRC?]`.
    static func parseMeasurement(_ record: [UInt8]) -> Measurement? {
        guard record.count >= 6, Int(record[0]) == record.count else { return nil }
        let flags = record[1]
        let glucose = sfloat(UInt16(record[2]) | (UInt16(record[3]) << 8))
        let timeOffset = Int(record[4]) | (Int(record[5]) << 8)
        var index = 6

        var annunciation: [UInt8] = []
        for bit in [UInt8(0x20), 0x40, 0x80] where flags & bit != 0 {
            guard index < record.count else { return nil }
            annunciation.append(record[index])
            index += 1
        }

        var trend: Double?
        if flags & 0x01 != 0 {
            guard index + 2 <= record.count else { return nil }
            trend = sfloat(UInt16(record[index]) | (UInt16(record[index + 1]) << 8))
            index += 2
        }
        var quality: Double?
        if flags & 0x02 != 0 {
            guard index + 2 <= record.count else { return nil }
            quality = sfloat(UInt16(record[index]) | (UInt16(record[index + 1]) << 8))
            index += 2
        }

        var crcValid: Bool?
        if record.count - index == 2 {
            crcValid = hasValidE2eCrc(record)
        } else if record.count != index {
            return nil
        }

        return Measurement(flags: flags, glucoseMgDl: glucose, timeOffsetMinutes: timeOffset, annunciation: annunciation, trendMgDlPerMinute: trend, quality: quality, crcValid: crcValid)
    }

    // MARK: - CGM Status (0x2AA9)

    /// `[timeOffset u16, status 3 octets, E2E-CRC]`: minutes since session start.
    static func statusTimeOffsetMinutes(_ bytes: [UInt8]) -> Int? {
        guard bytes.count >= 2 else { return nil }
        if bytes.count >= 7, !hasValidE2eCrc(Array(bytes[0..<7])) { return nil }
        return Int(bytes[0]) | (Int(bytes[1]) << 8)
    }

    /// Juggluco treats every 4-byte SOCP (0x2AAC) indication as the answer to "Get CGM
    /// Communication Interval" (observed: `03 05 7D 8D`, interval 5 minutes).
    static func isCommunicationIntervalResponse(_ bytes: [UInt8]) -> Bool {
        bytes.count == 4
    }
}
