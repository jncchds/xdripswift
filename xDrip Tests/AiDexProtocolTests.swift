//
//  AiDexProtocolTests.swift
//  xDrip Tests
//
//  Test vectors come from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG):
//  SerialCrypto.kt, Crc16CcittFalse.kt and AiDexNativeTests.kt (HCI-trace and live-log values).
//  The BOND, command and frame ciphertexts were generated independently with Python's
//  `cryptography` AES-CFB128 to cross-check the CommonCrypto-based implementation.
//

import XCTest
@testable import xdrip

final class AiDexProtocolTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        [UInt8](Data(hexadecimalString: hex.replacingOccurrences(of: " ", with: ""))!)
    }

    private func hex(_ bytes: [UInt8]) -> String {
        Data(bytes).hexEncodedString()
    }

    // MARK: - CRC-8/MAXIM

    func testCrc8MaximCheckValue() {
        XCTAssertEqual(AiDexCrc8Maxim.checksum([UInt8]()), 0x00)
        XCTAssertEqual(AiDexCrc8Maxim.checksum([0x00]), 0x00)
        XCTAssertEqual(AiDexCrc8Maxim.checksum(Array("123456789".utf8)), 0xA1)
    }

    // MARK: - CRC-16/CCITT-FALSE

    func testCrc16MatchesHciTraceCommands() {
        XCTAssertEqual(AiDexCrc16CcittFalse.checksum([0x10]), 0xF3C1)
        XCTAssertEqual(AiDexCrc16CcittFalse.checksum([0x11]), 0xE3E0)
        XCTAssertEqual(AiDexCrc16CcittFalse.checksum([0x21]), 0xD5B3)
        XCTAssertEqual(AiDexCrc16CcittFalse.checksum([0xF2]), 0x2EAD)
    }

    func testMakeCommand() {
        XCTAssertEqual(AiDexCrc16CcittFalse.makeCommand(opcode: 0x11), [0x11, 0xE0, 0xE3])
        XCTAssertEqual(AiDexCrc16CcittFalse.makeCommand(opcode: 0x10), [0x10, 0xC1, 0xF3])
        XCTAssertEqual(AiDexCrc16CcittFalse.makeCommand(opcode: 0xF2), [0xF2, 0xAD, 0x2E])
        XCTAssertEqual(AiDexCrc16CcittFalse.makeCommand(opcode: 0x23, params: AiDexCommandBuilder.u16(14400)), [0x23, 0x40, 0x38, 0x9D, 0xA9])
    }

    func testLiveLogHistoryCommandsHaveValidTrailers() {
        let commands = [
            "23 40 38 9D A9", "23 B7 38 CB 23", "23 2E 39 99 91", "23 A5 39 FB 56", "23 1C 3A 0D C2",
            "23 93 3A AB C9", "23 0A 3B F9 7B", "23 81 3B 9B BC", "23 F8 3B 5A 0E",
        ]
        for command in commands {
            XCTAssertTrue(AiDexCrc16CcittFalse.isValidTrailer(bytes(command)), command)
        }
        XCTAssertFalse(AiDexCrc16CcittFalse.isValidTrailer(bytes("23 40 38 9D AA")))
        XCTAssertFalse(AiDexCrc16CcittFalse.isValidTrailer([0x11]))
    }

    // MARK: - serial derivation (SerialCrypto.kt, sensor 2222267V4E)

    func testSerialToBytes() {
        XCTAssertEqual(AiDexSerialCrypto.serialToBytes("2222267V4E"), [2, 2, 2, 2, 2, 6, 7, 31, 4, 14])
        XCTAssertEqual(AiDexSerialCrypto.numericValue(of: "a"), 10)
        XCTAssertEqual(AiDexSerialCrypto.numericValue(of: "Z"), 35)
        XCTAssertEqual(AiDexSerialCrypto.numericValue(of: "-"), 0)
    }

    func testDeriveSecretAndIv() {
        XCTAssertEqual(hex(AiDexSerialCrypto.deriveSecret(bareSerial: "2222267V4E")), "4b76169576da80e4eeacf886230873d2")
        XCTAssertEqual(hex(AiDexSerialCrypto.deriveIv(bareSerial: "2222267V4E")), "14cb6a3a39b96c448ebc39185f70f8aa")
    }

    func testFGenerationSerialDerivesCapturedChallenge() {
        let serial = AiDexSerialIdentity.bareSerial("AiDEX F-22222FZXKT")
        XCTAssertEqual(hex(AiDexSerialCrypto.deriveSecret(bareSerial: serial)), "f0740dc2fa51f24a884f61fc4c14885b")
    }

    // MARK: - identity from the advertised name

    func testSerialFromAdvertisedName() {
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("AiDEX X-2222267V4E"), "2222267V4E")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("X-2222267V4E"), "2222267V4E")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("AiDEX x-2222293NWA"), "2222293NWA")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("AiDEX F-22222FZXKT"), "22222FZXKT")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("F-22222FZXKT"), "22222FZXKT")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("AiDEX G-22222GZXKT"), "22222GZXKT")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("Q-22222QZXKT"), "22222QZXKT")
        XCTAssertEqual(AiDexSerialIdentity.bareSerial("2222267V4E"), "2222267V4E")
        XCTAssertEqual(AiDexSerialIdentity.serial(fromAdvertisedName: "Smart-22222BZTJ3"), "22222BZTJ3")
        XCTAssertEqual(AiDexSerialIdentity.serial(fromAdvertisedName: "IndiaX-22222E7T6K"), "22222E7T6K")
        XCTAssertEqual(AiDexSerialIdentity.serial(fromAdvertisedName: "VitaTok-22222DA48D"), "22222DA48D")
        XCTAssertEqual(AiDexSerialIdentity.serial(fromAdvertisedName: "Linx X-2222293NWA"), "2222293NWA")
        XCTAssertNil(AiDexSerialIdentity.serial(fromAdvertisedName: "Dexcom G7"))
        XCTAssertNil(AiDexSerialIdentity.serial(fromAdvertisedName: "DXCM12"))
    }

    func testKnownNamePrefixes() {
        XCTAssertTrue(AiDexOpcodes.isAiDexDeviceName("AiDEX X-2222267V4E"))
        XCTAssertTrue(AiDexOpcodes.isAiDexDeviceName("Smart-22222BZTJ3"))
        XCTAssertTrue(AiDexOpcodes.isAiDexDeviceName("IndiaX-22222E7T6K"))
        XCTAssertTrue(AiDexOpcodes.isAiDexDeviceName("VitaTok-22222DA48D"))
        XCTAssertFalse(AiDexOpcodes.isAiDexDeviceName("Dexcom G7"))
        XCTAssertFalse(AiDexOpcodes.isAiDexDeviceName("Smartwatch-22222BZTJ3"))
        XCTAssertFalse(AiDexOpcodes.isAiDexDeviceName(nil))
    }

    func testKeyExchangeUsesBareSerialForRebrandedNames() {
        let exchange = AiDexKeyExchange(serial: "Smart-22222BZTJ3")
        XCTAssertEqual(exchange.bareSerial, "22222BZTJ3")
        XCTAssertEqual(exchange.challenge, AiDexSerialCrypto.deriveSecret(bareSerial: "22222BZTJ3"))
        XCTAssertEqual(exchange.iv, AiDexSerialCrypto.deriveIv(bareSerial: "22222BZTJ3"))
    }

    // MARK: - AES-128-CFB

    /// NIST SP 800-38A F.3.13, CFB128-AES128 encrypt, block 1
    func testNistCfb128Vector() {
        let key = bytes("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = bytes("000102030405060708090a0b0c0d0e0f")
        let plain = bytes("6bc1bee22e409f96e93d7e117393172a")
        let cipher = bytes("3b3fd92eb72dad20333449f8e83cfb4a")
        XCTAssertEqual(AiDexAesCfb128.encrypt(plain, key: key, iv: iv), cipher)
        XCTAssertEqual(AiDexAesCfb128.decrypt(cipher, key: key, iv: iv), plain)
    }

    func testCfbRoundTripWithPartialBlock() {
        let key = bytes("2b7e151628aed2a6abf7158809cf4f3c")
        let iv = bytes("000102030405060708090a0b0c0d0e0f")
        let plain = (0..<37).map { UInt8($0) }
        let encrypted = AiDexAesCfb128.encrypt(plain, key: key, iv: iv)
        XCTAssertEqual(encrypted?.count, 37)
        XCTAssertEqual(AiDexAesCfb128.decrypt(encrypted ?? [], key: key, iv: iv), plain)
        XCTAssertNil(AiDexAesCfb128.encrypt([], key: key, iv: iv))
        XCTAssertNil(AiDexAesCfb128.encrypt(plain, key: [0x00], iv: iv))
    }

    func testBondDecryptionYieldsSessionKey() {
        let iv = AiDexSerialCrypto.deriveIv(bareSerial: "2222267V4E")
        let pairKey = (0..<16).map { UInt8($0) }
        let sessionKey = (0xA0...0xAF).map { UInt8($0) }
        let bond = bytes("7cb69015161bb3b2de2a38d1e43903963b")

        XCTAssertEqual(AiDexCrc8Maxim.checksum(sessionKey), 0x36)
        XCTAssertEqual(AiDexAesCfb128.decryptBondData(bond, pairKey: pairKey, iv: iv), sessionKey)

        var corrupted = bond
        corrupted[16] ^= 0x01
        XCTAssertNil(AiDexAesCfb128.decryptBondData(corrupted, pairKey: pairKey, iv: iv))
        XCTAssertNil(AiDexAesCfb128.decryptBondData(Array(bond.prefix(16)), pairKey: pairKey, iv: iv))
    }

    func testKeyExchangeEncryptsCommandsAndDecryptsFrames() {
        var exchange = AiDexKeyExchange(serial: "AiDEX X-2222267V4E")
        XCTAssertFalse(exchange.isComplete)
        XCTAssertNil(exchange.encrypt([0x22]))

        exchange.setPairKey((0..<16).map { UInt8($0) })
        XCTAssertTrue(exchange.decryptBond(bytes("7cb69015161bb3b2de2a38d1e43903963b")))
        XCTAssertTrue(exchange.isComplete)

        XCTAssertEqual(AiDexCommandBuilder.encrypted(AiDexOpcodes.getHistoryRange, keyExchange: exchange), bytes("e9bb62"))

        let frame = exchange.decrypt(bytes("ca6b8533fb1cf85cd44c01aac37cd7057c"))
        XCTAssertEqual(frame, bytes("010002002B003F844F03860B4302007DCE"))
    }

    // MARK: - frames

    func testParseDataFrameFromLog() throws {
        // JugglucoNG rawr.txt example
        let frame = bytes("01 00 02 00 2B 00 3F 84 4F 03 86 0B 43 02 00 7D CE")
        XCTAssertTrue(AiDexParser.dataFrameCrcIsValid(frame))
        let parsed = try XCTUnwrap(AiDexParser.parseDataFrame(frame))
        XCTAssertEqual(parsed.opcode, 0x01)
        XCTAssertEqual(parsed.timeOffsetMinutes, 43)
        XCTAssertEqual(parsed.rawGlucosePacked, 0x843F)
        XCTAssertEqual(parsed.glucoseMgDl, 63, accuracy: 0.01)
        XCTAssertEqual(parsed.i1, 8.47, accuracy: 0.001)
        XCTAssertEqual(parsed.i2, 29.50, accuracy: 0.001)
        XCTAssertEqual(parsed.crc16, 0xCE7D)
        XCTAssertTrue(parsed.isValid)

        var corrupted = frame
        corrupted[6] ^= 0x01
        XCTAssertFalse(AiDexParser.dataFrameCrcIsValid(corrupted))
    }

    func testParseDataFrameEdgeCases() throws {
        XCTAssertNil(AiDexParser.parseDataFrame([0x01, 0x02, 0x03]))
        XCTAssertNil(AiDexParser.parseDataFrame([UInt8](repeating: 0, count: 16)))
        XCTAssertNil(AiDexParser.parseDataFrame([UInt8](repeating: 0, count: 18)))

        var sentinel = [UInt8](repeating: 0, count: 17)
        sentinel[6] = 0xFF
        sentinel[7] = 0x03
        XCTAssertFalse(try XCTUnwrap(AiDexParser.parseDataFrame(sentinel)).isValid)

        var halfScale = [UInt8](repeating: 0, count: 17)
        halfScale[0] = 0xD2
        halfScale[6] = 100
        let half = try XCTUnwrap(AiDexParser.parseDataFrame(halfScale))
        XCTAssertEqual(half.glucoseMgDl, 50, accuracy: 0.01)
        XCTAssertTrue(half.isValid)

        var offset = [UInt8](repeating: 0, count: 17)
        offset[0] = 0xA1
        offset[1] = 0x84
        offset[2] = 0x03
        offset[3] = 0xFF
        offset[4] = 0xED
        offset[5] = 0x08
        offset[6] = 80
        let parsed = try XCTUnwrap(AiDexParser.parseDataFrame(offset))
        XCTAssertEqual(parsed.timeOffsetMinutes, 2285)
        XCTAssertEqual(parsed.glucoseMgDl, 80, accuracy: 0.01)
    }

    func testBatteryFromStatusFrame() {
        XCTAssertEqual(AiDexParser.batteryMillivolts(fromStatusFrame: [0x00, 0x08, 0x06, 0x00, 0x00]), 1544)
        XCTAssertNil(AiDexParser.batteryMillivolts(fromStatusFrame: [0x00, 0x00, 0x00, 0x00, 0x00]))
    }

    // MARK: - F002 responses

    func testCalibratedHistoryFromLiveLog() {
        let response = bytes("230040384280424041803f803e803d403e80729b")
        XCTAssertTrue(AiDexCrc16CcittFalse.isValidTrailer(response))
        let entries = AiDexParser.parseCalibratedHistory(AiDexParser.responsePayload(response))
        XCTAssertEqual(entries.map(\.timeOffsetMinutes), Array(14400...14406))
        XCTAssertEqual(entries.map(\.glucoseMgDl), [66, 66, 65, 63, 62, 61, 62])
        XCTAssertFalse(entries.contains { $0.isSentinel })
    }

    func testCalibratedHistoryStatusAndSentinel() {
        let entries = AiDexParser.parseCalibratedHistory([0x00, 0x00, 0x42, 0x84, 0xFF, 0x03])
        XCTAssertEqual(entries.count, 2)
        XCTAssertTrue(entries[0].statusBit)
        XCTAssertEqual(entries[0].glucoseMgDl, 66)
        XCTAssertTrue(entries[1].isSentinel)
        XCTAssertTrue(AiDexParser.parseCalibratedHistory([0x00, 0x00, 0x00]).isEmpty)
    }

    func testHistoryRange() {
        let range = AiDexParser.parseHistoryRange([0x22, 0x00, 0x01, 0x00, 0x02, 0x00, 0x40, 0x38])
        XCTAssertEqual(range, AiDexHistoryRange(briefStart: 1, rawStart: 2, newest: 14400))
        XCTAssertNil(AiDexParser.parseHistoryRange([0x22, 0x00]))
    }

    func testStartupDeviceInfoWithAckAndModelCode() throws {
        // [0x10, 0x01 ACK, model code 0x8000, fw 1.7, hw 2.1, 15 days, code, "GX-01S"]
        var response: [UInt8] = [0x10, 0x01, 0x00, 0x80, 0x01, 0x07, 0x02, 0x01, 0x0F, 0x00]
        response += Array("GX-01S".utf8) + [0x00, 0x00]
        let crc = AiDexCrc16CcittFalse.checksum(response)
        response += [UInt8(crc & 0xFF), UInt8(crc >> 8)]

        let info = try XCTUnwrap(AiDexParser.parseStartupDeviceInfo(response: response))
        XCTAssertEqual(info.firmwareVersion, "1.7")
        XCTAssertEqual(info.hardwareVersion, "2.1")
        XCTAssertEqual(info.wearDays, 15)
        XCTAssertEqual(info.modelName, "GX-01S")
    }

    func testLocalStartTime() throws {
        // 2025-03-01 10:00:00, UTC+1 (4 quarters), no DST
        let payload: [UInt8] = [0xE9, 0x07, 3, 1, 10, 0, 0, 4, 0]
        let parsed = try XCTUnwrap(AiDexParser.parseLocalStartTime(payload))
        XCTAssertFalse(parsed.isAllZeros)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        XCTAssertEqual(parsed.date, calendar.date(from: DateComponents(year: 2025, month: 3, day: 1, hour: 9)))

        // negative offset: UTC-5 = -20 quarters
        let west = try XCTUnwrap(AiDexParser.parseLocalStartTime([0xE9, 0x07, 3, 1, 10, 0, 0, 0xEC, 0]))
        XCTAssertEqual(west.tzQuarters, -20)
        XCTAssertEqual(west.date, calendar.date(from: DateComponents(year: 2025, month: 3, day: 1, hour: 15)))

        let zeros = try XCTUnwrap(AiDexParser.parseLocalStartTime([UInt8](repeating: 0, count: 9)))
        XCTAssertTrue(zeros.isAllZeros)
        XCTAssertNil(zeros.date)

        XCTAssertNil(AiDexParser.parseLocalStartTime([0xD0, 0x07, 1, 1, 0, 0, 0]), "year 2000 is implausible")
        XCTAssertNil(AiDexParser.parseLocalStartTime([0xE9, 0x07]))
    }

    func testNewSensorParamsUseStandardOffsetAndDst() throws {
        let amsterdam = try XCTUnwrap(TimeZone(identifier: "Europe/Amsterdam"))
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = amsterdam
        let summer = try XCTUnwrap(calendar.date(from: DateComponents(year: 2025, month: 7, day: 15, hour: 13, minute: 45, second: 30)))
        XCTAssertEqual(AiDexCommandBuilder.newSensorParams(date: summer, timeZone: amsterdam), [0xE9, 0x07, 7, 15, 13, 45, 30, 4, 4])

        let winter = try XCTUnwrap(calendar.date(from: DateComponents(year: 2025, month: 1, day: 2, hour: 3, minute: 4, second: 5)))
        XCTAssertEqual(AiDexCommandBuilder.newSensorParams(date: winter, timeZone: amsterdam), [0xE9, 0x07, 1, 2, 3, 4, 5, 4, 0])

        let newYork = try XCTUnwrap(TimeZone(identifier: "America/New_York"))
        XCTAssertEqual(AiDexCommandBuilder.newSensorParams(date: winter, timeZone: newYork).suffix(2), [0xEC, 0x00])
    }
}
