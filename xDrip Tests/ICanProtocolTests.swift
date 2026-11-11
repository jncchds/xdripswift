//
//  ICanProtocolTests.swift
//  xDrip Tests
//
//  Live-frame vectors come from JugglucoNG's ICanHealthLiveCbcVectorTests.kt (GPL-3.0), captured
//  from the official iOS app (iCGM-t3) and a TECNO iCGM-t6. Warm-up values (5.97 / 3.85 mmol/L)
//  are the history values quoted in JugglucoNG's docs/ican-cgm-protocol.md §5. The auth token and
//  the SN batch were generated with Python's `cryptography` AES-CBC as an independent check.
//

import XCTest
@testable import xdrip

final class ICanProtocolTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        [UInt8](Data(hexadecimalString: hex.replacingOccurrences(of: " ", with: ""))!)
    }

    func testIvLayout() {
        XCTAssertEqual(ICanProtocol.iv(challenge: [0xA1, 0xA2, 0xA3, 0xA4]),
                       [0, 0xA1, 0, 0, 0, 0, 0xA2, 0, 0, 0, 0xA3, 0, 0, 0, 0, 0xA4])
        XCTAssertNil(ICanProtocol.iv(challenge: [1, 2, 3]))
    }

    func testCapturedLiveFramesAfterWarmup() throws {
        let key = ICanProtocol.newGlucoseKey
        let seq18 = try XCTUnwrap(ICanProtocol.parseLiveFrame(bytes("12 00 02 C1 CD 90 F4 FD AF 6C 42 AC D5 C9 87 B6 52 2B 7D"), key: key, challenge: [0x30, 0x13, 0xAA, 0x84], warmupMinutes: 0, newFamily: true))
        XCTAssertEqual(seq18.sequence, 18)
        XCTAssertEqual(seq18.glucoseMmol, 17.55, accuracy: 0.0001)
        XCTAssertEqual(seq18.launcherState, 0x80)

        let seq30 = try XCTUnwrap(ICanProtocol.parseLiveFrame(bytes("1E 00 02 E2 0C C3 32 50 31 C3 EE FD B3 49 7B 5A A3 05 2B"), key: key, challenge: [0xC6, 0x18, 0x3B, 0xBD], warmupMinutes: 0, newFamily: true))
        XCTAssertEqual(seq30.sequence, 30)
        XCTAssertEqual(seq30.glucoseMmol, 5.73, accuracy: 0.0001)

        let seq117 = try XCTUnwrap(ICanProtocol.parseLiveFrame(bytes("75 00 02 D4 22 8E 35 9E 64 5F 00 98 00 FF 86 4A CA 2F 4A"), key: key, challenge: [0xF8, 0x93, 0x7B, 0x8C], warmupMinutes: 0, newFamily: true))
        XCTAssertEqual(seq117.sequence, 117)
        XCTAssertEqual(seq117.glucoseMmol, 31.34, accuracy: 0.0001)
    }

    func testWarmupXorMatchesHistory() throws {
        let key = ICanProtocol.newGlucoseKey
        let seq18 = try XCTUnwrap(ICanProtocol.parseLiveFrame(bytes("12 00 02 C1 CD 90 F4 FD AF 6C 42 AC D5 C9 87 B6 52 2B 7D"), key: key, challenge: [0x30, 0x13, 0xAA, 0x84], warmupMinutes: 120, newFamily: true))
        XCTAssertEqual(seq18.glucoseMmol, 5.97, accuracy: 0.0001)

        let seq117 = try XCTUnwrap(ICanProtocol.parseLiveFrame(bytes("75 00 02 D4 22 8E 35 9E 64 5F 00 98 00 FF 86 4A CA 2F 4A"), key: key, challenge: [0xF8, 0x93, 0x7B, 0x8C], warmupMinutes: 120, newFamily: true))
        XCTAssertEqual(seq117.glucoseMmol, 3.85, accuracy: 0.0001)
    }

    func testT6FrameWithOldKey() throws {
        // JugglucoNG rebuilds the wire frame by ECB-encrypting the captured ECB-decrypted block.
        let ecbBlock = bytes("0D 71 0D 02 48 03 19 00 00 00 6B 00 00 03 03 D1")
        let ciphertext = try XCTUnwrap(AiDexAesCfb128.ecbEncrypt(block: ecbBlock, key: ICanProtocol.oldGlucoseKey))
        XCTAssertEqual(Data(ciphertext).hexEncodedString(), "3bab61f4f5b42f9f4879a905c0a126f9")
        let reading = try XCTUnwrap(ICanProtocol.parseLiveFrame([0x48, 0x03, 0x02] + ciphertext, key: ICanProtocol.oldGlucoseKey, challenge: [0xF1, 0x18, 0x6B, 0xD2], warmupMinutes: 0, newFamily: false))
        XCTAssertEqual(reading.sequence, 840)
        XCTAssertEqual(reading.glucoseMmol, 5.25, accuracy: 0.0001)
        XCTAssertEqual(reading.launcherState, 0x80)
        XCTAssertEqual(reading.glucoseMgDl, 5.25 * 18.0182, accuracy: 0.001)
    }

    func testLiveFrameRejectsWrongChallenge() {
        XCTAssertNil(ICanProtocol.parseLiveFrame(bytes("1E 00 02 E2 0C C3 32 50 31 C3 EE FD B3 49 7B 5A A3 05 2B"), key: ICanProtocol.newGlucoseKey, challenge: [0x00, 0x18, 0x3B, 0xBD], warmupMinutes: 0, newFamily: true))
    }

    func testAuthToken() {
        let packet = ICanProtocol.authTokenPacket(challenge: [0x30, 0x13, 0xAA, 0x84], userId: "", authKey: ICanProtocol.newAuthKey)
        XCTAssertEqual(packet.map { Data($0).hexEncodedString() }, "f41069e58ee12cc9c724536aa3267dda2933")
        XCTAssertNil(ICanProtocol.authTokenPacket(challenge: [1, 2, 3], userId: "", authKey: ICanProtocol.newAuthKey))
    }

    func testUserIdNormalisationAndRecovery() throws {
        XCTAssertEqual(ICanProtocol.normalizedUserId(nil), "000000000000")
        XCTAssertEqual(ICanProtocol.normalizedUserId("AB 12"), "AB1200000000")
        XCTAssertEqual(ICanProtocol.normalizedUserId("X123456789012345"), "456789012345")

        let challenge: [UInt8] = [0x30, 0x13, 0xAA, 0x84]
        let cipher = try XCTUnwrap(ICanProtocol.cbcEncrypt(Array("AB12".utf8), key: ICanProtocol.oldAuthKey, iv: try XCTUnwrap(ICanProtocol.iv(challenge: challenge))))
        let reject: [UInt8] = [0x1C, 0xF4, 0x02] + cipher + [0x01]
        XCTAssertEqual(ICanProtocol.recoverUserId(fromReject: reject, challenge: challenge, authKey: ICanProtocol.oldAuthKey), "AB12")
        XCTAssertNil(ICanProtocol.recoverUserId(fromReject: [0x1C, 0xF4, 0x02] + cipher + [0x00], challenge: challenge, authKey: ICanProtocol.oldAuthKey))
        XCTAssertEqual(ICanProtocol.authResult([0x1C, 0xF4, 0x01]), 0x01)
    }

    func testChallengeMarkerAndRacp() {
        XCTAssertEqual(ICanProtocol.challenge(fromResponse: bytes("06 F3 01 F1 18 6B D2")), [0xF1, 0x18, 0x6B, 0xD2])
        XCTAssertNil(ICanProtocol.challenge(fromResponse: bytes("06 F3 02 F1 18 6B D2")))
        XCTAssertEqual(ICanProtocol.sensorInfoMarker(bytes("1C F6 01 4E 02")), 590)
        XCTAssertEqual(ICanProtocol.sensorInfoMarker(bytes("1C F6 01 FF FF")), 0xFFFF)
        XCTAssertEqual(ICanProtocol.racpResult(bytes("06 00 F1 01")), 0x01)
        XCTAssertEqual(ICanProtocol.racpResult(bytes("06 00 01 0A")), 0x0A)
        XCTAssertNil(ICanProtocol.racpResult(bytes("06 01 F1 01")))
        XCTAssertEqual(ICanProtocol.reportGlucoseHistory(fromSequence: 303, modern: true), [0xF1, 0x03, 0x02, 0x01, 0x2F, 0x01])
        XCTAssertEqual(ICanProtocol.reportGlucoseHistory(fromSequence: 0, modern: false), [0x01, 0x03, 0x02, 0x01, 0x01, 0x00])
    }

    func testSnGlucoseBatch() throws {
        let frame = bytes("534e142a52024acb0846f1cae9a5720dee58c63bc61500")
        let readings = try XCTUnwrap(ICanProtocol.parseGlucoseSnBatch(frame, key: ICanProtocol.oldGlucoseKey, challenge: [1, 2, 3, 4], readingIntervalMinutes: 3))
        XCTAssertEqual(readings.map(\.sequence), [300, 303])
        XCTAssertEqual(readings[0].glucoseMmol, 5.25, accuracy: 0.0001)
        XCTAssertEqual(readings[1].glucoseMmol, 6.00, accuracy: 0.0001)
        XCTAssertNil(ICanProtocol.parseGlucoseSnBatch(frame, key: ICanProtocol.newGlucoseKey, challenge: [1, 2, 3, 4], readingIntervalMinutes: 3))
    }

    func testKeyFamilyAndProfile() {
        XCTAssertTrue(ICanProtocol.usesNewKeyFamily(serial: "ABCDEFGHIJ05XX", softwareVersion: nil))
        XCTAssertFalse(ICanProtocol.usesNewKeyFamily(serial: "ABCDEFGHIJ03XX", softwareVersion: nil))
        XCTAssertTrue(ICanProtocol.usesNewKeyFamily(serial: "short", softwareVersion: "V1.2.3.4.507"))
        XCTAssertFalse(ICanProtocol.usesNewKeyFamily(serial: nil, softwareVersion: nil))

        XCTAssertEqual(ICanProtocol.profile(model: "iCGM-t3", serial: nil, softwareVersion: nil).warmupMinutes, 120)
        XCTAssertEqual(ICanProtocol.profile(model: "iCGM-t6", serial: nil, softwareVersion: nil).warmupMinutes, 30)
        XCTAssertEqual(ICanProtocol.profile(model: "i7 pro", serial: nil, softwareVersion: nil).readingIntervalMinutes, 1)
        XCTAssertEqual(ICanProtocol.status([0x48, 0x03, 0x80, 0x00, 0x00, 0x00])?.sequence, 840)
    }

    func testDeviceNames() {
        XCTAssertTrue(ICanProtocol.isICanDeviceName("iCGM-t3 1234"))
        XCTAssertTrue(ICanProtocol.isICanDeviceName("Sinocare CGM"))
        XCTAssertFalse(ICanProtocol.isICanDeviceName("AiDEX X-2222267V4E"))
        XCTAssertFalse(ICanProtocol.isICanDeviceName(nil))
    }
}
