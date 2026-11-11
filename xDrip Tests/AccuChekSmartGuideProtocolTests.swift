//
//  AccuChekSmartGuideProtocolTests.swift
//  xDrip Tests
//
//  Frames come from Juggluco's comments in cpp/accu/java.cpp and AccuGattCallback.java
//  (GPL-3.0, Jaap Korthals Altes). The E2E-CRC variant (CRC-16/MCRF4XX) was identified by
//  checking it against all of those captured frames.
//

import XCTest
@testable import xdrip

final class AccuChekSmartGuideProtocolTests: XCTestCase {

    private func bytes(_ hex: String) -> [UInt8] {
        [UInt8](Data(hexadecimalString: hex.replacingOccurrences(of: " ", with: ""))!)
    }

    func testSerialFromName() {
        XCTAssertEqual(AccuChekSmartGuideProtocol.serial(fromAdvertisedName: "AC-1234567890"), "1234567890")
        XCTAssertNil(AccuChekSmartGuideProtocol.serial(fromAdvertisedName: "XAC-1234"))
        XCTAssertNil(AccuChekSmartGuideProtocol.serial(fromAdvertisedName: "AC-"))
        XCTAssertNil(AccuChekSmartGuideProtocol.serial(fromAdvertisedName: nil))
    }

    func testCommandsMatchJuggluco() {
        XCTAssertEqual(AccuChekSmartGuideProtocol.getCommunicationInterval, [0x02, 0x95, 0x2C])
        XCTAssertEqual(AccuChekSmartGuideProtocol.getFirstCalibrationValue, [0x05, 0x00, 0x00, 0x8E, 0x00])
        XCTAssertEqual(AccuChekSmartGuideProtocol.getLastCalibrationValue, [0x05, 0xFF, 0xFF, 0x36, 0xF0])
        // Juggluco indexCmd: 01 03 01 <u16 LE>
        XCTAssertEqual(AccuChekSmartGuideProtocol.reportRecords(fromTimeOffset: 4762), [0x01, 0x03, 0x01, 0x9A, 0x12])
        XCTAssertEqual(AccuChekSmartGuideProtocol.reportRecords(fromTimeOffset: -5), [0x01, 0x03, 0x01, 0x00, 0x00])
    }

    func testE2eCrcOnCapturedFrames() {
        XCTAssertTrue(AccuChekSmartGuideProtocol.hasValidE2eCrc(bytes("03 05 7D 8D")))
        XCTAssertTrue(AccuChekSmartGuideProtocol.hasValidE2eCrc(bytes("9A 12 00 02 00 52 8B")))
        XCTAssertTrue(AccuChekSmartGuideProtocol.hasValidE2eCrc(bytes("0E C3 FF 07 AF 46 08 02 FF 07 FF 07 EA 5C")))
        XCTAssertTrue(AccuChekSmartGuideProtocol.hasValidE2eCrc(bytes("0F E3 02 08 E5 15 08 02 40 F0 FF 38 00 64 27")))
        XCTAssertFalse(AccuChekSmartGuideProtocol.hasValidE2eCrc(bytes("03 05 7D 8E")))
    }

    func testStatusTimeOffset() {
        // captured: 2AA9 read 9A 12 00 02 00 52 8B
        XCTAssertEqual(AccuChekSmartGuideProtocol.statusTimeOffsetMinutes(bytes("9A 12 00 02 00 52 8B")), 4762)
        XCTAssertNil(AccuChekSmartGuideProtocol.statusTimeOffsetMinutes(bytes("9A 12 00 02 00 52 8C")))
        XCTAssertNil(AccuChekSmartGuideProtocol.statusTimeOffsetMinutes([0x9A]))
    }

    func testSfloat() {
        XCTAssertEqual(AccuChekSmartGuideProtocol.sfloat(0x0078), 120)
        XCTAssertEqual(AccuChekSmartGuideProtocol.sfloat(0xE064), 1.0, accuracy: 1e-9)
        XCTAssertEqual(AccuChekSmartGuideProtocol.sfloat(0xFFF0), -1.6, accuracy: 1e-9)
        XCTAssertTrue(AccuChekSmartGuideProtocol.sfloat(0x07FF).isNaN)
        XCTAssertTrue(AccuChekSmartGuideProtocol.sfloat(0x0800).isNaN)
        XCTAssertEqual(AccuChekSmartGuideProtocol.sfloat(0x07FE), .infinity)
        XCTAssertEqual(AccuChekSmartGuideProtocol.sfloat(0x0802), -.infinity)
    }

    func testValidReading() throws {
        // flags 0x43 like Juggluco's AccuData: 120 mg/dL at minute 100, trend -1.0, quality 100
        let record = bytes("0d437800640002f6ff64005fd6")
        let measurement = try XCTUnwrap(AccuChekSmartGuideProtocol.parseMeasurement(record))
        XCTAssertEqual(measurement.glucoseMgDl, 120)
        XCTAssertEqual(measurement.timeOffsetMinutes, 100)
        XCTAssertEqual(measurement.annunciation, [0x02])
        XCTAssertEqual(measurement.trendMgDlPerMinute ?? 0, -1.0, accuracy: 1e-9)
        XCTAssertEqual(measurement.quality, 100)
        XCTAssertEqual(measurement.crcValid, true)
        XCTAssertTrue(measurement.isUsableReading)

        var corrupted = record
        corrupted[2] = 0x79
        XCTAssertFalse(try XCTUnwrap(AccuChekSmartGuideProtocol.parseMeasurement(corrupted)).isUsableReading)
    }

    func testSensorErrorRecord() throws {
        let measurement = try XCTUnwrap(AccuChekSmartGuideProtocol.parseMeasurement(bytes("0E C3 FF 07 AF 46 08 02 FF 07 FF 07 EA 5C")))
        XCTAssertTrue(measurement.glucoseMgDl.isNaN)
        XCTAssertEqual(measurement.timeOffsetMinutes, 0x46AF)
        XCTAssertEqual(measurement.annunciation.count, 2)
        XCTAssertEqual(measurement.crcValid, true)
        XCTAssertFalse(measurement.isUsableReading)
        XCTAssertFalse(measurement.isBelowRange)
    }

    func testBelowRangeRecord() throws {
        let measurement = try XCTUnwrap(AccuChekSmartGuideProtocol.parseMeasurement(bytes("0F E3 02 08 E5 15 08 02 40 F0 FF 38 00 64 27")))
        XCTAssertEqual(measurement.glucoseMgDl, -.infinity)
        XCTAssertEqual(measurement.timeOffsetMinutes, 0x15E5)
        XCTAssertEqual(measurement.annunciation, [0x08, 0x02, 0x40])
        XCTAssertEqual(measurement.trendMgDlPerMinute ?? 0, -1.6, accuracy: 1e-9)
        XCTAssertEqual(measurement.quality, 56)
        XCTAssertTrue(measurement.isBelowRange)
        XCTAssertFalse(measurement.isUsableReading)
    }

    func testSeveralRecordsInOneNotification() {
        let two = bytes("0d437800640002f6ff64005fd6") + bytes("0E C3 FF 07 AF 46 08 02 FF 07 FF 07 EA 5C")
        let measurements = AccuChekSmartGuideProtocol.parseMeasurements(two)
        XCTAssertEqual(measurements.count, 2)
        XCTAssertEqual(measurements.map(\.timeOffsetMinutes), [100, 0x46AF])
        // a size byte that points past the end stops parsing
        XCTAssertTrue(AccuChekSmartGuideProtocol.parseMeasurements([0x20, 0x43, 0x00]).isEmpty)
    }

    func testCommunicationIntervalResponse() {
        XCTAssertTrue(AccuChekSmartGuideProtocol.isCommunicationIntervalResponse(bytes("03 05 7D 8D")))
        XCTAssertFalse(AccuChekSmartGuideProtocol.isCommunicationIntervalResponse(bytes("1C 05 01 00 00")))
    }
}
