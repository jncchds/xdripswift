//
//  CGMAccuChekSmartGuideTransmitter.swift
//  xdrip
//
//  Direct Bluetooth connection to Accu-Chek SmartGuide sensors.
//
//  Connection sequence ported from Juggluco / JugglucoNG (GPL-3.0, Jaap Korthals Altes,
//  https://github.com/j-kaltes/Juggluco and https://github.com/ctqvva/JugglucoNG),
//  Common/src/dex/java/tk/glucodata/AccuGattCallback.java and cpp/accu/java.cpp.
//

import Foundation
import CoreBluetooth
import os

/// Accu-Chek SmartGuide (Roche) CGM transmitter.
///
/// The sensor implements the Bluetooth SIG CGM profile (service 0x181F) and calculates glucose
/// itself. Reading CGM Status needs an encrypted link: the first connection triggers the iOS
/// pairing dialog, where the user enters the PIN from the sensor package.
///
/// Juggluco takes two paths depending on Android's bond state. iOS has no bond-state API, so the
/// "already paired" path is chosen from a per-serial flag stored after a complete setup. ATT
/// authentication errors and `peerRemovedPairingInformation` clear that flag again.
@objcMembers
class CGMAccuChekSmartGuideTransmitter: BluetoothTransmitter, CGMTransmitter {

    // MARK: - UUIDs

    private static let cgmServiceUUID = CBUUID(string: "181F")
    private static let deviceInformationServiceUUID = CBUUID(string: "180A")
    private static let measurementUUID = CBUUID(string: "2AA7")
    private static let featureUUID = CBUUID(string: "2AA8")
    private static let statusUUID = CBUUID(string: "2AA9")
    private static let sessionStartTimeUUID = CBUUID(string: "2AAA")
    private static let sessionRunTimeUUID = CBUUID(string: "2AAB")
    private static let racpUUID = CBUUID(string: "2A52")
    private static let controlPointUUID = CBUUID(string: "2AAC")
    private static let firmwareUUID = CBUUID(string: "2A26")
    private static let hardwareUUID = CBUUID(string: "2A27")
    private static let manufacturerUUID = CBUUID(string: "2A29")
    private static let modelUUID = CBUUID(string: "2A24")
    private static let serialUUID = CBUUID(string: "2A25")

    private let CBUUID_Service_SmartGuide = "181F"
    private let CBUUID_Receive_SmartGuide = "2AA7"
    private let CBUUID_Write_SmartGuide = "2AAC"

    // MARK: - timing

    private let sensorLifeDays: Double = 14
    private let setupTimeout: TimeInterval = 90
    private let packetInactivityTimeout: TimeInterval = 12 * 60
    private let maximumBackfillMinutes = 12 * 60
    private let reconnectDelays: [TimeInterval] = [1, 5, 15, 30, 60, 120]
    private let sensorSessionTolerance: TimeInterval = 10 * 60

    // MARK: - state (centralQueue only)

    private var characteristics: [CBUUID: CBCharacteristic] = [:]
    private var setupStarted = false
    private var pairedPath = false
    /// Juggluco's phase: 0 first setup, 1 after communication interval, 2 calibration, 3 records
    private var phase = 0
    private var readQueue: [CBUUID] = []
    private var notificationQueue: [CBUUID] = []
    private var enablingNotifications = false
    private var connectionGeneration = 0
    private var watchdogGeneration = 0
    private var packetWatchdogGeneration = 0
    private var reconnectGeneration = 0
    private var consecutiveFailures = 0
    private weak var lastPeripheral: CBPeripheral?

    private var firmware: String?
    private var hardware: String?
    private var model: String?
    private var lastReportedStatus: String?

    private var serialNumber: String?

    private(set) weak var cgmTransmitterDelegate: CGMTransmitterDelegate?
    private weak var cGMAccuChekSmartGuideTransmitterDelegate: CGMAccuChekSmartGuideTransmitterDelegate?

    private let log = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryCGMAccuChekSmartGuide)

    // MARK: - init

    init(address: String?, name: String?, serialNumber: String?, bluetoothTransmitterDelegate: BluetoothTransmitterDelegate, cGMAccuChekSmartGuideTransmitterDelegate: CGMAccuChekSmartGuideTransmitterDelegate?, cGMTransmitterDelegate: CGMTransmitterDelegate) {

        var addressAndName: BluetoothTransmitter.DeviceAddressAndName = .notYetConnected(expectedName: AccuChekSmartGuideProtocol.namePrefix)
        if let address {
            addressAndName = .alreadyConnectedBefore(address: address, name: name)
        }

        self.cgmTransmitterDelegate = cGMTransmitterDelegate
        self.cGMAccuChekSmartGuideTransmitterDelegate = cGMAccuChekSmartGuideTransmitterDelegate
        self.serialNumber = serialNumber ?? AccuChekSmartGuideProtocol.serial(fromAdvertisedName: name)

        super.init(addressAndName: addressAndName, CBUUID_Advertisement: CBUUID_Service_SmartGuide, servicesCBUUIDs: [CBUUID(string: CBUUID_Service_SmartGuide), CBUUID(string: "180A")], CBUUID_ReceiveCharacteristic: CBUUID_Receive_SmartGuide, CBUUID_WriteCharacteristic: CBUUID_Write_SmartGuide, bluetoothTransmitterDelegate: bluetoothTransmitterDelegate)
    }

    // MARK: - CBCentralManagerDelegate

    override func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        if deviceAddress == nil {
            // The base class matches "AC-" anywhere in the name; require it as prefix here.
            let advertisedName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name
            guard let serial = AccuChekSmartGuideProtocol.serial(fromAdvertisedName: advertisedName) else { return }
            serialNumber = serial
        }
        super.centralManager(central, didDiscover: peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    override func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        lastPeripheral = peripheral
        resetConnectionState()
        if serialNumber == nil {
            serialNumber = AccuChekSmartGuideProtocol.serial(fromAdvertisedName: peripheral.name)
        }
        if let serial = serialNumber {
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMAccuChekSmartGuideTransmitterDelegate?.received(serialNumber: serial, cGMAccuChekSmartGuideTransmitter: self)
            }
        }
        super.centralManager(central, didConnect: peripheral)
        armSetupWatchdog()
        armPacketWatchdog()
    }

    override func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        if let cbError = error as? CBError, cbError.code == .peerRemovedPairingInformation {
            trace("SmartGuide: sensor removed its pairing; forget it in iOS Bluetooth settings", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error)
            setPairedFlag(false)
            reportStatus("Pairing removed by sensor")
            DispatchQueue.main.async { [weak self] in
                self?.bluetoothTransmitterDelegate?.error(message: Texts_BluetoothPeripheralView.accuChekForgetInIOSSettings)
            }
        }
        if phase < 3 { consecutiveFailures += 1 }
        resetConnectionState()
        super.centralManager(central, didDisconnectPeripheral: peripheral, error: error)
    }

    override func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        cancelConnectionTimer()
        consecutiveFailures += 1
        trace("SmartGuide: failed to connect: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, error?.localizedDescription ?? "no error")
        reconnectAfterDisconnect(central)
    }

    override func reconnectAfterDisconnect(_ central: CBCentralManager) {
        guard let peripheral = lastPeripheral else { return }
        let delay = reconnectDelays[min(consecutiveFailures, reconnectDelays.count - 1)]
        reconnectGeneration += 1
        let generation = reconnectGeneration
        runOnCentralQueue(after: delay) { [weak self, weak peripheral, weak central] in
            guard let self, let peripheral, let central, self.reconnectGeneration == generation,
                  peripheral.state == .disconnected else { return }
            central.connect(peripheral, options: [
                CBConnectPeripheralOptionNotifyOnConnectionKey: true,
                CBConnectPeripheralOptionNotifyOnDisconnectionKey: true,
            ])
        }
    }

    override func prepareForRelease() {
        runOnCentralQueue { [weak self] in
            self?.reconnectGeneration += 1
            self?.watchdogGeneration += 1
            self?.packetWatchdogGeneration += 1
        }
        super.prepareForRelease()
    }

    // MARK: - CBPeripheralDelegate

    override func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        // Not calling super: the base class would enable 2AA7 right away, before pairing.
        if let error {
            trace("SmartGuide: characteristic discovery error: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, error.localizedDescription)
        }
        for characteristic in service.characteristics ?? [] {
            characteristics[characteristic.uuid] = characteristic
        }
        let allDiscovered = (peripheral.services ?? []).allSatisfy { $0.characteristics != nil }
        guard allDiscovered, !setupStarted else { return }

        let required = [Self.measurementUUID, Self.statusUUID, Self.racpUUID, Self.controlPointUUID]
        guard required.allSatisfy({ characteristics[$0] != nil }) else {
            trace("SmartGuide: CGM characteristics missing, disconnecting", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error)
            disconnect()
            return
        }
        setupStarted = true
        pairedPath = isPairedFlagSet()
        phase = pairedPath ? 2 : 0
        trace("SmartGuide: setup start, paired before %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, pairedPath.description)

        if pairedPath {
            startNotificationChain()
        } else {
            // Reading CGM Status needs encryption: iOS shows the pairing dialog (sensor PIN).
            reportStatus("Pairing")
            read(Self.statusUUID)
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didUpdateNotificationStateFor: characteristic, error: error)
        if let error {
            trace("SmartGuide: notify on %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
            if Self.isAuthenticationError(error) {
                setPairedFlag(false)
            }
        }
        guard enablingNotifications else { return }
        if !notificationQueue.isEmpty {
            setNotify(notificationQueue.removeFirst())
            return
        }
        enablingNotifications = false
        // Juggluco onDescriptorWrite(CGM control point)
        if pairedPath {
            read(Self.statusUUID)
        } else {
            write(AccuChekSmartGuideProtocol.getCommunicationInterval, to: Self.controlPointUUID)
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didUpdateValueFor: characteristic, error: error)

        if let error {
            trace("SmartGuide: read of %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
            if Self.isAuthenticationError(error) {
                // pairing was declined or the stored link key is gone
                setPairedFlag(false)
                reportStatus("Pairing failed")
                DispatchQueue.main.async { [weak self] in
                    self?.bluetoothTransmitterDelegate?.pairingFailed()
                }
                consecutiveFailures += 1
                disconnect()
                return
            }
            // Juggluco disconnects after a failed read as well.
            disconnect()
            return
        }
        guard let value = characteristic.value else { return }
        let bytes = [UInt8](value)

        switch characteristic.uuid {
        case Self.measurementUUID:
            handleMeasurements(bytes)
        case Self.controlPointUUID:
            handleControlPointIndication(bytes)
        case Self.racpUUID:
            trace("SmartGuide: RACP response %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, Data(bytes).hexEncodedString())
        case Self.statusUUID:
            handleStatus(bytes)
        case Self.featureUUID:
            // Juggluco then reads Appearance, which CoreBluetooth does not expose; go on with status.
            phase = 1
            read(Self.statusUUID)
        case Self.sessionStartTimeUUID:
            read(Self.sessionRunTimeUUID)
        case Self.sessionRunTimeUUID:
            write(AccuChekSmartGuideProtocol.getFirstCalibrationValue, to: Self.controlPointUUID)
        case Self.firmwareUUID, Self.hardwareUUID, Self.manufacturerUUID, Self.modelUUID, Self.serialUUID:
            let text = String(bytes: bytes, encoding: .utf8)?.trimmingCharacters(in: CharacterSet(charactersIn: "\0 "))
            if characteristic.uuid == Self.firmwareUUID { firmware = text }
            if characteristic.uuid == Self.hardwareUUID { hardware = text }
            if characteristic.uuid == Self.modelUUID { model = text }
            continueDeviceInformationReads()
        default:
            break
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didWriteValueFor: characteristic, error: error)
        guard let error else { return }
        trace("SmartGuide: write to %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
        if Self.isAuthenticationError(error) {
            setPairedFlag(false)
            disconnect()
        }
    }

    // MARK: - setup sequence

    private func handleStatus(_ bytes: [UInt8]) {
        if let minutes = AccuChekSmartGuideProtocol.statusTimeOffsetMinutes(bytes) {
            updateSessionStart(timeOffsetMinutes: minutes)
        } else {
            trace("SmartGuide: CGM status not usable: %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, Data(bytes).hexEncodedString())
        }
        switch phase {
        case 0:
            // first status read succeeded: the link is encrypted
            reportStatus("Paired, reading sensor information")
            readQueue = [Self.firmwareUUID, Self.hardwareUUID, Self.manufacturerUUID, Self.modelUUID, Self.serialUUID].filter { characteristics[$0] != nil }
            continueDeviceInformationReads()
        case 1:
            if characteristics[Self.sessionStartTimeUUID] != nil {
                read(Self.sessionStartTimeUUID)
            } else {
                write(AccuChekSmartGuideProtocol.getFirstCalibrationValue, to: Self.controlPointUUID)
            }
        default:
            write(AccuChekSmartGuideProtocol.getLastCalibrationValue, to: Self.controlPointUUID)
        }
    }

    private func continueDeviceInformationReads() {
        if !readQueue.isEmpty {
            read(readQueue.removeFirst())
            return
        }
        let (firmware, hardware, model) = (self.firmware, self.hardware, self.model)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMAccuChekSmartGuideTransmitterDelegate?.received(firmware: firmware, hardware: hardware, model: model, cGMAccuChekSmartGuideTransmitter: self)
        }
        startNotificationChain()
    }

    private func startNotificationChain() {
        notificationQueue = [Self.racpUUID, Self.controlPointUUID]
        enablingNotifications = true
        setNotify(Self.measurementUUID)
    }

    private func handleControlPointIndication(_ bytes: [UInt8]) {
        trace("SmartGuide: control point indication %{public}@ (phase %{public}d)", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, Data(bytes).hexEncodedString(), phase)
        if AccuChekSmartGuideProtocol.isCommunicationIntervalResponse(bytes) {
            if characteristics[Self.featureUUID] != nil {
                read(Self.featureUUID)
            } else {
                phase = 1
                read(Self.statusUUID)
            }
            return
        }
        if phase == 1 {
            phase = 2
            read(Self.statusUUID)
        } else if phase == 2 {
            phase = 3
            requestRecords()
        }
    }

    private func requestRecords() {
        watchdogGeneration += 1
        consecutiveFailures = 0
        setPairedFlag(true)
        reportStatus("Connected")

        let currentOffset = storedSessionStart().map { Int(Date().timeIntervalSince($0) / 60) }
        var from = AccuChekSmartGuideProtocol.warmupMinutes
        if let currentOffset {
            from = max(from, currentOffset - maximumBackfillMinutes)
        }
        if let last = storedLastOffset() {
            from = max(from, last + AccuChekSmartGuideProtocol.recordIntervalMinutes)
        }
        trace("SmartGuide: requesting records from offset %{public}d", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, from)
        write(AccuChekSmartGuideProtocol.reportRecords(fromTimeOffset: from), to: Self.racpUUID)
    }

    // MARK: - readings

    private func updateSessionStart(timeOffsetMinutes: Int) {
        let candidate = Date().addingTimeInterval(TimeInterval(-timeOffsetMinutes * 60))
        // Keep a stable start; replace it only for a new session (Juggluco: only before data).
        if let stored = storedSessionStart(), abs(stored.timeIntervalSince(candidate)) < sensorSessionTolerance {
            return
        }
        trace("SmartGuide: session start %{public}@ (offset %{public}d min)", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, candidate.description, timeOffsetMinutes)
        storeSessionStart(candidate)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMAccuChekSmartGuideTransmitterDelegate?.received(sensorStartDate: candidate, cGMAccuChekSmartGuideTransmitter: self)
        }
    }

    private func handleMeasurements(_ bytes: [UInt8]) {
        let measurements = AccuChekSmartGuideProtocol.parseMeasurements(bytes)
        guard !measurements.isEmpty else {
            trace("SmartGuide: unparsable measurement %{public}@", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, Data(bytes).hexEncodedString())
            return
        }
        guard var start = storedSessionStart() else {
            trace("SmartGuide: measurement before session start is known, ignored", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error)
            return
        }

        let now = Date()
        var lastOffset = storedLastOffset()
        var lastValue = storedLastValue()
        var readings: [GlucoseData] = []

        for measurement in measurements {
            guard lastOffset.map({ measurement.timeOffsetMinutes > $0 }) ?? true else { continue }

            var value: Double?
            if measurement.isUsableReading {
                value = measurement.glucoseMgDl
            } else if measurement.isBelowRange, let previousOffset = lastOffset, let previousValue = lastValue,
                      previousValue < 120, (5..<30).contains(measurement.timeOffsetMinutes - previousOffset) {
                // Juggluco: the sensor's "below range" record after a falling value is stored as 39 mg/dL
                value = 39
            }
            guard let value else {
                trace("SmartGuide: no glucose in record at offset %{public}d (flags %{public}@)", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .info, measurement.timeOffsetMinutes, String(format: "%02X", measurement.flags))
                reportStatus("Sensor error or warming up")
                continue
            }

            var timeStamp = start.addingTimeInterval(TimeInterval(measurement.timeOffsetMinutes * 60))
            if timeStamp > now {
                // Juggluco moves the start so the record is not in the future.
                start = now.addingTimeInterval(TimeInterval(-measurement.timeOffsetMinutes * 60))
                storeSessionStart(start)
                timeStamp = now
            }
            let isBackfill = now.timeIntervalSince(timeStamp) > 6 * 60
            readings.append(GlucoseData(timeStamp: timeStamp, glucoseLevelRaw: value, backfilledAt: isBackfill ? now : nil))
            lastOffset = measurement.timeOffsetMinutes
            lastValue = value
        }

        guard let newestOffset = lastOffset, let newestValue = lastValue, !readings.isEmpty else { return }
        storeLastOffset(newestOffset, value: newestValue)
        armPacketWatchdog()
        reportStatus("Streaming")

        // youngest first
        readings.sort { $0.timeStamp > $1.timeStamp }
        let sensorAge = TimeInterval(newestOffset * 60)
        let sessionStart = start
        let tolerance = sensorSessionTolerance
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let active = UserDefaults.standard.activeSensorStartDate, abs(active.timeIntervalSince(sessionStart)) > tolerance {
                self.cgmTransmitterDelegate?.newSensorDetected(sensorStartDate: sessionStart)
            }
            self.cgmTransmitterDelegate?.cgmTransmitterInfoReceived(glucoseData: &readings, transmitterBatteryInfo: nil, sensorAge: sensorAge)
        }
    }

    // MARK: - GATT helpers

    private func read(_ uuid: CBUUID) {
        guard let characteristic = characteristics[uuid] else {
            trace("SmartGuide: %{public}@ missing", log: log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, uuid.uuidString)
            return
        }
        readValueForCharacteristic(for: characteristic)
    }

    private func write(_ bytes: [UInt8], to uuid: CBUUID) {
        guard let characteristic = characteristics[uuid] else { return }
        _ = writeDataToPeripheral(data: Data(bytes), characteristicToWriteTo: characteristic, type: .withResponse)
    }

    private func setNotify(_ uuid: CBUUID) {
        guard let characteristic = characteristics[uuid] else { return }
        setNotifyValue(true, for: characteristic)
    }

    private func resetConnectionState() {
        connectionGeneration += 1
        watchdogGeneration += 1
        characteristics = [:]
        setupStarted = false
        pairedPath = false
        phase = 0
        readQueue = []
        notificationQueue = []
        enablingNotifications = false
    }

    private func armSetupWatchdog() {
        watchdogGeneration += 1
        let generation = watchdogGeneration
        runOnCentralQueue(after: setupTimeout) { [weak self] in
            guard let self, self.watchdogGeneration == generation, self.phase < 3,
                  self.getConnectionStatus() == .connected else { return }
            trace("SmartGuide: setup stalled in phase %{public}d", log: self.log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, self.phase)
            self.consecutiveFailures += 1
            self.disconnect()
        }
    }

    private func armPacketWatchdog() {
        packetWatchdogGeneration += 1
        let generation = packetWatchdogGeneration
        runOnCentralQueue(after: packetInactivityTimeout) { [weak self] in
            guard let self, self.packetWatchdogGeneration == generation, self.getConnectionStatus() == .connected else { return }
            trace("SmartGuide: no reading for %{public}d s, recycling connection", log: self.log, category: ConstantsLog.categoryCGMAccuChekSmartGuide, type: .error, Int(self.packetInactivityTimeout))
            self.disconnect()
        }
    }

    private func reportStatus(_ status: String) {
        guard status != lastReportedStatus else { return }
        lastReportedStatus = status
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMAccuChekSmartGuideTransmitterDelegate?.received(sensorStatus: status, cGMAccuChekSmartGuideTransmitter: self)
        }
    }

    private static func isAuthenticationError(_ error: Error) -> Bool {
        if let attError = error as? CBATTError {
            switch attError.code {
            case .insufficientAuthentication, .insufficientEncryption, .insufficientEncryptionKeySize, .insufficientAuthorization:
                return true
            default:
                return false
            }
        }
        if let cbError = error as? CBError {
            return cbError.code == .peerRemovedPairingInformation || cbError.code == .encryptionTimedOut
        }
        return false
    }

    // MARK: - per-serial persistence (UserDefaults; nothing secret: the link key lives in iOS)

    private func key(_ name: String) -> String? {
        serialNumber.map { "accuChekSmartGuide.\(name).\($0.uppercased())" }
    }

    private func isPairedFlagSet() -> Bool {
        key("paired").map { UserDefaults.standard.bool(forKey: $0) } ?? false
    }

    private func setPairedFlag(_ paired: Bool) {
        guard let key = key("paired") else { return }
        UserDefaults.standard.set(paired, forKey: key)
    }

    private func storedSessionStart() -> Date? {
        key("sessionStart").flatMap { UserDefaults.standard.object(forKey: $0) as? Date }
    }

    private func storeSessionStart(_ date: Date) {
        guard let key = key("sessionStart") else { return }
        UserDefaults.standard.set(date, forKey: key)
        // a new session invalidates the record cursor
        if let offsetKey = self.key("lastOffset"), let lastOffset = storedLastOffset(),
           Date().timeIntervalSince(date) < TimeInterval(lastOffset * 60) - sensorSessionTolerance {
            UserDefaults.standard.removeObject(forKey: offsetKey)
        }
    }

    private func storedLastOffset() -> Int? {
        key("lastOffset").flatMap { UserDefaults.standard.object(forKey: $0) as? Int }
    }

    private func storedLastValue() -> Double? {
        key("lastValue").flatMap { UserDefaults.standard.object(forKey: $0) as? Double }
    }

    private func storeLastOffset(_ offset: Int, value: Double) {
        guard let offsetKey = key("lastOffset"), let valueKey = key("lastValue") else { return }
        UserDefaults.standard.set(offset, forKey: offsetKey)
        UserDefaults.standard.set(value, forKey: valueKey)
    }

    // MARK: - CGMTransmitter

    func cgmTransmitterType() -> CGMTransmitterType {
        .accuChekSmartGuide
    }

    func maxSensorAgeInDays() -> Double? {
        sensorLifeDays
    }

    func sensorWarmupDurationInMinutes() -> Double? {
        Double(AccuChekSmartGuideProtocol.warmupMinutes)
    }

    func getCBUUID_Service() -> String { CBUUID_Service_SmartGuide }

    func getCBUUID_Receive() -> String { CBUUID_Receive_SmartGuide }

    func needsSensorStartTime() -> Bool { false }

    /// The sensor sends calibrated mg/dL values.
    func isWebOOPEnabled() -> Bool { true }

    func nonWebOOPAllowed() -> Bool { false }
}
