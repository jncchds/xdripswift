//
//  CGMICanTransmitter.swift
//  xdrip
//
//  Direct Bluetooth connection to Sinocare iCan i3/i6 sensors (iCGM-t3/t6 and relatives).
//
//  Connection sequence ported from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG),
//  Common/src/main/java/tk/glucodata/drivers/icanhealth/ICanHealthBleManager.kt and
//  docs/ican-cgm-protocol.md.
//

import Foundation
import CoreBluetooth
import os

/// Sinocare iCan CGM transmitter.
///
/// Sequence (JugglucoNG / official iOS app capture): DIS reads → indications on 0x2AAC → `F3`
/// challenge → `F4 10 <token>` → `1C F4 01` accepted → `F6` calibration marker → notifications on
/// 0x2AA7 and RACP → CGM Status → RACP glucose history → 19-byte live frames every 3 minutes.
///
/// Limits of this port:
/// - Only sensors that are already running are supported. Starting a fresh sensor needs the
///   vendor calibration table (`correctCode`) from the Sinocare cloud, which is not ported; such
///   sensors reportedly stop producing after about a week. A sensor in launcher state "idle" is
///   reported and not started.
/// - A sensor started by the vendor app expects that app's user id. Like JugglucoNG, the id is
///   recovered from the sensor's rejection and the authentication is retried once.
/// - No user calibration (vendor libAlg port) and no original (current/temperature) history.
@objcMembers
class CGMICanTransmitter: BluetoothTransmitter, CGMTransmitter {

    // MARK: - UUIDs

    private static let measurementUUID = CBUUID(string: "2AA7")
    private static let statusUUID = CBUUID(string: "2AA9")
    private static let sessionStartTimeUUID = CBUUID(string: "2AAA")
    private static let racpUUID = CBUUID(string: "2A52")
    private static let opsUUID = CBUUID(string: "2AAC")
    private static let modelUUID = CBUUID(string: "2A24")
    private static let serialUUID = CBUUID(string: "2A25")
    private static let softwareUUID = CBUUID(string: "2A28")

    private let CBUUID_Service_ICan = "181F"
    private let CBUUID_Receive_ICan = "2AA7"
    private let CBUUID_Write_ICan = "2AAC"

    // MARK: - timing

    private let setupTimeout: TimeInterval = 60
    private let packetInactivityTimeout: TimeInterval = 10 * 60
    private let maximumBackfillMinutes = 12 * 60
    private let reconnectDelays: [TimeInterval] = [2, 8, 15, 30, 60, 120]
    private let sensorSessionTolerance: TimeInterval = 10 * 60
    /// JugglucoNG MIN_VALID_GLUCOSE_MGDL / MAX_VALID_GLUCOSE_MGDL
    private let validGlucoseRange: ClosedRange<Double> = 10...551
    /// JugglucoNG MIN_VENDOR_HISTORY_MTU
    private let modernHistoryMinimumMtu = 247

    // MARK: - state (centralQueue only)

    private enum Phase: String { case idle, discovering, readingIdentity, authenticating, configuring, streaming }

    private var phase: Phase = .idle
    private var characteristics: [CBUUID: CBCharacteristic] = [:]
    private var readQueue: [CBUUID] = []
    private var notificationQueue: [CBUUID] = []
    private var challenge: [UInt8]?
    private var authRetried = false
    private var authenticated = false
    private var historyRequested = false
    private var historyTailRetried = false
    private var historyReadings: [ICanProtocol.Reading] = []
    private var historyStartSequence = 0
    private var currentSequence: Int?
    private var sessionAnchor: Date?
    private var modernHistoryCommands = true
    private var connectionGeneration = 0
    private var watchdogGeneration = 0
    private var packetWatchdogGeneration = 0
    private var reconnectGeneration = 0
    private var consecutiveFailures = 0
    private var idleReported = false
    private var lastReportedStatus: String?
    private weak var lastPeripheral: CBPeripheral?

    private var serialNumber: String?
    private var softwareVersion: String?
    private var model: String?

    private(set) weak var cgmTransmitterDelegate: CGMTransmitterDelegate?
    private weak var cGMICanTransmitterDelegate: CGMICanTransmitterDelegate?

    private let log = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryCGMICan)

    // MARK: - init

    init(address: String?, name: String?, serialNumber: String?, bluetoothTransmitterDelegate: BluetoothTransmitterDelegate, cGMICanTransmitterDelegate: CGMICanTransmitterDelegate?, cGMTransmitterDelegate: CGMTransmitterDelegate) {

        var addressAndName: BluetoothTransmitter.DeviceAddressAndName = .notYetConnected(expectedName: nil)
        if let address {
            addressAndName = .alreadyConnectedBefore(address: address, name: name)
        }

        self.cgmTransmitterDelegate = cGMTransmitterDelegate
        self.cGMICanTransmitterDelegate = cGMICanTransmitterDelegate
        self.serialNumber = serialNumber

        super.init(addressAndName: addressAndName, CBUUID_Advertisement: CBUUID_Service_ICan, servicesCBUUIDs: [CBUUID(string: CBUUID_Service_ICan), CBUUID(string: "180A")], CBUUID_ReceiveCharacteristic: CBUUID_Receive_ICan, CBUUID_WriteCharacteristic: CBUUID_Write_ICan, bluetoothTransmitterDelegate: bluetoothTransmitterDelegate)
    }

    // MARK: - CBCentralManagerDelegate

    override func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        if deviceAddress == nil {
            let advertisedName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name
            guard ICanProtocol.isICanDeviceName(advertisedName) else { return }
        }
        super.centralManager(central, didDiscover: peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    override func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        lastPeripheral = peripheral
        resetConnectionState()
        phase = .discovering
        // MTU decides between the F1 and the legacy 01 history command family.
        let mtu = peripheral.maximumWriteValueLength(for: .withoutResponse) + 3
        modernHistoryCommands = mtu >= modernHistoryMinimumMtu
        trace("iCan: connected, MTU %{public}d", log: log, category: ConstantsLog.categoryCGMICan, type: .info, mtu)
        super.centralManager(central, didConnect: peripheral)
        armSetupWatchdog()
        armPacketWatchdog()
    }

    override func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        if phase != .streaming { consecutiveFailures += 1 }
        resetConnectionState()
        super.centralManager(central, didDisconnectPeripheral: peripheral, error: error)
    }

    override func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        cancelConnectionTimer()
        consecutiveFailures += 1
        trace("iCan: failed to connect: %{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .error, error?.localizedDescription ?? "no error")
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
        // Not calling super: the base class would enable 2AA7 before authentication.
        for characteristic in service.characteristics ?? [] {
            characteristics[characteristic.uuid] = characteristic
        }
        guard (peripheral.services ?? []).allSatisfy({ $0.characteristics != nil }), phase == .discovering else { return }
        guard characteristics[Self.measurementUUID] != nil, characteristics[Self.opsUUID] != nil else {
            trace("iCan: CGM characteristics missing, disconnecting", log: log, category: ConstantsLog.categoryCGMICan, type: .error)
            disconnect()
            return
        }
        phase = .readingIdentity
        reportStatus("Reading sensor information")
        readQueue = [Self.serialUUID, Self.softwareUUID, Self.modelUUID].filter { characteristics[$0] != nil }
        continueReads()
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didUpdateNotificationStateFor: characteristic, error: error)
        if let error {
            trace("iCan: notify on %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
        }
        if phase == .readingIdentity, characteristic.uuid == Self.opsUUID {
            // ops indications are on: start the vendor authentication
            phase = .authenticating
            reportStatus("Authenticating")
            write(ICanProtocol.requestChallenge, to: Self.opsUUID)
            return
        }
        guard phase == .configuring else { return }
        if !notificationQueue.isEmpty {
            setNotify(notificationQueue.removeFirst())
            return
        }
        // notifications ready: read the session counter, then ask for history
        readQueue = [Self.statusUUID, Self.sessionStartTimeUUID].filter { characteristics[$0] != nil }
        continueReads()
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didUpdateValueFor: characteristic, error: error)
        if let error {
            trace("iCan: update of %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
            if !readQueue.isEmpty || characteristic.uuid == Self.statusUUID || characteristic.uuid == Self.sessionStartTimeUUID {
                continueReads()
            }
            return
        }
        guard let value = characteristic.value else { return }
        let bytes = [UInt8](value)

        switch characteristic.uuid {
        case Self.serialUUID:
            let text = Self.text(bytes)
            if !text.isEmpty {
                serialNumber = text
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.cGMICanTransmitterDelegate?.received(serialNumber: text, cGMICanTransmitter: self)
                }
            }
            continueReads()
        case Self.softwareUUID:
            softwareVersion = Self.text(bytes)
            continueReads()
        case Self.modelUUID:
            model = Self.text(bytes)
            continueReads()
        case Self.statusUUID:
            handleStatus(bytes)
            continueReads()
        case Self.sessionStartTimeUUID:
            // The stored wall clock is the writer's local time and often hours off; the minute
            // counter in CGM Status is used for timestamps instead (JugglucoNG notes §7).
            continueReads()
        case Self.opsUUID:
            handleOpsIndication(bytes)
        case Self.racpUUID:
            handleRacp(bytes)
        case Self.measurementUUID:
            handleMeasurement(bytes)
        default:
            break
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didWriteValueFor: characteristic, error: error)
        if let error {
            trace("iCan: write to %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
        }
    }

    // MARK: - setup sequence

    private func continueReads() {
        if !readQueue.isEmpty {
            read(readQueue.removeFirst())
            return
        }
        switch phase {
        case .readingIdentity:
            let (model, software) = (self.model, self.softwareVersion)
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMICanTransmitterDelegate?.received(model: model, softwareVersion: software, cGMICanTransmitter: self)
            }
            trace("iCan: serial %{public}@ software %{public}@ model %{public}@ (new key family %{public}@)", log: log, category: ConstantsLog.categoryCGMICan, type: .info, serialNumber ?? "nil", softwareVersion ?? "nil", model ?? "nil", newKeyFamily.description)
            setNotify(Self.opsUUID)
        case .configuring:
            enterStreaming()
        default:
            break
        }
    }

    private var newKeyFamily: Bool {
        ICanProtocol.usesNewKeyFamily(serial: serialNumber, softwareVersion: softwareVersion)
    }

    private var profile: ICanProtocol.Profile {
        ICanProtocol.profile(model: model, serial: serialNumber, softwareVersion: softwareVersion)
    }

    private func handleOpsIndication(_ bytes: [UInt8]) {
        if let newChallenge = ICanProtocol.challenge(fromResponse: bytes) {
            challenge = newChallenge
            let userId = storedUserId() ?? ""
            guard let packet = ICanProtocol.authTokenPacket(challenge: newChallenge, userId: userId, authKey: ICanProtocol.authKey(newFamily: newKeyFamily)) else {
                trace("iCan: could not build the auth token", log: log, category: ConstantsLog.categoryCGMICan, type: .error)
                disconnect()
                return
            }
            write(packet, to: Self.opsUUID, logPayload: false)
            return
        }
        if let marker = ICanProtocol.sensorInfoMarker(bytes) {
            trace("iCan: calibration marker 0x%{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .info, String(format: "%04X", marker))
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMICanTransmitterDelegate?.received(calibrationMarker: marker, cGMICanTransmitter: self)
            }
            startConfiguring()
            return
        }
        guard let result = ICanProtocol.authResult(bytes), phase == .authenticating else {
            trace("iCan: unhandled ops indication %{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .debug, Data(bytes).hexEncodedString())
            return
        }
        if result == 0x01 {
            authenticated = true
            trace("iCan: authenticated", log: log, category: ConstantsLog.categoryCGMICan, type: .info)
            write(ICanProtocol.requestSensorInfo, to: Self.opsUUID)
            // JugglucoNG continues after 1.5 s without an F6 answer
            let generation = connectionGeneration
            runOnCentralQueue(after: 1.5) { [weak self] in
                guard let self, self.connectionGeneration == generation, self.phase == .authenticating else { return }
                self.startConfiguring()
            }
            return
        }
        if !authRetried, let challenge,
           let recovered = ICanProtocol.recoverUserId(fromReject: bytes, challenge: challenge, authKey: ICanProtocol.authKey(newFamily: newKeyFamily)) {
            // started by the vendor app: retry once with the id the sensor expects
            authRetried = true
            storeUserId(recovered)
            trace("iCan: authentication rejected, retrying with the recovered user id", log: log, category: ConstantsLog.categoryCGMICan, type: .info)
            write(ICanProtocol.requestChallenge, to: Self.opsUUID)
            return
        }
        trace("iCan: authentication rejected (0x%{public}@)", log: log, category: ConstantsLog.categoryCGMICan, type: .error, String(format: "%02X", result))
        reportStatus("Authentication rejected")
        consecutiveFailures += 1
        disconnect()
    }

    private func startConfiguring() {
        guard phase == .authenticating else { return }
        phase = .configuring
        notificationQueue = characteristics[Self.racpUUID] != nil ? [Self.racpUUID] : []
        setNotify(Self.measurementUUID)
    }

    private func enterStreaming() {
        phase = .streaming
        watchdogGeneration += 1
        consecutiveFailures = 0
        reportStatus("Connected")
        requestHistory()
    }

    private func handleStatus(_ bytes: [UInt8]) {
        guard let status = ICanProtocol.status(bytes) else { return }
        currentSequence = status.sequence
        trace("iCan: status sequence %{public}d launcher state 0x%{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .info, status.sequence, String(format: "%02X", status.launcherState))
        if status.launcherState == 0x00 {
            reportStatus("Sensor not started")
            if !idleReported {
                idleReported = true
                DispatchQueue.main.async { [weak self] in
                    self?.bluetoothTransmitterDelegate?.error(message: Texts_BluetoothPeripheralView.iCanStartWithVendorApp)
                }
            }
            return
        }
        if status.launcherState == 0x40 {
            reportStatus("Sensor ended")
        }
        let anchor = Date().addingTimeInterval(TimeInterval(-status.sequence * 60))
        if let stored = storedSessionAnchor(), abs(stored.timeIntervalSince(anchor)) < sensorSessionTolerance {
            sessionAnchor = stored
        } else {
            sessionAnchor = anchor
            storeSessionAnchor(anchor)
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMICanTransmitterDelegate?.received(sensorStartDate: anchor, cGMICanTransmitter: self)
            }
        }
    }

    // MARK: - history

    private func requestHistory(fromTail: Bool = false) {
        guard authenticated, characteristics[Self.racpUUID] != nil, let currentSequence, sessionAnchor != nil else { return }
        let interval = profile.readingIntervalMinutes
        var from: Int
        if fromTail {
            from = currentSequence - interval
        } else {
            from = max(interval, currentSequence - maximumBackfillMinutes)
            if let last = storedLastSequence() {
                from = max(from, last + interval)
            }
        }
        guard from <= currentSequence else { return }
        historyRequested = true
        historyReadings = []
        historyStartSequence = from
        reportStatus("Reading history")
        trace("iCan: requesting glucose history from sequence %{public}d (modern %{public}@)", log: log, category: ConstantsLog.categoryCGMICan, type: .info, from, modernHistoryCommands.description)
        write(ICanProtocol.reportGlucoseHistory(fromSequence: from, modern: modernHistoryCommands), to: Self.racpUUID)
    }

    private func handleRacp(_ bytes: [UInt8]) {
        guard let result = ICanProtocol.racpResult(bytes) else { return }
        trace("iCan: RACP result 0x%{public}@", log: log, category: ConstantsLog.categoryCGMICan, type: .info, String(format: "%02X", result))
        let readings = historyReadings
        historyReadings = []
        historyRequested = false
        if result == 0x0A && !historyTailRetried {
            // JugglucoNG #678: a refused range is retried once from the live edge
            historyTailRetried = true
            requestHistory(fromTail: true)
            return
        }
        if result == 0x02 && modernHistoryCommands {
            // command family not supported: try the legacy 01 family once
            modernHistoryCommands = false
            requestHistory()
            return
        }
        deliver(readings, isBackfill: true)
        reportStatus("Streaming")
    }

    // MARK: - readings

    private func handleMeasurement(_ bytes: [UInt8]) {
        guard let challenge else {
            trace("iCan: measurement before authentication, ignored", log: log, category: ConstantsLog.categoryCGMICan, type: .debug)
            return
        }
        let key = ICanProtocol.glucoseKey(newFamily: newKeyFamily)
        let warmup = profile.warmupMinutes

        if ICanProtocol.isSnBatch(bytes) {
            guard historyRequested else { return }
            if let batch = ICanProtocol.parseGlucoseSnBatch(bytes, key: key, challenge: challenge, readingIntervalMinutes: profile.readingIntervalMinutes) {
                historyReadings.append(contentsOf: batch)
            } else {
                trace("iCan: SN history batch not usable", log: log, category: ConstantsLog.categoryCGMICan, type: .info)
            }
            return
        }
        if bytes.count == 16 {
            if historyRequested, let record = ICanProtocol.parseHistoryRecord(bytes, key: key, challenge: challenge, warmupMinutes: warmup, newFamily: newKeyFamily) {
                historyReadings.append(record)
            }
            return
        }
        guard let reading = ICanProtocol.parseLiveFrame(bytes, key: key, challenge: challenge, warmupMinutes: warmup, newFamily: newKeyFamily) else {
            trace("iCan: measurement of %{public}d bytes not parsed", log: log, category: ConstantsLog.categoryCGMICan, type: .info, bytes.count)
            return
        }
        // a 19-byte frame behind the live edge while history runs is a history record
        if historyRequested, let currentSequence, reading.sequence < currentSequence {
            historyReadings.append(reading)
            return
        }
        currentSequence = max(currentSequence ?? reading.sequence, reading.sequence)
        deliver([reading], isBackfill: false)
    }

    /// Delivers readings newer than the last delivered sequence, timestamped from the session
    /// anchor (live readings use the receipt time).
    private func deliver(_ readings: [ICanProtocol.Reading], isBackfill: Bool) {
        guard let anchor = sessionAnchor else { return }
        let now = Date()
        // Live readings must be newer than the last delivered one. Backfill is bounded by its own
        // request start, so a live reading that arrived during the download does not drop it.
        let storedLast = storedLastSequence()
        let minimumSequence = isBackfill ? historyStartSequence : (storedLast.map { $0 + 1 } ?? 0)
        var newestSequence: Int?
        var glucoseData: [GlucoseData] = []
        for reading in readings.sorted(by: { $0.sequence < $1.sequence }) {
            guard reading.sequence >= minimumSequence, newestSequence.map({ reading.sequence > $0 }) ?? true else { continue }
            guard validGlucoseRange.contains(reading.glucoseMgDl) else {
                trace("iCan: glucose %{public}d mg/dL at sequence %{public}d out of range", log: log, category: ConstantsLog.categoryCGMICan, type: .info, Int(reading.glucoseMgDl), reading.sequence)
                continue
            }
            let timeStamp = isBackfill ? min(now, anchor.addingTimeInterval(TimeInterval(reading.sequence * 60))) : now
            glucoseData.append(GlucoseData(timeStamp: timeStamp, glucoseLevelRaw: reading.glucoseMgDl, backfilledAt: isBackfill ? now : nil))
            newestSequence = reading.sequence
        }
        guard let newest = newestSequence, !glucoseData.isEmpty else { return }
        if newest > (storedLast ?? -1) {
            storeLastSequence(newest)
        }
        armPacketWatchdog()
        if !isBackfill { reportStatus("Streaming") }

        glucoseData.sort { $0.timeStamp > $1.timeStamp }
        trace("iCan: delivering %{public}d reading(s), newest sequence %{public}d", log: log, category: ConstantsLog.categoryCGMICan, type: .info, glucoseData.count, newest)
        let sensorAge = TimeInterval(newest * 60)
        let tolerance = sensorSessionTolerance
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let active = UserDefaults.standard.activeSensorStartDate, abs(active.timeIntervalSince(anchor)) > tolerance {
                self.cgmTransmitterDelegate?.newSensorDetected(sensorStartDate: anchor)
            }
            self.cgmTransmitterDelegate?.cgmTransmitterInfoReceived(glucoseData: &glucoseData, transmitterBatteryInfo: nil, sensorAge: sensorAge)
        }
    }

    // MARK: - GATT helpers

    private func read(_ uuid: CBUUID) {
        guard let characteristic = characteristics[uuid] else { continueReads(); return }
        readValueForCharacteristic(for: characteristic)
    }

    private func write(_ bytes: [UInt8], to uuid: CBUUID, logPayload: Bool = true) {
        guard let characteristic = characteristics[uuid] else { return }
        _ = writeDataToPeripheral(data: Data(bytes), characteristicToWriteTo: characteristic, type: .withResponse, logPayload: logPayload)
    }

    private func setNotify(_ uuid: CBUUID) {
        guard let characteristic = characteristics[uuid] else { return }
        setNotifyValue(true, for: characteristic)
    }

    private static func text(_ bytes: [UInt8]) -> String {
        (String(bytes: bytes, encoding: .ascii) ?? "").trimmingCharacters(in: CharacterSet(charactersIn: "\0 "))
    }

    private func resetConnectionState() {
        connectionGeneration += 1
        watchdogGeneration += 1
        phase = .idle
        characteristics = [:]
        readQueue = []
        notificationQueue = []
        challenge = nil
        authRetried = false
        authenticated = false
        historyRequested = false
        historyTailRetried = false
        historyReadings = []
        currentSequence = nil
    }

    private func armSetupWatchdog() {
        watchdogGeneration += 1
        let generation = watchdogGeneration
        runOnCentralQueue(after: setupTimeout) { [weak self] in
            guard let self, self.watchdogGeneration == generation, self.phase != .streaming,
                  self.getConnectionStatus() == .connected else { return }
            trace("iCan: setup stalled in phase %{public}@", log: self.log, category: ConstantsLog.categoryCGMICan, type: .error, self.phase.rawValue)
            self.consecutiveFailures += 1
            self.disconnect()
        }
    }

    private func armPacketWatchdog() {
        packetWatchdogGeneration += 1
        let generation = packetWatchdogGeneration
        runOnCentralQueue(after: packetInactivityTimeout) { [weak self] in
            guard let self, self.packetWatchdogGeneration == generation, self.getConnectionStatus() == .connected else { return }
            trace("iCan: no reading for %{public}d s, recycling connection", log: self.log, category: ConstantsLog.categoryCGMICan, type: .error, Int(self.packetInactivityTimeout))
            self.disconnect()
        }
    }

    private func reportStatus(_ status: String) {
        guard status != lastReportedStatus else { return }
        lastReportedStatus = status
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMICanTransmitterDelegate?.received(sensorStatus: status, cGMICanTransmitter: self)
        }
    }

    // MARK: - per-serial persistence (UserDefaults; the user id is an activation fingerprint, not a key)

    private func key(_ name: String) -> String? {
        serialNumber.map { "iCan.\(name).\($0.uppercased())" }
    }

    private func storedUserId() -> String? {
        key("userId").flatMap { UserDefaults.standard.string(forKey: $0) }
    }

    private func storeUserId(_ userId: String) {
        guard let key = key("userId") else { return }
        UserDefaults.standard.set(userId, forKey: key)
    }

    private func storedSessionAnchor() -> Date? {
        key("sessionAnchor").flatMap { UserDefaults.standard.object(forKey: $0) as? Date }
    }

    private func storeSessionAnchor(_ date: Date) {
        guard let key = key("sessionAnchor") else { return }
        UserDefaults.standard.set(date, forKey: key)
        // a new session invalidates the sequence cursor
        if let sequenceKey = self.key("lastSequence") {
            UserDefaults.standard.removeObject(forKey: sequenceKey)
        }
    }

    private func storedLastSequence() -> Int? {
        key("lastSequence").flatMap { UserDefaults.standard.object(forKey: $0) as? Int }
    }

    private func storeLastSequence(_ sequence: Int) {
        guard let key = key("lastSequence") else { return }
        UserDefaults.standard.set(sequence, forKey: key)
    }

    // MARK: - CGMTransmitter

    func cgmTransmitterType() -> CGMTransmitterType {
        .iCan
    }

    func maxSensorAgeInDays() -> Double? {
        Double(profile.ratedLifetimeDays)
    }

    func sensorWarmupDurationInMinutes() -> Double? {
        Double(profile.warmupMinutes)
    }

    func getCBUUID_Service() -> String { CBUUID_Service_ICan }

    func getCBUUID_Receive() -> String { CBUUID_Receive_ICan }

    func needsSensorStartTime() -> Bool { false }

    /// The sensor sends calibrated glucose (hundredths of mmol/L).
    func isWebOOPEnabled() -> Bool { true }

    func nonWebOOPAllowed() -> Bool { false }
}
