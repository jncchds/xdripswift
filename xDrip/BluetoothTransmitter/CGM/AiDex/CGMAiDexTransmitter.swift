//
//  CGMAiDexTransmitter.swift
//  xdrip
//
//  Direct Bluetooth connection to AiDex X / LinX sensors (MicroTech Medical GX series, also sold
//  as LinX, Lumiflex, GlucoRx AiDEX, Vista, Smart, IndiaX, VitaTok).
//
//  Protocol ported from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG, a fork of
//  Juggluco by Jaap Korthals Altes), mainly
//  Common/src/main/java/tk/glucodata/drivers/aidex/native/ble/AiDexBleManager.kt.
//  The Android bond-state logic was redesigned for iOS, which exposes neither bond state nor the
//  MAC address (see "Pairing on iOS" below).
//

import Foundation
import CoreBluetooth
import os

/// AiDex X / LinX CGM transmitter.
///
/// Wire protocol (service 0x181F, the standard CGM service UUID):
/// - F001: authentication. Writing the serial-derived challenge needs an encrypted link, which
///   is when iOS shows its pairing dialog. The sensor notifies the 16-byte PAIR key.
/// - F002: read = 17-byte BOND vector (AES-CFB with the PAIR key). Write = encrypted command,
///   notify = encrypted response. Readable and writable without link encryption.
/// - F003: notify = encrypted 17-byte glucose frame about once a minute, 5-byte status frame
///   (battery) every few minutes.
///
/// Pairing on iOS: JugglucoNG decides between "saved key" and "fresh pair" from Android's bond
/// state. iOS has no bond-state API, so this class keeps its own facts in the Keychain record
/// (`AiDexPairingRecord`): whether a PAIR key exists and whether this phone ever completed an
/// F001 write (`linkPaired`). ATT and connection errors update those facts:
/// - F001 write fails with insufficient authentication/encryption: the user declined the iOS
///   dialog or iOS lost its link key, `linkPaired` becomes false.
/// - Disconnect with `peerRemovedPairingInformation`: the sensor dropped its bond while iOS kept
///   one. iOS will not pair again until the user forgets the sensor in iOS Settings.
/// - BOND decryption/CRC failure with a saved key: the sensor issued a new PAIR key. After
///   three failures a fresh F001 pairing is attempted, but only if `linkPaired`, because the
///   sensor accepts F001 only from the phone it is bonded with.
/// - F001 notifies a single 0x00: the sensor refuses to hand out a key (bonded elsewhere).
@objcMembers
class CGMAiDexTransmitter: BluetoothTransmitter, CGMTransmitter {

    // MARK: - UUIDs

    private static let serviceUUID = CBUUID(string: "181F")
    private static let authCharacteristicUUID = CBUUID(string: "F001")
    private static let commandCharacteristicUUID = CBUUID(string: "F002")
    private static let dataCharacteristicUUID = CBUUID(string: "F003")
    private static let sessionStartTimeCharacteristicUUID = CBUUID(string: "2AAA")

    private let CBUUID_Service_AiDex = "181F"
    private let CBUUID_Receive_AiDex = "F003"
    private let CBUUID_Write_AiDex = "F002"

    // MARK: - timing (JugglucoNG AiDexBleManager constants where available)

    /// KEY_EXCHANGE_TIMEOUT_MS is 35 s; fresh pairing gets longer for the iOS pairing dialog.
    private let savedKeyExchangeTimeout: TimeInterval = 35
    private let freshPairExchangeTimeout: TimeInterval = 75
    /// short BOND reads are retried once after 400 ms (BOND_REREAD_DELAY_MS)
    private let bondRereadDelay: TimeInterval = 0.4
    /// live frames arrive every 60 s; JugglucoNG refreshes notifications after 80 s without one
    private let noStreamRefreshTimeout: TimeInterval = 80
    /// recycle the connection when nothing valid arrived for this long
    private let packetInactivityTimeout: TimeInterval = 5 * 60
    /// INITIAL_HISTORY_REQUEST_DELAY_MS: history waits for the first live frame, at most 65 s
    private let initialHistoryDelay: TimeInterval = 65
    private let commandTimeout: TimeInterval = 6
    /// HISTORY_PAGE_TIMEOUT_MS
    private let historyPageTimeout: TimeInterval = 25
    private let maximumBackfill: TimeInterval = 12 * 60 * 60
    private let maximumHistoryPages = 200
    private let reconnectDelays: [TimeInterval] = [1, 5, 15, 30, 60, 120, 300]
    private let savedKeyFailuresBeforeRepair = 3
    private let sensorSessionTolerance: TimeInterval = 10 * 60

    // MARK: - state (centralQueue only)

    private enum Phase: String {
        case idle, discovering, enablingNotifications, awaitingPairKey, readingBond, streaming
    }

    private struct PendingCommand {
        let opcode: UInt8
        let params: [UInt8]
        let timeout: TimeInterval
    }

    private var phase: Phase = .idle
    private var connectionGeneration = 0

    private weak var lastPeripheral: CBPeripheral?
    private var authCharacteristic: CBCharacteristic?
    private var commandCharacteristic: CBCharacteristic?
    private var dataCharacteristic: CBCharacteristic?
    private var sessionStartTimeCharacteristic: CBCharacteristic?

    private var notificationQueue: [CBCharacteristic] = []
    private var keyExchange: AiDexKeyExchange?
    private var usingSavedKey = false
    private var freshPairWrittenThisConnection = false
    private var bondReadPending = false
    private var shortBondReads = 0
    private var pairKeyAwaitingValidation = false

    private var commandQueue: [PendingCommand] = []
    private var commandInFlight: UInt8?
    private var commandGeneration = 0

    private var historyRequested = false
    private var historyNewestOffset = 0
    private var historyEntries: [AiDexHistoryEntry] = []
    private var historyPages = 0
    private var historyRangeReceivedAt: Date?
    /// offset after which history is still missing, captured before live frames move it
    private var historyFromOffset: Int?

    private var activationAttemptedThisConnection = false
    private var noStreamRefreshDone = false
    private var lastF003At: Date?
    private var lastDeliveredLiveOffset: Int?
    private var lastLiveReceiptDate: Date?
    private var liveAnchorStartDate: Date?
    private var lastInferredStartReported: Date?
    private var reportedStartDate: Date?
    private var wearDays: Int?
    private var lastReportedBatteryMillivolts: Int?
    private var lastReportedStatus: String?

    private var consecutiveFailures = 0
    private var savedKeyFailures = 0
    private var forceFreshPairing = false
    private var refusalReported = false

    private var watchdogGeneration = 0
    private var packetWatchdogGeneration = 0
    private var reconnectGeneration = 0

    /// bare serial, from the stored value or from the advertised name
    private var serialNumber: String?

    private let pairingStore: AiDexPairingStore

    private(set) weak var cgmTransmitterDelegate: CGMTransmitterDelegate?
    private weak var cGMAiDexTransmitterDelegate: CGMAiDexTransmitterDelegate?

    private let log = OSLog(subsystem: ConstantsLog.subSystem, category: ConstantsLog.categoryCGMAiDex)

    // MARK: - init

    /// - parameters:
    ///     - address: CoreBluetooth identifier from a previous connection, nil when scanning
    ///     - name: advertised name from a previous connection
    ///     - serialNumber: bare serial stored for this sensor, if known
    init(address: String?, name: String?, serialNumber: String?, bluetoothTransmitterDelegate: BluetoothTransmitterDelegate, cGMAiDexTransmitterDelegate: CGMAiDexTransmitterDelegate?, cGMTransmitterDelegate: CGMTransmitterDelegate, pairingStore: AiDexPairingStore = .shared) {

        var addressAndName: BluetoothTransmitter.DeviceAddressAndName = .notYetConnected(expectedName: nil)
        if let address {
            addressAndName = .alreadyConnectedBefore(address: address, name: name)
        }

        self.cgmTransmitterDelegate = cGMTransmitterDelegate
        self.cGMAiDexTransmitterDelegate = cGMAiDexTransmitterDelegate
        self.pairingStore = pairingStore
        self.serialNumber = serialNumber ?? name.flatMap(AiDexSerialIdentity.serial(fromAdvertisedName:))

        // Scanning is filtered on the CGM service UUID so it also works in the background. The
        // advertised name is checked in didDiscover because AiDex rebrands use many prefixes.
        super.init(addressAndName: addressAndName, CBUUID_Advertisement: CBUUID_Service_AiDex, servicesCBUUIDs: [CBUUID(string: CBUUID_Service_AiDex)], CBUUID_ReceiveCharacteristic: CBUUID_Receive_AiDex, CBUUID_WriteCharacteristic: CBUUID_Write_AiDex, bluetoothTransmitterDelegate: bluetoothTransmitterDelegate)
    }

    // MARK: - CBCentralManagerDelegate

    override func centralManager(_ central: CBCentralManager, didDiscover peripheral: CBPeripheral, advertisementData: [String: Any], rssi RSSI: NSNumber) {
        // A known sensor is matched on its CoreBluetooth identifier by the base class.
        if deviceAddress == nil {
            let advertisedName = (advertisementData[CBAdvertisementDataLocalNameKey] as? String) ?? peripheral.name
            // The scan is already filtered on service 0x181F; the name must also carry a serial.
            guard let advertisedName,
                  let serial = AiDexSerialIdentity.serial(fromAdvertisedName: advertisedName) else {
                return
            }
            if let wanted = serialNumber, wanted.caseInsensitiveCompare(serial) != .orderedSame {
                trace("AiDex: ignoring sensor %{public}@, waiting for %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, serial, wanted)
                return
            }
            serialNumber = serial
        }
        super.centralManager(central, didDiscover: peripheral, advertisementData: advertisementData, rssi: RSSI)
    }

    override func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        lastPeripheral = peripheral
        resetConnectionState()
        phase = .discovering
        if serialNumber == nil, let name = peripheral.name {
            serialNumber = AiDexSerialIdentity.serial(fromAdvertisedName: name)
        }
        if let serialNumber {
            historyFromOffset = storedLastOffset(serial: serialNumber).map { $0 + 1 }
            let serial = serialNumber
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMAiDexTransmitterDelegate?.received(serialNumber: serial, cGMAiDexTransmitter: self)
            }
        }
        super.centralManager(central, didConnect: peripheral)
        armPacketWatchdog()
    }

    override func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        if let cbError = error as? CBError, cbError.code == .peerRemovedPairingInformation {
            // The sensor no longer knows this phone while iOS still holds a link key. iOS will not
            // pair again until the user removes the sensor from Settings > Bluetooth.
            trace("AiDex: sensor removed its pairing information; forget the sensor in iOS Bluetooth settings", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
            updateRecord { $0.linkPaired = false }
            reportStatus("Pairing removed by sensor")
            DispatchQueue.main.async { [weak self] in
                self?.bluetoothTransmitterDelegate?.error(message: Texts_BluetoothPeripheralView.aiDexForgetInIOSSettings)
            }
        }
        if phase != .streaming && phase != .idle {
            consecutiveFailures += 1
        }
        resetConnectionState()
        super.centralManager(central, didDisconnectPeripheral: peripheral, error: error)
    }

    override func centralManager(_ central: CBCentralManager, didFailToConnect peripheral: CBPeripheral, error: Error?) {
        lastPeripheral = peripheral
        cancelConnectionTimer()
        consecutiveFailures += 1
        trace("AiDex: failed to connect: %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, error?.localizedDescription ?? "no error")
        reconnectAfterDisconnect(central)
    }

    /// Back off after failed setups so a sensor that refuses us is not hammered.
    override func reconnectAfterDisconnect(_ central: CBCentralManager) {
        guard let peripheral = lastPeripheral else { return }
        let delay = reconnectDelays[min(consecutiveFailures, reconnectDelays.count - 1)]
        reconnectGeneration += 1
        let generation = reconnectGeneration
        trace("AiDex: reconnecting in %{public}d s (failures %{public}d)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, Int(delay), consecutiveFailures)
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
            self?.commandGeneration += 1
        }
        super.prepareForRelease()
    }

    // MARK: - CBPeripheralDelegate

    override func peripheral(_ peripheral: CBPeripheral, didDiscoverCharacteristicsFor service: CBService, error: Error?) {
        // The base class stores F002 as write and F003 as receive characteristic and enables F003.
        super.peripheral(peripheral, didDiscoverCharacteristicsFor: service, error: error)

        guard service.uuid == Self.serviceUUID, let characteristics = service.characteristics else { return }
        for characteristic in characteristics {
            switch characteristic.uuid {
            case Self.authCharacteristicUUID: authCharacteristic = characteristic
            case Self.commandCharacteristicUUID: commandCharacteristic = characteristic
            case Self.dataCharacteristicUUID: dataCharacteristic = characteristic
            case Self.sessionStartTimeCharacteristicUUID: sessionStartTimeCharacteristic = characteristic
            default: break
            }
        }

        guard authCharacteristic != nil, let commandCharacteristic, dataCharacteristic != nil else {
            trace("AiDex: F001/F002/F003 missing, disconnecting", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
            disconnect()
            return
        }

        // F003 is enabled by the base class; F002 follows, F001 only for a fresh pairing.
        phase = .enablingNotifications
        notificationQueue = [commandCharacteristic]
        if shouldFreshPair(), let authCharacteristic {
            notificationQueue.append(authCharacteristic)
        }
        armSetupWatchdog(timeout: savedKeyExchangeTimeout)
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateNotificationStateFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didUpdateNotificationStateFor: characteristic, error: error)

        if let error {
            // JugglucoNG continues with the next characteristic after a failed CCCD write. An auth
            // error here means iOS is pairing; CoreBluetooth retries the write after pairing.
            trace("AiDex: notify on %{public}@ failed: %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, characteristic.uuid.uuidString, error.localizedDescription)
        }

        guard phase == .enablingNotifications else { return }
        if !notificationQueue.isEmpty {
            let next = notificationQueue.removeFirst()
            setNotifyValue(true, for: next)
            return
        }
        // The last queued characteristic (F002 or F001) answered.
        if characteristic.uuid == Self.commandCharacteristicUUID || characteristic.uuid == Self.authCharacteristicUUID {
            startKeyExchange()
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didUpdateValueFor characteristic: CBCharacteristic, error: Error?) {
        // F001 carries the PAIR key: do not let the base class trace its bytes.
        if characteristic.uuid == Self.authCharacteristicUUID {
            requestSignalStrengthForTraceIfNeeded(from: peripheral)
            guard error == nil, let value = characteristic.value else {
                trace("AiDex: F001 update error: %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, error?.localizedDescription ?? "no value")
                return
            }
            handleAuthNotification([UInt8](value))
            return
        }

        super.peripheral(peripheral, didUpdateValueFor: characteristic, error: error)

        if let error {
            if characteristic.uuid == Self.commandCharacteristicUUID, bondReadPending {
                bondReadPending = false
                failKeyExchange(reason: "F002 BOND read failed: " + error.localizedDescription)
            } else if characteristic.uuid == Self.sessionStartTimeCharacteristicUUID {
                // fall back to the encrypted raw 0x21 query
                enqueueCommand(AiDexOpcodes.getStartTime)
            }
            return
        }
        guard let value = characteristic.value else { return }
        let bytes = [UInt8](value)

        switch characteristic.uuid {
        case Self.commandCharacteristicUUID:
            if bondReadPending {
                bondReadPending = false
                handleBondData(bytes)
            } else {
                handleCommandResponse(bytes)
            }
        case Self.dataCharacteristicUUID:
            handleDataNotification(bytes)
        case Self.sessionStartTimeCharacteristicUUID:
            handleStartTime(AiDexParser.parseLocalStartTime(bytes), source: "2AAA", allowActivation: true)
        default:
            break
        }
    }

    override func peripheral(_ peripheral: CBPeripheral, didWriteValueFor characteristic: CBCharacteristic, error: Error?) {
        super.peripheral(peripheral, didWriteValueFor: characteristic, error: error)

        guard characteristic.uuid == Self.authCharacteristicUUID else {
            if let error, characteristic.uuid == Self.commandCharacteristicUUID {
                trace("AiDex: F002 write failed: %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, error.localizedDescription)
            }
            return
        }

        if let error {
            let authenticationError = Self.isAuthenticationError(error)
            trace("AiDex: F001 write failed (auth error %{public}@): %{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, authenticationError.description, error.localizedDescription)
            if authenticationError {
                updateRecord { $0.linkPaired = false }
            }
            if phase == .awaitingPairKey {
                // The challenge never reached the sensor: the iOS dialog was declined or failed.
                DispatchQueue.main.async { [weak self] in
                    self?.bluetoothTransmitterDelegate?.pairingFailed()
                }
                failKeyExchange(reason: "F001 challenge write failed")
            }
            return
        }

        if phase == .awaitingPairKey {
            // A completed F001 write proves an encrypted link, so iOS now holds a link key.
            freshPairWrittenThisConnection = true
            trace("AiDex: challenge accepted on an encrypted link, waiting for PAIR key", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
        }
    }

    // MARK: - key exchange

    private func shouldFreshPair() -> Bool {
        guard let serialNumber, let record = pairingStore.load(serial: serialNumber) else { return true }
        return forceFreshPairing && record.linkPaired
    }

    private func startKeyExchange() {
        guard let serialNumber else {
            trace("AiDex: no serial in the advertised name, cannot derive keys", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
            reportStatus("Serial number unknown")
            disconnect()
            return
        }
        var exchange = AiDexKeyExchange(serial: serialNumber)
        bondReadPending = false
        shortBondReads = 0

        if !shouldFreshPair(), let record = pairingStore.load(serial: serialNumber) {
            exchange.setPairKey([UInt8](record.pairKey))
            keyExchange = exchange
            usingSavedKey = true
            pairKeyAwaitingValidation = false
            phase = .readingBond
            reportStatus("Authenticating")
            trace("AiDex: key exchange with saved PAIR key", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
            armSetupWatchdog(timeout: savedKeyExchangeTimeout)
            readBondData()
            return
        }

        guard let authCharacteristic else { return }
        keyExchange = exchange
        usingSavedKey = false
        phase = .awaitingPairKey
        reportStatus("Pairing")
        trace("AiDex: fresh pairing, writing challenge to F001", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
        armSetupWatchdog(timeout: freshPairExchangeTimeout)
        // iOS shows its own pairing dialog when this write meets an unencrypted link.
        _ = writeDataToPeripheral(data: Data(exchange.challenge), characteristicToWriteTo: authCharacteristic, type: .withResponse, logPayload: false)
    }

    private func handleAuthNotification(_ bytes: [UInt8]) {
        guard bytes.count >= 16 else {
            if bytes == [0x00] {
                // The sensor declined to issue a key: it is bonded to another phone or app.
                trace("AiDex: sensor refused to issue a PAIR key", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
                reportStatus("Sensor refused pairing")
                if !refusalReported {
                    refusalReported = true
                    DispatchQueue.main.async { [weak self] in
                        self?.bluetoothTransmitterDelegate?.error(message: Texts_BluetoothPeripheralView.aiDexPairingRefused)
                    }
                }
            } else {
                trace("AiDex: short F001 notification (%{public}d bytes)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, bytes.count)
            }
            return
        }
        guard phase == .awaitingPairKey, keyExchange != nil, keyExchange?.pairKey == nil else { return }
        keyExchange?.setPairKey(Array(bytes[0..<16]))
        pairKeyAwaitingValidation = true
        // Getting the notification also proves the challenge reached the sensor.
        freshPairWrittenThisConnection = true
        trace("AiDex: PAIR key received, reading BOND data", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
        phase = .readingBond
        readBondData()
    }

    private func readBondData() {
        guard let commandCharacteristic else { return }
        bondReadPending = true
        readValueForCharacteristic(for: commandCharacteristic)
    }

    private func handleBondData(_ bytes: [UInt8]) {
        guard phase == .readingBond, keyExchange != nil else { return }
        if bytes.count < 17 {
            if shortBondReads < 1 {
                shortBondReads += 1
                trace("AiDex: short BOND read (%{public}d bytes), reading again", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, bytes.count)
                let generation = connectionGeneration
                runOnCentralQueue(after: bondRereadDelay) { [weak self] in
                    guard let self, self.connectionGeneration == generation, self.phase == .readingBond else { return }
                    self.readBondData()
                }
            } else {
                failKeyExchange(reason: "sensor refused BOND data (\(bytes.count) bytes)")
            }
            return
        }
        guard keyExchange?.decryptBond(Array(bytes[0..<17])) == true else {
            failKeyExchange(reason: "BOND decryption or CRC failed")
            return
        }
        trace("AiDex: session key established", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
        sendPostBondConfigIfLinkPaired()

        if freshPairWrittenThisConnection {
            // JugglucoNG: a sensor drops CCCDs written before the link was encrypted. Rewrite them.
            let generation = connectionGeneration
            runOnCentralQueue(after: 0.5) { [weak self] in
                guard let self, self.connectionGeneration == generation else { return }
                for characteristic in [self.dataCharacteristic, self.commandCharacteristic].compactMap({ $0 }) {
                    self.setNotifyValue(false, for: characteristic)
                    self.setNotifyValue(true, for: characteristic)
                }
                self.enterStreaming()
            }
        } else {
            enterStreaming()
        }
    }

    /// Writes the encrypted `10 C1 F3` config to F001 only when the link is known to be paired.
    /// On an unpaired link the write would trigger an iOS pairing dialog the sensor refuses;
    /// JugglucoNG skips it there too and the sensor streams without it.
    private func sendPostBondConfigIfLinkPaired() {
        guard let serialNumber, let authCharacteristic, let config = keyExchange?.postBondConfig() else { return }
        let linkPaired = freshPairWrittenThisConnection || (pairingStore.load(serial: serialNumber)?.linkPaired ?? false)
        guard linkPaired else {
            trace("AiDex: link not paired, skipping post-BOND config", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
            return
        }
        _ = writeDataToPeripheral(data: Data(config), characteristicToWriteTo: authCharacteristic, type: .withResponse, logPayload: false)
    }

    private func failKeyExchange(reason: String) {
        trace("AiDex: key exchange failed (%{public}@, saved key %{public}@)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, reason, usingSavedKey.description)
        consecutiveFailures += 1
        if usingSavedKey {
            savedKeyFailures += 1
            if savedKeyFailures >= savedKeyFailuresBeforeRepair {
                let linkPaired = serialNumber.flatMap { pairingStore.load(serial: $0)?.linkPaired } ?? false
                if linkPaired {
                    // The sensor accepts F001 from the phone it is bonded to: replace the key.
                    trace("AiDex: saved key rejected %{public}d times, pairing again over F001", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, savedKeyFailures)
                    forceFreshPairing = true
                    savedKeyFailures = 0
                } else if !refusalReported {
                    refusalReported = true
                    reportStatus("Saved pairing key rejected")
                    DispatchQueue.main.async { [weak self] in
                        self?.bluetoothTransmitterDelegate?.error(message: Texts_BluetoothPeripheralView.aiDexSavedKeyRejected)
                    }
                }
            }
        }
        keyExchange?.reset()
        phase = .idle
        disconnect()
    }

    // MARK: - streaming

    private func enterStreaming() {
        phase = .streaming
        watchdogGeneration += 1
        consecutiveFailures = 0
        reportStatus("Connected, waiting for data")
        trace("AiDex: streaming", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)

        enqueueCommand(AiDexOpcodes.getStartupDeviceInfo)
        let linkPaired = freshPairWrittenThisConnection || (serialNumber.flatMap { pairingStore.load(serial: $0)?.linkPaired } ?? false)
        if linkPaired, let sessionStartTimeCharacteristic {
            // 2AAA may need an encrypted link; reading it on an unpaired link would show a dialog.
            readValueForCharacteristic(for: sessionStartTimeCharacteristic)
        } else {
            enqueueCommand(AiDexOpcodes.getStartTime)
        }

        let generation = connectionGeneration
        runOnCentralQueue(after: noStreamRefreshTimeout) { [weak self] in
            guard let self, self.connectionGeneration == generation, self.phase == .streaming,
                  self.lastF003At == nil, !self.noStreamRefreshDone else { return }
            self.noStreamRefreshDone = true
            trace("AiDex: no F003 frame yet, refreshing notifications", log: self.log, category: ConstantsLog.categoryCGMAiDex, type: .info)
            for characteristic in [self.dataCharacteristic, self.commandCharacteristic].compactMap({ $0 }) {
                self.setNotifyValue(false, for: characteristic)
                self.setNotifyValue(true, for: characteristic)
            }
        }
        runOnCentralQueue(after: initialHistoryDelay) { [weak self] in
            guard let self, self.connectionGeneration == generation else { return }
            self.requestHistoryIfNeeded()
        }
    }

    private func handleDataNotification(_ encrypted: [UInt8]) {
        guard let keyExchange, keyExchange.isComplete else {
            trace("AiDex: F003 before session key, ignored", log: log, category: ConstantsLog.categoryCGMAiDex, type: .debug)
            return
        }
        lastF003At = Date()
        guard let decrypted = keyExchange.decrypt(encrypted) else { return }

        switch decrypted.count {
        case AiDexOpcodes.statusFrameLength:
            if let millivolts = AiDexParser.batteryMillivolts(fromStatusFrame: decrypted), millivolts != lastReportedBatteryMillivolts {
                lastReportedBatteryMillivolts = millivolts
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.cGMAiDexTransmitterDelegate?.received(batteryMillivolts: millivolts, cGMAiDexTransmitter: self)
                }
            }
        case AiDexOpcodes.dataFrameLength:
            guard AiDexParser.dataFrameCrcIsValid(decrypted), let frame = AiDexParser.parseDataFrame(decrypted) else {
                trace("AiDex: F003 frame failed CRC or parsing", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
                return
            }
            handleLiveFrame(frame)
        default:
            trace("AiDex: F003 frame of %{public}d bytes ignored", log: log, category: ConstantsLog.categoryCGMAiDex, type: .debug, decrypted.count)
        }
    }

    private func handleLiveFrame(_ frame: AiDexGlucoseFrame) {
        guard frame.isValid else {
            trace("AiDex: sensor reports no valid glucose yet (offset %{public}d min)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, frame.timeOffsetMinutes)
            reportStatus("Warming up or no valid reading")
            return
        }
        armPacketWatchdog()
        consecutiveFailures = 0
        savedKeyFailures = 0
        forceFreshPairing = false
        persistValidatedPairKeyIfNeeded()
        reportStatus("Streaming")

        guard frame.timeOffsetMinutes != lastDeliveredLiveOffset else { return }
        lastDeliveredLiveOffset = frame.timeOffsetMinutes

        let receiptDate = Date()
        let sensorAge = TimeInterval(frame.timeOffsetMinutes * 60)
        let inferredStart = receiptDate.addingTimeInterval(-sensorAge)
        liveAnchorStartDate = inferredStart
        lastLiveReceiptDate = receiptDate
        if let serialNumber {
            storeLastOffset(frame.timeOffsetMinutes, serial: serialNumber)
        }

        trace("AiDex: glucose %{public}d mg/dL, offset %{public}d min, opcode 0x%{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, Int(frame.glucoseMgDl.rounded()), frame.timeOffsetMinutes, Self.hex(frame.opcode))

        // Session changes are detected from the live minute counter only. Mixing it with the
        // sensor's wall-clock start (2AAA, time-zone dependent) could flip between two values
        // and start a new xDrip sensor on every reconnect.
        let tolerance = sensorSessionTolerance
        var reportInferredStart = false
        if reportedStartDate == nil, lastInferredStartReported.map({ abs($0.timeIntervalSince(inferredStart)) > 120 }) ?? true {
            lastInferredStartReported = inferredStart
            reportInferredStart = true
        }
        var readings = [GlucoseData(timeStamp: receiptDate, glucoseLevelRaw: frame.glucoseMgDl)]
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            if let active = UserDefaults.standard.activeSensorStartDate,
               abs(active.timeIntervalSince(inferredStart)) > tolerance {
                trace("AiDex: sensor session changed", log: self.log, category: ConstantsLog.categoryCGMAiDex, type: .info)
                self.cgmTransmitterDelegate?.newSensorDetected(sensorStartDate: inferredStart)
            }
            self.cgmTransmitterDelegate?.cgmTransmitterInfoReceived(glucoseData: &readings, transmitterBatteryInfo: nil, sensorAge: sensorAge)
            if reportInferredStart {
                self.cGMAiDexTransmitterDelegate?.received(sensorStartDate: inferredStart, cGMAiDexTransmitter: self)
            }
        }

        requestHistoryIfNeeded()
    }

    /// A fresh PAIR key is stored only after a CRC-valid live frame proved it end to end.
    private func persistValidatedPairKeyIfNeeded() {
        guard pairKeyAwaitingValidation, let serialNumber, let pairKey = keyExchange?.pairKey else { return }
        let record = AiDexPairingRecord(serial: serialNumber, pairKey: Data(pairKey), linkPaired: freshPairWrittenThisConnection, savedAt: Date())
        guard pairingStore.save(record) else {
            trace("AiDex: could not store the PAIR key in the Keychain, will retry", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error)
            return
        }
        pairKeyAwaitingValidation = false
        refusalReported = false
        trace("AiDex: PAIR key validated and stored", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
        DispatchQueue.main.async { [weak self] in
            self?.bluetoothTransmitterDelegate?.successfullyPaired()
        }
    }

    // MARK: - F002 commands

    private func enqueueCommand(_ opcode: UInt8, params: [UInt8] = [], timeout: TimeInterval? = nil) {
        commandQueue.append(PendingCommand(opcode: opcode, params: params, timeout: timeout ?? commandTimeout))
        sendNextCommand()
    }

    private func sendNextCommand() {
        guard commandInFlight == nil, phase == .streaming, !commandQueue.isEmpty,
              let commandCharacteristic, let keyExchange else { return }
        let command = commandQueue.removeFirst()
        guard let encrypted = AiDexCommandBuilder.encrypted(command.opcode, command.params, keyExchange: keyExchange) else {
            sendNextCommand()
            return
        }

        commandInFlight = command.opcode
        commandGeneration += 1
        let generation = commandGeneration
        let type: CBCharacteristicWriteType = commandCharacteristic.properties.contains(.writeWithoutResponse) ? .withoutResponse : .withResponse
        _ = writeDataToPeripheral(data: Data(encrypted), characteristicToWriteTo: commandCharacteristic, type: type, logPayload: false)

        runOnCentralQueue(after: command.timeout) { [weak self] in
            guard let self, self.commandGeneration == generation, self.commandInFlight == command.opcode else { return }
            trace("AiDex: no response to 0x%{public}@", log: self.log, category: ConstantsLog.categoryCGMAiDex, type: .error, Self.hex(command.opcode))
            self.commandInFlight = nil
            if command.opcode == AiDexOpcodes.getHistoriesRaw || command.opcode == AiDexOpcodes.getHistoryRange {
                self.finishHistory()
            }
            self.sendNextCommand()
        }
    }

    private func handleCommandResponse(_ encrypted: [UInt8]) {
        guard let keyExchange, keyExchange.isComplete, let plaintext = keyExchange.decrypt(encrypted), let opcode = plaintext.first else { return }

        if AiDexOpcodes.dataOpcodes.contains(opcode), !AiDexCrc16CcittFalse.isValidTrailer(plaintext) {
            trace("AiDex: CRC failed for response 0x%{public}@, rejected", log: log, category: ConstantsLog.categoryCGMAiDex, type: .error, Self.hex(opcode))
            if commandInFlight == opcode { commandInFlight = nil }
            if opcode == AiDexOpcodes.getHistoriesRaw || opcode == AiDexOpcodes.getHistoryRange { finishHistory() }
            sendNextCommand()
            return
        }

        if commandInFlight == opcode {
            commandInFlight = nil
            commandGeneration += 1
        }

        switch opcode {
        case AiDexOpcodes.getStartupDeviceInfo:
            if let info = AiDexParser.parseStartupDeviceInfo(response: plaintext) {
                trace("AiDex: model %{public}@ firmware %{public}@ hardware %{public}@ wear days %{public}d", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, info.modelName, info.firmwareVersion, info.hardwareVersion, info.wearDays)
                if info.wearDays > 0 { wearDays = info.wearDays }
                DispatchQueue.main.async { [weak self] in
                    guard let self else { return }
                    self.cGMAiDexTransmitterDelegate?.received(deviceInfo: info, cGMAiDexTransmitter: self)
                }
            }
        case AiDexOpcodes.getStartTime:
            handleStartTime(AiDexParser.parseLocalStartTime(AiDexParser.responsePayload(plaintext)), source: "0x21", allowActivation: false)
        case AiDexOpcodes.setNewSensor:
            let status = plaintext.count > 1 ? plaintext[1] : 0xFF
            trace("AiDex: activation answered with status 0x%{public}@", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, Self.hex(status))
            if status == 0x00 {
                reportStatus("Sensor activated, warming up")
                let generation = connectionGeneration
                runOnCentralQueue(after: 2) { [weak self] in
                    guard let self, self.connectionGeneration == generation else { return }
                    if let sessionStartTimeCharacteristic = self.sessionStartTimeCharacteristic {
                        self.readValueForCharacteristic(for: sessionStartTimeCharacteristic)
                    } else {
                        self.enqueueCommand(AiDexOpcodes.getStartTime)
                    }
                }
            }
        case AiDexOpcodes.getHistoryRange:
            handleHistoryRange(plaintext)
        case AiDexOpcodes.getHistoriesRaw:
            handleHistoryPage(plaintext)
        default:
            trace("AiDex: response 0x%{public}@ (%{public}d bytes) not used", log: log, category: ConstantsLog.categoryCGMAiDex, type: .debug, Self.hex(opcode), plaintext.count)
        }
        sendNextCommand()
    }

    // MARK: - session start / activation

    private func handleStartTime(_ startTime: AiDexLocalStartTime?, source: StaticString, allowActivation: Bool) {
        guard let startTime else {
            trace("AiDex: start time from %{public}@ not usable", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, source.description)
            return
        }
        if startTime.isAllZeros {
            trace("AiDex: start time from %{public}@ is zero, sensor not activated", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, source.description)
            if allowActivation && !activationAttemptedThisConnection {
                // JugglucoNG auto-activates a fresh sensor from the CGM session characteristic.
                activationAttemptedThisConnection = true
                trace("AiDex: activating new sensor (SET_NEW_SENSOR)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info)
                enqueueCommand(AiDexOpcodes.setNewSensor, params: AiDexCommandBuilder.newSensorParams(date: Date(), timeZone: .current))
            }
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.cGMAiDexTransmitterDelegate?.received(sensorStartDate: nil, cGMAiDexTransmitter: self)
            }
            return
        }
        guard let date = startTime.date, date < Date().addingTimeInterval(24 * 3600) else { return }
        reportedStartDate = date
        trace("AiDex: sensor started %{public}@ (from %{public}@)", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, date.description, source.description)
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMAiDexTransmitterDelegate?.received(sensorStartDate: date, cGMAiDexTransmitter: self)
        }
    }

    // MARK: - history backfill

    private func requestHistoryIfNeeded() {
        guard phase == .streaming, !historyRequested, keyExchange?.isComplete == true else { return }
        historyRequested = true
        enqueueCommand(AiDexOpcodes.getHistoryRange)
    }

    private func handleHistoryRange(_ response: [UInt8]) {
        guard let range = AiDexParser.parseHistoryRange(response), range.newest > 0 else {
            finishHistory()
            return
        }
        historyRangeReceivedAt = Date()
        historyNewestOffset = range.newest
        historyEntries = []
        historyPages = 0

        let maximumBackfillMinutes = Int(maximumBackfill / 60)
        var from = max(range.rawStart, range.newest - maximumBackfillMinutes)
        if let historyFromOffset, historyFromOffset <= range.newest + 1 {
            from = max(from, historyFromOffset)
        }
        trace("AiDex: history range raw %{public}d...%{public}d, requesting from %{public}d", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, range.rawStart, range.newest, from)
        guard from <= range.newest else {
            finishHistory()
            return
        }
        enqueueCommand(AiDexOpcodes.getHistoriesRaw, params: AiDexCommandBuilder.u16(from), timeout: historyPageTimeout)
    }

    private func handleHistoryPage(_ response: [UInt8]) {
        let entries = AiDexParser.parseCalibratedHistory(AiDexParser.responsePayload(response))
        historyPages += 1
        guard let last = entries.last else {
            finishHistory()
            return
        }
        historyEntries.append(contentsOf: entries)
        let next = last.timeOffsetMinutes + 1
        if next <= historyNewestOffset && historyPages < maximumHistoryPages {
            enqueueCommand(AiDexOpcodes.getHistoriesRaw, params: AiDexCommandBuilder.u16(next), timeout: historyPageTimeout)
        } else {
            finishHistory()
        }
    }

    /// Delivers the downloaded calibrated history as backfill, one value per 5 minutes.
    private func finishHistory() {
        let entries = historyEntries
        historyEntries = []
        guard !entries.isEmpty else { return }

        // History offsets share the live frame's minute counter, so the live anchor is preferred.
        let anchorCandidate: Date?
        if let liveAnchorStartDate {
            anchorCandidate = liveAnchorStartDate
        } else if let reportedStartDate {
            anchorCandidate = reportedStartDate
        } else if let historyRangeReceivedAt {
            anchorCandidate = historyRangeReceivedAt.addingTimeInterval(TimeInterval(-historyNewestOffset * 60))
        } else {
            anchorCandidate = nil
        }
        guard let anchor = anchorCandidate else { return }

        let now = Date()
        let liveCutoff = lastLiveReceiptDate?.addingTimeInterval(-30) ?? now
        let alignment = (lastDeliveredLiveOffset ?? historyNewestOffset) % 5
        let valid = entries.filter {
            !$0.isSentinel
                && $0.glucoseMgDl >= AiDexOpcodes.minValidGlucose
                && $0.glucoseMgDl <= AiDexOpcodes.maxValidGlucose
                && $0.timeOffsetMinutes % 5 == alignment
        }
        var readings: [GlucoseData] = valid.compactMap { entry -> GlucoseData? in
            let timeStamp = anchor.addingTimeInterval(TimeInterval(entry.timeOffsetMinutes * 60))
            guard timeStamp < liveCutoff, timeStamp <= now else { return nil }
            return GlucoseData(timeStamp: timeStamp, glucoseLevelRaw: Double(entry.glucoseMgDl), backfilledAt: now)
        }
        // youngest first
        readings.sort { $0.timeStamp > $1.timeStamp }
        guard let youngest = readings.first else { return }

        let youngestOffset = Int(youngest.timeStamp.timeIntervalSince(anchor) / 60)
        if let serialNumber, let maxOffset = entries.map(\.timeOffsetMinutes).max(), (storedLastOffset(serial: serialNumber) ?? -1) < maxOffset {
            storeLastOffset(maxOffset, serial: serialNumber)
        }
        trace("AiDex: delivering %{public}d backfill readings", log: log, category: ConstantsLog.categoryCGMAiDex, type: .info, readings.count)
        DispatchQueue.main.async { [weak self] in
            self?.cgmTransmitterDelegate?.cgmTransmitterInfoReceived(glucoseData: &readings, transmitterBatteryInfo: nil, sensorAge: TimeInterval(youngestOffset * 60))
        }
    }

    // MARK: - watchdogs

    private func armSetupWatchdog(timeout: TimeInterval) {
        watchdogGeneration += 1
        let generation = watchdogGeneration
        runOnCentralQueue(after: timeout) { [weak self] in
            guard let self, self.watchdogGeneration == generation, self.phase != .streaming, self.phase != .idle else { return }
            trace("AiDex: setup stalled in phase %{public}@", log: self.log, category: ConstantsLog.categoryCGMAiDex, type: .error, self.phase.rawValue)
            if self.phase == .readingBond || self.phase == .awaitingPairKey {
                self.failKeyExchange(reason: "timeout")
            } else {
                self.consecutiveFailures += 1
                self.disconnect()
            }
        }
    }

    private func armPacketWatchdog() {
        packetWatchdogGeneration += 1
        let generation = packetWatchdogGeneration
        runOnCentralQueue(after: packetInactivityTimeout) { [weak self] in
            guard let self, self.packetWatchdogGeneration == generation, self.getConnectionStatus() == .connected else { return }
            trace("AiDex: no valid reading for %{public}d s, recycling connection", log: self.log, category: ConstantsLog.categoryCGMAiDex, type: .error, Int(self.packetInactivityTimeout))
            self.disconnect()
        }
    }

    // MARK: - helpers

    private func resetConnectionState() {
        connectionGeneration += 1
        watchdogGeneration += 1
        commandGeneration += 1
        phase = .idle
        authCharacteristic = nil
        commandCharacteristic = nil
        dataCharacteristic = nil
        sessionStartTimeCharacteristic = nil
        notificationQueue = []
        keyExchange = nil
        usingSavedKey = false
        freshPairWrittenThisConnection = false
        bondReadPending = false
        shortBondReads = 0
        pairKeyAwaitingValidation = false
        commandQueue = []
        commandInFlight = nil
        historyRequested = false
        historyEntries = []
        historyPages = 0
        activationAttemptedThisConnection = false
        noStreamRefreshDone = false
        lastF003At = nil
    }

    private func updateRecord(_ change: (inout AiDexPairingRecord) -> Void) {
        guard let serialNumber, var record = pairingStore.load(serial: serialNumber) else { return }
        change(&record)
        pairingStore.save(record)
    }

    private func reportStatus(_ status: String) {
        guard status != lastReportedStatus else { return }
        lastReportedStatus = status
        DispatchQueue.main.async { [weak self] in
            guard let self else { return }
            self.cGMAiDexTransmitterDelegate?.received(sensorStatus: status, cGMAiDexTransmitter: self)
        }
    }

    private static func hex(_ byte: UInt8) -> String {
        String(format: "%02X", byte)
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

    private func lastOffsetKey(_ serial: String) -> String {
        "aidex.lastOffset." + serial.uppercased()
    }

    private func storedLastOffset(serial: String) -> Int? {
        UserDefaults.standard.object(forKey: lastOffsetKey(serial)) as? Int
    }

    private func storeLastOffset(_ offset: Int, serial: String) {
        UserDefaults.standard.set(offset, forKey: lastOffsetKey(serial))
    }

    // MARK: - CGMTransmitter

    func cgmTransmitterType() -> CGMTransmitterType {
        .aiDex
    }

    func maxSensorAgeInDays() -> Double? {
        // Sensor-reported wear days (0x10); AiDex X and LinX are 15-day sensors.
        Double(wearDays ?? 15)
    }

    func getCBUUID_Service() -> String { CBUUID_Service_AiDex }

    func getCBUUID_Receive() -> String { CBUUID_Receive_AiDex }

    /// The sensor owns its session; xDrip detects it from the sensor's minute counter.
    func needsSensorStartTime() -> Bool { false }

    /// Values are factory calibrated by the sensor.
    func isWebOOPEnabled() -> Bool { true }

    func nonWebOOPAllowed() -> Bool { false }
}
