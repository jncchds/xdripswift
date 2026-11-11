//
//  BluetoothPeripheralManager+CGMAiDexTransmitterDelegate.swift
//  xdrip
//
//  Persists AiDex X / LinX sensor details reported by CGMAiDexTransmitter.
//

import Foundation

extension BluetoothPeripheralManager: CGMAiDexTransmitterDelegate {

    func received(serialNumber: String, cGMAiDexTransmitter: CGMAiDexTransmitter) {
        guard let aiDex = getAiDex(cGMAiDexTransmitter: cGMAiDexTransmitter),
              aiDex.blePeripheral.sensorSerialNumber != serialNumber else { return }
        aiDex.blePeripheral.sensorSerialNumber = serialNumber
        coreDataManager.saveChanges()
    }

    func received(deviceInfo: AiDexStartupDeviceInfo, cGMAiDexTransmitter: CGMAiDexTransmitter) {
        guard let aiDex = getAiDex(cGMAiDexTransmitter: cGMAiDexTransmitter) else { return }
        aiDex.firmware = deviceInfo.firmwareVersion
        aiDex.hardware = deviceInfo.hardwareVersion
        aiDex.modelName = deviceInfo.modelName
        if deviceInfo.wearDays > 0 {
            aiDex.wearDays = Int16(clamping: deviceInfo.wearDays)
            if aiDex.blePeripheral.shouldconnect {
                UserDefaults.standard.activeSensorMaxSensorAgeInDays = Double(deviceInfo.wearDays)
            }
        }
        coreDataManager.saveChanges()
    }

    func received(batteryMillivolts: Int, cGMAiDexTransmitter: CGMAiDexTransmitter) {
        guard let aiDex = getAiDex(cGMAiDexTransmitter: cGMAiDexTransmitter) else { return }
        aiDex.batteryMillivolts = Int32(clamping: batteryMillivolts)
        coreDataManager.saveChanges()
    }

    func received(sensorStartDate: Date?, cGMAiDexTransmitter: CGMAiDexTransmitter) {
        guard let aiDex = getAiDex(cGMAiDexTransmitter: cGMAiDexTransmitter), aiDex.sensorStartDate != sensorStartDate else { return }
        aiDex.sensorStartDate = sensorStartDate
        coreDataManager.saveChanges()
    }

    func received(sensorStatus: String, cGMAiDexTransmitter: CGMAiDexTransmitter) {
        guard let aiDex = getAiDex(cGMAiDexTransmitter: cGMAiDexTransmitter), aiDex.sensorStatus != sensorStatus else { return }
        aiDex.sensorStatus = sensorStatus
        coreDataManager.saveChanges()
    }

    private func getAiDex(cGMAiDexTransmitter: CGMAiDexTransmitter) -> AiDex? {
        guard let index = bluetoothTransmitters.firstIndex(of: cGMAiDexTransmitter),
              let aiDex = bluetoothPeripherals[index] as? AiDex else { return nil }
        return aiDex
    }
}
