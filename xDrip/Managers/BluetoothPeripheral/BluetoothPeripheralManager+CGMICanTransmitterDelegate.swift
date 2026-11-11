//
//  BluetoothPeripheralManager+CGMICanTransmitterDelegate.swift
//  xdrip
//
//  Persists Sinocare iCan details reported by CGMICanTransmitter.
//

import Foundation

extension BluetoothPeripheralManager: CGMICanTransmitterDelegate {

    func received(serialNumber: String, cGMICanTransmitter: CGMICanTransmitter) {
        guard let iCan = getICan(cGMICanTransmitter), iCan.blePeripheral.sensorSerialNumber != serialNumber else { return }
        iCan.blePeripheral.sensorSerialNumber = serialNumber
        coreDataManager.saveChanges()
    }

    func received(model: String?, softwareVersion: String?, cGMICanTransmitter: CGMICanTransmitter) {
        guard let iCan = getICan(cGMICanTransmitter) else { return }
        iCan.modelName = model ?? iCan.modelName
        iCan.softwareVersion = softwareVersion ?? iCan.softwareVersion
        coreDataManager.saveChanges()
    }

    func received(sensorStartDate: Date, cGMICanTransmitter: CGMICanTransmitter) {
        guard let iCan = getICan(cGMICanTransmitter) else { return }
        iCan.sensorStartDate = sensorStartDate
        coreDataManager.saveChanges()
    }

    func received(calibrationMarker: Int, cGMICanTransmitter: CGMICanTransmitter) {
        guard let iCan = getICan(cGMICanTransmitter) else { return }
        iCan.calibrationMarker = Int32(clamping: calibrationMarker)
        coreDataManager.saveChanges()
    }

    func received(sensorStatus: String, cGMICanTransmitter: CGMICanTransmitter) {
        guard let iCan = getICan(cGMICanTransmitter), iCan.sensorStatus != sensorStatus else { return }
        iCan.sensorStatus = sensorStatus
        coreDataManager.saveChanges()
    }

    private func getICan(_ transmitter: CGMICanTransmitter) -> ICan? {
        guard let index = bluetoothTransmitters.firstIndex(of: transmitter),
              let iCan = bluetoothPeripherals[index] as? ICan else { return nil }
        return iCan
    }
}
