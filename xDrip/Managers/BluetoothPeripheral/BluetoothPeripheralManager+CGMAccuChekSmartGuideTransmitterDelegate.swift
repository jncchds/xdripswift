//
//  BluetoothPeripheralManager+CGMAccuChekSmartGuideTransmitterDelegate.swift
//  xdrip
//
//  Persists Accu-Chek SmartGuide details reported by CGMAccuChekSmartGuideTransmitter.
//

import Foundation

extension BluetoothPeripheralManager: CGMAccuChekSmartGuideTransmitterDelegate {

    func received(serialNumber: String, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter) {
        guard let smartGuide = getAccuChekSmartGuide(cGMAccuChekSmartGuideTransmitter),
              smartGuide.blePeripheral.sensorSerialNumber != serialNumber else { return }
        smartGuide.blePeripheral.sensorSerialNumber = serialNumber
        coreDataManager.saveChanges()
    }

    func received(firmware: String?, hardware: String?, model: String?, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter) {
        guard let smartGuide = getAccuChekSmartGuide(cGMAccuChekSmartGuideTransmitter) else { return }
        smartGuide.firmware = firmware ?? smartGuide.firmware
        smartGuide.hardware = hardware ?? smartGuide.hardware
        smartGuide.modelName = model ?? smartGuide.modelName
        coreDataManager.saveChanges()
    }

    func received(sensorStartDate: Date, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter) {
        guard let smartGuide = getAccuChekSmartGuide(cGMAccuChekSmartGuideTransmitter) else { return }
        smartGuide.sensorStartDate = sensorStartDate
        coreDataManager.saveChanges()
    }

    func received(sensorStatus: String, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter) {
        guard let smartGuide = getAccuChekSmartGuide(cGMAccuChekSmartGuideTransmitter), smartGuide.sensorStatus != sensorStatus else { return }
        smartGuide.sensorStatus = sensorStatus
        coreDataManager.saveChanges()
    }

    private func getAccuChekSmartGuide(_ transmitter: CGMAccuChekSmartGuideTransmitter) -> AccuChekSmartGuide? {
        guard let index = bluetoothTransmitters.firstIndex(of: transmitter),
              let smartGuide = bluetoothPeripherals[index] as? AccuChekSmartGuide else { return nil }
        return smartGuide
    }
}
