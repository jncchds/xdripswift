//
//  AccuChekSmartGuide+BluetoothPeripheral.swift
//  xdrip
//

import Foundation

extension AccuChekSmartGuide: BluetoothPeripheral {

    func bluetoothPeripheralType() -> BluetoothPeripheralType {
        return .AccuChekSmartGuideType
    }

}
