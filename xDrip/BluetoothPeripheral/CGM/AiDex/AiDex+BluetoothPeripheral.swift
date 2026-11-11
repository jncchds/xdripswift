//
//  AiDex+BluetoothPeripheral.swift
//  xdrip
//

import Foundation

extension AiDex: BluetoothPeripheral {

    func bluetoothPeripheralType() -> BluetoothPeripheralType {
        return .AiDexType
    }

}
