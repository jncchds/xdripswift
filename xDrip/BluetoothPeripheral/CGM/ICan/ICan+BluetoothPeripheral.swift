//
//  ICan+BluetoothPeripheral.swift
//  xdrip
//

import Foundation

extension ICan: BluetoothPeripheral {

    func bluetoothPeripheralType() -> BluetoothPeripheralType {
        return .ICanType
    }

}
