//
//  CGMAiDexTransmitterDelegate.swift
//  xdrip
//
//  AiDex-specific sensor information that does not belong to the common glucose delegate.
//  Implementations persist the values in the AiDex Core Data entity. Called on the main thread.
//

import Foundation

protocol CGMAiDexTransmitterDelegate: AnyObject {

    /// Bare serial parsed from the advertised name, for example "2222267V4E".
    func received(serialNumber: String, cGMAiDexTransmitter: CGMAiDexTransmitter)

    /// Startup device info (raw 0x10): firmware, hardware, wear days and model.
    func received(deviceInfo: AiDexStartupDeviceInfo, cGMAiDexTransmitter: CGMAiDexTransmitter)

    /// Battery voltage decoded from the 5-byte F003 status frame.
    func received(batteryMillivolts: Int, cGMAiDexTransmitter: CGMAiDexTransmitter)

    /// Session start reported by the sensor (CGM Session Start Time or raw 0x21), or inferred from
    /// the live frame offset. Nil while the sensor has not been activated.
    func received(sensorStartDate: Date?, cGMAiDexTransmitter: CGMAiDexTransmitter)

    /// Short English status for the detail screen and trace, for example "Streaming".
    func received(sensorStatus: String, cGMAiDexTransmitter: CGMAiDexTransmitter)
}
