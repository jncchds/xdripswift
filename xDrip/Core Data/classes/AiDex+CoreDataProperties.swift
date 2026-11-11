//
//  AiDex+CoreDataProperties.swift
//  xdrip
//

import Foundation
import CoreData

extension AiDex {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<AiDex> {
        return NSFetchRequest<AiDex>(entityName: "AiDex")
    }

    /// blePeripheral is required to conform to protocol BluetoothPeripheral
    @NSManaged public var blePeripheral: BLEPeripheral

    /// battery voltage from the F003 status frame, 0 if not yet received
    @NSManaged public var batteryMillivolts: Int32

    /// firmware version reported by the startup device info (0x10)
    @NSManaged public var firmware: String?

    /// hardware version reported by the startup device info (0x10)
    @NSManaged public var hardware: String?

    /// model name reported by the startup device info (0x10), for example "GX-01S"
    @NSManaged public var modelName: String?

    /// sensor session start, from the sensor or inferred from the live frame offset
    @NSManaged public var sensorStartDate: Date?

    /// last status reported by the transmitter
    @NSManaged public var sensorStatus: String?

    /// wear days reported by the sensor, 0 if not yet received
    @NSManaged public var wearDays: Int16

}
