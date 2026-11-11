//
//  AccuChekSmartGuide+CoreDataProperties.swift
//  xdrip
//

import Foundation
import CoreData

extension AccuChekSmartGuide {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<AccuChekSmartGuide> {
        return NSFetchRequest<AccuChekSmartGuide>(entityName: "AccuChekSmartGuide")
    }

    /// blePeripheral is required to conform to protocol BluetoothPeripheral
    @NSManaged public var blePeripheral: BLEPeripheral

    /// Device Information Service firmware revision
    @NSManaged public var firmware: String?

    /// Device Information Service hardware revision
    @NSManaged public var hardware: String?

    /// Device Information Service model number
    @NSManaged public var modelName: String?

    /// session start derived from the CGM Status time offset
    @NSManaged public var sensorStartDate: Date?

    /// last status reported by the transmitter
    @NSManaged public var sensorStatus: String?

}
