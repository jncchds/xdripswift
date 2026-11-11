//
//  ICan+CoreDataProperties.swift
//  xdrip
//

import Foundation
import CoreData

extension ICan {

    @nonobjc public class func fetchRequest() -> NSFetchRequest<ICan> {
        return NSFetchRequest<ICan>(entityName: "ICan")
    }

    /// blePeripheral is required to conform to protocol BluetoothPeripheral
    @NSManaged public var blePeripheral: BLEPeripheral

    /// vendor calibration table marker from `F6`: -1 unknown, 0xFFFF not installed
    @NSManaged public var calibrationMarker: Int32

    /// Device Information Service model number, for example "iCGM-t3"
    @NSManaged public var modelName: String?

    /// session start derived from the CGM Status minute counter
    @NSManaged public var sensorStartDate: Date?

    /// last status reported by the transmitter
    @NSManaged public var sensorStatus: String?

    /// Device Information Service software revision (selects the key family)
    @NSManaged public var softwareVersion: String?

}
