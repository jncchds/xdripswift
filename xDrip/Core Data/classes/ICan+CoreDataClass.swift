//
//  ICan+CoreDataClass.swift
//  xdrip
//
//  Core Data entity for a Sinocare iCan sensor connected directly over Bluetooth.
//

import Foundation
import CoreData

public class ICan: NSManagedObject {

    init(address: String, name: String, alias: String?, nsManagedObjectContext: NSManagedObjectContext) {

        let entity = NSEntityDescription.entity(forEntityName: "ICan", in: nsManagedObjectContext)!

        super.init(entity: entity, insertInto: nsManagedObjectContext)

        blePeripheral = BLEPeripheral(address: address, name: name, alias: alias, bluetoothPeripheralType: .ICanType, nsManagedObjectContext: nsManagedObjectContext)

        // not read yet
        calibrationMarker = -1

    }

    private override init(entity: NSEntityDescription, insertInto context: NSManagedObjectContext?) {
        super.init(entity: entity, insertInto: context)
    }

}
