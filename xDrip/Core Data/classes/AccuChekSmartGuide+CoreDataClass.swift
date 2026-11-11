//
//  AccuChekSmartGuide+CoreDataClass.swift
//  xdrip
//
//  Core Data entity for an Accu-Chek SmartGuide sensor connected directly over Bluetooth.
//

import Foundation
import CoreData

public class AccuChekSmartGuide: NSManagedObject {

    init(address: String, name: String, alias: String?, nsManagedObjectContext: NSManagedObjectContext) {

        let entity = NSEntityDescription.entity(forEntityName: "AccuChekSmartGuide", in: nsManagedObjectContext)!

        super.init(entity: entity, insertInto: nsManagedObjectContext)

        blePeripheral = BLEPeripheral(address: address, name: name, alias: alias, bluetoothPeripheralType: .AccuChekSmartGuideType, nsManagedObjectContext: nsManagedObjectContext)

        // the advertised name is "AC-<serial>"
        blePeripheral.sensorSerialNumber = AccuChekSmartGuideProtocol.serial(fromAdvertisedName: name)

    }

    private override init(entity: NSEntityDescription, insertInto context: NSManagedObjectContext?) {
        super.init(entity: entity, insertInto: context)
    }

}
