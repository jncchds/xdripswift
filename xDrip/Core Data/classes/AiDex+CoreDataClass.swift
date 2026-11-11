//
//  AiDex+CoreDataClass.swift
//  xdrip
//
//  Core Data entity for an AiDex X / LinX sensor connected directly over Bluetooth.
//

import Foundation
import CoreData

public class AiDex: NSManagedObject {

    init(address: String, name: String, alias: String?, nsManagedObjectContext: NSManagedObjectContext) {

        let entity = NSEntityDescription.entity(forEntityName: "AiDex", in: nsManagedObjectContext)!

        super.init(entity: entity, insertInto: nsManagedObjectContext)

        blePeripheral = BLEPeripheral(address: address, name: name, alias: alias, bluetoothPeripheralType: .AiDexType, nsManagedObjectContext: nsManagedObjectContext)

        // the serial is part of the advertised name, for example "AiDEX X-2222267V4E"
        blePeripheral.sensorSerialNumber = AiDexSerialIdentity.serial(fromAdvertisedName: name)

    }

    private override init(entity: NSEntityDescription, insertInto context: NSManagedObjectContext?) {
        super.init(entity: entity, insertInto: context)
    }

}
