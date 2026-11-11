//
//  CGMAccuChekSmartGuideTransmitterDelegate.swift
//  xdrip
//
//  Accu-Chek SmartGuide details that do not belong to the common glucose delegate.
//  Implementations persist them in the AccuChekSmartGuide Core Data entity. Called on main.
//

import Foundation

protocol CGMAccuChekSmartGuideTransmitterDelegate: AnyObject {

    /// serial taken from the advertised name "AC-<serial>"
    func received(serialNumber: String, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter)

    /// Device Information Service values; nil when not read
    func received(firmware: String?, hardware: String?, model: String?, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter)

    /// session start derived from the CGM Status time offset
    func received(sensorStartDate: Date, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter)

    /// short English status for the detail screen and trace
    func received(sensorStatus: String, cGMAccuChekSmartGuideTransmitter: CGMAccuChekSmartGuideTransmitter)
}
