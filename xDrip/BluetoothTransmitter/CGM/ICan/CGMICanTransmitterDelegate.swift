//
//  CGMICanTransmitterDelegate.swift
//  xdrip
//
//  iCan details that do not belong to the common glucose delegate. Called on the main thread.
//

import Foundation

protocol CGMICanTransmitterDelegate: AnyObject {

    /// sensor serial read from the Device Information Service
    func received(serialNumber: String, cGMICanTransmitter: CGMICanTransmitter)

    /// model number and software revision from the Device Information Service
    func received(model: String?, softwareVersion: String?, cGMICanTransmitter: CGMICanTransmitter)

    /// session start derived from the CGM Status minute counter
    func received(sensorStartDate: Date, cGMICanTransmitter: CGMICanTransmitter)

    /// vendor calibration table marker (`F6`), 0xFFFF = no table written
    func received(calibrationMarker: Int, cGMICanTransmitter: CGMICanTransmitter)

    /// short English status for the detail screen and trace
    func received(sensorStatus: String, cGMICanTransmitter: CGMICanTransmitter)
}
