//
//  AiDexCrypto.swift
//  xdrip
//
//  Checksums and AES-128-CFB used by the AiDex X / LinX Bluetooth protocol.
//
//  Ported from JugglucoNG (GPL-3.0, https://github.com/ctqvva/JugglucoNG, a fork of Juggluco by
//  Jaap Korthals Altes), files Common/src/main/java/tk/glucodata/drivers/aidex/native/crypto/
//  Crc8Maxim.kt, Crc16CcittFalse.kt, AesCfb128.kt and SerialCrypto.kt.
//  The JugglucoNG code credits its own reverse engineering of the vendor libblecomm-lib.so.
//

import Foundation
import CommonCrypto
import CryptoKit

/// CRC-8/MAXIM (Dallas), polynomial 0x31 reflected. Verifies the decrypted 17-byte BOND vector.
enum AiDexCrc8Maxim {

    private static let table: [UInt8] = [
        0x00, 0x5e, 0xbc, 0xe2, 0x61, 0x3f, 0xdd, 0x83, 0xc2, 0x9c, 0x7e, 0x20, 0xa3, 0xfd, 0x1f, 0x41,
        0x9d, 0xc3, 0x21, 0x7f, 0xfc, 0xa2, 0x40, 0x1e, 0x5f, 0x01, 0xe3, 0xbd, 0x3e, 0x60, 0x82, 0xdc,
        0x23, 0x7d, 0x9f, 0xc1, 0x42, 0x1c, 0xfe, 0xa0, 0xe1, 0xbf, 0x5d, 0x03, 0x80, 0xde, 0x3c, 0x62,
        0xbe, 0xe0, 0x02, 0x5c, 0xdf, 0x81, 0x63, 0x3d, 0x7c, 0x22, 0xc0, 0x9e, 0x1d, 0x43, 0xa1, 0xff,
        0x46, 0x18, 0xfa, 0xa4, 0x27, 0x79, 0x9b, 0xc5, 0x84, 0xda, 0x38, 0x66, 0xe5, 0xbb, 0x59, 0x07,
        0xdb, 0x85, 0x67, 0x39, 0xba, 0xe4, 0x06, 0x58, 0x19, 0x47, 0xa5, 0xfb, 0x78, 0x26, 0xc4, 0x9a,
        0x65, 0x3b, 0xd9, 0x87, 0x04, 0x5a, 0xb8, 0xe6, 0xa7, 0xf9, 0x1b, 0x45, 0xc6, 0x98, 0x7a, 0x24,
        0xf8, 0xa6, 0x44, 0x1a, 0x99, 0xc7, 0x25, 0x7b, 0x3a, 0x64, 0x86, 0xd8, 0x5b, 0x05, 0xe7, 0xb9,
        0x8c, 0xd2, 0x30, 0x6e, 0xed, 0xb3, 0x51, 0x0f, 0x4e, 0x10, 0xf2, 0xac, 0x2f, 0x71, 0x93, 0xcd,
        0x11, 0x4f, 0xad, 0xf3, 0x70, 0x2e, 0xcc, 0x92, 0xd3, 0x8d, 0x6f, 0x31, 0xb2, 0xec, 0x0e, 0x50,
        0xaf, 0xf1, 0x13, 0x4d, 0xce, 0x90, 0x72, 0x2c, 0x6d, 0x33, 0xd1, 0x8f, 0x0c, 0x52, 0xb0, 0xee,
        0x32, 0x6c, 0x8e, 0xd0, 0x53, 0x0d, 0xef, 0xb1, 0xf0, 0xae, 0x4c, 0x12, 0x91, 0xcf, 0x2d, 0x73,
        0xca, 0x94, 0x76, 0x28, 0xab, 0xf5, 0x17, 0x49, 0x08, 0x56, 0xb4, 0xea, 0x69, 0x37, 0xd5, 0x8b,
        0x57, 0x09, 0xeb, 0xb5, 0x36, 0x68, 0x8a, 0xd4, 0x95, 0xcb, 0x29, 0x77, 0xf4, 0xaa, 0x48, 0x16,
        0xe9, 0xb7, 0x55, 0x0b, 0x88, 0xd6, 0x34, 0x6a, 0x2b, 0x75, 0x97, 0xc9, 0x4a, 0x14, 0xf6, 0xa8,
        0x74, 0x2a, 0xc8, 0x96, 0x15, 0x4b, 0xa9, 0xf7, 0xb6, 0xe8, 0x0a, 0x54, 0xd7, 0x89, 0x6b, 0x35,
    ]

    static func checksum<S: Sequence>(_ bytes: S) -> UInt8 where S.Element == UInt8 {
        var accumulator: UInt8 = 0
        for byte in bytes {
            accumulator = table[Int(byte ^ accumulator)]
        }
        return accumulator
    }
}

/// CRC-16/CCITT-FALSE (poly 0x1021, init 0xFFFF). Little-endian trailer of every F002 command,
/// of F002 data responses and of the 17-byte F003 glucose frame.
enum AiDexCrc16CcittFalse {

    static func checksum<S: Sequence>(_ bytes: S) -> UInt16 where S.Element == UInt8 {
        var crc: UInt16 = 0xFFFF
        for byte in bytes {
            crc ^= UInt16(byte) << 8
            for _ in 0..<8 {
                crc = (crc & 0x8000) != 0 ? (crc << 1) ^ 0x1021 : crc << 1
            }
        }
        return crc
    }

    /// `[opcode, params..., crcLo, crcHi]`
    static func makeCommand(opcode: UInt8, params: [UInt8] = []) -> [UInt8] {
        let payload = [opcode] + params
        let crc = checksum(payload)
        return payload + [UInt8(crc & 0xFF), UInt8(crc >> 8)]
    }

    /// True if the last two bytes are the little-endian CRC of everything before them.
    static func isValidTrailer(_ bytes: [UInt8]) -> Bool {
        guard bytes.count >= 3 else { return false }
        let expected = checksum(bytes[0..<(bytes.count - 2)])
        let actual = UInt16(bytes[bytes.count - 2]) | (UInt16(bytes[bytes.count - 1]) << 8)
        return expected == actual
    }
}

/// AES-128 in full-block CFB mode (CFB-128), built from single-block AES-ECB.
///
/// Every message is encrypted on its own, starting again from the serial-derived IV: there is no
/// chaining between successive notifications or commands.
enum AiDexAesCfb128 {

    private static let blockSize = 16

    static func encrypt(_ plaintext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        process(plaintext, key: key, iv: iv, encrypting: true)
    }

    static func decrypt(_ ciphertext: [UInt8], key: [UInt8], iv: [UInt8]) -> [UInt8]? {
        process(ciphertext, key: key, iv: iv, encrypting: false)
    }

    /// Decrypts the 17-byte BOND vector read from F002 with the PAIR key and returns the
    /// 16-byte session key when its CRC-8 (byte 16) matches; nil otherwise.
    static func decryptBondData(_ bondData: [UInt8], pairKey: [UInt8], iv: [UInt8]) -> [UInt8]? {
        guard bondData.count == 17, pairKey.count == 16, iv.count == 16,
              let decrypted = decrypt(bondData, key: pairKey, iv: iv) else { return nil }
        let sessionKey = Array(decrypted[0..<16])
        guard decrypted[16] == AiDexCrc8Maxim.checksum(sessionKey) else { return nil }
        return sessionKey
    }

    /// AES-128-ECB encryption of a single 16-byte block.
    static func ecbEncrypt(block: [UInt8], key: [UInt8]) -> [UInt8]? {
        guard block.count == blockSize, key.count == kCCKeySizeAES128 else { return nil }
        var output = [UInt8](repeating: 0, count: blockSize)
        var moved = 0
        let status = key.withUnsafeBytes { keyBytes in
            block.withUnsafeBytes { blockBytes in
                CCCrypt(
                    CCOperation(kCCEncrypt),
                    CCAlgorithm(kCCAlgorithmAES),
                    CCOptions(kCCOptionECBMode),
                    keyBytes.baseAddress, key.count,
                    nil,
                    blockBytes.baseAddress, block.count,
                    &output, output.count,
                    &moved
                )
            }
        }
        guard status == CCCryptorStatus(kCCSuccess), moved == blockSize else { return nil }
        return output
    }

    private static func process(_ input: [UInt8], key: [UInt8], iv: [UInt8], encrypting: Bool) -> [UInt8]? {
        guard key.count == 16, iv.count == 16, !input.isEmpty else { return nil }
        var output = [UInt8](repeating: 0, count: input.count)
        var feedback = iv
        var offset = 0
        while offset < input.count {
            let chunk = min(blockSize, input.count - offset)
            guard let keystream = ecbEncrypt(block: feedback, key: key) else { return nil }
            for i in 0..<chunk {
                output[offset + i] = input[offset + i] ^ keystream[i]
            }
            if chunk == blockSize {
                // The feedback register is always the ciphertext block.
                feedback = encrypting ? Array(output[offset..<(offset + blockSize)]) : Array(input[offset..<(offset + blockSize)])
            }
            offset += chunk
        }
        return output
    }
}

/// Derives the F001 challenge ("secret") and the AES IV from the bare sensor serial.
///
/// Verified in JugglucoNG with sensor 2222267V4E:
///   secret = 4b76169576da80e4eeacf886230873d2, IV = 14cb6a3a39b96c448ebc39185f70f8aa
enum AiDexSerialCrypto {

    /// '0'-'9' -> 0-9, 'A'-'Z' / 'a'-'z' -> 10-35, anything else -> 0.
    static func numericValue(of character: Character) -> UInt8 {
        guard let ascii = character.asciiValue else { return 0 }
        switch ascii {
        case 0x30...0x39: return ascii - 0x30
        case 0x41...0x5A: return ascii - 0x41 + 10
        case 0x61...0x7A: return ascii - 0x61 + 10
        default: return 0
        }
    }

    static func serialToBytes(_ bareSerial: String) -> [UInt8] {
        bareSerial.map(numericValue(of:))
    }

    /// MD5 of every serial value mapped to `(v * 13 + 61) & 0xFF`.
    static func deriveSecret(bareSerial: String) -> [UInt8] {
        md5(serialToBytes(bareSerial).map { UInt8(truncatingIfNeeded: Int($0) * 13 + 61) })
    }

    /// MD5 of every serial value mapped to `(v * 17 + 19) & 0xFF`.
    static func deriveIv(bareSerial: String) -> [UInt8] {
        md5(serialToBytes(bareSerial).map { UInt8(truncatingIfNeeded: Int($0) * 17 + 19) })
    }

    private static func md5(_ bytes: [UInt8]) -> [UInt8] {
        Array(Insecure.MD5.hash(data: Data(bytes)))
    }
}
