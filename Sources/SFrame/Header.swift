// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Foundation

/// SFrame Header.
public struct Header {
    /// Max 3-bit value.
    private static let maxSmallValue: UInt64 = 7

    /// ID for the key in use.
    internal let keyId: KeyId
    /// Counter value used in this message.
    internal let counter: Counter

    /// Create a new header with the given key ID and counter.
    /// - Parameter keyId: The key ID.
    /// - Parameter counter: The counter value.
    public init(keyId: KeyId, counter: Counter) {
        self.keyId = keyId
        self.counter = counter
    }

    /// Decode an SFrame header from its encoded wire format.
    /// - Parameter data: The encoded data.
    /// - Parameter read: The running offset read from data, in bytes.
    public init(from data: Data, read: inout Int) throws(SFrameError) {
        guard let configByte = data.first else {
            throw SFrameError.malformedCipherText
        }
        read += 1

        // Parse config byte
        let hasExtendedKID = (configByte & 0b10000000) != 0
        let hasExtendedCTR = (configByte & 0b00001000) != 0

        // Decode KID
        if hasExtendedKID {
            self.keyId = try Self.decodeInteger(configByte >> 4, data: data, read: &read)
        } else {
            self.keyId = UInt64((configByte >> 4) & 0b111)
        }

        // Decode CTR
        if hasExtendedCTR {
            self.counter = try Self.decodeInteger(configByte, data: data, read: &read)
        } else {
            self.counter = UInt64(configByte & 0b111)
        }
    }

    private static func decodeInteger(_ value: UInt8, data: Data, read: inout Int) throws(SFrameError) -> UInt64 {
        guard !data.isEmpty, data[0] != 0 else {
            throw SFrameError.malformedCipherText
        }

        let length = Int(value & 0b111) + 1
        guard data.count >= read + length else {
            throw SFrameError.malformedCipherText
        }
        var bytes = [UInt8]()
        for _ in 0..<length {
            bytes.append(data[read])
            read += 1
        }

        var value: UInt64 = 0
        for byte in bytes {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }

    /// Encode an SFrame Header into its wire format.
    /// - Parameter data: The data to encode into.
    public func encode(into data: inout Data) {
        // Determine if KID and CTR need extended encoding
        let needExtendedKID = self.keyId > Self.maxSmallValue
        let needExtendedCTR = self.counter > Self.maxSmallValue

        // Create config byte
        var configByte: UInt8 = 0

        if needExtendedKID {
            configByte |= 0b10000000 // Set X flag
            let kidBytes = self.minimalBytes(for: self.keyId)
            precondition(kidBytes.count <= 8)
            configByte |= UInt8(kidBytes.count - 1) << 4 // Set K field
        } else {
            configByte |= UInt8(self.keyId) << 4 // Set K field directly
        }

        if needExtendedCTR {
            configByte |= 0b00001000 // Set Y flag
            let ctrBytes = self.minimalBytes(for: self.counter)
            precondition(ctrBytes.count <= 8)
            configByte |= UInt8(ctrBytes.count - 1) // Set C field
        } else {
            configByte |= UInt8(self.counter) // Set C field directly
        }

        data.append(configByte)

        // Encode extended KID if needed
        if needExtendedKID {
            data.append(contentsOf: self.minimalBytes(for: self.keyId))
        }

        // Encode extended CTR if needed
        if needExtendedCTR {
            data.append(contentsOf: self.minimalBytes(for: self.counter))
        }
    }

    private func minimalBytes(for value: UInt64) -> [UInt8] {
        precondition(value > Self.maxSmallValue)
        var bytes = withUnsafeBytes(of: value.bigEndian) { Array($0) }
        while bytes.first == 0 && bytes.count > 1 {
            bytes.removeFirst()
        }
        assert(bytes.count <= 8)
        return bytes
    }
}
