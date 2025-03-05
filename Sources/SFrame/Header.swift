import Foundation

/// SFrame Header.
internal struct Header {
    /// Max 3-bit value.
    private static let maxSmallValue: UInt64 = 7

    /// ID for the key in use.
    internal let keyId: KeyId
    /// Counter value used in this message.
    internal let counter: Counter

    internal init(keyId: KeyId, counter: Counter) {
        self.keyId = keyId
        self.counter = counter
    }

    /// Decode an SFrame header from its encoded wire format.
    /// - Parameter data: The encoded data.
    /// - Parameter read: The running offset read from data, in bytes.
    internal init(from data: Data, read: inout Int) throws {
        guard let configByte = data.first else {
            throw SFrameError.malformedCipherText
        }
        read += 1

        // Parse config byte
        let hasExtendedKID = (configByte & 0b10000000) != 0
        let hasExtendedCTR = (configByte & 0b00001000) != 0

        // Decode KID
        if hasExtendedKID {
            let kidLength = Int((configByte >> 4) & 0b111) + 1
            guard data.count >= read + kidLength else {
                throw SFrameError.malformedCipherText
            }
            var kidBytes = [UInt8]()
            for _ in 0..<kidLength {
                kidBytes.append(data[read])
                read += 1
            }
            self.keyId = Self.decodeInteger(from: kidBytes)
        } else {
            self.keyId = UInt64((configByte >> 4) & 0b111)
        }

        // Decode CTR
        if hasExtendedCTR {
            let ctrLength = Int(configByte & 0b111) + 1
            guard data.count >= read + ctrLength else {
                throw SFrameError.malformedCipherText
            }
            var ctrBytes = [UInt8]()
            for _ in 0..<ctrLength {
                ctrBytes.append(data[read])
                read += 1
            }
            self.counter = Self.decodeInteger(from: ctrBytes)
        } else {
            self.counter = UInt64(configByte & 0b111)
        }
    }

    private static func decodeInteger(from bytes: [UInt8]) -> UInt64 {
        var value: UInt64 = 0
        for byte in bytes {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }

    /// Encode an SFrame Header into its wire format.
    /// - Parameter data: The data to encode into.
    internal func encode(into data: inout Data) throws {
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
        return bytes
    }
}
