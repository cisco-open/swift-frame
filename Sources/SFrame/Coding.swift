import Foundation

extension CipherText {
    /// Decode an SFrame CipherText from its wire format.
    /// - Parameters:
    ///  - tagLength: The length of the authentication tag.
    ///  - data: The encoded data.
    ///  - read: The running offset read from data, in bytes.
    public init(tagLength: Int, from data: Data, read: inout Int) throws {
        self.header = try .init(from: data, read: &read)
        self.encrypted = data[read..<(data.count - tagLength)]
        read += self.encrypted.count
        self.authenticationTag = data[read..<data.count]
        read += self.authenticationTag.count
    }

    /// Encode the SFrame CipherText into its wire format.
    /// - Parameter data: The data to encode into.
    public func encode(into data: inout Data) throws {
        try self.header.encode(into: &data)
        data.append(self.encrypted)
        data.append(self.authenticationTag)
    }
}

extension Header {
    /// Max 3-bit value.
    private static let maxSmallValue: UInt64 = 7

    /// Decode an SFrame header from its encoded wire format.
    /// - Parameter data: The encoded data.
    /// - Parameter read: The running offset read from data, in bytes.
    public init(from data: Data, read: inout Int) throws {
        guard let configByte = data.first else {
            throw DecodingError.dataCorrupted(.init(codingPath: [],
                                                    debugDescription: "Data was empty"))
        }

        read += 1

        // Parse config byte
        let hasExtendedKID = (configByte & 0b10000000) != 0
        let hasExtendedCTR = (configByte & 0b00001000) != 0

        // Decode KID
        if hasExtendedKID {
            let kidLength = Int((configByte >> 4) & 0b111) + 1
            var kidBytes = [UInt8]()
            for _ in 0..<kidLength {
                kidBytes.append(data[read])
                read += 1
            }
            self.keyId = try Self.decodeInteger(from: kidBytes)
        } else {
            self.keyId = UInt64((configByte >> 4) & 0b111)
        }

        // Decode CTR
        if hasExtendedCTR {
            let ctrLength = Int(configByte & 0b111) + 1
            var ctrBytes = [UInt8]()
            for _ in 0..<ctrLength {
                ctrBytes.append(data[read])
                read += 1
            }
            self.counter = try Self.decodeInteger(from: ctrBytes)
        } else {
            self.counter = UInt64(configByte & 0b111)
        }
    }

    /// Encode an SFrame Header into its wire format.
    /// - Parameter data: The data to encode into.
    public func encode(into data: inout Data) throws {
        // Determine if KID and CTR need extended encoding
        let needExtendedKID = self.keyId > Self.maxSmallValue
        let needExtendedCTR = self.counter > Self.maxSmallValue

        // Create config byte
        var configByte: UInt8 = 0

        if needExtendedKID {
            configByte |= 0b10000000 // Set X flag
            let kidBytes = self.minimalBytes(for: self.keyId)
            guard kidBytes.count <= 8 else {
                throw EncodingError.invalidValue(self.keyId,
                                                 .init(codingPath: [], debugDescription: "KID too large"))
            }
            configByte |= UInt8(kidBytes.count - 1) << 4 // Set K field
        } else {
            configByte |= UInt8(self.keyId) << 4 // Set K field directly
        }

        if needExtendedCTR {
            configByte |= 0b00001000 // Set Y flag
            let ctrBytes = self.minimalBytes(for: self.counter)
            guard ctrBytes.count <= 8 else {
                throw EncodingError.invalidValue(self.counter, .init(codingPath: [], debugDescription: "CTR too large"))
            }
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
        var bytes = withUnsafeBytes(of: value.bigEndian) { Array($0) }
        while bytes.first == 0 && bytes.count > 1 {
            bytes.removeFirst()
        }
        return bytes
    }

    private static func decodeInteger(from bytes: [UInt8]) throws -> UInt64 {
        var value: UInt64 = 0
        for byte in bytes {
            value = (value << 8) | UInt64(byte)
        }
        return value
    }
}
