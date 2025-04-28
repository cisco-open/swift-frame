// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Foundation
@testable import SFrame
import Testing

internal enum Fixtures {
    internal static let testVectors = try! loadTestVectors() // swiftlint:disable:this force_try
}

internal struct HeaderTestVector: Decodable, CustomStringConvertible {
    private enum CodingKeys: CodingKey {
        case kid
        case ctr
        case encoded
    }

    internal var description: String {
        "Header Vector: kid: \(self.kid)), ctr: \(self.ctr)"
    }

    internal let kid: KeyId
    internal let ctr: Counter
    internal let encoded: Data

    internal init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.kid = try container.decode(KeyId.self, forKey: .kid)
        self.ctr = try container.decode(KeyId.self, forKey: .ctr)
        let encoded = try container.decode(String.self, forKey: .encoded)
        self.encoded = hexToData(encoded)
    }
}

internal struct CryptoTestVector: Decodable, CustomStringConvertible {
    private enum CodingKeys: String, CodingKey {
        case encKey = "enc_key"
        case authKey = "auth_key"
        case plainText = "pt"
        case cipherText = "ct"
        case cipherSuite = "cipher_suite"
        case key = "key"
        case nonce = "nonce"
        case aad = "aad"
    }

    internal var description: String {
        "AES CTR HMAC SHA256 Vector: \(self.cipherSuite)"
    }

    internal let cipherSuite: CipherSuiteIdentifier
    internal let key: Data
    internal let encKey: Data
    internal let authKey: Data
    internal let nonce: Data
    internal let aad: Data
    internal let plainText: Data
    internal let cipherText: Data

    internal init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let encKey = try container.decode(String.self, forKey: .encKey)
        self.encKey = hexToData(encKey)
        let authKey = try container.decode(String.self, forKey: .authKey)
        self.authKey = hexToData(authKey)
        let plainText = try container.decode(String.self, forKey: .plainText)
        self.plainText = hexToData(plainText)
        let cipherText = try container.decode(String.self, forKey: .cipherText)
        self.cipherText = hexToData(cipherText)
        self.cipherSuite = try container.decode(CipherSuiteIdentifier.self, forKey: .cipherSuite)
        let key = try container.decode(String.self, forKey: .key)
        self.key = hexToData(key)
        let nonce = try container.decode(String.self, forKey: .nonce)
        self.nonce = hexToData(nonce)
        let aad = try container.decode(String.self, forKey: .aad)
        self.aad = hexToData(aad)
    }
}

internal struct SFrameTestVector: Decodable, CustomStringConvertible { // swiftlint:disable:this file_types_order
    private enum CodingKeys: String, CodingKey {
        case cipherSuite = "cipher_suite"
        case baseKey = "base_key"
        case sframeKeyLabel = "sframe_key_label"
        case sframeSaltLabel = "sframe_salt_label"
        case sframeSecret = "sframe_secret"
        case sframeKey = "sframe_key"
        case sframeSalt = "sframe_salt"
        case plainText = "pt"
        case cipherText = "ct"
        case kid = "kid"
        case ctr = "ctr"
        case metadata = "metadata"
    }

    internal var description: String {
        "SFrame Vector: \(self.cipherSuite)"
    }

    internal let cipherSuite: CipherSuiteIdentifier
    internal let kid: KeyId
    internal let ctr: Counter
    internal let baseKey: Data
    internal let sframeKeyLabel: Data
    internal let sframeSaltLabel: Data
    internal let sframeSecret: Data
    internal let sframeKey: Data
    internal let sframeSalt: Data
    internal let metadata: Data
    internal let plainText: Data
    internal let cipherText: Data

    internal init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.cipherSuite = try container.decode(CipherSuiteIdentifier.self, forKey: .cipherSuite)
        let baseKey = try container.decode(String.self, forKey: .baseKey)
        self.baseKey = hexToData(baseKey)
        let sframeKeyLabel = try container.decode(String.self, forKey: .sframeKeyLabel)
        self.sframeKeyLabel = hexToData(sframeKeyLabel)
        let sframeSaltLabel = try container.decode(String.self, forKey: .sframeSaltLabel)
        self.sframeSaltLabel = hexToData(sframeSaltLabel)
        let sframeSecret = try container.decode(String.self, forKey: .sframeSecret)
        self.sframeSecret = hexToData(sframeSecret)
        let sframeKey = try container.decode(String.self, forKey: .sframeKey)
        self.sframeKey = hexToData(sframeKey)
        let sframeSalt = try container.decode(String.self, forKey: .sframeSalt)
        self.sframeSalt = hexToData(sframeSalt)
        let metadata = try container.decode(String.self, forKey: .metadata)
        self.metadata = hexToData(metadata)
        let plainText = try container.decode(String.self, forKey: .plainText)
        self.plainText = hexToData(plainText)
        let cipherText = try container.decode(String.self, forKey: .cipherText)
        self.cipherText = hexToData(cipherText)
        self.kid = try container.decode(KeyId.self, forKey: .kid)
        self.ctr = try container.decode(Counter.self, forKey: .ctr)
    }
}

internal struct TestVectors: Decodable {
    private enum CodingKeys: String, CodingKey {
        case header = "header"
        case crypto = "aes_ctr_hmac"
        case sframe = "sframe"
    }

    internal let header: [HeaderTestVector]
    internal let crypto: [CryptoTestVector]
    internal let sframe: [SFrameTestVector]
}

internal func parseHex(_ hex: String) -> UInt64 {
    .init(hex.replacingOccurrences(of: "0x",
                                   with: ""),
          radix: 16)! // swiftlint:disable:this force_unwrapping
}

internal func toHex(_ value: UInt64) -> String {
    .init(format: "0x%016llx", value)
}

internal func hexToData(_ hex: String) -> Data {
    assert(hex.count.isMultiple(of: 2))
    var data = Data(capacity: hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        let byte = hex[index..<next]
        data.append(UInt8(byte, radix: 16)!) // swiftlint:disable:this force_unwrapping
        index = next
    }
    return data
}

internal enum TestError: Error {
    case missingVectors
    case unsupportedCipherSuite
}

internal func loadTestVectors() throws -> TestVectors {
    guard let vectorsUrl = Bundle.module.url(forResource: "rfc_vectors", withExtension: "json") else {
        throw TestError.missingVectors
    }
    let file = try Data(contentsOf: vectorsUrl)
    return try JSONDecoder().decode(TestVectors.self, from: file)
}

private struct EncodeBigEndianTests {
    @Test("Encode Big Endian - No Padding")
    func testEncodeBigEndianNoPadding() {
        let u64: UInt64 = 12_345
        let size = MemoryLayout<UInt64>.size
        var matching = Data(capacity: size)
        u64.encodeBigEndian(size, into: &matching)
        let decoded = matching.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }.bigEndian
        #expect(u64 == decoded)
    }

    @Test("Encode Big Endian - Padding")
    func testEncodeBigEndian() {
        let u32: UInt32 = 12_345
        let size = MemoryLayout<UInt64>.size
        var matching = Data(capacity: size)
        u32.encodeBigEndian(size, into: &matching)
        let decoded = matching.withUnsafeBytes { $0.loadUnaligned(as: UInt64.self) }.bigEndian
        #expect(u32 == decoded)
    }
}

private struct TestDataExtensions {
    @Test("XOR Length")
    func testXORLength() {
        let lhs = Data([1, 2, 3])
        let rhs = Data([4, 5, 6, 7])
        #expect(performing: {
            _ = try lhs ^ rhs
        }, throws: { $0 as? DataError == DataError.lengthMismatch })
    }
}
