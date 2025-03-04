import Foundation
import SFrame

internal enum Fixtures {
    internal static let testVectors = try! loadTestVectors() // swiftlint:disable:this force_try
}

internal struct TestVectors: Decodable {
    internal let headers: [SerializedHeader]
    internal let sframe: [SFrameVector]
}

internal struct SerializedHeader: Decodable, CustomStringConvertible {
    internal var description: String {
        "kid(\(self.kid)) ctr(\(self.ctr))"
    }

    internal let kid: KeyId
    internal let ctr: Counter
    internal let header: Data

    private enum CodingKeys: CodingKey {
        case kid
        case ctr
        case header
    }

    internal init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kid = try container.decode(String.self, forKey: .kid)
        self.kid = parseHex(kid)
        let counter = try container.decode(String.self, forKey: .ctr)
        self.ctr = parseHex(counter)
        let header = try container.decode(String.self, forKey: .header)
        self.header = hexToData(header)
    }
}

internal struct SerializedCryptoVector: Decodable {
    internal let cipherSuite: String
    internal let key: String
    internal let encKey: String
    internal let authKey: String
    internal let nonce: String
    internal let aad: String
    internal let plainText: String
    internal let cipherText: String

    private enum CodingKeys: String, CodingKey {
        case encKey = "enc_key"
        case authKey = "auth_key"
        case plainText = "pt"
        case cipherText = "ct"
        case cipherSuite = "cipherSuite"
        case key = "key"
        case nonce = "nonce"
        case aad = "aad"
    }
}

internal struct SFrameVector: Decodable {
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

    internal init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let cipherSuite = try container.decode(String.self, forKey: .cipherSuite)
        self.cipherSuite = UInt32(parseHex(cipherSuite))
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
        let kid = try container.decode(String.self, forKey: .kid)
        self.kid = KeyId(parseHex(kid))
        let ctr = try container.decode(String.self, forKey: .ctr)
        self.ctr = Counter(parseHex(ctr))
    }
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
}

internal func loadTestVectors() throws -> TestVectors {
    guard let vectorsUrl = Bundle.module.url(forResource: "rfc_vectors", withExtension: "json") else {
        throw TestError.missingVectors
    }
    let file = try Data(contentsOf: vectorsUrl)
    return try JSONDecoder().decode(TestVectors.self, from: file)
}
