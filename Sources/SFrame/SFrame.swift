import CryptoKit
import Foundation

/// SFrame cipher suite identifier type.
public typealias CipherSuiteIdentifier = UInt32
/// SFrame Key Identifier type.
public typealias KeyId = UInt64
/// SFrame Counter value type.
public typealias Counter = UInt64

/// SFrame Encrypted Blob.
public struct CipherText {
    /// SFrame Header.
    public let header: Header
    /// The encrypted payload.
    public let encrypted: Data
    /// The authentication tag.
    public let authenticationTag: Data

    /// Create an SFrame CipherText message.
    /// - Parameter header: The SFrame ``Header`` for this message.
    /// - Parameter encrypted: The encrypted payload.
    /// - Parameter authenticationTag: The authentication tag.
    public init(header: Header, encrypted: Data, authenticationTag: Data) {
        self.header = header
        self.encrypted = encrypted
        self.authenticationTag = authenticationTag
    }
}

/// SFrame Header.
public struct Header {
    /// ID for the key in use.
    public let keyId: KeyId
    /// Counter value used in this message.
    public let counter: Counter

    /// Create an SFrame Header for a message.
    /// - Parameter keyId: The key ID used to encrypt this message.
    /// - Parameter counter: The counter value for this message.
    public init(keyId: KeyId, counter: Counter) {
        self.keyId = keyId
        self.counter = counter
    }
}

private protocol KeyContext {
    var key: SymmetricKey { get }
    var salt: ContiguousBytes { get }
}

private struct SendKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
    let counter: Counter

    static func incrementing(_ context: Self) -> Self {
        .init(key: context.key,
              salt: context.salt,
              counter: context.counter + 1)
    }
}

private struct ReceiveKeyContext: KeyContext {
    let key: SymmetricKey
    let salt: ContiguousBytes
}

public enum SFrameError: Error {
    case badLabel
    case invalidKeyId
}

extension SymmetricKey {
    private static let keyLabelPrefix = "SFrame 1.0 Secret key "
    private static let saltLabelPrefix = "SFrame 1.0 Secret salt "

    /// Perform the SFrame key derivation on this base key.
    /// - Parameter keyId: The base key's identifier.
    /// - Parameter provider: Crypto operation provider.
    /// - Parameter cipherSuite: The cipher suite to use.
    /// - Returns: The derived key and salt.
    internal func sframeDerive(keyId: KeyId,
                               provider: some CryptoProvider) throws -> (key: SymmetricKey, salt: SymmetricKey) {
        // Get secret.
        let secret = SymmetricKey(data: provider.hkdfExtract(inputKeyMaterial: self, salt: .none))

        // Derive Key.
        let keyLabel = try self.buildKeyLabel(Self.keyLabelPrefix, keyId: keyId, cipherSuite: provider.suite)
        let key = provider.hkdfExpand(pseudoRandomKey: secret, info: keyLabel, outputByteCount: provider.suite.nk)

        // Derive Salt.
        let saltLabel = try self.buildKeyLabel(Self.saltLabelPrefix, keyId: keyId, cipherSuite: provider.suite)
        let salt = provider.hkdfExpand(pseudoRandomKey: secret, info: saltLabel, outputByteCount: provider.suite.nn)
        return (key: key, salt: salt)
    }

    private func buildKeyLabel(_ label: String, keyId: KeyId, cipherSuite: CipherSuite) throws -> Data {
        guard var data = label.data(using: .utf8) else {
            throw SFrameError.badLabel
        }
        data.append(Swift.withUnsafeBytes(of: keyId.bigEndian) { Data($0) })
        data.append(Swift.withUnsafeBytes(of: UInt16(cipherSuite.identifier).bigEndian) { Data($0) })
        return data
    }
}

// swiftlint:disable identifier_name

/// Represents a cipher suite.
public struct CipherSuite: Sendable {
    // SFrame Cipher Suite Registry Identifier.
    public let identifier: UInt32
    /// Size of the hash function output.
    public let nh: Int
    /// Compound AEAD key size, if applicable.
    public let nka: Int?
    /// Size of the encryption key.
    public let nk: Int
    /// Size of the nonce.
    public let nn: Int
    /// Size of the authentication tag.
    public let nt: Int
}

/// SFrame cipher suites by registered identifier.
public enum CipherSuites: UInt32, Sendable {
    case aes_128_ctr_hmac_sha256_80 = 1
    case aes_128_ctr_hmac_sha256_64 = 2
    case aes_128_ctr_hmac_sha256_32 = 3
    case aes_128_gcm_sha256_128 = 4
    case aes_256_gcm_sha512_128 = 5
}

// swiftlint:enable identifier_name

/// SFrame Cipher Suite Registry.
public let registry: [CipherSuites: CipherSuite] = [
    .aes_128_ctr_hmac_sha256_80: .init(identifier: 1, nh: 32, nka: 16, nk: 48, nn: 12, nt: 10),
    .aes_128_ctr_hmac_sha256_64: .init(identifier: 2, nh: 32, nka: 16, nk: 48, nn: 12, nt: 8),
    .aes_128_ctr_hmac_sha256_32: .init(identifier: 3, nh: 32, nka: 16, nk: 48, nn: 12, nt: 4),
    .aes_128_gcm_sha256_128: .init(identifier: 4, nh: 64, nka: nil, nk: 16, nn: 12, nt: 16),
    .aes_256_gcm_sha512_128: .init(identifier: 5, nh: 64, nka: nil, nk: 32, nn: 12, nt: 16)
]

public class Context: SFrame {
    private var keys: [KeyId: KeyContext] = [:]
    private let crypto: any CryptoProvider

    public init(provider: any CryptoProvider) {
        self.crypto = provider
    }

    public func addSendKey(_ keyId: KeyId, key: SymmetricKey, currentCounter: Counter = 0) throws {
        guard self.keys[keyId] == nil else {
            throw SFrameError.invalidKeyId
        }
        let derived = try key.sframeDerive(keyId: keyId,
                                           provider: self.crypto)
        self.keys[keyId] = SendKeyContext(key: derived.key,
                                          salt: derived.salt,
                                          counter: currentCounter)
    }

    public func addReceiveKey(_ keyId: KeyId, key: SymmetricKey) throws {
        guard self.keys[keyId] == nil else {
            throw SFrameError.invalidKeyId
        }
        let derived = try key.sframeDerive(keyId: keyId,
                                           provider: self.crypto)
        self.keys[keyId] = ReceiveKeyContext(key: derived.key, salt: derived.salt)
    }

    private func formNonce(counter: UInt64, salt: some ContiguousBytes) throws -> Data {
        var nonce = try Data(contiguousNoCopy: salt)
        withUnsafeBytes(of: counter.bigEndian) { counterBytes in
            zip(counterBytes, nonce.indices.suffix(MemoryLayout<UInt64>.size))
                .forEach { nonce[$1] ^= $0 }
        }
        return nonce
    }

    public func encrypt(_ keyId: KeyId, metadata: Data?, plaintext: Data) throws -> CipherText {
        // Ensure we have a matching encryption key.
        guard let context = self.keys[keyId],
              let sendContext = context as? SendKeyContext else {
            throw SFrameError.invalidKeyId
        }

        // Derive the nonce.
        let nonceBytes = try self.formNonce(counter: sendContext.counter, salt: sendContext.salt)

        // Prepare the header & aad.
        let header = Header(keyId: keyId, counter: sendContext.counter)
        var aad = Data()
        try header.encode(into: &aad)
        if let metadata {
            aad.append(metadata)
        }

        // Seal.
        let sealedBox = try self.crypto.seal(plainText: plaintext,
                                             using: sendContext.key,
                                             nonce: .init(nonceBytes),
                                             authenticating: aad)
        self.keys[keyId] = SendKeyContext.incrementing(sendContext)
        return .init(header: header,
                     encrypted: sealedBox.encrypted,
                     authenticationTag: sealedBox.authTag)
    }

    public func decrypt(metadata: Data, ciphertext: Data) throws -> Data {
        // Decode the constituant parts.
        var read = 0
        let ciphertext = try CipherText(tagLength: self.crypto.suite.nt, from: ciphertext, read: &read)

        // Ensure we have a matching decryption key.
        guard let context = self.keys[ciphertext.header.keyId],
              context is ReceiveKeyContext else {
            throw SFrameError.invalidKeyId
        }

        let nonce = try self.formNonce(counter: ciphertext.header.counter, salt: context.salt)
        var result = Data()
        try ciphertext.header.encode(into: &result)
        result.append(metadata)
        let aad = result
        struct SealedBoxImpl: SealedBox {
            let authTag: Data
            let encrypted: Data
            let nonceBytes: Data
        }
        let sealedBox = SealedBoxImpl(authTag: ciphertext.authenticationTag,
                                      encrypted: ciphertext.encrypted,
                                      nonceBytes: nonce)
        return try self.crypto.open(box: sealedBox, using: context.key, authenticating: aad)
    }
}

/// SFrame operations.
public protocol SFrame {
    /// Add a key to be used for sending/encryption.
    /// - Parameter keyId: The key's identifier.
    /// - Parameter key: The base key.
    /// - Parameter currentCounter: The counter value to start from.
    /// - Throws: If the key is already in use.
    mutating func addSendKey(_ keyId: KeyId, key: SymmetricKey, currentCounter: Counter) throws

    /// Add a key to be used for receiving/decryption.
    /// - Parameter keyId: The key's identifier.
    /// - Parameter key: The base key.
    /// - Throws: If the key is already in use.
    mutating func addReceiveKey(_ keyId: KeyId, key: SymmetricKey) throws

    /// Encrypt a payload, authenticating metadata.
    /// - Parameter keyId: The key to use for encryption.
    /// - Parameter metadata: Metadata to authenticate.
    /// - Parameter plaintext: The payload to encrypt.
    /// - Returns: The encrypted SFrame ciphertext.
    /// - Throws: If the key is not found, a receive key was used, or encryption fails.
    mutating func encrypt(_ keyId: KeyId, metadata: Data?, plaintext: Data) throws -> CipherText

    /// Decrypt a payload, authenticating metadata.
    /// - Parameter metadata: Metadata to authenticate.
    /// - Parameter ciphertext: The encrypted payload.
    /// - Returns: The decrypted payload.
    /// - Throws: If the key is not found, a send key was used, decryption fails,
    /// or the metadata can't be authenticated.
    func decrypt(metadata: Data, ciphertext: Data) throws -> Data
}
