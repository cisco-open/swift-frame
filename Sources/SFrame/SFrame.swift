import Crypto
import Foundation

/// SFrame cipher suite identifier type.
public typealias CipherSuiteIdentifier = UInt32
/// SFrame Key Identifier type.
public typealias KeyId = UInt64
/// SFrame Counter value type.
public typealias Counter = UInt64

public enum SFrameError: Error {
    case badLabel
    case invalidKeyId
    case badParameter
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
    mutating func encrypt(_ keyId: KeyId, metadata: Data?, plaintext: Data) throws -> Data

    /// Decrypt a payload, authenticating metadata.
    /// - Parameter metadata: Metadata to authenticate.
    /// - Parameter ciphertext: The encrypted payload.
    /// - Returns: The decrypted payload.
    /// - Throws: If the key is not found, a send key was used, decryption fails,
    /// or the metadata can't be authenticated.
    func decrypt(metadata: Data, ciphertext: Data) throws -> Data
}
