import Crypto
import Foundation

/// Represents the output of an encryption operation.
public protocol SealedBox {
    /// The authentication tag.
    var authTag: Data { get }
    /// The encrypted ciphertext.
    var encrypted: Data { get }
    /// The bytes of the nonce.
    var nonceBytes: Data { get }
}

/// A provider of cryptographic operations for SFrame.
public protocol CryptoProvider {
    /// The hash function in use.
    associatedtype Hash: CryptoKit.HashFunction
    /// The suite in use.
    var suite: CipherSuite { get }

    /// HKDF Extract.
    /// - Parameter inputKeyMaterial: The base key to derive from.
    /// - Parameter salt: The salt to use.
    /// - Returns: The derived key.
    func hkdfExtract(inputKeyMaterial: SymmetricKey, salt: Data?) -> HashedAuthenticationCode<Hash>

    /// HKDF Expand.
    /// - Parameter pseudoRandomKey: The key to expand.
    /// - Parameter info: The shared info for derivation.
    /// - Parameter outputByteCount: The length of the derived key, in bytes.
    func hkdfExpand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) -> SymmetricKey

    /// Seal a plaintext message with authenticating data.
    /// - Parameters:
    ///  - plainText: The plaintext message.
    ///  - using: The key to use.
    ///  - nonce: The nonce to use.
    ///  - authenticating: The data to authenticate.
    ///  - Returns: The sealed box output.
    func seal(plainText: Data, using: SymmetricKey, nonce: Data, authenticating: Data) throws -> SealedBox

    /// Decrypt and verify a message.
    /// - Parameters:
    ///   - box: The sealed box to open.
    ///   - using: The key to use.
    ///   - authenticating: The data to authenticate.
    /// - Returns: The decrypted plaintext.
    func open(box: SealedBox, using: SymmetricKey, authenticating: Data) throws -> Data
}
