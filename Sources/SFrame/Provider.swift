// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Represents the output of an encryption operation.
public protocol SealedBox {
    /// The authentication tag.
    var authTag: Data { get }
    /// The encrypted ciphertext.
    var encrypted: Data { get }
    /// The bytes of the nonce used for this operation.
    var nonceBytes: Data { get }
}

/// A provider of cryptographic operations potentially required by SFrame.
public protocol CryptoProvider {
    /// The suite in use.
    var suite: CipherSuite { get }

    /// HKDF Extract.
    /// - Parameter inputKeyMaterial: The base key to derive from.
    /// - Parameter salt: The salt to use.
    /// - Returns: The derived key.
    func hkdfExtract(inputKeyMaterial: SymmetricKey, salt: Data?) throws -> Data

    /// HKDF Expand.
    /// - Parameter pseudoRandomKey: The key to expand.
    /// - Parameter info: The shared info for derivation.
    /// - Parameter outputByteCount: The length of the derived key, in bytes.
    func hkdfExpand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) throws -> SymmetricKey

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
    func open(box: some SealedBox, using: SymmetricKey, authenticating: Data) throws -> Data

    /// AES CTR Encryption operation used internally by SFrame's AES-CTR with SHA2 implementation.
    /// - Parameters:
    ///   - key: The key to use.
    ///   - nonce: The nonce to use.
    ///   - plainText: The plaintext to encrypt.
    /// - Returns: The encrypted ciphertext.
    func encryptCtr(key: SymmetricKey, nonce: Data, plainText: Data) throws -> Data

    /// AES CTR Decryption operation used internally by SFrame's AES-CTR with SHA2 implementation.
    /// - Parameters:
    ///   - key: The key to use.
    ///   - nonce: The nonce to use.
    ///   - cipherText: The ciphertext to decrypt.
    /// - Returns: The decrypted plaintext.
    func decryptCtr(key: SymmetricKey, nonce: Data, cipherText: Data) throws -> Data

    /// HMAC operation used internally by SFrame's AES-CTR with SHA2 implementation.
    /// - Parameters:
    ///  - key: The key to use.
    ///  - data: The data to authenticate.
    func hmac(key: SymmetricKey, data: Data) throws -> Data

    /// A cryptographic constant-time comparison.
    /// This will return false immediately if the two values are not equal size.
    /// - Parameters:
    ///  - lhs: The left-hand side to compare.
    ///  - rhs: The right-hand side to compare.
    /// - Returns: True if the two values are equal, false otherwise.
    func constantTimeCompare(lhs: Data, rhs: Data) throws -> Bool
}

/// Standard errors thrown by a Provider.
public enum CryptoProviderError: Error {
    /// This provider does not support the requested cipher suite.
    case unsupportedCipherSuite
}
