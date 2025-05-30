// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// SFrame cipher suite identifier type.
public typealias CipherSuiteIdentifier = UInt32
/// SFrame Key Identifier type.
public typealias KeyId = UInt64
/// SFrame Counter value type.
public typealias Counter = UInt64

public enum SFrameError: Error {
    case missingKey
    case existingKey
    case badParameter
    case malformedCipherText

    public var localizedDescription: String {
        switch self {
        case .missingKey:
            return "The required key is missing."

        case .existingKey:
            return "This key already exists."

        case .badParameter:
            return "A bit size parameter was invalid."

        case .malformedCipherText:
            return "The ciphertext is malformed."
        }
    }
}

/// The operation this key is to be used for.
@frozen
public enum KeyUsage {
    /// This key is for encryption / sending.
    case encrypt
    /// This key is for decryption / receiving.
    case decrypt
}

/// SFrame operations.
public protocol SFrame {
    /// Add a key to be used for encryption or decryption.
    /// - Parameter keyId: The key's identifier.
    /// - Parameter key: The base key.
    /// - Throws: If the key is already in use.
    mutating func addKey(_ keyId: KeyId, key: SymmetricKey, usage: KeyUsage) throws

    /// Encrypt a payload, authenticating metadata.
    /// - Parameter keyId: The key to use for encryption.
    /// - Parameter plaintext: The payload to encrypt.
    /// - Parameter metadata: Metadata to authenticate.
    /// - Returns: The encrypted SFrame ciphertext.
    /// - Throws: If the key is not found, a receive key was used, or encryption fails.
    mutating func protect(_ keyId: KeyId, plaintext: Data, metadata: Data?) throws -> Data

    /// Decrypt a payload, authenticating metadata.
    /// - Parameter ciphertext: The encrypted payload.
    /// - Parameter metadata: Metadata to authenticate.
    /// - Returns: The decrypted payload.
    /// - Throws: If the key is not found, a send key was used, decryption fails,
    /// or the metadata can't be authenticated.
    func unprotect(ciphertext: Data, metadata: Data?) throws -> Data
}
