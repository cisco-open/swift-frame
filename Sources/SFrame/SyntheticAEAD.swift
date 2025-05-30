// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

public enum SyntheticAEADError: Error {
    case missingKeySize
    case authenticationFailure
    case badKeySize

    public var localizedDescription: String {
        switch self {
        case .missingKeySize:
            return "The cipher suite does not specify a key size."

        case .authenticationFailure:
            return "Authentication failed."

        case .badKeySize:
            return "The provided key size does not match the cipher suite requirements."
        }
    }
}

/// SFrame AES-CTR with SHA2 implementation.
public class SyntheticAEAD {
    private let suite: CipherSuite
    private let provider: CryptoProvider
    private let encKey: SymmetricKey
    private let authKey: SymmetricKey

    /// Prepare a new AEAD operation.
    /// - Parameters:
    ///   - suite: The cipher suite to use.
    ///   - provider: The crypto provider to use.
    ///   - sframeKey: The base AEAD key.
    public init(suite: CipherSuite, provider: CryptoProvider, sframeKey: SymmetricKey) throws {
        guard let nka = suite.nka else {
            throw SyntheticAEADError.missingKeySize
        }
        guard (sframeKey.bitCount / 8) == nka + suite.nh else {
            throw SyntheticAEADError.badKeySize
        }

        self.suite = suite
        self.provider = provider
        (self.encKey, self.authKey) = sframeKey.withUnsafeBytes { bytes in
            let encKey = bytes.prefix(nka)
            let authKey = bytes.suffix(suite.nh)
            return (SymmetricKey(data: encKey), SymmetricKey(data: authKey))
        }
    }

    /// Encrypt a message.
    /// - Parameters:
    ///   - nonce: The nonce to use.
    ///   - aad: The additional authenticated data.
    ///   - plainText: The plaintext to encrypt.
    /// - Returns: A sealed box containing the encryption result.
    public func seal(nonce: Data, aad: Data, plainText: Data) throws -> SealedBox {
        let initialCounter = nonce + Data(count: 4)
        let cipherText = try self.provider.ctr(key: self.encKey,
                                               nonce: initialCounter,
                                               data: plainText)
        let tag = try self.computeTag(nonce: nonce, aad: aad, cipherText: cipherText)
        return SealedDataBox(authTag: tag, encrypted: cipherText, nonceBytes: initialCounter)
    }

    /// Decrypt a message.
    /// - Parameters:
    ///   - box: An encrypted box.
    ///   - aad: Data to authenticate.
    /// - Returns: The decrypted plaintext.
    /// - Throws: ``SyntheticAEADError.authenticationFailure`` if the authentication fails. Otherwise HMAC failure.
    public func open(box: SealedBox, aad: Data) throws -> Data {
        let candidateTag = try self.computeTag(nonce: box.nonceBytes, aad: aad, cipherText: box.encrypted)
        guard try self.provider.constantTimeCompare(lhs: candidateTag, rhs: box.authTag) else {
            throw SyntheticAEADError.authenticationFailure
        }
        let initialCounter = box.nonceBytes + Data(count: 4)
        return try self.provider.ctr(key: self.encKey,
                                     nonce: initialCounter,
                                     data: box.encrypted)
    }

    private func computeTag(nonce: Data, aad: Data, cipherText: Data) throws -> Data {
        let encodeSize = 8
        let expectedEncodes = 3
        var authData = Data(capacity: encodeSize * expectedEncodes)
        aad.count.encodeBigEndian(encodeSize, into: &authData)
        cipherText.count.encodeBigEndian(encodeSize, into: &authData)
        self.suite.nt.encodeBigEndian(encodeSize, into: &authData)
        authData = authData + nonce + aad + cipherText
        let tag = try self.provider.hmac(key: self.authKey, data: authData)
        return tag.prefix(self.suite.nt)
    }
}
