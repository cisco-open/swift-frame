// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import _CryptoExtras
import Crypto
import Foundation

/// Crypto Provider for SwiftCrypto. CryptoKit on Apple, BoringSSL elsewhere.
public struct SwiftCryptoProvider: CryptoProvider {
    /// The suite in use.
    public let suite: CipherSuite

    public init(suite: CipherSuite) {
        self.suite = suite
    }

    public func seal(plainText: Data, using: SymmetricKey, nonce: Data, authenticating: Data) throws -> any SealedBox {
        switch self.suite.identifier {
        case CipherSuites.aes_128_gcm_sha256_128.rawValue,
             CipherSuites.aes_256_gcm_sha512_128.rawValue:
            return try AES.GCM.seal(plainText, using: using, nonce: .init(data: nonce), authenticating: authenticating)

        case CipherSuites.aes_128_ctr_hmac_sha256_32.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_64.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_80.rawValue:
            return try SyntheticAEAD(suite: self.suite,
                                     provider: self,
                                     sframeKey: using).encrypt(nonce: nonce,
                                                               aad: authenticating,
                                                               plainText: plainText)

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }

    public func open(box: some SealedBox, using: SymmetricKey, authenticating: Data) throws -> Data {
        switch self.suite.identifier {
        // GCM.
        case CipherSuites.aes_128_gcm_sha256_128.rawValue,
             CipherSuites.aes_256_gcm_sha512_128.rawValue:
            try AES.GCM.open(.init(box), using: using, authenticating: authenticating)

        // CTR.
        case CipherSuites.aes_128_ctr_hmac_sha256_32.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_64.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_80.rawValue:
            try SyntheticAEAD(suite: self.suite,
                              provider: self,
                              sframeKey: using).decrypt(box: box, aad: authenticating)

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }

    public func hkdfExpand(pseudoRandomKey: SymmetricKey, info: Data, outputByteCount: Int) throws -> SymmetricKey {
        switch self.suite.identifier {
        // SHA256.
        case CipherSuites.aes_128_gcm_sha256_128.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_32.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_64.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_80.rawValue:
            HKDF<SHA256>.expand(pseudoRandomKey: pseudoRandomKey, info: info, outputByteCount: outputByteCount)

        // SHA512.
        case CipherSuites.aes_256_gcm_sha512_128.rawValue:
            HKDF<SHA512>.expand(pseudoRandomKey: pseudoRandomKey, info: info, outputByteCount: outputByteCount)

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }

    public func hkdfExtract(inputKeyMaterial: SymmetricKey, salt: Data?) throws -> Data {
        switch self.suite.identifier {
        // SHA256.
        case CipherSuites.aes_128_gcm_sha256_128.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_32.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_64.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_80.rawValue:
            .init(HKDF<SHA256>.extract(inputKeyMaterial: inputKeyMaterial, salt: salt))

        // SHA512.
        case CipherSuites.aes_256_gcm_sha512_128.rawValue:
            .init(HKDF<SHA512>.extract(inputKeyMaterial: inputKeyMaterial, salt: salt))

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }

    public func hmac(key: SymmetricKey, data: Data) throws -> Data {
        switch self.suite.identifier {
        // SHA256.
        case CipherSuites.aes_128_ctr_hmac_sha256_32.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_64.rawValue,
             CipherSuites.aes_128_ctr_hmac_sha256_80.rawValue:
            .init(HMAC<SHA256>.authenticationCode(for: data, using: key))

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }

    public func encryptCtr(key: SymmetricKey, nonce: Data, plainText: Data) throws -> Data {
        try AES._CTR.encrypt(plainText, using: key, nonce: .init(nonceBytes: nonce))
    }

    public func decryptCtr(key: SymmetricKey, nonce: Data, cipherText: Data) throws -> Data {
        try AES._CTR.decrypt(cipherText, using: key, nonce: .init(nonceBytes: nonce))
    }
}

// SwiftCrypto does not expose a constant time algorithm,
// but Digest equality is in constant time, so we internally
// implement a thin Digest to access this.
extension SwiftCryptoProvider { // swiftlint:disable:this no_grouping_extension
    private struct _Digest<T: Bytes>: Digest {
        static var byteCount: Int { T.count / 8 }
        private let bytes: Data

        init(_ bytes: Data) {
            self.bytes = bytes
        }

        // Forward.
        func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
            try self.bytes.withUnsafeBytes(body)
        }

        // Matches the SwiftCrypto implementation.
        func hash(into hasher: inout Hasher) {
            self.withUnsafeBytes { hasher.combine(bytes: $0) }
        }
    }

    private protocol Bytes {
        static var count: Int { get }
    }

    private enum ThirtyTwo: Bytes { static let count = 32 }
    private enum SixtyFour: Bytes { static let count = 64 }
    private enum Eighty: Bytes { static let count = 80 }

    /// Constant time comparison using custom Digests.
    public func constantTimeCompare(lhs: Data, rhs: Data) throws -> Bool {
        guard lhs.count == rhs.count,
              lhs.count == self.suite.nt else {
            return false
        }
        return switch self.suite.nt * 8 {
        case ThirtyTwo.count:
            _Digest<ThirtyTwo>(lhs) == rhs

        case SixtyFour.count:
            _Digest<SixtyFour>(lhs) == rhs

        case Eighty.count:
            _Digest<Eighty>(lhs) == rhs

        default:
            throw CryptoProviderError.unsupportedCipherSuite
        }
    }
}

/// Sealed box bindings for SwiftCrypto.
extension AES.GCM.SealedBox: SealedBox {
    public var authTag: Data { self.tag }
    public var encrypted: Data { self.ciphertext }
    public var nonceBytes: Data { .init(contiguousNoCopy: self.nonce) }

    internal init(_ box: SealedBox) throws {
        try self.init(nonce: .init(data: box.nonceBytes), ciphertext: box.encrypted, tag: box.authTag)
    }
}
