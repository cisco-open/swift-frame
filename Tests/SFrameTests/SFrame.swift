// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SFrame
import Testing

private func makeSFrame(_ suite: UInt32) throws -> SFrame {
    // Prepare.
    guard let supported = CipherSuites(rawValue: suite),
          let resolvedSuite = registry[supported] else {
        throw TestError.unsupportedCipherSuite
    }
    return Context(provider: SwiftCryptoProvider(suite: resolvedSuite))
}

private struct SFrameVectorTests {
    @Test("Encrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorEncrypt(_ vector: SFrameTestVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addKey(vector.kid, key: baseKey, usage: .encrypt)
        // Spin up to the vector's counter value.
        for _ in 0..<vector.ctr {
            _ = try sframe.protect(vector.kid, plaintext: .init(), metadata: vector.metadata)
        }
        let cipherText = try sframe.protect(vector.kid, plaintext: vector.plainText, metadata: vector.metadata)
        #expect(cipherText == vector.cipherText)
    }

    @Test("Decrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorDecrypt(_ vector: SFrameTestVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addKey(vector.kid, key: baseKey, usage: .decrypt)
        let decrypted = try sframe.unprotect(ciphertext: vector.cipherText, metadata: vector.metadata)
        #expect(decrypted == vector.plainText)
    }
}

private struct SFrameTests {
    @Test("Key Misuse - Missing")
    func testEncryptBadKid() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        #expect(performing: {
            try sframe.protect(0, plaintext: .init(), metadata: nil)
        }, throws: { $0 as? SFrameError == SFrameError.missingKey })
    }

    @Test("Key Misuse - Add decrypt with existing encrypt should fail")
    func testEncryptWithDecryptKey() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        let keyId: KeyId = 1
        let key = SymmetricKey(size: .bits128)
        try sframe.addKey(keyId, key: key, usage: .decrypt)
        #expect(performing: {
            try sframe.addKey(keyId, key: key, usage: .encrypt)
        }, throws: { $0 as? SFrameError == SFrameError.existingKey })
    }

    @Test("Key Misuse - Add encrypt with existing decrypt should fail")
    func testDecryptWithEncryptKey() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        let keyId: KeyId = 2
        let key = SymmetricKey(size: .bits128)
        try sframe.addKey(keyId, key: key, usage: .encrypt)
        #expect(performing: {
            try sframe.addKey(keyId, key: key, usage: .decrypt)
        }, throws: { $0 as? SFrameError == SFrameError.existingKey })
    }

    @Test("Key Update", arguments: [KeyUsage.encrypt, KeyUsage.decrypt])
    func testKeyUpdate(_ usage: KeyUsage) throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        let keyId: KeyId = 2
        let key = SymmetricKey(size: .bits128)
        try sframe.addKey(keyId, key: key, usage: usage)
        let updatedKey = SymmetricKey(size: .bits128)
        try sframe.addKey(keyId, key: updatedKey, usage: usage)
    }
}
