// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
@testable import SFrame
import Testing

private struct AEADTests {
    @Test("AES CTR HMAC Encrypt", arguments: Fixtures.testVectors.crypto)
    private func testAEADEncrypt(_ vector: CryptoTestVector) throws {
        guard let known = CipherSuites(rawValue: vector.cipherSuite),
              let suite = registry[known] else { throw TestError.unsupportedCipherSuite }
        let aead = try SyntheticAEAD(suite: suite,
                                     provider: SwiftCryptoProvider(suite: suite),
                                     sframeKey: .init(data: vector.key))
        let cipherText = try aead.seal(nonce: vector.nonce, aad: vector.aad, plainText: vector.plainText)
        #expect(cipherText.encrypted + cipherText.authTag == vector.cipherText)
    }

    @Test("AES CTR HMAC Decrypt", arguments: Fixtures.testVectors.crypto)
    private func testAEADDecrypt(_ vector: CryptoTestVector) throws {
        guard let known = CipherSuites(rawValue: vector.cipherSuite),
              let suite = registry[known] else { throw TestError.unsupportedCipherSuite }
        let aead = try SyntheticAEAD(suite: suite,
                                     provider: SwiftCryptoProvider(suite: suite),
                                     sframeKey: .init(data: vector.key))
        let encrypted = vector.cipherText.prefix(vector.cipherText.count - suite.nt)
        let tag = vector.cipherText.suffix(suite.nt)
        let box = SealedDataBox(authTag: tag, encrypted: encrypted, nonceBytes: vector.nonce)
        let plainText = try aead.open(box: box, aad: vector.aad)
        #expect(plainText == vector.plainText)
    }
}
