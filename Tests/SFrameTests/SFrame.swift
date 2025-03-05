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
    @Test("Throw on missing key")
    private func testEncryptBadKid() throws {
        let suite = registry[.aes_128_ctr_hmac_sha256_32]! // swiftlint:disable:this force_unwrapping
        let provider = SwiftCryptoProvider(suite: suite)
        let sframe = Context(provider: provider)
        #expect(performing: {
            try sframe.encrypt(0, metadata: nil, plaintext: .init())
        }, throws: { $0 as? SFrameError == SFrameError.invalidKeyId })
    }

    @Test("Encrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorEncrypt(_ vector: SFrameVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addSendKey(vector.kid, key: baseKey, currentCounter: vector.ctr)
        let cipherText = try sframe.encrypt(vector.kid, metadata: vector.metadata, plaintext: vector.plainText)
        #expect(cipherText == vector.cipherText)
    }

    @Test("Decrypt Vector", arguments: Fixtures.testVectors.sframe)
    private func testSFrameVectorDecrypt(_ vector: SFrameVector) throws {
        var sframe = try makeSFrame(vector.cipherSuite)
        let baseKey = SymmetricKey(data: vector.baseKey)
        try sframe.addReceiveKey(vector.kid, key: baseKey)
        let decrypted = try sframe.decrypt(metadata: vector.metadata, ciphertext: vector.cipherText)
        #expect(decrypted == vector.plainText)
    }
}
