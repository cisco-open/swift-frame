// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SFrame
import Testing

@Test("Example Usage")
private func example() throws {
    // Setup SFrame context.
    guard let suite = registry[.aes_128_ctr_hmac_sha256_32] else {
        throw TestError.unsupportedCipherSuite
    }
    let provider = SwiftCryptoProvider(suite: suite)

    // Add a shared key to SFrame, and use it to encrypt a message.
    let keyId: UInt64 = 1
    let ourSharedKey = SymmetricKey(size: .bits128)
    let metadata = Data([1, 2, 3, 4])

    // Encrypt.
    let message = Data([5, 6, 7, 8])
    let send = Context(provider: provider)
    try send.addKey(keyId, key: ourSharedKey, usage: .encrypt)
    let encrypted = try send.encrypt(keyId, plaintext: message, metadata: metadata)

    // Decrypt.
    let receive = Context(provider: provider)
    try receive.addKey(keyId, key: ourSharedKey, usage: .decrypt)
    let decrypted = try receive.decrypt(ciphertext: encrypted, metadata: metadata)
    #expect(message == decrypted)
}
