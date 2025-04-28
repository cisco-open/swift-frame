// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SFrame
import Testing

@Test("Example Usage")
private func example() throws {
    // Setup.
    guard let suite = registry[.aes_128_ctr_hmac_sha256_32] else {
        throw TestError.unsupportedCipherSuite
    }
    let provider = SwiftCryptoProvider(suite: suite)
    let keyId: UInt64 = 1
    let ourSharedKey = SymmetricKey(size: .bits128)
    let metadata = Data([1, 2, 3, 4])

    // Add the shared key to a context for sending, and use it to encrypt a message.
    let send = Context(provider: provider)
    try send.addKey(keyId, key: ourSharedKey, usage: .encrypt)
    let message = Data([5, 6, 7, 8])
    let encrypted = try send.protect(keyId, plaintext: message, metadata: metadata)

    // Adding the same key to a context for a different use is forbidden.
    #expect(throws: SFrameError.existingKey) {
        try send.addKey(keyId, key: ourSharedKey, usage: .decrypt)
    }

    // Add a shared key to a different context for receiving, and use it to decrypt a message.
    let receive = Context(provider: provider)
    try receive.addKey(keyId, key: ourSharedKey, usage: .decrypt)
    let decrypted = try receive.unprotect(ciphertext: encrypted, metadata: metadata)
    #expect(message == decrypted)
}
