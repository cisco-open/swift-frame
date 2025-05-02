// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
@testable import SFrame
import Testing

private struct MLSTests {
    let maxOverhead = 17 + 16

    @Test("Roundtrip", arguments: CipherSuites.allCases)
    func roundtrip(_ suite: CipherSuites) throws {
        guard let suite = registry[suite] else {
            throw TestError.unsupportedCipherSuite
        }
        let epochBits = 2
        let testEpochs: MLS.EpochID = 1 << (epochBits + 1)
        let epochRounds = 10
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let senderIdB = MLS.SenderID(0xA1A1A1A1)

        let provider = SwiftCryptoProvider(suite: suite)
        let memberA = try MLS(provider: provider, epochBits: epochBits)
        let memberB = try MLS(provider: provider, epochBits: epochBits)
        for epochId in 0..<testEpochs {
            let sframeEpochSecret = SymmetricKey(data: Data(repeating: UInt8(epochId), count: 8))
            try memberA.addEpoch(epochId: epochId,
                                 sframeEpochSecret: sframeEpochSecret,
                                 senderBits: nil)
            try memberB.addEpoch(epochId: epochId,
                                 sframeEpochSecret: sframeEpochSecret,
                                 senderBits: nil)
            for _ in 0..<epochRounds {
                // A->B.
                let encryptedAB = try memberA.protect(epochId: epochId,
                                                      senderId: senderIdA,
                                                      plaintext: plaintext,
                                                      metadata: metadata)
                let decryptedAB = try memberB.unprotect(ciphertext: encryptedAB, metadata: metadata)
                #expect(plaintext == decryptedAB)

                // B->A.
                let encryptedBA = try memberB.protect(epochId: epochId,
                                                      senderId: senderIdB,
                                                      plaintext: plaintext,
                                                      metadata: metadata)
                let decryptedBA = try memberA.unprotect(ciphertext: encryptedBA, metadata: metadata)
                #expect(plaintext == decryptedBA)
            }
        }
    }

    @Test("Roundtrip with context", arguments: [CipherSuites.aes_128_gcm_sha256_128])
    func roundtripContext(_ suite: CipherSuites) throws { // swiftlint:disable:this function_body_length
        guard let suite = registry[suite] else {
            throw TestError.unsupportedCipherSuite
        }
        let provider = SwiftCryptoProvider(suite: suite)

        let epochBits = 4
        let testEpochs: MLS.EpochID = 1 << (epochBits + 1)
        let epochRounds = 10
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let senderIdB = MLS.SenderID(0xA1A1A1A1)
        let senderIdBits = 32
        let contextId0: UInt64 = 0xB0B0
        let contextId1: UInt64 = 0xB1B1

        let memberA0 = try MLS(provider: provider, epochBits: epochBits)
        let memberA1 = try MLS(provider: provider, epochBits: epochBits)
        let memberB = try MLS(provider: provider, epochBits: epochBits)
        for epochId in 0..<testEpochs {
            let sframeEpochSecret = SymmetricKey(data: Data(repeating: UInt8(epochId), count: 8))
            try memberA0.addEpoch(epochId: epochId,
                                  sframeEpochSecret: sframeEpochSecret,
                                  senderBits: senderIdBits)
            try memberA1.addEpoch(epochId: epochId,
                                  sframeEpochSecret: sframeEpochSecret,
                                  senderBits: senderIdBits)
            try memberB.addEpoch(epochId: epochId,
                                 sframeEpochSecret: sframeEpochSecret,
                                 senderBits: nil)
            for _ in 0..<epochRounds {
                // A->B.
                let encryptedAB0 = try memberA0.protect(epochId: epochId,
                                                        senderId: senderIdA,
                                                        plaintext: plaintext,
                                                        metadata: metadata,
                                                        contextId: contextId0)
                let decryptedAB0 = try memberB.unprotect(ciphertext: encryptedAB0, metadata: metadata)
                #expect(plaintext == decryptedAB0)

                let encryptedAB1 = try memberA1.protect(epochId: epochId,
                                                        senderId: senderIdA,
                                                        plaintext: plaintext,
                                                        metadata: metadata,
                                                        contextId: contextId1)
                let decryptedAB1 = try memberB.unprotect(ciphertext: encryptedAB1, metadata: metadata)
                #expect(plaintext == decryptedAB1)

                #expect(encryptedAB0 != encryptedAB1)

                // B->A.
                let encryptedBA = try memberB.protect(epochId: epochId,
                                                      senderId: senderIdB,
                                                      plaintext: plaintext,
                                                      metadata: metadata)
                let decryptedBA0 = try memberA0.unprotect(ciphertext: encryptedBA, metadata: metadata)
                let decryptedBA1 = try memberA1.unprotect(ciphertext: encryptedBA, metadata: metadata)
                #expect(plaintext == decryptedBA0)
                #expect(plaintext == decryptedBA1)
            }
        }
    }

    @Test("Failure after purge", arguments: CipherSuites.allCases)
    func failureAfterPurge(_ suite: CipherSuites) throws {
        guard let suite = registry[suite] else {
            throw TestError.unsupportedCipherSuite
        }
        let provider = SwiftCryptoProvider(suite: suite)

        let epochBits = 2
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let sframeEpochSecret1 = SymmetricKey(data: Data(repeating: 1, count: 32))
        let sframeEpochSecret2 = SymmetricKey(data: Data(repeating: 2, count: 32))

        let memberA = try MLS(provider: provider, epochBits: epochBits)
        let memberB = try MLS(provider: provider, epochBits: epochBits)

        // Install epoch 1 and create a ciphertext
        let epochId1: MLS.EpochID = 1
        try memberA.addEpoch(epochId: epochId1,
                             sframeEpochSecret: sframeEpochSecret1)
        try memberB.addEpoch(epochId: epochId1,
                             sframeEpochSecret: sframeEpochSecret1)

        let encryptedAB1 = try memberA.protect(epochId: epochId1,
                                               senderId: senderIdA,
                                               plaintext: plaintext,
                                               metadata: metadata)

        // Install epoch 2
        let epochId2: MLS.EpochID = 2
        try memberA.addEpoch(epochId: epochId2,
                             sframeEpochSecret: sframeEpochSecret2)
        try memberB.addEpoch(epochId: epochId2,
                             sframeEpochSecret: sframeEpochSecret2)

        // Purge epoch 1 and verify failure
        memberA.purgeBefore(keep: epochId2)
        memberB.purgeBefore(keep: epochId2)

        #expect(throws: MLSError.unknownEpoch) {
            try memberA.protect(epochId: epochId1,
                                senderId: senderIdA,
                                plaintext: plaintext,
                                metadata: metadata)
        }
        #expect(throws: MLSError.unknownEpoch) {
            try memberB.unprotect(ciphertext: encryptedAB1, metadata: metadata)
        }

        let encryptedAB2 = try memberA.protect(epochId: epochId2,
                                               senderId: senderIdA,
                                               plaintext: plaintext,
                                               metadata: metadata)
        let decryptedAB2 = try memberB.unprotect(ciphertext: encryptedAB2,
                                                 metadata: metadata)
        #expect(plaintext == decryptedAB2)
    }

    @Test("Epoch Bits")
    func testEpochBits() throws {
        guard let suite = registry[.aes_128_gcm_sha256_128] else {
            throw TestError.unsupportedCipherSuite
        }
        let provider = SwiftCryptoProvider(suite: suite)
        let secret = SymmetricKey(size: .bits128)

        // Too small.
        #expect(throws: MLSError.badEpochBits) {
            try MLS(provider: provider, epochBits: 0, reserveCapacity: false)
        }

        // Too big.
        #expect(throws: MLSError.badEpochBits) {
            try MLS(provider: provider, epochBits: MLS.EpochID.bitWidth, reserveCapacity: false)
        }

        // Just right.
        for epochBits in 1..<MLS.EpochID.bitWidth {
            let mls = try MLS(provider: provider, epochBits: epochBits, reserveCapacity: false)
            let maxEpochId = MLS.EpochID.max(epochBits)
            try mls.addEpoch(epochId: maxEpochId, sframeEpochSecret: secret)
            precondition(UInt64.max == .max(UInt64.bitWidth))
            let maxSenderId = MLS.SenderID.max(KeyId.bitWidth - epochBits)
            _ = try mls.protect(epochId: maxEpochId,
                                senderId: maxSenderId,
                                plaintext: .init())
        }
    }

    @Test("Sender ID Overflow Protection")
    func testSenderIdOverflow() throws {
        guard let suite = registry[.aes_128_gcm_sha256_128] else {
            throw TestError.unsupportedCipherSuite
        }
        let provider = SwiftCryptoProvider(suite: suite)
        let secret = SymmetricKey(size: .bits128)
        for epochBits in 1..<MLS.EpochID.bitWidth {
            let senderBits = MLS.EpochID.bitWidth - epochBits
            let mls = try MLS(provider: provider, epochBits: epochBits, reserveCapacity: false)
            try mls.addEpoch(epochId: 0, sframeEpochSecret: secret)
            let maxSender = MLS.SenderID.max(senderBits)
            // Don't overflow.
            _ = try mls.protect(epochId: 0, senderId: maxSender, plaintext: .init())
            // Overflow.
            #expect(throws: MLSError.senderOverflow) {
                _ = try mls.protect(epochId: 0, senderId: maxSender + 1, plaintext: .init())
            }
        }
    }

    @Test("Context ID Overflow Protections")
    func testContextIdOverflow() throws {
        guard let suite = registry[.aes_128_gcm_sha256_128] else {
            throw TestError.unsupportedCipherSuite
        }
        let provider = SwiftCryptoProvider(suite: suite)
        let secret = SymmetricKey(size: .bits128)
        for epochBits in 1..<MLS.EpochID.bitWidth {
            let mls = try MLS(provider: provider, epochBits: epochBits, reserveCapacity: false)
            let senderBits = KeyId.bitWidth - epochBits
            try mls.addEpoch(epochId: 0, sframeEpochSecret: secret, senderBits: KeyId.bitWidth - epochBits)
            let maxSender = MLS.SenderID.max(senderBits)
            // Don't overflow.
            let contextBits = KeyId.bitWidth - epochBits - senderBits
            let maxContext = MLS.ContextID.max(contextBits)
            _ = try mls.protect(epochId: 0,
                                senderId: maxSender,
                                plaintext: .init(),
                                metadata: nil,
                                contextId: maxContext)
            // Overflow.
            #expect(throws: MLSError.contextOverflow) {
                _ = try mls.protect(epochId: 0,
                                    senderId: maxSender,
                                    plaintext: .init(),
                                    metadata: nil,
                                    contextId: maxContext + 1)
            }
        }
    }
}

extension CipherSuites: CaseIterable {
    public static let allCases: [CipherSuites] = [
        .aes_128_ctr_hmac_sha256_32,
        .aes_128_ctr_hmac_sha256_64,
        .aes_128_ctr_hmac_sha256_80,
        .aes_128_gcm_sha256_128,
        .aes_256_gcm_sha512_128
    ]
}
