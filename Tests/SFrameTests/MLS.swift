// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation
import SFrame
import Testing

private struct MLSTests {
    let maxOverhead = 17 + 16

    @Test("Roundtrip", arguments: CipherSuites.allCases)
    func roundtrip(_ suite: CipherSuites) throws {
        guard let suite = registry[suite] else {
            throw TestError.unsupportedCipherSuite
        }
        let epochBits: UInt = 2
        let testEpochs: MLS.EpochID = 1 << (epochBits + 1)
        let epochRounds = 10
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let senderIdB = MLS.SenderID(0xA1A1A1A1)

        let provider = SwiftCryptoProvider(suite: suite)
        let memberA = MLS(provider: provider, epochBits: epochBits)
        let memberB = MLS(provider: provider, epochBits: epochBits)
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

        let epochBits: UInt = 4
        let testEpochs: MLS.EpochID = 1 << (epochBits + 1)
        let epochRounds = 10
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let senderIdB = MLS.SenderID(0xA1A1A1A1)
        let senderIdBits: UInt = 32
        let contextId0: UInt64 = 0xB0B0
        let contextId1: UInt64 = 0xB1B1

        let memberA0 = MLS(provider: provider, epochBits: epochBits)
        let memberA1 = MLS(provider: provider, epochBits: epochBits)
        let memberB = MLS(provider: provider, epochBits: epochBits)
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

        let epochBits: UInt = 2
        let metadata = Data("00010203".utf8)
        let plaintext = Data("04050607".utf8)
        let senderIdA = MLS.SenderID(0xA0A0A0A0)
        let sframeEpochSecret1 = SymmetricKey(data: Data(repeating: 1, count: 32))
        let sframeEpochSecret2 = SymmetricKey(data: Data(repeating: 2, count: 32))

        let memberA = MLS(provider: provider, epochBits: epochBits)
        let memberB = MLS(provider: provider, epochBits: epochBits)

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
