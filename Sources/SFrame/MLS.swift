// SPDX-FileCopyrightText: 2025 Cisco
//
// SPDX-License-Identifier: Apache-2.0

import Crypto
import Foundation

/// Possible errors that can occur in the MLS context.
public enum MLSError: Error {
    /// The epoch was unknown.
    case unknownEpoch
    /// Sender ID was greater than the maximum allowed.
    case senderOverflow
    /// Context ID was greater than the maximum allowed.
    case contextOverflow
    /// Epoch bits must be 0 < x < 64.
    case badEpochBits
}

/// Provides an interface to utilize SFrame with MLS keying.
public class MLS {
    /// Identifier for an Epoch in MLS.
    public typealias EpochID = UInt64
    /// Identifier for a sender in MLS.
    public typealias SenderID = UInt64
    /// Context value type for MLS.
    public typealias ContextID = UInt64

    /// Epoch key storage.
    private class EpochKeys {
        /// The full epoch identifier of this epoch.
        let fullEpoch: EpochID
        /// The secret material for this epoch.
        let sframeEpochSecret: SymmetricKey
        /// Number of bits allocated for the sender ID.
        let senderBits: UInt8
        /// Number of bits allocated for the context ID.
        let contextBits: UInt8
        /// Maximum allowed sender ID.
        let maxSenderId: UInt64
        /// Maximum allowed context ID.
        let maxContextId: UInt64

        private let provider: CryptoProvider

        /// Initialize a new epoch with the provided secret and bit allocations.
        init(provider: CryptoProvider,
             fullEpoch: EpochID,
             sframeEpochSecret: SymmetricKey,
             epochBits: UInt8,
             senderBits: Int?) throws {
            self.provider = provider
            precondition(epochBits > 0)
            precondition(epochBits <= 63)

            // Resolve sender bits.
            let keyIdBits: UInt8 = 64
            if let senderBits {
                guard senderBits <= keyIdBits - epochBits else {
                    throw SFrameError.badParameter
                }
                precondition(senderBits > 0 && senderBits <= 64 - epochBits)
                self.senderBits = UInt8(senderBits)
            } else {
                self.senderBits = keyIdBits - epochBits
            }

            self.fullEpoch = fullEpoch
            self.sframeEpochSecret = sframeEpochSecret
            self.contextBits = keyIdBits - self.senderBits - epochBits
            precondition(self.contextBits >= 0 && self.contextBits <= 62)
            self.maxSenderId = .max(Int(self.senderBits))
            self.maxContextId = .max(Int(self.contextBits))
        }

        /// Derive a base key for a specific sender.
        func baseKey(senderId: SenderID) throws -> SymmetricKey {
            let size = MemoryLayout<UInt64>.size
            var encoded = Data(capacity: size)
            senderId.encodeBigEndian(size, into: &encoded)
            return try self.provider.hkdfExpand(pseudoRandomKey: self.sframeEpochSecret,
                                                info: encoded,
                                                outputByteCount: self.provider.suite.nh)
        }
    }

    /// Number of bits used for the epoch in the key ID.
    private let epochBits: UInt8

    /// Mask to extract the epoch portion of a key ID.
    private let epochMask: UInt64

    /// Cache of epoch keys to avoid recomputing.
    private var epochCache: [EpochID: EpochKeys] = [:]

    // SFrame Context.
    private let sframe: Context
    private let provider: CryptoProvider

    /// Initialize a new MLS context.
    /// - Parameters:
    ///   - provider: The crypto provider to use.
    ///   - epochBits: Number of bits (1..63) to allocate for the epoch in the key ID.
    ///   - reserveCapacity: Whether to reserve capacity for the epoch cache. For large epoch,
    ///                    this may not be desirable.
    /// - Throws: ``MLSError.badEpochBits`` if the epoch bit size are invalid.
    public init(provider: some CryptoProvider, epochBits: Int, reserveCapacity: Bool = true) throws(MLSError) {
        guard epochBits < EpochID.bitWidth,
              epochBits > 0 else {
            throw MLSError.badEpochBits
        }
        self.epochBits = UInt8(epochBits)
        let capacity = UInt64.max(epochBits)
        self.epochMask = capacity
        if reserveCapacity {
            let reserve = Int(min(capacity, UInt64(Int.max)))
            self.epochCache.reserveCapacity(reserve)
        }
        self.provider = provider
        self.sframe = .init(provider: provider)
    }

    /// Add a new epoch to the context.
    /// - Parameters:
    ///  - epochId: The epoch identifier.
    ///  - sframeEpochSecret: The secret material for this epoch.
    ///  - senderBits: Optional number of bits to allocate for the sender ID.
    public func addEpoch(epochId: EpochID, sframeEpochSecret: SymmetricKey, senderBits: Int? = nil) throws {
        let index = epochId & UInt64(self.epochMask)
        if self.epochCache[index] != nil {
            self.purgeEpoch(epochId: index)
        }
        do {
            let keys = try EpochKeys(provider: self.provider,
                                     fullEpoch: epochId,
                                     sframeEpochSecret: sframeEpochSecret,
                                     epochBits: self.epochBits,
                                     senderBits: senderBits)
            self.epochCache[index] = keys
        } catch {
            self.epochCache.removeValue(forKey: index)
            throw error
        }
    }

    /// Purge all epochs before the provided epoch.
    /// - Parameter including: The epoch to keep and all after.
    public func purgeBefore(keep including: EpochID) {
        for index in self.epochCache.keys.sorted() {
            guard index < including else { break }
            self.purgeEpoch(epochId: index)
            self.epochCache.removeValue(forKey: index)
        }
    }

    /// Purge all keys from a specific epoch.
    /// - Parameter epochId: The epoch to purge.
    private func purgeEpoch(epochId: EpochID) {
        let dropBits = epochId & self.epochMask
        for key in self.sframe.sendKeys.keys {
            guard key & self.epochMask == dropBits else { continue }
            self.sframe.sendKeys.removeValue(forKey: key)
        }
        for key in self.sframe.recvKeys.keys {
            guard key & self.epochMask == dropBits else { continue }
            self.sframe.recvKeys.removeValue(forKey: key)
        }
    }

    /// Form a key ID from the provided components.
    /// - Parameters:
    ///   - epochId: The epoch identifier.
    ///   - senderId: The sender identifier.
    ///   - contextId: The context identifier.
    /// - Returns: The constructed key ID.
    /// - Throws: ``MLSError`` if the components are invalid.
    private func formKeyId(epochId: EpochID, senderId: SenderID, contextId: ContextID) throws(MLSError) -> KeyId {
        // Sanity check we can get a valid epoch.
        let epochIndex = epochId & self.epochMask
        guard let epoch = self.epochCache[epochIndex] else { throw MLSError.unknownEpoch }
        guard senderId <= epoch.maxSenderId else { throw MLSError.senderOverflow }
        guard contextId <= epoch.maxContextId else { throw MLSError.contextOverflow }

        let senderPart = senderId << self.epochBits
        let contextPart: UInt64
        if epoch.contextBits > 0 {
            contextPart = contextId << (self.epochBits + epoch.senderBits)
        } else {
            contextPart = 0
        }
        return contextPart | senderPart | epochIndex
    }

    /// Ensure a key is available for the provided key ID and usage.
    /// - Parameter keyId: The key ID.
    /// - Parameter usage: The intended key usage.
    /// - Throws: Error if the epoch is missing or the key could not be added.
    private func ensureKey(keyId: KeyId, usage: KeyUsage) throws {
        let index = keyId & self.epochMask
        guard let epoch = self.epochCache[index] else { throw MLSError.unknownEpoch }

        // Is there anything to do?
        switch usage {
        case .encrypt:
            guard self.sframe.sendKeys[keyId] == nil else {
                return
            }

        case .decrypt:
            guard self.sframe.recvKeys[keyId] == nil else {
                return
            }
        }

        // Derive and add the key.
        let senderId = keyId >> self.epochBits
        try self.sframe.addKey(keyId, key: epoch.baseKey(senderId: senderId), usage: usage)
    }

    /// Protect plaintext using the provided epoch and sender.
    /// - Parameters:
    ///   - epochId: The epoch identifier.
    ///   - senderId: The sender identifier.
    ///   - plaintext: The plaintext to protect.
    ///   - metadata: Optional additional authenticated data.
    ///   - contextId: Optional context value, or 0.
    /// - Returns: The protected ciphertext.
    /// - Throws: Error if protection fails.
    public func protect(epochId: EpochID,
                        senderId: SenderID,
                        plaintext: Data,
                        metadata: Data? = nil,
                        contextId: ContextID = 0) throws -> Data {
        let keyId = try self.formKeyId(epochId: epochId,
                                       senderId: senderId,
                                       contextId: contextId)
        try self.ensureKey(keyId: keyId, usage: .encrypt)
        return try self.sframe.protect(keyId,
                                       plaintext: plaintext,
                                       metadata: metadata)
    }

    /// Unprotect ciphertext.
    /// - Parameters:
    ///   - ciphertext: The ciphertext to unprotect.
    ///   - metadata: Optional additional authenticated data.
    /// - Returns: The unprotected plaintext.
    /// - Throws: Error if unprotection fails.
    public func unprotect(ciphertext: Data, metadata: Data? = nil) throws -> Data {
        // Parse the header to get the key ID
        var read = 0
        let header = try Header(from: ciphertext, read: &read)

        // Ensure the key is available
        try self.ensureKey(keyId: header.keyId, usage: .decrypt)

        // Unprotect.
        return try self.sframe.unprotect(ciphertext: ciphertext, metadata: metadata)
    }
}

extension FixedWidthInteger {
    /// Get the max value for the provided number of bits
    /// - Parameter bits: The number of bits.
    /// - Returns: The maximum value for the provided number of bits.
    internal static func max(_ bits: Int) -> Self {
        let one = Self(1)
        return (one << bits) &- one
    }
}
