import Foundation

public enum DataError: Error {
    case lengthMismatch
}

// SealedBox implementation.
internal struct SealedDataBox: SealedBox {
    internal let authTag: Data
    internal let encrypted: Data
    internal let nonceBytes: Data
}

extension Data {
    /// Initialize a view into a contiguous byte buffer.
    /// - Parameter bytes: The contiguous byte buffer to expose a view into.
    internal init(contiguousNoCopy bytes: ContiguousBytes) {
        let view = UnsafeMutableRawBufferPointer(bytes.withUnsafeBytes { .init(mutating: $0) })
        guard !view.isEmpty else {
            self.init()
            return
        }
        self.init(bytesNoCopy: view.baseAddress!, // swiftlint:disable:this force_unwrapping
                  count: view.count,
                  deallocator: .none)
    }

    /// XOR two data buffers together byte by byte.
    /// - Parameters:
    ///  - lhs: The left hand side of the XOR operation.
    ///  - rhs: The right hand side of the XOR operation.
    /// - Returns: A new ``Data`` containing the XOR'd bytes.
    internal static func ^ (lhs: Data, rhs: Data) throws -> Data {
        guard lhs.count == rhs.count else {
            throw DataError.lengthMismatch
        }
        return .init(zip(lhs, rhs).map(^))
    }

    /// Get a hex string representation of the data.
    /// - Returns: The hex string representation.
    internal func toHex() -> String {
        self.map { .init(format: "%02x", $0) }.joined()
    }
}

extension FixedWidthInteger {
    /// Encode the integer as big endian into a data buffer, of the given size.
    /// - Parameters:
    ///   - length: The number of bytes to write.
    ///   - into: The buffer to write into.
    internal func encodeBigEndian(_ length: Int, into: inout Data) {
        let padding = length - MemoryLayout<Self>.size
        if padding > 0 {
            into.append(contentsOf: repeatElement(0, count: padding))
        }
        withUnsafeBytes(of: self.bigEndian) { bytes in
            let min = Swift.min(length, MemoryLayout<Self>.size)
            into.append(contentsOf: bytes.suffix(min))
        }
    }
}
