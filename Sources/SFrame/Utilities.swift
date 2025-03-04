import Foundation

public enum DataError: Error {
    case badAccess
}

extension Data {
    /// Initialize a view into a contiguous byte buffer.
    public init(contiguousNoCopy bytes: ContiguousBytes) throws {
        let view = UnsafeMutableRawBufferPointer(bytes.withUnsafeBytes { .init(mutating: $0) })
        guard let baseAddress = view.baseAddress else {
            throw DataError.badAccess
        }
        self.init(bytesNoCopy: baseAddress, count: view.count, deallocator: .none)
    }

    /// XOR two data buffers.
    public static func ^ (lhs: Data, rhs: Data) -> Data {
        .init(zip(lhs, rhs).map { $0 ^ $1 })
    }
}
