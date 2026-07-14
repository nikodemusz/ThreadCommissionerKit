import Foundation
import CThreadCommissioner

/// Errors thrown by the raw mbedTLS EC-JPAKE wrapper.
public enum RawECJPAKEError: Error, LocalizedError, Sendable {
    case invalidCode(String)
    case mbedTLSFailure(operation: String, code: Int32, message: String)
    case outputTooLarge(operation: String, capacity: Int)

    public var errorDescription: String? {
        switch self {
        case .invalidCode(let message):
            return message
        case .mbedTLSFailure(let operation, let code, let message):
            return "\(operation) failed: \(code) - \(message)"
        case .outputTooLarge(let operation, let capacity):
            return "\(operation) produced more than \(capacity) bytes"
        }
    }
}

/// Thin Swift wrapper around mbedTLS `mbedtls_ecjpake_*`.
///
/// This exposes the raw EC-JPAKE rounds, unlike ``ThreadDTLSClient`` which lets
/// mbedTLS consume them internally as part of a DTLS handshake. Tandem pump
/// pairing uses these raw round payloads over BLE, so callers can drive their own
/// transport while still relying on mbedTLS for the elliptic-curve primitive.
public final class RawECJPAKEEngine: @unchecked Sendable {
    public enum Role: Sendable {
        case client
        case server

        fileprivate var mbedTLSRole: mbedtls_ecjpake_role {
            switch self {
            case .client: return MBEDTLS_ECJPAKE_CLIENT
            case .server: return MBEDTLS_ECJPAKE_SERVER
            }
        }
    }

    private let context: UnsafeMutablePointer<mbedtls_ecjpake_context>
    private let entropy: UnsafeMutablePointer<mbedtls_entropy_context>
    private let ctrdrbg: UnsafeMutablePointer<mbedtls_ctr_drbg_context>

    /// Creates a raw EC-JPAKE context using the ASCII pairing/admin code as the
    /// low-entropy shared secret.
    ///
    /// Thread commissioning commonly uses 6-12 digits. Tandem newer firmware uses
    /// a 6-digit code; this initializer accepts any non-empty ASCII code and leaves
    /// stricter validation to the caller.
    public init(code: String, role: Role = .client, personalization: String = "raw_ecjpake") throws {
        let trimmed = code.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, trimmed.allSatisfy({ $0.isASCII }) else {
            throw RawECJPAKEError.invalidCode("EC-JPAKE code must be non-empty ASCII.")
        }

        context = UnsafeMutablePointer.allocate(capacity: 1)
        entropy = UnsafeMutablePointer.allocate(capacity: 1)
        ctrdrbg = UnsafeMutablePointer.allocate(capacity: 1)

        mbedtls_ecjpake_init(context)
        mbedtls_entropy_init(entropy)
        mbedtls_ctr_drbg_init(ctrdrbg)

        let seedResult = personalization.withCString { persPtr in
            mbedtls_ctr_drbg_seed(
                ctrdrbg,
                mbedtls_entropy_func,
                entropy,
                persPtr,
                strlen(persPtr)
            )
        }
        try Self.check(seedResult, operation: "mbedtls_ctr_drbg_seed")

        let setupResult = trimmed.withCString { codePtr -> Int32 in
            let secret = UnsafePointer<UInt8>(OpaquePointer(codePtr))
            return mbedtls_ecjpake_setup(
                context,
                role.mbedTLSRole,
                MBEDTLS_MD_SHA256,
                MBEDTLS_ECP_DP_SECP256R1,
                secret,
                strlen(codePtr)
            )
        }
        try Self.check(setupResult, operation: "mbedtls_ecjpake_setup")
    }

    deinit {
        mbedtls_ecjpake_free(context)
        mbedtls_ctr_drbg_free(ctrdrbg)
        mbedtls_entropy_free(entropy)
        context.deallocate()
        ctrdrbg.deallocate()
        entropy.deallocate()
    }

    /// mbedTLS round-one payload. For P-256 EC-JPAKE this is normally 330 bytes.
    public func writeRoundOne(capacity: Int = 512) throws -> Data {
        try writeBuffer(capacity: capacity, operation: "mbedtls_ecjpake_write_round_one") { buffer, size, written in
            mbedtls_ecjpake_write_round_one(
                context,
                buffer,
                size,
                written,
                mbedtls_ctr_drbg_random,
                ctrdrbg
            )
        }
    }

    public func readRoundOne(_ data: Data) throws {
        let result = data.withUnsafeBytes { rawBuffer -> Int32 in
            guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return mbedtls_ecjpake_read_round_one(context, base, data.count)
        }
        try Self.check(result, operation: "mbedtls_ecjpake_read_round_one")
    }

    /// mbedTLS round-two payload. For P-256 EC-JPAKE this is normally 165 bytes.
    public func writeRoundTwo(capacity: Int = 256) throws -> Data {
        try writeBuffer(capacity: capacity, operation: "mbedtls_ecjpake_write_round_two") { buffer, size, written in
            mbedtls_ecjpake_write_round_two(
                context,
                buffer,
                size,
                written,
                mbedtls_ctr_drbg_random,
                ctrdrbg
            )
        }
    }

    public func readRoundTwo(_ data: Data) throws {
        let result = data.withUnsafeBytes { rawBuffer -> Int32 in
            guard let base = rawBuffer.bindMemory(to: UInt8.self).baseAddress else { return -1 }
            return mbedtls_ecjpake_read_round_two(context, base, data.count)
        }
        try Self.check(result, operation: "mbedtls_ecjpake_read_round_two")
    }

    public func deriveSecret(capacity: Int = 128) throws -> Data {
        try writeBuffer(capacity: capacity, operation: "mbedtls_ecjpake_derive_secret") { buffer, size, written in
            mbedtls_ecjpake_derive_secret(
                context,
                buffer,
                size,
                written,
                mbedtls_ctr_drbg_random,
                ctrdrbg
            )
        }
    }

    private func writeBuffer(
        capacity: Int,
        operation: String,
        call: (UnsafeMutablePointer<UInt8>, Int, UnsafeMutablePointer<Int>) -> Int32
    ) throws -> Data {
        var output = [UInt8](repeating: 0, count: capacity)
        var written = 0
        let result = output.withUnsafeMutableBufferPointer { buffer -> Int32 in
            guard let base = buffer.baseAddress else { return -1 }
            return call(base, capacity, &written)
        }
        try Self.check(result, operation: operation)
        guard written <= capacity else {
            throw RawECJPAKEError.outputTooLarge(operation: operation, capacity: capacity)
        }
        return Data(output.prefix(written))
    }

    private static func check(_ result: Int32, operation: String) throws {
        guard result == 0 else {
            var buffer = [Int8](repeating: 0, count: 160)
            mbedtls_strerror(result, &buffer, buffer.count)
            throw RawECJPAKEError.mbedTLSFailure(
                operation: operation,
                code: result,
                message: String(cString: buffer)
            )
        }
    }
}
