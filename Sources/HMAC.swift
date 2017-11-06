/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import CommonCrypto

/**
 * An enumeration of HMAC algorithms.
 *
 * Use objects of this type to authenticate messages with HMAC hashes.
 */

enum HMAC {

    /// The HMAC-SHA-1 algorithm.
    case sha1

    /// The HMAC-SHA-1 algorithm.
    case sha224

    /// The HMAC-SHA-1 algorithm.
    case sha256

    /// The HMAC-SHA-1 algorithm.
    case sha384

    /// The HMAC-SHA-1 algorithm.
    case sha512

}

// MARK: - Algorithm Details

extension HMAC {

    /// The raw algorithm identifier for CommonCrypto.
    private var algorithm: CCHmacAlgorithm {

        switch self {
        case .sha1: return CCHmacAlgorithm(kCCHmacAlgSHA1)
        case .sha224: return CCHmacAlgorithm(kCCHmacAlgSHA224)
        case .sha256: return CCHmacAlgorithm(kCCHmacAlgSHA256)
        case .sha384: return CCHmacAlgorithm(kCCHmacAlgSHA384)
        case .sha512: return CCHmacAlgorithm(kCCHmacAlgSHA512)
        }

    }

    /// The length of digests produced by the algorithm.
    private var digestLength: Int {

        switch self {
        case .sha1: return Int(CC_SHA1_DIGEST_LENGTH)
        case .sha224: return Int(CC_SHA224_DIGEST_LENGTH)
        case .sha256: return Int(CC_SHA256_DIGEST_LENGTH)
        case .sha384: return Int(CC_SHA384_DIGEST_LENGTH)
        case .sha512: return Int(CC_SHA512_DIGEST_LENGTH)
        }

    }

}

// MARK: - Hash Computation

extension HMAC {

    /**
     * Authenticates the message with the specified key. This generates the HMAC digest for the message.
     *
     * - parameter message: The message to authenticate.
     * - parameter key: The key to use to sign the message.
     *
     * - returns: The HMAC digest as a `Data` object.
     */

    func authenticate(_ message: Data, with key: Data) -> Data {

        let bytesAlignment = MemoryLayout<UInt8>.alignment

        let outputBytes = UnsafeMutableRawPointer.allocate(bytes: digestLength,
                                                           alignedTo: bytesAlignment)

        defer {
            outputBytes.deallocate(bytes: digestLength, alignedTo: bytesAlignment)
        }

        message.withUnsafeBytes { (messageBytes: UnsafePointer<UInt8>) in

            key.withUnsafeBytes { (keyBytes: UnsafePointer<UInt8>) in

                CCHmac(self.algorithm,
                       UnsafeRawPointer(keyBytes),
                       key.count,
                       UnsafeRawPointer(messageBytes),
                       message.count,
                       outputBytes)

            }

        }

        let hashBytes = UnsafeRawPointer(outputBytes)
        return Data(bytes: hashBytes, count: digestLength)

    }

}
