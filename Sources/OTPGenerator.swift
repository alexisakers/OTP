/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation

/**
 * Generates HOTP authentication codes from a generation request.
 */

public enum OTPGenerator {

    static let powerDigits: [Int] = [1,10,100,1000,10000,100000,1000000,10000000,100000000]

    /**
     * Generates an OTP code using a request descriptor.
     *
     * - parameter request: The code generation request.
     * - returns: The generated OTP code.
     */

    public static func generateCode(for request: OTPGenerationRequest) -> String {
        let hmacDigest = authenticate(request)
        return truncateDigest(hmacDigest, length: request.codeLength)
    }

    /**
     * Computes the HMAC digest for the request.
     *
     * - parameter request: The request to authenticate.
     */

    static func authenticate(_ request: OTPGenerationRequest) -> Data {
        return request.hmac.authenticate(request.movingFactor, with: request.sharedSecret)
    }

    /**
     * Truncates the OTP digest and returns an OTP code of the given length.
     *
     * - parameter digest: A HMAC digest of at least 20 bytes (SHA-1 or bigger).
     * - parameter length: The length of the OTP code to generate.
     *
     * - returns: The String containing the OTP code.
     */

    static func truncateDigest(_ digest: Data, length: Int)  -> String {

        let offset = Int(digest.last! & 0xf)

        let binaryCode = (Int(digest[offset]) & 0x7f) << 24
            | (Int(digest[offset+1]) & 0xff) << 16
            | (Int(digest[offset+2]) & 0xff) <<  8
            | (Int(digest[offset+3]) & 0xff)

        let otp = binaryCode % powerDigits[length]
        var result = String(otp)

        while result.count < length {
            result = "0" + result
        }

        return result

    }

}
