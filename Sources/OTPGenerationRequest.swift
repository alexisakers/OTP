/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import Crypto

/**
 * A data structure describing
 */

public enum OTPGenerationRequest {

    /**
     * A request to generate an HOTP code.
     *
     * This is based on an increasing counter synchronized between the server and the client.
     *
     * - parameter counter: The current counter index.
     * - parameter sharedSecret: The secret shared between the two entities.
     * - parameter codeLength: The number of digits in the generated code.
     */

    case hotp(counter: UInt64, sharedSecret: Data, codeLength: Int)

    /**
     * A request to generate an TOTP code.
     *
     * This is based on based on a representation of the counter as a time factor.
     *
     * - parameter initialTime: The initial counter time.
     * - parameter currentTime: The current Unix time.
     * - parameter timeStep: The time step, in seconds. Usually 30 seconds.
     * - parameter sharedSecret: The secret shared between the two entities.
     * - parameter codeLength: The number of digits in the generated code.
     * - parameter hmac: The hashing algorithm to use to generate the code.
     */

    case totp(initialTime: TimeInterval, currentTime: TimeInterval, timeStep: TimeInterval, sharedSecret: Data, codeLength: Int, hmac: HMAC)

}

// MARK: - Configuration

extension OTPGenerationRequest {
    
    var movingFactor: Data {

        var movingCounter: UInt64

        switch self {
        case .hotp(let counter, _, _):
            movingCounter = counter
        case .totp(let initialTime, let currentTime, let timeStep, _, _, _):
            let factor = floor((currentTime - initialTime) / timeStep)
            movingCounter = UInt64(factor)
        }

        return OTPGenerationRequest.makeMovingFactorBytes(with: movingCounter)

    }

    var sharedSecret: Data {

        switch self {
        case .hotp(_, let sharedSecret, _):
            return sharedSecret
        case .totp(_, _, _, let sharedSecret, _, _):
            return sharedSecret
        }

    }

    var codeLength: Int {

        switch self {
        case .hotp(_, _, let codeLength):
            return codeLength
        case .totp(_, _, _, _, let codeLength, _):
            return codeLength
        }

    }

    var hmac: HMAC {

        switch self {
        case .hotp:
            return .sha1
        case .totp(_, _, _, _, _, let hmac):
            return hmac
        }

    }

    static func makeMovingFactorBytes(with movingFactor: UInt64) -> Data {

        var movingFactor = movingFactor

        var message = [UInt8](repeating: 0, count: 8)

        for i in (0 ..< message.count).reversed() {
            message[i] = UInt8(movingFactor & 0xff);
            movingFactor >>= 8;
        }

        return Data(message)

    }

}
