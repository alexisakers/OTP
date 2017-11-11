/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import Crypto

/**
 * Represents a standard Time-Based One-Time Password Key.
 */

public class OTPKey {

    /**
     * The signature algorithms for the key.
     */

    public enum Algorithm: String {

        /// The SHA1 algorithm.
        case sha1 = "SHA1"

        /// The SHA256 algorithm.
        case sha256 = "SHA256"

        /// The SHA512 algorithm.
        case sha512 = "SHA512"

    }

    /**
     * The key generation mode.
     */

    public enum Mode: String {

        /// HMAC One-Time Password.
        case hotp

        /// Time-Based One-Time Password.
        case totp

    }

    // MARK: - Properties

    /// The key generation mode.
    public let mode: Mode

    /// The name of the account.
    public let accountName: String

    /// The issuer prefix from the label, identifying the service provider.
    public let issuerPrefix: String?

    /// The shared secret.
    public let sharedSecret: Data

    /// The name of the issuer, identifying the service provider.
    public var issuer: String? = nil

    /// The signature algorithms for the key. Defaults to SHA1.
    public var algorithm: Algorithm = .sha1

    /// The number of digits to generate. Defaults to 6.
    public var digits: Int = 6

    /// The current counter value. Must be provided for HOTP keys.
    public var counter: UInt64 = 0

    /// The period that a TOTP code will be valid for, in seconds. Defaults to 30.
    public var period: TimeInterval = 30

    /// The Unix time to start counting time steps. Defaults to Epoch.
    public var initialTime: TimeInterval = 0

    // MARK: - Initialization

    /**
     * Creates a new One-Time Password Key.
     *
     * - parameter mode: The key mode.
     * - parameter accountName: The name of the account (typically the username of email address).
     * - parameter issuerPrefix: An optional prefix identifying the service provider.
     * - parameter secret: The shared secret key.
     */

    public init(mode: Mode, accountName: String, issuerPrefix: String?, sharedSecret: Data) {
        self.mode = mode
        self.accountName = accountName
        self.issuerPrefix = issuerPrefix
        self.sharedSecret = sharedSecret
    }

}

extension OTPKey {

    /// The HMAC algorithm to use for the key.
    var hmac: HMAC {

        switch algorithm {
        case .sha1: return .sha1
        case .sha256: return .sha256
        case .sha512: return .sha512
        }

    }

    /**
     * Creates an OTP generation request for the key at the given time.
     *
     * - parameter currentTime: The time when the request was initiated.
     * - returns: The request object to use with `OTPGenerator` to get an OTP token for this key.
     */

    public func makeOTPRequest(currentTime: TimeInterval) -> OTPGenerationRequest {

        switch mode {
        case .hotp:
            return .hotp(counter: counter, sharedSecret: sharedSecret, codeLength: digits)

        case .totp:
            return .totp(initialTime: initialTime, currentTime: currentTime, timeStep: period,
                         sharedSecret: sharedSecret, codeLength: digits, hmac: hmac)

        }

    }

}
