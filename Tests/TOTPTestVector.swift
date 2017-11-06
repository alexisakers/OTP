/**
 *  OTP
 *  Copyright (c) 2017 Alexis Aubry. Licensed under the MIT license.
 */

import Foundation
import OTP

struct TOTPTestVector {

    let sharedSecret: Data
    let timeStep: TimeInterval
    let initialTime: TimeInterval
    let time: TimeInterval
    let hmac: HMAC
    let codeLength: Int

    let movingFactor: Data
    let expectedTOTP: String
    let expectedHash: Data

    func makeRequest() -> OTPGenerationRequest {

        return OTPGenerationRequest.totp(initialTime: initialTime,
                                         currentTime: time,
                                         timeStep: timeStep,
                                         sharedSecret: sharedSecret,
                                         codeLength: codeLength,
                                         hmac: hmac)

    }

}

/**
 * A set of test values to validate the algorithm.
 */

enum OTPTestSuite {

    private struct TOTPSubvector {

        let time: TimeInterval
        let hmac: HMAC
        let movingFactor: Data
        let expectedTOTP: String
        let expectedHash: Data

        init(_ time: TimeInterval, _ hmac: HMAC, _ movingFactor: Data, _ expectedTOTP: String, _ expectedHash: Data) {
            self.time = time
            self.hmac = hmac
            self.movingFactor = movingFactor
            self.expectedTOTP = expectedTOTP
            self.expectedHash = expectedHash
        }

    }

    static func movingFactorHash() -> [(OTPGenerationRequest, Data)] {

        let sharedSecret: Data = "3132333435363738393031323334353637383930"

        return [
            (OTPGenerationRequest.hotp(counter: 0, sharedSecret: sharedSecret, codeLength: 6), "cc93cf18508d94934c64b65d8ba7667fb7cde4b0"),
            (OTPGenerationRequest.hotp(counter: 1, sharedSecret: sharedSecret, codeLength: 6), "75a48a19d4cbe100644e8ac1397eea747a2d33ab"),
            (OTPGenerationRequest.hotp(counter: 2, sharedSecret: sharedSecret, codeLength: 6), "0bacb7fa082fef30782211938bc1c5e70416ff44"),
            (OTPGenerationRequest.hotp(counter: 3, sharedSecret: sharedSecret, codeLength: 6), "66c28227d03a2d5529262ff016a1e6ef76557ece"),
            (OTPGenerationRequest.hotp(counter: 4, sharedSecret: sharedSecret, codeLength: 6), "a904c900a64b35909874b33e61c5938a8e15ed1c"),
            (OTPGenerationRequest.hotp(counter: 5, sharedSecret: sharedSecret, codeLength: 6), "a37e783d7b7233c083d4f62926c7a25f238d0316"),
            (OTPGenerationRequest.hotp(counter: 6, sharedSecret: sharedSecret, codeLength: 6), "bc9cd28561042c83f219324d3c607256c03272ae"),
            (OTPGenerationRequest.hotp(counter: 7, sharedSecret: sharedSecret, codeLength: 6), "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa"),
            (OTPGenerationRequest.hotp(counter: 8, sharedSecret: sharedSecret, codeLength: 6), "1b3c89f65e6c9e883012052823443f048b4332db"),
            (OTPGenerationRequest.hotp(counter: 9, sharedSecret: sharedSecret, codeLength: 6), "1637409809a679dc698207310c8c7fc07290d9e5")
        ]

    }

    static func truncation() -> [(Int, Data, String)] {

        return [

            (6, "1f8698690e02ca16618550ef7f19da8e945b555a", "872921"),
            (6, "cc93cf18508d94934c64b65d8ba7667fb7cde4b0", "755224"),
            (6, "75a48a19d4cbe100644e8ac1397eea747a2d33ab", "287082"),
            (6, "0bacb7fa082fef30782211938bc1c5e70416ff44", "359152"),
            (6, "66c28227d03a2d5529262ff016a1e6ef76557ece", "969429"),
            (6, "a904c900a64b35909874b33e61c5938a8e15ed1c", "338314"),
            (6, "a37e783d7b7233c083d4f62926c7a25f238d0316", "254676"),
            (6, "bc9cd28561042c83f219324d3c607256c03272ae", "287922"),
            (6, "a4fb960c0bc06e1eabb804e5b397cdc4b45596fa", "162583"),
            (6, "1b3c89f65e6c9e883012052823443f048b4332db", "399871"),
            (6, "1637409809a679dc698207310c8c7fc07290d9e5", "520489"),

            (8, "75a48a19d4cbe100644e8ac1397eea747a2d33ab", "94287082"),
            (8, "392514c9dd4165d4709456062c78e04e16e68718515951333bdb8b26caa3053c", "46119246"),
            (8, "6f76f324230cefda1d3f65309a0badb36efce9528ada64967d71e4e9d74c4aa37fe7650f931ab86ddccc2d38962d720ee626a20feb311b485a92e3bb0796df28", "90693936"),

            (8, "278c02e53610f84c40bd9135acd4101012410a14", "07081804"),
            (8, "4eed729864525d771326c6049bc885629fb8813ebb417e5704df02358793f056", "68084774"),
            (8, "b3381250260d6a9e811ae58dfa406705e38c804c97528d5a7ed8ee533331f8c43cc3454911ad1d2761f9380170c0b180a657e3a944c796e05d09f2d1630b7505", "25091201"),

            (8, "907cd1a9116564ecb9d5d1780325f246173fe703", "89005924"),
            (8, "3befb8821caef9df4e05790da0966163f4e38feee7f71fcd289c3de48d3486d9", "91819424"),
            (8, "87d0cfb5d4e968d7d9041a5cf21dd7d460705784004f0244edb98004e6cf9942ace539d621c97dc0fb75f6f10d64af1f09ecae83ea7f1213c7fa187dfaf6b938", "93441116"),

            (8, "25a326d31fc366244cad054976020c7b56b13d5f", "69279037"),
            (8, "a4e8eabbe549adfa65408945a9282cb93f394f06c0d4f122260963641bc3abe2", "90698825"),
            (8, "129baa738cfa1565a24297237bce282671ff6e261754eb7011e1e75bd2555b326313142a1f9fe2f31d9ce6cc95d3b16a0dee56f2492f2f76885702d98bfadc93", "38618901"),

            (8, "ab07e97e2c1278769dbcd75783aabde75ed8550a", "65353130"),
            (8, "1363cc0ee3557f092e5b55ea3ddb06bcd20f063ce393ccf670059e3ca44941f8", "77737706"),
            (8, "562298a02af13e7522127adee3dc6678d53669ca2b7016186968f9a9c14f51d1e7098ba91293a01b5f3bab4207a2af5ce332a45f2c2ff2b9885aa42ff61cb426", "47863826")

        ]

    }

    static func totp() -> [TOTPTestVector] {

        let sharedSecret1: Data = "3132333435363738393031323334353637383930"
        let sharedSecret256: Data = "3132333435363738393031323334353637383930" + "313233343536373839303132"
        let sharedSecret512: Data = "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "3132333435363738393031323334353637383930" + "31323334"

        let timeStep: TimeInterval = 30
        let initialTime: TimeInterval = 0

        let subvectors = [
            TOTPSubvector(59, .sha1, "0000000000000001", "94287082", "75a48a19d4cbe100644e8ac1397eea747a2d33ab"),
            TOTPSubvector(59, .sha256, "0000000000000001", "46119246", "392514c9dd4165d4709456062c78e04e16e68718515951333bdb8b26caa3053c"),
            TOTPSubvector(59, .sha512, "0000000000000001", "90693936", "6f76f324230cefda1d3f65309a0badb36efce9528ada64967d71e4e9d74c4aa37fe7650f931ab86ddccc2d38962d720ee626a20feb311b485a92e3bb0796df28"),

            TOTPSubvector(1111111109, .sha1, "00000000023523EC", "07081804", "278c02e53610f84c40bd9135acd4101012410a14"),
            TOTPSubvector(1111111109, .sha256, "00000000023523EC", "68084774", "4eed729864525d771326c6049bc885629fb8813ebb417e5704df02358793f056"),
            TOTPSubvector(1111111109, .sha512, "00000000023523EC", "25091201", "b3381250260d6a9e811ae58dfa406705e38c804c97528d5a7ed8ee533331f8c43cc3454911ad1d2761f9380170c0b180a657e3a944c796e05d09f2d1630b7505"),

            TOTPSubvector(1234567890, .sha1, "000000000273EF07", "89005924", "907cd1a9116564ecb9d5d1780325f246173fe703"),
            TOTPSubvector(1234567890, .sha256, "000000000273EF07", "91819424", "3befb8821caef9df4e05790da0966163f4e38feee7f71fcd289c3de48d3486d9"),
            TOTPSubvector(1234567890, .sha512, "000000000273EF07", "93441116", "87d0cfb5d4e968d7d9041a5cf21dd7d460705784004f0244edb98004e6cf9942ace539d621c97dc0fb75f6f10d64af1f09ecae83ea7f1213c7fa187dfaf6b938"),

            TOTPSubvector(2000000000, .sha1, "0000000003F940AA", "69279037", "25a326d31fc366244cad054976020c7b56b13d5f"),
            TOTPSubvector(2000000000, .sha256, "0000000003F940AA", "90698825", "a4e8eabbe549adfa65408945a9282cb93f394f06c0d4f122260963641bc3abe2"),
            TOTPSubvector(2000000000, .sha512, "0000000003F940AA", "38618901", "129baa738cfa1565a24297237bce282671ff6e261754eb7011e1e75bd2555b326313142a1f9fe2f31d9ce6cc95d3b16a0dee56f2492f2f76885702d98bfadc93"),

            TOTPSubvector(20000000000, .sha1, "0000000027BC86AA", "65353130", "ab07e97e2c1278769dbcd75783aabde75ed8550a"),
            TOTPSubvector(20000000000, .sha256, "0000000027BC86AA", "77737706", "1363cc0ee3557f092e5b55ea3ddb06bcd20f063ce393ccf670059e3ca44941f8"),
            TOTPSubvector(20000000000, .sha512, "0000000027BC86AA", "47863826", "562298a02af13e7522127adee3dc6678d53669ca2b7016186968f9a9c14f51d1e7098ba91293a01b5f3bab4207a2af5ce332a45f2c2ff2b9885aa42ff61cb426"),
        ]

        return subvectors.map {

            let sharedSecret: Data

            switch $0.hmac {
            case .sha1:
                sharedSecret = sharedSecret1
            case .sha256:
                sharedSecret = sharedSecret256
            case .sha512:
                sharedSecret = sharedSecret512
            default:
                fatalError("Unsupported HMAC")
            }

            return TOTPTestVector(sharedSecret: sharedSecret, timeStep: timeStep, initialTime: initialTime, time: $0.time, hmac: $0.hmac, codeLength: 8, movingFactor: $0.movingFactor, expectedTOTP: $0.expectedTOTP, expectedHash: $0.expectedHash)

        }

    }

}
 