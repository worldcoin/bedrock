import Foundation
import XCTest
@testable import Bedrock

final class BedrockDeviceProofTests: XCTestCase {
    func testRestoredRootSignsOnlyTrustedDeviceChallenges() throws {
        let root = try RootKey.fromJson(jsonStr: "{\"version\":\"V1\",\"key\":\"\(String(repeating: "11", count: 32))\"}")
        let expires = Int(Date().timeIntervalSince1970) + 300
        let challenge = Data("{\"version\":1,\"issuer\":\"https://auth.world.org\",\"ceremony_id\":\"019af784-3d00-7000-8000-000000000001\",\"nonce\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"expires_at\":\(expires)}".utf8)
        let proof = try root.createWorldIdDeviceProof(challenge: challenge, expectedIssuer: "https://auth.world.org")
        XCTAssertEqual(proof.publicKey, "A78Nb3lXB_knP6aCAH-jz__oN54VcvsG8pPSq4Nb1JNI")
        XCTAssertFalse(proof.signature.isEmpty)
        XCTAssertThrowsError(try root.createWorldIdDeviceProof(challenge: challenge, expectedIssuer: "https://foreign.example")) { error in
            guard case DeviceProofError.InvalidChallenge = error else {
                return XCTFail("Expected InvalidChallenge, got \(error)")
            }
        }
    }
}
