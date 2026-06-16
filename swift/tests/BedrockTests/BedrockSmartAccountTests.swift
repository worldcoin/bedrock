import Darwin
import XCTest

@testable import Bedrock

/// Raw C `siegel_fill` symbol. Declared with `@_silgen_name` since the
/// function is `extern "C"` in the bedrock cdylib but is not part of the
/// uniffi-generated FFI headers.
@_silgen_name("siegel_fill")
private func siegel_fill(_ handle: UInt64, _ src: UnsafePointer<UInt8>, _ len: Int) -> Int32

/// Test [`SmartAccountKeyManager`] that delivers a hex-encoded
/// private key in a fresh [`SiegelSession`] on every call. Production
/// foreign code would fetch the secret from the platform key store
/// (e.g. Keychain) into a mutable `Data` / `[UInt8]`, fill the siegel,
/// then zeroize the source buffer.
final class TestKeyManager: SmartAccountKeyManager, @unchecked Sendable {
    // Naturally in production, the key should never live in memory like this.
    private let hexKey: String

    init(_ hexKey: String) {
        self.hexKey = hexKey
    }

    func getEoaPrivateKey() -> SiegelSession {
        var raw = Array(hexKey.utf8)
        if raw.isEmpty {
            raw = [0]
        }
        defer {
            raw.withUnsafeMutableBufferPointer { buf in
                if let base = buf.baseAddress {
                    memset_s(base, buf.count, 0, buf.count)
                }
            }
        }
        guard let session = try? SiegelSession(len: UInt32(raw.count)) else {
            fatalError("SiegelSession(len:) must succeed for non-empty len")
        }
        let fillResult = raw.withUnsafeBufferPointer { buf -> Int32 in
            siegel_fill(session.handleId(), buf.baseAddress!, raw.count)
        }
        precondition(fillResult == 0, "siegel_fill failed with code \(fillResult)")
        return session
    }
}

final class BedrockSmartAccountTests: XCTestCase {

    // Well-known Anvil test private key and address
    let testPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    let testWalletAddress = "0x4564420674EA68fcc61b463C0494807C759d47e6"
    let chainId: UInt32 = 10  // Optimism

    private func makeAccount(
        privateKey: String? = nil,
        walletAddress: String? = nil
    ) throws -> SafeSmartAccount {
        try SafeSmartAccount(
            keyManager: TestKeyManager(privateKey ?? testPrivateKey),
            walletAddress: walletAddress ?? testWalletAddress
        )
    }

    func testSafeSmartAccountCreation() throws {
        let account = try makeAccount()
        XCTAssertNotNil(account)
    }

    func testPersonalSign() throws {
        let account = try makeAccount()

        // Test message signing - using same parameters as Rust test
        let message = "Hello, Safe Smart Account!"
        let signature = try account.personalSign(
            chainId: 1,
            message: message
        ).toHexString()

        // Expected signature from Rust test
        // swiftlint:disable:next line_length
        let expectedSignature = "0xa9781c5233828575e8c7bababbef2b05b9f60a0c34581173655e6deaa40a3a8a0357d8877723588478c0113c630f68f6d118de0a0a97b6a5fa0284beeec721431c"

        // Verify we got the exact expected signature
        XCTAssertEqual(
            signature, expectedSignature, "Signature should match the expected value from Rust test"
        )

        // Additional checks
        XCTAssertFalse(signature.isEmpty, "Signature should not be empty")
        XCTAssertTrue(signature.hasPrefix("0x"), "Signature should start with 0x")
        XCTAssertEqual(signature.count, 132, "Signature should be 132 characters long")
    }

    func testMultipleMessages() throws {
        let account = try makeAccount()

        // Test signing multiple messages
        let messages = [
            "Message 1",
            "Another test message",
            "Special characters: !@#$%^&*()",
            "Numbers: 1234567890",
            "Empty string test: "
        ]

        for message in messages {
            let signature = try account.personalSign(
                chainId: chainId,
                message: message
            ).toHexString()

            XCTAssertFalse(signature.isEmpty, "Signature for '\(message)' should not be empty")
            XCTAssertEqual(
                signature.count, 132, "Signature for '\(message)' should be 132 characters")
        }
    }

    func testInvalidPrivateKey() {
        // Test with invalid private key - should throw
        XCTAssertThrowsError(
            try makeAccount(privateKey: "invalid_key")
        ) { error in
            // Verify we got an error
            XCTAssertNotNil(error)
        }
    }

    func testEmptyPrivateKey() {
        // Test with empty private key - should throw
        XCTAssertThrowsError(
            try makeAccount(privateKey: "")
        ) { error in
            XCTAssertNotNil(error)
        }
    }

    func testInvalidWalletAddress() {
        // Test with invalid wallet address format
        XCTAssertThrowsError(
            try makeAccount(walletAddress: "invalid_address")
        ) { error in
            XCTAssertNotNil(error)
        }
    }

    func testDifferentChainIds() throws {
        let account = try makeAccount()

        // Test signing with different chain IDs
        let chainIds: [UInt32] = [1, 10, 137, 42161]  // Ethereum, Optimism, Polygon, Arbitrum
        let message = "Testing different chains"

        var signatures: [String] = []

        for chainId in chainIds {
            let signature = try account.personalSign(
                chainId: chainId,
                message: message
            ).toHexString()

            XCTAssertFalse(signature.isEmpty, "Signature for chain \(chainId) should not be empty")
            XCTAssertEqual(
                signature.count, 132, "Signature for chain \(chainId) should be 132 characters")

            // Signatures should be different for different chain IDs
            if !signatures.isEmpty {
                XCTAssertFalse(
                    signatures.contains(signature),
                    "Signature for chain \(chainId) should be unique")
            }
            signatures.append(signature)
        }
    }

    func testLongMessage() throws {
        let account = try makeAccount()

        // Test with a very long message
        let longMessage = String(repeating: "Lorem ipsum dolor sit amet. ", count: 100)

        let signature = try account.personalSign(
            chainId: chainId,
            message: longMessage
        ).toHexString()

        XCTAssertFalse(signature.isEmpty, "Signature for long message should not be empty")
        XCTAssertEqual(signature.count, 132, "Signature for long message should be 132 characters")
    }

    func testUnicodeMessage() throws {
        let account = try makeAccount()

        // Test with unicode characters
        let unicodeMessage = "Hello 世界 🌍 Здравствуй мир"

        let signature = try account.personalSign(
            chainId: chainId,
            message: unicodeMessage
        ).toHexString()

        XCTAssertFalse(signature.isEmpty, "Signature for unicode message should not be empty")
        XCTAssertEqual(
            signature.count, 132, "Signature for unicode message should be 132 characters")
    }

    func testComputeWalletAddressForFreshAccount() throws {
        let walletAddress = try computeWalletAddressForFreshAccount(
            eoaAddress: "0x521abb206fb9969aa9382b68aa578769420e95fc"
        )

        XCTAssertEqual(walletAddress, "0xea51b7e5c07bb29237194aa14618057333435f3e")
    }
}
