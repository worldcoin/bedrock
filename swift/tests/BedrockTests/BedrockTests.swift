import XCTest
@testable import Bedrock

final class BedrockTests: XCTestCase {

    // Well-known Anvil test private key and address
    let testPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    let testWalletAddress = "0x4564420674EA68fcc61b463C0494807C759d47e6"
    let chainId: UInt32 = 10 // Optimism

    func testSafeSmartAccountCreation() throws {
        // Test creating a SafeSmartAccount instance
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

        // If we get here without throwing, the account was created successfully
        XCTAssertNotNil(account)
    }

    func testPersonalSign() throws {
        // Create account
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

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
        XCTAssertEqual(signature, expectedSignature, "Signature should match the expected value from Rust test")

        // Additional checks
        XCTAssertFalse(signature.isEmpty, "Signature should not be empty")
        XCTAssertTrue(signature.hasPrefix("0x"), "Signature should start with 0x")
        XCTAssertEqual(signature.count, 132, "Signature should be 132 characters long")
    }

    func testMultipleMessages() throws {
        // Create account
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

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
            )
            ).toHexString()
            
            XCTAssertFalse(signature.isEmpty, "Signature for '\(message)' should not be empty")
            XCTAssertEqual(signature.count, 132, "Signature for '\(message)' should be 132 characters")
        }
    }

    func testInvalidPrivateKey() {
        // Test with invalid private key - should throw
        XCTAssertThrowsError(
            try SafeSmartAccount(
                privateKey: "invalid_key",
                walletAddress: testWalletAddress
            )
        ) { error in
            // Verify we got an error
            XCTAssertNotNil(error)
        }
    }

    func testEmptyPrivateKey() {
        // Test with empty private key - should throw
        XCTAssertThrowsError(
            try SafeSmartAccount(
                privateKey: "",
                walletAddress: testWalletAddress
            )
        ) { error in
            XCTAssertNotNil(error)
        }
    }

    func testInvalidWalletAddress() {
        // Test with invalid wallet address format
        XCTAssertThrowsError(
            try SafeSmartAccount(
                privateKey: testPrivateKey,
                walletAddress: "invalid_address"
            )
        ) { error in
            XCTAssertNotNil(error)
        }
    }

    func testDifferentChainIds() throws {
        // Create account
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

        // Test signing with different chain IDs
        let chainIds: [UInt32] = [1, 10, 137, 42161] // Ethereum, Optimism, Polygon, Arbitrum
        let message = "Testing different chains"

        var signatures: [String] = []

        for chainId in chainIds {
            let signature = try account.personalSign(
                chainId: chainId,
                message: message
            ).toHexString()
            
            XCTAssertFalse(signature.isEmpty, "Signature for chain \(chainId) should not be empty")
            XCTAssertEqual(signature.count, 132, "Signature for chain \(chainId) should be 132 characters")

            // Signatures should be different for different chain IDs
            if !signatures.isEmpty {
                XCTAssertFalse(signatures.contains(signature),
                    "Signature for chain \(chainId) should be unique")
            }
            signatures.append(signature)
        }
    }

    func testLongMessage() throws {
        // Create account
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

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
        // Create account
        let account = try SafeSmartAccount(
            privateKey: testPrivateKey,
            walletAddress: testWalletAddress
        )

        // Test with unicode characters
        let unicodeMessage = "Hello 世界 🌍 Здравствуй мир"

        let signature = try account.personalSign(
            chainId: chainId,
            message: unicodeMessage
        ).toHexString()
        
        XCTAssertFalse(signature.isEmpty, "Signature for unicode message should not be empty")
        XCTAssertEqual(signature.count, 132, "Signature for unicode message should be 132 characters")
    }
}
