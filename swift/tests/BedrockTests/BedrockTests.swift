import XCTest

@testable import Bedrock

final class BedrockTests: XCTestCase {

    // Well-known Anvil test private key and address
    let testPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    let testWalletAddress = "0x4564420674EA68fcc61b463C0494807C759d47e6"
    let chainId: UInt32 = 10  // Optimism

    func testToolingDemoLogPrefixing() throws {
        // Test the ToolingDemo to verify log prefixing works
        let demo = ToolingDemo()
        
        // These calls should generate logs with [ToolingDemo] prefix
        demo.logMessage(message: "Testing log prefixing from Swift")
        demo.testLogLevels()
        
        let result = demo.getDemoResult()
        XCTAssertTrue(result.contains("ToolingDemo"), "Result should contain the demo name")
        XCTAssertTrue(result.contains("Demo result"), "Result should contain expected text")
    }

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
        let expectedSignature =
            "0xa9781c5233828575e8c7bababbef2b05b9f60a0c34581173655e6deaa40a3a8a0357d8877723588478c0113c630f68f6d118de0a0a97b6a5fa0284beeec721431c"

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
            "Empty string test: ",
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
        XCTAssertEqual(
            signature.count, 132, "Signature for unicode message should be 132 characters")
    }

    // MARK: - Error Handling Tests

    // Test: Strongly typed errors for validation and known cases
    func testDemoAuthenticate_StronglyTypedErrors() throws {
        let demo = ToolingDemo()

        // Success case - now includes result from post-auth operation
        let result = try demo.demoAuthenticate(username: "testuser", password: "validpassword")
        XCTAssertTrue(result.contains("Welcome, testuser!"))
        XCTAssertTrue(result.contains("Successfully processed: auth_data_testuser"))

        // Empty username - InvalidInput
        XCTAssertThrowsError(try demo.demoAuthenticate(username: "", password: "password")) { error in
            if let demoError = error as? DemoError,
                case .InvalidInput(let message) = demoError
            {
                XCTAssertTrue(message.contains("Username cannot be empty"))
            } else {
                XCTFail("Expected InvalidInput error")
            }
        }

        // Wrong credentials - AuthenticationFailed
        XCTAssertThrowsError(try demo.demoAuthenticate(username: "admin", password: "wrongpassword")) {
            error in
            if let demoError = error as? DemoError,
                case .AuthenticationFailed(let message) = demoError
            {
                XCTAssertTrue(message.contains("Authentication failed") && message.contains("401"))
            } else {
                XCTFail("Expected AuthenticationFailed error")
            }
        }

        // Slow user - NetworkTimeout
        XCTAssertThrowsError(try demo.demoAuthenticate(username: "slowuser", password: "password")) {
            error in
            if let demoError = error as? DemoError,
                case .NetworkTimeout(let message) = demoError
            {
                XCTAssertTrue(message.contains("Network timeout") && message.contains("30"))
            } else {
                XCTFail("Expected NetworkTimeout error")
            }
        }
    }

    // Test: Generic errors for complex anyhow error chains
    func testDemoGenericOperation_AnyhowChains() throws {
        let demo = ToolingDemo()

        // Success case
        let result = try demo.demoGenericOperation(input: "valid_input")
        XCTAssertEqual(result, "Successfully processed: valid_input")

        // Empty input - Generic error
        XCTAssertThrowsError(try demo.demoGenericOperation(input: "")) { error in
            if let demoError = error as? DemoError,
                case .Generic(let message) = demoError
            {
                XCTAssertTrue(message.contains("Input cannot be empty"))
            } else {
                XCTFail("Expected Generic error")
            }
        }

        // Network error - Generic error with anyhow context
        XCTAssertThrowsError(try demo.demoGenericOperation(input: "network_error")) { error in
            if let demoError = error as? DemoError,
                case .Generic(let message) = demoError
            {
                XCTAssertTrue(message.contains("Connection timed out"))
            } else {
                XCTFail("Expected Generic error")
            }
        }

        // Parse error - Generic error with anyhow context
        XCTAssertThrowsError(try demo.demoGenericOperation(input: "parse_error")) { error in
            if let demoError = error as? DemoError,
                case .Generic(let message) = demoError
            {
                XCTAssertTrue(message.contains("Failed to parse input as JSON"))
            } else {
                XCTFail("Expected Generic error")
            }
        }
    }

    // Test: Mixed usage - structured validation + generic processing
    func testDemoMixedOperation_CombinedApproach() throws {
        let demo = ToolingDemo()

        // Success case
        let result = try demo.demoMixedOperation(operation: "process", data: "valid_data")
        XCTAssertTrue(result.contains("Processed:"))

        // Empty operation - InvalidInput (strongly typed validation)
        XCTAssertThrowsError(try demo.demoMixedOperation(operation: "", data: "data")) { error in
            if let demoError = error as? DemoError,
                case .InvalidInput(let message) = demoError
            {
                XCTAssertTrue(message.contains("Operation cannot be empty"))
            } else {
                XCTFail("Expected InvalidInput error")
            }
        }

        // Unknown operation - InvalidInput (strongly typed validation)
        XCTAssertThrowsError(try demo.demoMixedOperation(operation: "unknown", data: "data")) { error in
            if let demoError = error as? DemoError,
                case .InvalidInput(let message) = demoError
            {
                XCTAssertTrue(message.contains("Unknown operation"))
            } else {
                XCTFail("Expected InvalidInput error")
            }
        }

        // Process operation with trigger_error - Generic error (anyhow processing)
        XCTAssertThrowsError(try demo.demoMixedOperation(operation: "process", data: "trigger_error")) {
            error in
            if let demoError = error as? DemoError,
                case .Generic(let message) = demoError
            {
                XCTAssertTrue(
                    message.contains("Operation failed")
                        && message.contains("Simulated processing failure"))
            } else {
                XCTFail("Expected Generic error with anyhow-style message")
            }
        }
    }

    // Test: Unified error handling across all demo functions
    func testUnifiedErrorHandling() {
        let demo = ToolingDemo()
        var caughtErrors: [DemoError] = []

        // Collect errors from different functions - all use same DemoError type
        do { _ = try demo.demoAuthenticate(username: "admin", password: "wrongpassword") } catch let
            error as DemoError
        { caughtErrors.append(error) } catch { XCTFail("Expected DemoError") }

        do { _ = try demo.demoGenericOperation(input: "network_error") } catch let error as DemoError {
            caughtErrors.append(error)
        } catch { XCTFail("Expected DemoError") }

        do { _ = try demo.demoMixedOperation(operation: "process", data: "trigger_error") } catch let
            error as DemoError
        { caughtErrors.append(error) } catch { XCTFail("Expected DemoError") }

        // Verify we have the three core error patterns
        XCTAssertEqual(caughtErrors.count, 3)

        // Strongly typed error
        if case .AuthenticationFailed = caughtErrors[0] {
        } else {
            XCTFail("Expected AuthenticationFailed")
        }

        // Generic error from anyhow chain
        if case .Generic = caughtErrors[1] {} else { XCTFail("Expected Generic") }

        // Generic error with prefix
        if case .Generic = caughtErrors[2] {} else { XCTFail("Expected Generic") }

        // All errors provide consistent localized descriptions
        for error in caughtErrors {
            XCTAssertFalse(error.localizedDescription.isEmpty)
        }
    }
}
