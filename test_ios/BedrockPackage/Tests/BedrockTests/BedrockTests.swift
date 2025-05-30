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
            ethereumKey: testPrivateKey,
            walletAddress: testWalletAddress
        )
        
        // If we get here without throwing, the account was created successfully
        XCTAssertNotNil(account)
    }
    
    func testPersonalSign() throws {
        // Create account
        let account = try SafeSmartAccount(
            ethereumKey: testPrivateKey,
            walletAddress: testWalletAddress
        )
        
        // Test message signing
        let message = "Hello from Bedrock!"
        let signature = try account.personalSign(
            chainId: chainId,
            message: message
        )
        
        // Verify we got a signature
        XCTAssertFalse(signature.isEmpty, "Signature should not be empty")
        XCTAssertTrue(signature.hasPrefix("0x"), "Signature should start with 0x")
        
        // A valid signature should be 132 characters (0x + 130 hex chars)
        XCTAssertEqual(signature.count, 132, "Signature should be 132 characters long")
    }
    
    func testMultipleMessages() throws {
        // Create account
        let account = try SafeSmartAccount(
            ethereumKey: testPrivateKey,
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
            
            XCTAssertFalse(signature.isEmpty, "Signature for '\(message)' should not be empty")
            XCTAssertEqual(signature.count, 132, "Signature for '\(message)' should be 132 characters")
        }
    }
    
    func testInvalidPrivateKey() {
        // Test with invalid private key - should throw
        XCTAssertThrowsError(
            try SafeSmartAccount(
                ethereumKey: "invalid_key",
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
                ethereumKey: "",
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
                ethereumKey: testPrivateKey,
                walletAddress: "invalid_address"
            )
        ) { error in
            XCTAssertNotNil(error)
        }
    }
    
    func testDifferentChainIds() throws {
        // Create account
        let account = try SafeSmartAccount(
            ethereumKey: testPrivateKey,
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
            )
            
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
            ethereumKey: testPrivateKey,
            walletAddress: testWalletAddress
        )
        
        // Test with a very long message
        let longMessage = String(repeating: "Lorem ipsum dolor sit amet. ", count: 100)
        
        let signature = try account.personalSign(
            chainId: chainId,
            message: longMessage
        )
        
        XCTAssertFalse(signature.isEmpty, "Signature for long message should not be empty")
        XCTAssertEqual(signature.count, 132, "Signature for long message should be 132 characters")
    }
    
    func testUnicodeMessage() throws {
        // Create account
        let account = try SafeSmartAccount(
            ethereumKey: testPrivateKey,
            walletAddress: testWalletAddress
        )
        
        // Test with unicode characters
        let unicodeMessage = "Hello 世界 🌍 Здравствуй мир"
        
        let signature = try account.personalSign(
            chainId: chainId,
            message: unicodeMessage
        )
        
        XCTAssertFalse(signature.isEmpty, "Signature for unicode message should not be empty")
        XCTAssertEqual(signature.count, 132, "Signature for unicode message should be 132 characters")
    }
    
    // MARK: - Error Demos Tests
    
    func testStronglyTypedErrors_Success() throws {
        // Test successful authentication
        let result = try demoAuthenticate(username: "testuser", password: "validpassword123")
        XCTAssertEqual(result, "Welcome, testuser!")
    }
    
    func testStronglyTypedErrors_InvalidInput() {
        // Test empty username
        XCTAssertThrowsError(
            try demoAuthenticate(username: "", password: "validpassword123")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .invalidInput(let message):
                    XCTAssertEqual(message, "Username cannot be empty")
                default:
                    XCTFail("Expected InvalidInput error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
        
        // Test short password
        XCTAssertThrowsError(
            try demoAuthenticate(username: "testuser", password: "short")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .invalidInput(let message):
                    XCTAssertEqual(message, "Password must be at least 8 characters")
                default:
                    XCTFail("Expected InvalidInput error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    func testStronglyTypedErrors_AuthenticationFailed() {
        XCTAssertThrowsError(
            try demoAuthenticate(username: "admin", password: "wrongpassword")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .authenticationFailed(let code):
                    XCTAssertEqual(code, 401)
                default:
                    XCTFail("Expected AuthenticationFailed error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    func testStronglyTypedErrors_NetworkTimeout() {
        XCTAssertThrowsError(
            try demoAuthenticate(username: "slowuser", password: "validpassword123")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .networkTimeout(let seconds):
                    XCTAssertEqual(seconds, 30)
                default:
                    XCTFail("Expected NetworkTimeout error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    func testFlexibleErrors_Success() throws {
        // Test successful operation
        let result = try demoFlexibleOperation(input: "valid_input")
        XCTAssertEqual(result, "Successfully processed: valid_input")
    }
    
    func testFlexibleErrors_EmptyInput() {
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "")
        ) { error in
            // Note: With Arc<FlexibleErrorWrapper>, the error comes through as a different type
            // We need to check the actual error message
            let errorMessage = error.localizedDescription
            XCTAssertTrue(errorMessage.contains("Input cannot be empty"), 
                         "Expected error message about empty input, got: \(errorMessage)")
        }
    }
    
    func testFlexibleErrors_NetworkError() {
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "network_error")
        ) { error in
            let errorMessage = error.localizedDescription
            // With anyhow context, we should see the full error chain
            XCTAssertTrue(errorMessage.contains("Connection timed out") || 
                         errorMessage.contains("Network operation failed") ||
                         errorMessage.contains("Service call unsuccessful"), 
                         "Expected network-related error message, got: \(errorMessage)")
        }
    }
    
    func testFlexibleErrors_ParseError() {
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "parse_error")
        ) { error in
            let errorMessage = error.localizedDescription
            // With anyhow context, we should see the full error chain
            XCTAssertTrue(errorMessage.contains("Failed to parse server response") || 
                         errorMessage.contains("Data processing failed") ||
                         errorMessage.contains("Response format is invalid"), 
                         "Expected parse-related error message, got: \(errorMessage)")
        }
    }
    
    func testFlexibleErrors_AuthError() {
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "auth_error")
        ) { error in
            // With flexible errors, we primarily work with string descriptions
            let description = error.localizedDescription
            XCTAssertFalse(description.isEmpty, "Error description should not be empty")
            // The exact message depends on how UniFFI presents the Arc<FlexibleErrorWrapper>
            print("Flexible error description: \(description)")
            
            // Test that anyhow context chains are preserved in the error message
            XCTAssertTrue(description.contains("Authentication") || 
                         description.contains("credentials") ||
                         description.contains("auth"), 
                         "Expected authentication-related error content in: \(description)")
        }
    }
    
    func testFlexibleErrors_FileErrors() {
        // Test file not found
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "file_missing")
        ) { error in
            let errorMessage = error.localizedDescription
            XCTAssertTrue(errorMessage.contains("File not found") || 
                         errorMessage.contains("Could not find file") ||
                         errorMessage.contains("File system operation failed"), 
                         "Expected file not found error message, got: \(errorMessage)")
        }
        
        // Test permission denied
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "file_permission")
        ) { error in
            let errorMessage = error.localizedDescription
            XCTAssertTrue(errorMessage.contains("Permission denied") || 
                         errorMessage.contains("Access denied") ||
                         errorMessage.contains("Insufficient permissions"), 
                         "Expected permission error message, got: \(errorMessage)")
        }
    }
    
    func testFlexibleErrors_MultipleErrors() {
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "multiple_errors")
        ) { error in
            let errorMessage = error.localizedDescription
            // Should fail on the first error (auth)
            XCTAssertTrue(errorMessage.contains("Authentication failed") || 
                         errorMessage.contains("First operation failed"), 
                         "Expected first operation error message, got: \(errorMessage)")
        }
    }
    
    func testMixedErrors_Success() throws {
        let result = try demoMixedErrors(operation: "simple")
        XCTAssertEqual(result, "Simple operation completed")
    }
    
    func testMixedErrors_AuthError() {
        XCTAssertThrowsError(
            try demoMixedErrors(operation: "auth")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .authenticationFailed(let code):
                    XCTAssertEqual(code, 403)
                default:
                    XCTFail("Expected AuthenticationFailed error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    func testMixedErrors_TimeoutError() {
        XCTAssertThrowsError(
            try demoMixedErrors(operation: "timeout")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .networkTimeout(let seconds):
                    XCTAssertEqual(seconds, 60)
                default:
                    XCTFail("Expected NetworkTimeout error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    func testMixedErrors_InvalidOperation() {
        XCTAssertThrowsError(
            try demoMixedErrors(operation: "unknown")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .invalidInput(let message):
                    XCTAssertEqual(message, "Unknown operation: unknown")
                default:
                    XCTFail("Expected InvalidInput error, got \(strongError)")
                }
            } else {
                XCTFail("Expected StronglyTypedError, got \(type(of: error))")
            }
        }
    }
    
    // Test error message accessibility in both approaches
    func testErrorMessageComparison() {
        // Strongly typed error - structured access to error details
        XCTAssertThrowsError(
            try demoAuthenticate(username: "admin", password: "wrongpassword")
        ) { error in
            if let strongError = error as? StronglyTypedError {
                switch strongError {
                case .authenticationFailed(let code):
                    // With strongly typed errors, we get structured access to error data
                    XCTAssertEqual(code, 401)
                    let description = strongError.localizedDescription
                    XCTAssertTrue(description.contains("Authentication failed with code: 401"))
                default:
                    XCTFail("Expected AuthenticationFailed error")
                }
            }
        }
        
        // Flexible error - string-based error handling
        XCTAssertThrowsError(
            try demoFlexibleOperation(input: "network_error")
        ) { error in
            // With flexible errors, we primarily work with string descriptions
            let description = error.localizedDescription
            XCTAssertFalse(description.isEmpty, "Error description should not be empty")
            // The exact message depends on how UniFFI presents the Arc<FlexibleErrorWrapper>
            print("Flexible error description: \(description)")
        }
    }
} 