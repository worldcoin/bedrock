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
    
    func testDemoAuthenticate_Success() throws {
        // Test successful authentication
        let result = try demoAuthenticate(username: "testuser", password: "validpassword123")
        XCTAssertEqual(result, "Welcome, testuser!")
    }
    
    func testDemoAuthenticate_StronglyTypedErrors() {
        // Test empty username - should get InvalidInput
        XCTAssertThrowsError(
            try demoAuthenticate(username: "", password: "validpassword123")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .invalidInput(let message):
                    XCTAssertTrue(message.contains("Username cannot be empty"), 
                                 "Expected username error, got: \(message)")
                default:
                    XCTFail("Expected InvalidInput error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test short password - should get InvalidInput
        XCTAssertThrowsError(
            try demoAuthenticate(username: "testuser", password: "short")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .invalidInput(let message):
                    XCTAssertTrue(message.contains("Password must be at least 8 characters"), 
                                 "Expected password error, got: \(message)")
                default:
                    XCTFail("Expected InvalidInput error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test authentication failure - should get AuthenticationFailed
        XCTAssertThrowsError(
            try demoAuthenticate(username: "admin", password: "wrongpassword")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .authenticationFailed(let message):
                    XCTAssertTrue(message.contains("Authentication failed") && 
                                 message.contains("401"), 
                                 "Expected auth error with code 401, got: \(message)")
                default:
                    XCTFail("Expected AuthenticationFailed error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test network timeout - should get NetworkTimeout
        XCTAssertThrowsError(
            try demoAuthenticate(username: "slowuser", password: "validpassword123")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .networkTimeout(let message):
                    XCTAssertTrue(message.contains("Network timeout") && 
                                 message.contains("30"), 
                                 "Expected timeout error with 30 seconds, got: \(message)")
                default:
                    XCTFail("Expected NetworkTimeout error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
    }
    
    func testDemoGenericOperation_Success() throws {
        // Test successful operation
        let result = try demoGenericOperation(input: "valid_input")
        XCTAssertEqual(result, "Successfully processed: valid_input")
    }
    
    func testDemoGenericOperation_GenericErrors() {
        // Test empty input - should get Generic error
        XCTAssertThrowsError(
            try demoGenericOperation(input: "")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Input cannot be empty"), 
                                 "Expected empty input error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test network error - should get Generic error with anyhow context
        XCTAssertThrowsError(
            try demoGenericOperation(input: "network_error")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Connection timed out") || 
                                 message.contains("Network operation failed") ||
                                 message.contains("Service call unsuccessful"), 
                                 "Expected network-related error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test auth error - should get Generic error with anyhow context
        XCTAssertThrowsError(
            try demoGenericOperation(input: "auth_error")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Authentication failed") || 
                                 message.contains("Invalid credentials") ||
                                 message.contains("Authentication step failed"), 
                                 "Expected auth-related error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test parse error - should get Generic error with anyhow context
        XCTAssertThrowsError(
            try demoGenericOperation(input: "parse_error")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Failed to parse server response") || 
                                 message.contains("Data processing failed") ||
                                 message.contains("Response format is invalid"), 
                                 "Expected parse-related error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test file errors
        XCTAssertThrowsError(
            try demoGenericOperation(input: "file_missing")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("File not found") || 
                                 message.contains("Could not find file") ||
                                 message.contains("File system operation failed"), 
                                 "Expected file not found error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        XCTAssertThrowsError(
            try demoGenericOperation(input: "file_permission")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Permission denied") || 
                                 message.contains("Access denied") ||
                                 message.contains("Insufficient permissions"), 
                                 "Expected permission error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
    }
    
    func testDemoMixedOperations() throws {
        // Test successful validation and processing
        let result1 = try demoMixedOperations(operation: "validate_and_process", data: "valid_data_123")
        XCTAssertTrue(result1.contains("Processed:"))
        
        // Test successful auth and network operations
        let result2 = try demoMixedOperations(operation: "auth_then_timeout", data: "good_data")
        XCTAssertEqual(result2, "Authentication and network operations completed")
        
        // Test validation error (strongly typed)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "validate_and_process", data: "x")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .invalidInput(let message):
                    XCTAssertTrue(message.contains("Data must be at least 3 characters"), 
                                 "Expected validation error, got: \(message)")
                default:
                    XCTFail("Expected InvalidInput error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test auth failure (strongly typed)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "auth_then_timeout", data: "invalid_creds")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .authenticationFailed(let message):
                    XCTAssertTrue(message.contains("Authentication failed") && 
                                 message.contains("403"), 
                                 "Expected auth error with code 403, got: \(message)")
                default:
                    XCTFail("Expected AuthenticationFailed error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test timeout (strongly typed)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "auth_then_timeout", data: "slow_network")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .networkTimeout(let message):
                    XCTAssertTrue(message.contains("Network timeout") && 
                                 message.contains("45"), 
                                 "Expected timeout error with 45 seconds, got: \(message)")
                default:
                    XCTFail("Expected NetworkTimeout error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test complex chain operation (generic error)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "complex_chain", data: "auth")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .generic(let message):
                    XCTAssertTrue(message.contains("Complex operation chain failed") ||
                                 message.contains("Authentication failed") ||
                                 message.contains("Initial network call failed"), 
                                 "Expected complex chain error, got: \(message)")
                default:
                    XCTFail("Expected Generic error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test invalid operation (strongly typed)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "unknown", data: "any_data")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .invalidInput(let message):
                    XCTAssertTrue(message.contains("Unknown operation: unknown"), 
                                 "Expected unknown operation error, got: \(message)")
                default:
                    XCTFail("Expected InvalidInput error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
        
        // Test empty operation (strongly typed)
        XCTAssertThrowsError(
            try demoMixedOperations(operation: "", data: "any_data")
        ) { error in
            if let demoError = error as? DemoError {
                switch demoError {
                case .invalidInput(let message):
                    XCTAssertTrue(message.contains("Operation cannot be empty"), 
                                 "Expected empty operation error, got: \(message)")
                default:
                    XCTFail("Expected InvalidInput error, got \(demoError)")
                }
            } else {
                XCTFail("Expected DemoError, got \(type(of: error))")
            }
        }
    }
    
    // Test demonstrating the unified error handling approach
    func testUnifiedErrorHandling() {
        // This test shows how having a single error type makes error handling more consistent
        var caughtErrors: [DemoError] = []
        
        // Collect different types of errors
        do {
            _ = try demoAuthenticate(username: "admin", password: "wrongpassword")
        } catch let error as DemoError {
            caughtErrors.append(error)
        } catch {
            XCTFail("Expected DemoError")
        }
        
        do {
            _ = try demoGenericOperation(input: "auth_error")
        } catch let error as DemoError {
            caughtErrors.append(error)
        } catch {
            XCTFail("Expected DemoError")
        }
        
        do {
            _ = try demoMixedOperations(operation: "auth_then_timeout", data: "slow_network")
        } catch let error as DemoError {
            caughtErrors.append(error)
        } catch {
            XCTFail("Expected DemoError")
        }
        
        // Verify we caught different types of errors, all using the same error enum
        XCTAssertEqual(caughtErrors.count, 3)
        
        // Verify the error types
        if case .authenticationFailed(let message) = caughtErrors[0] {
            XCTAssertTrue(message.contains("Authentication failed") && message.contains("401"), 
                         "Expected auth error with code 401, got: \(message)")
        } else {
            XCTFail("Expected AuthenticationFailed error")
        }
        
        if case .generic(let message) = caughtErrors[1] {
            XCTAssertTrue(message.contains("Authentication"), 
                         "Expected authentication-related generic error, got: \(message)")
        } else {
            XCTFail("Expected Generic error")
        }
        
        if case .networkTimeout(let message) = caughtErrors[2] {
            XCTAssertTrue(message.contains("Network timeout") && message.contains("45"), 
                         "Expected timeout error with 45 seconds, got: \(message)")
        } else {
            XCTFail("Expected NetworkTimeout error")
        }
        
        // Demonstrate unified error message handling
        for error in caughtErrors {
            let description = error.localizedDescription
            XCTAssertFalse(description.isEmpty, "Error description should not be empty")
            print("Unified error: \(description)")
        }
    }
} 