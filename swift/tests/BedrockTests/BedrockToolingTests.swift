import XCTest

@testable import Bedrock

// Foreign Tests for tooling functionality (i.e. logging and error handling)
// The demo structs are only available in Foreign Tests and are not available in built binaries.

final class BedrockToolingTests: XCTestCase {

    func testToolingDemoLogPrefixing() throws {
        // Test the ToolingDemo to verify log prefixing works
        let demo = ToolingDemo()
        
        // These calls should generate logs with [Bedrock][ToolingDemo] prefix
        demo.logMessage(message: "Testing log prefixing from Swift")
        demo.testLogLevels()
        
        let result = demo.getDemoResult()
        XCTAssertTrue(result.contains("ToolingDemo"), "Result should contain the demo name")
        XCTAssertTrue(result.contains("Demo result"), "Result should contain expected text")
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
    
    // MARK: - BedrockConfig Tests
    
    func testBedrockConfigInitialization() throws {
        // Initialize config with staging environment
        setConfig(environment: .staging)
        
        // Verify current environment is staging
        let config = getConfig()
        XCTAssertNotNil(config, "Config should be available after initialization")
        XCTAssertEqual(config?.environment(), .staging, "Environment should be staging after initialization")
        
        // Verify config is initialized
        XCTAssertTrue(isInitialized(), "Config should be initialized")
        
        // Get config and verify environment
        if let config = getConfig() {
            XCTAssertEqual(config.environment(), .staging, "Config environment should be staging")
        } else {
            XCTFail("Config should be available after initialization")
        }
        
        // Try to initialize again - should be ignored (check logs for warning)
        setConfig(environment: .production)
        
        // Environment should still be staging
        let configAfterSecondInit = getConfig()
        XCTAssertEqual(configAfterSecondInit?.environment(), .staging, "Environment should remain staging after second init attempt")
    }
    
    func testBedrockConfigEnvironmentTypes() throws {
        // Test creating config with different environments
        let stagingConfig = BedrockConfig(environment: .staging)
        XCTAssertEqual(stagingConfig.environment(), .staging, "Staging config should have staging environment")
        
        let productionConfig = BedrockConfig(environment: .production)
        XCTAssertEqual(productionConfig.environment(), .production, "Production config should have production environment")
    }
    
    // MARK: - Async Operation Tests
    
    func testDemoAsyncOperation_Success() async throws {
        let demo = ToolingDemo()
        
        // Test successful async operation with short delay
        let result = try await demo.demoAsyncOperation(delayMs: 100)
        XCTAssertTrue(result.contains("Async operation completed after 100ms"))
        XCTAssertTrue(result.contains("completed"))
    }
    
    func testDemoAsyncOperation_Timeout() async throws {
        let demo = ToolingDemo()
        
        // Test async operation that should timeout (over 5000ms)
        do {
            _ = try await demo.demoAsyncOperation(delayMs: 6000)
            XCTFail("Expected timeout error")
        } catch let error as DemoError {
            if case .Generic(let message) = error {
                XCTAssertTrue(message.contains("timeout exceeded"))
                XCTAssertTrue(message.contains("5 seconds"))
            } else {
                XCTFail("Expected Generic error for timeout")
            }
        }
    }
    
    func testDemoAsyncOperation_MultipleOperations() async throws {
        let demo = ToolingDemo()
        
        // Test multiple async operations to ensure runtime stability
        let result1 = try await demo.demoAsyncOperation(delayMs: 50)
        let result2 = try await demo.demoAsyncOperation(delayMs: 100)
        let result3 = try await demo.demoAsyncOperation(delayMs: 150)
        
        XCTAssertTrue(result1.contains("completed after 50ms"))
        XCTAssertTrue(result2.contains("completed after 100ms"))
        XCTAssertTrue(result3.contains("completed after 150ms"))
    }
    
    func testDemoAsyncOperation_ConcurrentOperations() async throws {
        // This test specifically verifies that the automatic tokio runtime configuration
        // added by bedrock_export works correctly with concurrent async operations in Swift
        let demo = ToolingDemo()
        
        // Run concurrent async operations to stress test the runtime
        let delays: [UInt64] = [10, 25, 50, 75, 100]
        
        let results = try await withThrowingTaskGroup(of: String.self) { group in
            for delay in delays {
                group.addTask {
                    return try await demo.demoAsyncOperation(delayMs: delay)
                }
            }
            
            var collectedResults: [String] = []
            for try await result in group {
                collectedResults.append(result)
            }
            return collectedResults
        }
        
        // Verify all operations completed successfully
        XCTAssertEqual(results.count, 5)
        for result in results {
            XCTAssertTrue(result.contains("completed"))
            XCTAssertTrue(result.contains("ms"))
        }
    }
    
    func testDemoAsyncOperation_RuntimeIntegration() async throws {
        // Additional test to verify sequential async operations work correctly
        let demo = ToolingDemo()
        
        let delays: [UInt64] = [20, 40, 60, 80, 100]
        var results: [String] = []
        
        for delay in delays {
            let result = try await demo.demoAsyncOperation(delayMs: delay)
            results.append(result)
        }
        
        // Verify all operations completed successfully
        XCTAssertEqual(results.count, 5)
        for (index, result) in results.enumerated() {
            let expectedDelay = delays[index]
            XCTAssertTrue(result.contains("completed after \(expectedDelay)ms"))
        }
    }
} 