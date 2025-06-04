import XCTest

@testable import Bedrock

// Foreign Tests for tooling functionality (i.e. logging and error handling)
// The demo structs are only available in Foreign Tests and are not available in built binaries.

final class BedrockToolingTests: XCTestCase {

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