package bedrock

import uniffi.bedrock.DemoException
import uniffi.bedrock.ToolingDemo
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.coroutines.runBlocking

// Foreign Tests for tooling functionality (i.e. logging and error handling)
// The demo structs are only available in Foreign Tests and are not available in built binaries.

class BedrockToolingTests {
    @Test
    fun testToolingDemoLogPrefixing() {
        // Test the ToolingDemo to verify log prefixing works
        val demo = ToolingDemo()

        // These calls should generate logs with [Bedrock][ToolingDemo] prefix
        demo.logMessage("Testing log prefixing from Kotlin")
        demo.testLogLevels()

        val result = demo.getDemoResult()
        assertTrue(result.contains("ToolingDemo"), "Result should contain the demo name")
        assertTrue(result.contains("Demo result"), "Result should contain expected text")
    }

    // MARK: - Error Handling Tests

    // Test: Strongly typed errors for validation and known cases
    @Test
    fun testDemoAuthenticate_StronglyTypedErrors() {
        val demo = ToolingDemo()

        // Success case - now includes result from post-auth operation
        val result = demo.demoAuthenticate("testuser", "validpassword")
        assertTrue(result.contains("Welcome, testuser!"))
        assertTrue(result.contains("Successfully processed: auth_data_testuser"))

        // Empty username - InvalidInput
        val emptyUsernameException =
            assertFailsWith<DemoException.InvalidInput> {
                demo.demoAuthenticate("", "password")
            }
        assertTrue(emptyUsernameException.message?.contains("Username cannot be empty") == true)

        // Wrong credentials - AuthenticationFailed
        val wrongCredentialsException =
            assertFailsWith<DemoException.AuthenticationFailed> {
                demo.demoAuthenticate("admin", "wrongpassword")
            }
        assertEquals(401u, wrongCredentialsException.code)
        assertTrue(wrongCredentialsException.message?.contains("401") == true)

        // Slow user - NetworkTimeout
        val timeoutException =
            assertFailsWith<DemoException.NetworkTimeout> {
                demo.demoAuthenticate("slowuser", "password")
            }
        assertEquals(30u, timeoutException.seconds)
        assertTrue(timeoutException.message?.contains("30") == true)
    }

    // Test: Generic errors for complex anyhow error chains
    @Test
    fun testDemoGenericOperation_AnyhowChains() {
        val demo = ToolingDemo()

        // Success case
        val result = demo.demoGenericOperation("valid_input")
        assertEquals("Successfully processed: valid_input", result)

        // Empty input - Generic error
        val emptyInputException =
            assertFailsWith<DemoException.Generic> {
                demo.demoGenericOperation("")
            }
        assertTrue(emptyInputException.message?.contains("Input cannot be empty") == true)

        // Network error - Generic error with anyhow context
        val networkException =
            assertFailsWith<DemoException.Generic> {
                demo.demoGenericOperation("network_error")
            }
        assertTrue(networkException.message?.contains("Connection timed out") == true)

        // Parse error - Generic error with anyhow context
        val parseException =
            assertFailsWith<DemoException.Generic> {
                demo.demoGenericOperation("parse_error")
            }
        assertTrue(parseException.message?.contains("Failed to parse input as JSON") == true)
    }

    // Test: Mixed usage - structured validation + generic processing
    @Test
    fun testDemoMixedOperation_CombinedApproach() {
        val demo = ToolingDemo()

        // Success case
        val result = demo.demoMixedOperation("process", "valid_data")
        assertTrue(result.contains("Processed:"))

        // Empty operation - InvalidInput (strongly typed validation)
        val emptyOperationException =
            assertFailsWith<DemoException.InvalidInput> {
                demo.demoMixedOperation("", "data")
            }
        assertTrue(emptyOperationException.message?.contains("Operation cannot be empty") == true)

        // Unknown operation - InvalidInput (strongly typed validation)
        val unknownOperationException =
            assertFailsWith<DemoException.InvalidInput> {
                demo.demoMixedOperation("unknown", "data")
            }
        assertTrue(unknownOperationException.message?.contains("Unknown operation") == true)

        // Process operation with trigger_error - Generic error (anyhow processing)
        val processingException =
            assertFailsWith<DemoException.Generic> {
                demo.demoMixedOperation("process", "trigger_error")
            }
        assertTrue(processingException.message?.contains("Operation failed") == true)
        assertTrue(processingException.message?.contains("Simulated processing failure") == true)
    }

    // Test: Unified error handling across all demo functions
    @Test
    fun testUnifiedErrorHandling() {
        val demo = ToolingDemo()
        val caughtErrors = mutableListOf<DemoException>()

        // Collect errors from different functions - all use same DemoException type
        try {
            demo.demoAuthenticate("admin", "wrongpassword")
        } catch (error: DemoException.AuthenticationFailed) {
            caughtErrors.add(error)
        }

        try {
            demo.demoGenericOperation("network_error")
        } catch (error: DemoException.Generic) {
            caughtErrors.add(error)
        }

        try {
            demo.demoMixedOperation("process", "trigger_error")
        } catch (error: DemoException.Generic) {
            caughtErrors.add(error)
        }

        // Verify we have the three core error patterns
        assertEquals(3, caughtErrors.size)

        // Strongly typed error
        assertTrue(caughtErrors[0] is DemoException.AuthenticationFailed, "Expected AuthenticationFailed")

        // Generic error from anyhow chain
        assertTrue(caughtErrors[1] is DemoException.Generic, "Expected Generic")

        // Generic error with prefix
        assertTrue(caughtErrors[2] is DemoException.Generic, "Expected Generic")

        // All errors provide consistent message content
        for (error in caughtErrors) {
            assertTrue(error.message?.isNotEmpty() == true, "Error message should not be empty")
        }
    }

    // MARK: - BedrockConfig Tests

    @Test
    fun testBedrockConfigInitialization() {
        // Initialize config with staging environment
        uniffi.bedrock.setConfig(uniffi.bedrock.BedrockEnvironment.STAGING, uniffi.bedrock.Os.ANDROID)

        // Verify current environment is staging
        val config = uniffi.bedrock.getConfig()
        assertNotNull(config, "Config should be available after initialization")
        assertEquals(uniffi.bedrock.BedrockEnvironment.STAGING, config.environment(), "Environment should be staging after initialization")

        // Verify config is initialized
        assertTrue(uniffi.bedrock.isInitialized(), "Config should be initialized")

        // Try to initialize again - should be ignored (check logs for warning)
        uniffi.bedrock.setConfig(uniffi.bedrock.BedrockEnvironment.PRODUCTION, uniffi.bedrock.Os.ANDROID)

        // Environment should still be staging
        val configAfterSecondInit = uniffi.bedrock.getConfig()
        assertEquals(
            uniffi.bedrock.BedrockEnvironment.STAGING,
            configAfterSecondInit?.environment(),
            "Environment should remain staging after second init attempt",
        )
    }

    @Test
    fun testBedrockConfigEnvironmentTypes() {
        // Test creating config with different environments
        val stagingConfig = uniffi.bedrock.BedrockConfig(uniffi.bedrock.BedrockEnvironment.STAGING, uniffi.bedrock.Os.ANDROID)
        assertEquals(
            uniffi.bedrock.BedrockEnvironment.STAGING,
            stagingConfig.environment(),
            "Staging config should have staging environment",
        )

        val productionConfig = uniffi.bedrock.BedrockConfig(uniffi.bedrock.BedrockEnvironment.PRODUCTION, uniffi.bedrock.Os.ANDROID)
        assertEquals(
            uniffi.bedrock.BedrockEnvironment.PRODUCTION,
            productionConfig.environment(),
            "Production config should have production environment",
        )
    }

    // MARK: - Async Operation Tests
    
    @Test
    fun testDemoAsyncOperation_Success() = runBlocking {
        val demo = ToolingDemo()
        
        // Test successful async operation with short delay
        val result = demo.demoAsyncOperation(100uL)
        assertTrue(result.contains("Async operation completed after 100ms"))
        assertTrue(result.contains("completed"))
    }
    
    @Test
    fun testDemoAsyncOperation_Timeout() = runBlocking {
        val demo = ToolingDemo()
        
        // Test async operation that should timeout (over 5000ms)
        val timeoutException = assertFailsWith<DemoException.Generic> {
            demo.demoAsyncOperation(6000uL)
        }
        assertTrue(timeoutException.message?.contains("timeout exceeded") == true)
        assertTrue(timeoutException.message?.contains("5 seconds") == true)
    }
    
    @Test
    fun testDemoAsyncOperation_MultipleOperations() = runBlocking {
        val demo = ToolingDemo()
        
        // Test multiple async operations to ensure runtime stability
        val result1 = demo.demoAsyncOperation(50uL)
        val result2 = demo.demoAsyncOperation(100uL)
        val result3 = demo.demoAsyncOperation(150uL)
        
        assertTrue(result1.contains("completed after 50ms"))
        assertTrue(result2.contains("completed after 100ms"))
        assertTrue(result3.contains("completed after 150ms"))
    }
    
    @Test
    fun testDemoAsyncOperation_RuntimeIntegration() = runBlocking {
        // This test specifically verifies that the automatic tokio runtime configuration
        // added by bedrock_export works correctly in foreign code
        val demo = ToolingDemo()
        
        // Run a series of async operations to stress test the runtime
        val delays = listOf(10uL, 25uL, 50uL, 75uL, 100uL)
        val results = mutableListOf<String>()
        
        for (delay in delays) {
            val result = demo.demoAsyncOperation(delay)
            results.add(result)
        }
        
        // Verify all operations completed successfully
        assertEquals(5, results.size)
        for ((index, result) in results.withIndex()) {
            val expectedDelay = delays[index]
            assertTrue(result.contains("completed after ${expectedDelay}ms"))
        }
    }
}
