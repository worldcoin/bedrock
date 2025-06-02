use crate::{bedrock_export, debug, info, warn};

/// A simple demo struct to test tooling functionality like log prefixing and error handling.
#[derive(Debug, uniffi::Object)]
pub struct ToolingDemo;

/// Error type for demonstrating bedrock error handling patterns.
///
/// The `#[bedrock_error]` macro automatically:
/// - Adds `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// - Adds a `Generic { message: String }` variant
/// - Implements `From<anyhow::Error>` for automatic conversion
/// - Provides helper methods for error handling
#[crate::bedrock_error]
pub enum DemoError {
    // Strongly typed errors - use when you want structured access to error data
    /// Authentication failed with a specific error code
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed {
        /// The HTTP status code associated with the authentication failure
        code: u32,
    },
    /// Network operation timed out after specified number of seconds
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout {
        /// The number of seconds after which the operation timed out
        seconds: u32,
    },
    /// Invalid input was provided with a descriptive message
    #[error("Invalid input: {message}")]
    InvalidInput {
        /// A descriptive message explaining what was invalid about the input
        message: String,
    },
    // Note: Generic variant is automatically added by #[bedrock_error]
}

impl Default for ToolingDemo {
    fn default() -> Self {
        Self::new()
    }
}

/// Demonstrates automatic logging context injection with bedrock_export.
/// All public methods will automatically have [ToolingDemo] prefix in logs.
#[bedrock_export]
impl ToolingDemo {
    /// Creates a new tooling demo instance.
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        info!("Creating ToolingDemo instance");
        Self
    }

    /// Logs a simple message to test log prefixing.
    pub fn log_message(&self, message: &str) {
        info!("User message: {}", message);
    }

    /// Logs messages at different levels to test log prefixing.
    pub fn test_log_levels(&self) {
        debug!("This is a debug message from ToolingDemo");
        info!("This is an info message from ToolingDemo");
        warn!("This is a warning message from ToolingDemo");
    }

    /// Returns a simple result for testing.
    #[must_use]
    pub fn get_demo_result(&self) -> String {
        debug!("Generating demo result");
        "Demo result from ToolingDemo".to_string()
    }

    /// Demo: Strongly typed errors for known, structured error cases
    ///
    /// # Errors
    ///
    /// Returns `DemoError::InvalidInput` if username is empty.
    /// Returns `DemoError::AuthenticationFailed` if credentials are invalid.
    /// Returns `DemoError::NetworkTimeout` if user is "slowuser".
    /// Returns `DemoError::Generic` if the generic operation fails.
    pub fn demo_authenticate(
        &self,
        username: &str,
        password: &str,
    ) -> Result<String, DemoError> {
        info!("Attempting authentication for user: {}", username);

        if username.is_empty() {
            warn!("Authentication failed: empty username");
            return Err(DemoError::InvalidInput {
                message: "Username cannot be empty".to_string(),
            });
        }

        if username == "admin" && password == "wrongpassword" {
            warn!("Authentication failed: invalid credentials for admin");
            return Err(DemoError::AuthenticationFailed { code: 401 });
        }

        if username == "slowuser" {
            warn!("Authentication failed: network timeout for slowuser");
            return Err(DemoError::NetworkTimeout { seconds: 30 });
        }

        let welcome_message = format!("Welcome, {username}!");
        info!("Authentication successful for user: {}", username);

        let operation_result =
            self.demo_generic_operation(&format!("auth_data_{username}"))?;

        Ok(format!("{welcome_message} {operation_result}"))
    }

    /// Demo: Generic errors for complex operations with anyhow error chains
    ///
    /// # Errors
    ///
    /// Returns `DemoError::Generic` for various error conditions including
    /// empty input, network errors, parse errors, and deep chain errors.
    pub fn demo_generic_operation(&self, input: &str) -> Result<String, DemoError> {
        debug!("Starting generic operation with input: {}", input);

        let result: anyhow::Result<String> = (|| {
            if input.is_empty() {
                anyhow::bail!("Input cannot be empty");
            }

            if input == "network_error" {
                anyhow::bail!("Connection timed out after 30 seconds");
            }

            if input == "parse_error" {
                serde_json::from_str::<serde_json::Value>(input)
                    .with_context(|| "Failed to parse input as JSON")?;
            }

            if input == "deep_chain_error" {
                // Create a deep error chain to test the "caused by" formatting
                let root_error =
                    std::io::Error::new(std::io::ErrorKind::NotFound, "File not found");
                return Err(anyhow::Error::from(root_error)
                    .context("Failed to read configuration file")
                    .context("Unable to initialize database connection")
                    .context("Service startup failed"));
            }

            Ok(format!("Successfully processed: {input}"))
        })();

        match &result {
            Ok(success) => {
                info!("Generic operation completed successfully: {}", success);
            }
            Err(error) => warn!("Generic operation failed: {}", error),
        }

        DemoError::from_anyhow_result(result)
    }

    /// Demo: Mixed usage - structured errors for validation, generic for complex operations
    ///
    /// # Errors
    ///
    /// Returns `DemoError::InvalidInput` if operation is empty or unknown.
    /// Returns `DemoError::Generic` if the processing operation fails.
    pub fn demo_mixed_operation(
        &self,
        operation: &str,
        data: &str,
    ) -> Result<String, DemoError> {
        info!(
            "Starting mixed operation: {} with data: {}",
            operation, data
        );

        if operation.is_empty() {
            warn!("Mixed operation failed: empty operation name");
            return Err(DemoError::InvalidInput {
                message: "Operation cannot be empty".to_string(),
            });
        }

        if operation == "process" {
            info!("Processing data in mixed operation");
            let complex_result: anyhow::Result<String> = (|| {
                if data == "trigger_error" {
                    anyhow::bail!("Simulated processing failure");
                }

                Ok(format!("Processed: {data}"))
            })();

            let result = DemoError::from_anyhow_result_with_prefix(
                complex_result,
                "Operation failed",
            );

            match &result {
                Ok(success) => {
                    info!("Mixed operation completed successfully: {}", success);
                }
                Err(error) => warn!("Mixed operation failed: {}", error),
            }

            result
        } else {
            warn!("Mixed operation failed: unknown operation: {}", operation);
            Err(DemoError::InvalidInput {
                message: format!("Unknown operation: {operation}"),
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_functionality() {
        let demo = ToolingDemo::new();
        demo.log_message("Test message");
        demo.test_log_levels();
        let result = demo.get_demo_result();
        assert!(result.contains("Demo result"));
    }

    #[test]
    fn test_error_handling() {
        let demo = ToolingDemo::new();

        // Test success case
        let result = demo.demo_mixed_operation("process", "valid_data");
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Processed:"));

        // Test strongly typed error - empty operation
        let result = demo.demo_mixed_operation("", "data");
        assert!(result.is_err());
        if let Err(DemoError::InvalidInput { message }) = result {
            assert!(message.contains("Operation cannot be empty"));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test strongly typed error - unknown operation
        let result = demo.demo_mixed_operation("unknown", "data");
        assert!(result.is_err());
        if let Err(DemoError::InvalidInput { message }) = result {
            assert!(message.contains("Unknown operation"));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test generic error - anyhow style
        let result = demo.demo_mixed_operation("process", "trigger_error");
        assert!(result.is_err());
        if let Err(DemoError::Generic { message }) = result {
            assert!(message.contains("Operation failed"));
            assert!(message.contains("Simulated processing failure"));
        } else {
            panic!("Expected Generic error");
        }
    }

    #[test]
    fn test_authentication_demo() {
        let demo = ToolingDemo::new();

        // Test empty username
        let result = demo.demo_authenticate("", "password");
        assert!(result.is_err());
        if let Err(DemoError::InvalidInput { message }) = result {
            assert!(message.contains("Username cannot be empty"));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test wrong credentials
        let result = demo.demo_authenticate("admin", "wrongpassword");
        assert!(result.is_err());
        if let Err(DemoError::AuthenticationFailed { code }) = result {
            assert_eq!(code, 401);
        } else {
            panic!("Expected AuthenticationFailed error");
        }

        // Test network timeout
        let result = demo.demo_authenticate("slowuser", "password");
        assert!(result.is_err());
        if let Err(DemoError::NetworkTimeout { seconds }) = result {
            assert_eq!(seconds, 30);
        } else {
            panic!("Expected NetworkTimeout error");
        }
    }
}
