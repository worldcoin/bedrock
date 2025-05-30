///
/// The `#[bedrock_error]` macro automatically:
/// - Adds `#[derive(Debug, thiserror::Error, uniffi::Error)]` and `#[uniffi(flat_error)]`
/// - Adds a `Generic { message: String }` variant
/// - Implements `From<anyhow::Error>` for automatic conversion
/// - Provides helper methods for error handling
#[crate::bedrock_error]
pub enum DemoError {
    // Strongly typed errors - use when you want structured access to error data
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed { code: u32 },
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout { seconds: u32 },
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    // Note: Generic variant is automatically added by #[bedrock_error]
}

/// Demo: Strongly typed errors for known, structured error cases
#[uniffi::export]
pub fn demo_authenticate(
    username: String,
    password: String,
) -> Result<String, DemoError> {
    if username.is_empty() {
        return Err(DemoError::InvalidInput {
            message: "Username cannot be empty".to_string(),
        });
    }

    if username == "admin" && password == "wrongpassword" {
        return Err(DemoError::AuthenticationFailed { code: 401 });
    }

    if username == "slowuser" {
        return Err(DemoError::NetworkTimeout { seconds: 30 });
    }

    let welcome_message = format!("Welcome, {}!", username);

    let operation_result = demo_generic_operation(format!("auth_data_{}", username))?;

    Ok(format!("{} {}", welcome_message, operation_result))
}

/// Demo: Generic errors for complex operations with anyhow error chains
#[uniffi::export]
pub fn demo_generic_operation(input: String) -> Result<String, DemoError> {
    let result: anyhow::Result<String> = (|| {
        if input.is_empty() {
            anyhow::bail!("Input cannot be empty");
        }

        if input == "network_error" {
            anyhow::bail!("Connection timed out after 30 seconds");
        }

        if input == "parse_error" {
            serde_json::from_str::<serde_json::Value>(&input)
                .context("Failed to parse input as JSON")?;
        }

        Ok(format!("Successfully processed: {}", input))
    })();

    DemoError::from_anyhow_result(result)
}

/// Demo: Mixed usage - structured errors for validation, generic for complex operations
#[uniffi::export]
pub fn demo_mixed_operation(
    operation: String,
    data: String,
) -> Result<String, DemoError> {
    if operation.is_empty() {
        return Err(DemoError::InvalidInput {
            message: "Operation cannot be empty".to_string(),
        });
    }

    match operation.as_str() {
        "process" => {
            let complex_result: anyhow::Result<String> = (|| {
                if data == "trigger_error" {
                    anyhow::bail!("Simulated processing failure");
                }

                Ok(format!("Processed: {}", data))
            })();

            DemoError::from_anyhow_result_with_prefix(
                complex_result,
                "Operation failed",
            )
        }
        _ => Err(DemoError::InvalidInput {
            message: format!("Unknown operation: {}", operation),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_demo_mixed_operation() {
        // Test success case
        let result =
            demo_mixed_operation("process".to_string(), "valid_data".to_string());
        assert!(result.is_ok());
        assert!(result.unwrap().contains("Processed:"));

        // Test strongly typed error - empty operation
        let result = demo_mixed_operation("".to_string(), "data".to_string());
        assert!(result.is_err());
        if let Err(DemoError::InvalidInput { message }) = result {
            assert!(message.contains("Operation cannot be empty"));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test strongly typed error - unknown operation
        let result = demo_mixed_operation("unknown".to_string(), "data".to_string());
        assert!(result.is_err());
        if let Err(DemoError::InvalidInput { message }) = result {
            assert!(message.contains("Unknown operation"));
        } else {
            panic!("Expected InvalidInput error");
        }

        // Test generic error - anyhow style
        let result =
            demo_mixed_operation("process".to_string(), "trigger_error".to_string());
        assert!(result.is_err());
        if let Err(DemoError::Generic { message }) = result {
            assert!(message.contains("Operation failed"));
            assert!(message.contains("Simulated processing failure"));
        } else {
            panic!("Expected Generic error");
        }
    }
}
