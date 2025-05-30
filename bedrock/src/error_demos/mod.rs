/// Unified error type demonstrating both strongly typed and generic error handling
/// This shows how to combine specific error variants with flexible anyhow-based errors
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum DemoError {
    // Strongly typed error variants - these provide structured access to error data
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed { code: u32 },
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout { seconds: u32 },
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },

    // Generic variant for flexible error handling with anyhow
    // This allows for complex error chains and context while still being part of the main error type
    #[error("Generic error: {message}")]
    Generic { message: String },
}

impl From<anyhow::Error> for DemoError {
    fn from(err: anyhow::Error) -> Self {
        DemoError::Generic {
            message: err.to_string(),
        }
    }
}

/// Helper function that demonstrates real anyhow usage patterns
fn simulate_network_call(endpoint: &str) -> anyhow::Result<String> {
    use anyhow::Context;

    if endpoint.is_empty() {
        anyhow::bail!("Endpoint cannot be empty");
    }

    if endpoint == "timeout" {
        anyhow::bail!("Connection timed out after 30 seconds");
    }

    if endpoint == "auth" {
        Err(anyhow::anyhow!("Authentication failed"))
            .context("Invalid credentials provided")
            .context("Failed to authenticate with remote service")?;
    }

    if endpoint == "parse" {
        // Simulate a JSON parsing error
        let json_data = r#"{"incomplete": true"#; // Invalid JSON
        serde_json::from_str::<serde_json::Value>(json_data)
            .context("Failed to parse server response")
            .context("Response format is invalid")?;
    }

    Ok(format!("Successfully called {}", endpoint))
}

/// Helper function that demonstrates anyhow with external library errors
fn simulate_file_operation(filename: &str) -> anyhow::Result<String> {
    use anyhow::Context;

    if filename == "missing.txt" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "File not found",
        ))
        .context(format!("Could not find file: {}", filename))
        .context("File operation failed");
    }

    if filename == "permission.txt" {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ))
        .context(format!("Access denied for file: {}", filename))
        .context("Insufficient permissions");
    }

    Ok(format!("File {} processed successfully", filename))
}

/// Demo function that uses strongly typed errors for known error cases
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

    if password.len() < 8 {
        return Err(DemoError::InvalidInput {
            message: "Password must be at least 8 characters".to_string(),
        });
    }

    if username == "admin" && password == "wrongpassword" {
        return Err(DemoError::AuthenticationFailed { code: 401 });
    }

    if username == "slowuser" {
        return Err(DemoError::NetworkTimeout { seconds: 30 });
    }

    Ok(format!("Welcome, {}!", username))
}

/// Demo function that uses the generic error variant for complex anyhow patterns
#[uniffi::export]
pub fn demo_generic_operation(input: String) -> Result<String, DemoError> {
    use anyhow::Context;

    let result: anyhow::Result<String> = (|| {
        if input.is_empty() {
            anyhow::bail!("Input cannot be empty");
        }

        // Demonstrate chaining different types of operations that can fail
        match input.as_str() {
            "network_error" => {
                simulate_network_call("timeout")
                    .context("Network operation failed")
                    .context("Service call unsuccessful")?;
            }
            "auth_error" => {
                simulate_network_call("auth").context("Authentication step failed")?;
            }
            "parse_error" => {
                simulate_network_call("parse").context("Data processing failed")?;
            }
            "file_missing" => {
                simulate_file_operation("missing.txt")
                    .context("File system operation failed")?;
            }
            "file_permission" => {
                simulate_file_operation("permission.txt")
                    .context("File access operation failed")?;
            }
            "multiple_errors" => {
                // Demonstrate error accumulation
                simulate_network_call("auth").context("First operation failed")?;
                simulate_file_operation("missing.txt")
                    .context("Second operation failed")?;
            }
            _ => {
                // Successful case
            }
        }

        Ok(format!("Successfully processed: {}", input))
    })();

    result.map_err(DemoError::from)
}

/// Demo function that shows mixing both error patterns in a single function
#[uniffi::export]
pub fn demo_mixed_operations(
    operation: String,
    data: String,
) -> Result<String, DemoError> {
    // First, do some validation using strongly typed errors
    if operation.is_empty() {
        return Err(DemoError::InvalidInput {
            message: "Operation cannot be empty".to_string(),
        });
    }

    match operation.as_str() {
        "validate_and_process" => {
            // Start with validation (strongly typed)
            if data.len() < 3 {
                return Err(DemoError::InvalidInput {
                    message: "Data must be at least 3 characters".to_string(),
                });
            }

            // Then do complex processing (generic anyhow errors)
            let result = simulate_network_call(&data)
                .and_then(|_| simulate_file_operation("valid.txt"))
                .map_err(DemoError::from)?;

            Ok(format!("Processed: {}", result))
        }
        "auth_then_timeout" => {
            // Specific auth error first
            if data == "invalid_creds" {
                return Err(DemoError::AuthenticationFailed { code: 403 });
            }

            // Then a timeout scenario
            if data == "slow_network" {
                return Err(DemoError::NetworkTimeout { seconds: 45 });
            }

            Ok("Authentication and network operations completed".to_string())
        }
        "complex_chain" => {
            // This will use the generic error handling for complex anyhow chains
            use anyhow::Context;

            simulate_network_call(&data)
                .context("Initial network call failed")
                .and_then(|_| {
                    simulate_file_operation(&format!("{}.txt", data))
                        .context("Follow-up file operation failed")
                })
                .context("Complex operation chain failed")
                .map(|result| format!("Chain completed: {}", result))
                .map_err(DemoError::from)
        }
        _ => Err(DemoError::InvalidInput {
            message: format!("Unknown operation: {}", operation),
        }),
    }
}
