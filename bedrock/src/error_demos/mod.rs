use std::sync::Arc;

/// Example #1: Strongly typed enum-based errors
/// This is the traditional approach with specific error variants
#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum StronglyTypedError {
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed { code: u32 },
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout { seconds: u32 },
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
}

/// Example #2: Interface-based flexible errors (compatible with anyhow)
/// This allows for more flexible error handling while still providing structured access
#[derive(Debug, thiserror::Error)]
#[error("{inner}")]
pub struct FlexibleError {
    inner: anyhow::Error,
}

impl FlexibleError {
    /// Get the error message
    pub fn message(&self) -> String {
        self.inner.to_string()
    }

    /// Get the error chain as a vector of strings
    pub fn error_chain(&self) -> Vec<String> {
        self.inner.chain().map(|e| e.to_string()).collect()
    }

    /// Check if this error was caused by a specific error type
    pub fn is_caused_by(&self, error_type: &str) -> bool {
        self.inner.to_string().contains(error_type)
    }
}

impl From<anyhow::Error> for FlexibleError {
    fn from(inner: anyhow::Error) -> Self {
        Self { inner }
    }
}

// UniFFI export for the flexible error interface
#[derive(Debug, uniffi::Object)]
pub struct FlexibleErrorWrapper {
    error: FlexibleError,
}

#[uniffi::export]
impl FlexibleErrorWrapper {
    pub fn message(&self) -> String {
        self.error.message()
    }

    pub fn error_chain(&self) -> Vec<String> {
        self.error.error_chain()
    }

    pub fn is_caused_by(&self, error_type: String) -> bool {
        self.error.is_caused_by(&error_type)
    }
}

impl From<FlexibleError> for FlexibleErrorWrapper {
    fn from(error: FlexibleError) -> Self {
        Self { error }
    }
}

impl std::fmt::Display for FlexibleErrorWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.error)
    }
}

/// Demo functions that use strongly typed errors
#[uniffi::export]
pub fn demo_authenticate(
    username: String,
    password: String,
) -> Result<String, StronglyTypedError> {
    if username.is_empty() {
        return Err(StronglyTypedError::InvalidInput {
            message: "Username cannot be empty".to_string(),
        });
    }

    if password.len() < 8 {
        return Err(StronglyTypedError::InvalidInput {
            message: "Password must be at least 8 characters".to_string(),
        });
    }

    if username == "admin" && password == "wrongpassword" {
        return Err(StronglyTypedError::AuthenticationFailed { code: 401 });
    }

    if username == "slowuser" {
        return Err(StronglyTypedError::NetworkTimeout { seconds: 30 });
    }

    Ok(format!("Welcome, {}!", username))
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

/// Demo function that uses flexible errors with real anyhow patterns
#[uniffi::export]
pub fn demo_flexible_operation(
    input: String,
) -> Result<String, Arc<FlexibleErrorWrapper>> {
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

    match result {
        Ok(success) => Ok(success),
        Err(err) => Err(Arc::new(FlexibleError::from(err).into())),
    }
}

/// Demo function that shows mixing both error types
#[uniffi::export]
pub fn demo_mixed_errors(operation: String) -> Result<String, StronglyTypedError> {
    match operation.as_str() {
        "simple" => Ok("Simple operation completed".to_string()),
        "auth" => Err(StronglyTypedError::AuthenticationFailed { code: 403 }),
        "timeout" => Err(StronglyTypedError::NetworkTimeout { seconds: 60 }),
        _ => Err(StronglyTypedError::InvalidInput {
            message: format!("Unknown operation: {}", operation),
        }),
    }
}
