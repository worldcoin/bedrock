use crate::primitives::filesystem::FileSystemError;
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

/// Filesystem test module to avoid Context import conflicts
pub mod filesystem_tests {
    /// Test error enum to verify `FileSystemError` is automatically included
    #[crate::bedrock_error]
    pub enum FileSystemTestError {
        /// Custom test error
        #[error("test error: {message}")]
        TestError {
            /// The error message
            message: String,
        },
    }
}

pub use filesystem_tests::FileSystemTestError;

impl Default for ToolingDemo {
    fn default() -> Self {
        Self::new()
    }
}

/// Demonstrates automatic logging context injection with `bedrock_export`.
/// All public methods will automatically have [Bedrock][ToolingDemo] prefix in logs.
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

    /// Demo: Async operation that showcases automatic tokio runtime configuration
    ///
    /// This async method demonstrates that the `bedrock_export` macro automatically
    /// adds `async_runtime = "tokio"` to the `uniffi::export` attribute when any
    /// async functions are detected in the impl block.
    ///
    /// # Errors
    ///
    /// Returns `DemoError::Generic` if the async operation fails.
    pub async fn demo_async_operation(
        &self,
        delay_ms: u64,
    ) -> Result<String, DemoError> {
        info!("Starting async operation with delay: {}ms", delay_ms);

        // Simulate an async operation with a delay
        tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;

        if delay_ms > 5000 {
            warn!("Async operation failed: timeout exceeded");
            return Err(DemoError::Generic {
                message: "Operation timeout exceeded 5 seconds".to_string(),
            });
        }

        let result = format!("Async operation completed after {delay_ms}ms");
        info!("Async operation successful: {}", result);
        Ok(result)
    }
}

/// Test struct to verify filesystem middleware injection
#[derive(Default, uniffi::Object)]
pub struct FileSystemTester;

#[bedrock_export]
impl FileSystemTester {
    /// Creates a new `FileSystemTester` instance
    #[uniffi::constructor]
    #[must_use]
    pub fn new() -> Self {
        Self
    }

    /// Tests writing a file using the injected filesystem middleware
    ///
    /// # Errors
    /// - `FileSystemTestError` if filesystem operations fail
    pub fn test_write_file(
        &self,
        filename: &str,
        content: &str,
    ) -> Result<(), FileSystemTestError> {
        // _bedrock_fs is automatically injected by the macro
        // `FileSystemError` automatically converts to FileSystemTestError::FileSystem
        Ok(_bedrock_fs.write_file(filename, content.as_bytes().to_vec())?)
    }

    /// Tests reading a file using the injected filesystem middleware
    ///
    /// # Errors
    /// - `FileSystemTestError` if filesystem operations fail
    pub fn test_read_file(
        &self,
        filename: &str,
    ) -> Result<String, FileSystemTestError> {
        // `FileSystemError` from _bedrock_fs automatically converts to FileSystemTestError::FileSystem
        let data = _bedrock_fs.read_file(filename)?;
        String::from_utf8(data).map_err(|_| FileSystemTestError::TestError {
            message: "Invalid UTF-8 data".to_string(),
        })
    }

    /// Tests listing files in the current directory
    ///
    /// # Errors
    /// - `FileSystemError` if filesystem operations fail
    pub fn test_list_files(&self) -> Result<Vec<String>, FileSystemError> {
        _bedrock_fs.list_files(".")
    }

    /// Tests file existence check
    ///
    /// # Errors
    /// - `FileSystemError` if filesystem operations fail
    pub fn test_file_exists(&self, filename: &str) -> Result<bool, FileSystemError> {
        _bedrock_fs.file_exists(filename)
    }

    /// Tests deleting a file
    ///
    /// # Errors
    /// - `FileSystemError` if filesystem operations fail
    pub fn test_delete_file(&self, filename: &str) -> Result<(), FileSystemError> {
        _bedrock_fs.delete_file(filename)
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

    #[tokio::test]
    async fn test_async_demo() {
        let demo = ToolingDemo::new();

        // Test successful async operation
        let result = demo.demo_async_operation(100).await;
        assert!(result.is_ok());
        assert!(result.unwrap().contains("completed after 100ms"));

        // Test timeout error
        let result = demo.demo_async_operation(6000).await;
        assert!(result.is_err());
        if let Err(DemoError::Generic { message }) = result {
            assert!(message.contains("timeout exceeded"));
        } else {
            panic!("Expected Generic error for timeout");
        }
    }

    #[test]
    fn test_in_memory_filesystem_features() {
        use crate::primitives::filesystem::{FileSystem, InMemoryFileSystem};

        // Test creating filesystem with initial files
        let fs = InMemoryFileSystem::with_files(&[
            ("config.json", r#"{"app": "bedrock"}"#),
            ("data/users.txt", "alice\nbob\ncharlie"),
            ("logs/app.log", "Starting application..."),
        ]);

        // Test file count
        assert_eq!(fs.file_count(), 3);

        // Test file exists
        assert!(fs.contains_file("config.json"));
        assert!(fs.contains_file("data/users.txt"));
        assert!(!fs.contains_file("nonexistent.txt"));

        // Test reading file content
        assert_eq!(
            String::from_utf8(fs.read_file("config.json".to_string()).unwrap())
                .unwrap(),
            r#"{"app": "bedrock"}"#
        );

        // Test setting up additional files
        fs.write_file("temp/test.txt".to_string(), b"temporary data".to_vec())
            .unwrap();
        assert_eq!(fs.file_count(), 4);

        // Test directory setup
        fs.setup_directory("cache");
        // Directory markers don't count as files
        assert_eq!(fs.file_count(), 4);

        // Test listing all file paths
        let mut paths = fs.all_file_paths();
        paths.sort();
        assert_eq!(
            paths,
            vec![
                "config.json",
                "data/users.txt",
                "logs/app.log",
                "temp/test.txt"
            ]
        );

        // Test clear functionality
        fs.clear();
        assert_eq!(fs.file_count(), 0);
        assert!(!fs.contains_file("config.json"));
    }

    #[test]
    fn test_calculate_checksum_hex_small_file() {
        use crate::primitives::filesystem::{
            FileSystem, FileSystemExt, InMemoryFileSystem,
        };

        let fs = InMemoryFileSystem::new();
        fs.write_file("greeting.txt".to_string(), b"Hello, World!".to_vec())
            .unwrap();

        let checksum_hex = FileSystemExt::calculate_checksum_hex(&fs, "greeting.txt")
            .expect("checksum should compute successfully");
        let expected = hex::encode(blake3::hash(b"Hello, World!").as_bytes());
        assert_eq!(checksum_hex, expected);
    }

    #[test]
    fn test_calculate_checksum_hex_large_file_streaming() {
        use crate::primitives::filesystem::{
            FileSystem, FileSystemExt, InMemoryFileSystem,
        };

        let fs = InMemoryFileSystem::new();
        // Create a file larger than the 64 KiB streaming chunk size to ensure multiple iterations
        let data = vec![0_u8; 200_000];
        fs.write_file("large.bin".to_string(), data.clone())
            .unwrap();

        let checksum_hex = FileSystemExt::calculate_checksum_hex(&fs, "large.bin")
            .expect("checksum should compute successfully");
        let expected = hex::encode(blake3::hash(&data).as_bytes());
        assert_eq!(checksum_hex, expected);
    }
}
