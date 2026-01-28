/// Errors that can occur during migration operations
#[crate::bedrock_error]
pub enum MigrationError {
    /// An invalid operation was attempted
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    /// Key-value store operation failed
    #[error(transparent)]
    KeyValueStore(#[from] crate::device::KeyValueStoreError),

    /// JSON serialization/deserialization failed
    #[error("JSON error: {message}")]
    JsonError {
        /// The error message from serde_json
        message: String,
    },
}

impl From<serde_json::Error> for MigrationError {
    fn from(e: serde_json::Error) -> Self {
        Self::JsonError {
            message: e.to_string(),
        }
    }
}

/// Result type for migration operations
pub type MigrationResult<T> = std::result::Result<T, MigrationError>;
