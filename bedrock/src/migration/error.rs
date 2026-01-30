use thiserror::Error;

use crate::device::KeyValueStoreError;

/// Result type for migration operations
pub type MigrationResult<T> = std::result::Result<T, MigrationError>;

/// Error types for migration operations
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum MigrationError {
    /// Unexpected error with a message
    #[error("unexpected error: {0}")]
    UnexpectedError(String),

    /// Invalid operation error
    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    /// JSON serialization/deserialization error
    #[error(transparent)]
    SerdeJsonError(#[from] serde_json::Error),

    /// Device key-value store error
    #[error(transparent)]
    DeviceKeyValueStoreError(#[from] KeyValueStoreError),
}
