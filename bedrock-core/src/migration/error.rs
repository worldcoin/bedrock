use bedrock_macros::bedrock_error;

use crate::primitives::key_value_store::KeyValueStoreError;

/// Error types for migration operations
#[allow(clippy::module_name_repetitions)]
#[bedrock_error]
pub enum MigrationError {
    /// Invalid operation error
    #[error("invalid operation: {0}")]
    InvalidOperation(String),

    /// JSON serialization/deserialization error
    #[error("serde_json_error: {0}")]
    SerdeJsonError(String),

    /// Device key-value store error
    #[error(transparent)]
    DeviceKeyValueStoreError(#[from] KeyValueStoreError),

    /// Unexpected UniFFI callback error
    #[error("unexpected error in foreign callback: {0}")]
    UnexpectedUniFFICallbackError(String),
}

impl From<serde_json::Error> for MigrationError {
    fn from(error: serde_json::Error) -> Self {
        Self::SerdeJsonError(error.to_string())
    }
}

/// Converts unexpected UniFFI callback errors to `FileSystemError`.
///
/// This implementation is required for foreign trait support.
///
/// Without this implementation, unexpected foreign errors would panic the Rust code.
impl From<uniffi::UnexpectedUniFFICallbackError> for MigrationError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(error.reason)
    }
}
