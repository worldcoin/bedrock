//! Device abstractions for filesystem and key-value storage
//!
//! This module provides traits for interacting with device-level storage,
//! implemented by native platform code (Swift/Kotlin).

use thiserror::Error;

/// Errors that can occur during device filesystem operations
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
pub enum DeviceFileSystemError {
    /// Failed to read the file
    #[error("failed to read the file")]
    ReadFileError,
    /// Tried to read a file that doesn't exist
    #[error("tried to read a file that doesn't exist")]
    FileDoesNotExitError,
    /// Unexpected error in foreign callback
    #[error("unexpected error in foreign callback: {0}")]
    UnexpectedUniFFICallbackError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceFileSystemError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(e.reason)
    }
}

/// Boolean success indicator for filesystem operations
pub type Success = bool;

/// Trait for device filesystem operations
///
/// This trait is implemented by native platform code (Swift/Kotlin) to provide
/// filesystem access. All file paths are relative to the user data directory.
#[allow(clippy::missing_errors_doc)]
#[allow(clippy::module_name_repetitions)]
#[uniffi::export(with_foreign)]
pub trait DeviceFileSystem: Send + Sync {
    /// Returns the user data directory path
    fn get_user_data_directory(&self) -> String;

    /// Checks if a file exists at the given path
    fn file_exists(&self, file_path: String) -> bool;

    /// Reads a file from the given path
    fn read_file(&self, file_path: String) -> Result<Vec<u8>, DeviceFileSystemError>;

    /// Lists all files in a folder
    fn list_files(&self, folder_path: String) -> Vec<String>;

    /// Writes a file to the given path
    fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> Success;

    /// Deletes a file at the given path
    fn delete_file(&self, file_path: String) -> Success;
}

/// Safely call into the foreign `DeviceFileSystem.get_user_data_directory` callback.
///
/// Some foreign language implementations (e.g., Kotlin coroutines) may throw exceptions such as
/// `CancellationException` which cannot be represented in the `String` return type and can cause
/// FFI lifting to panic. This helper catches any panic that occurs during the callback invocation
/// and converts it into a `DeviceFileSystemError` so callers can propagate a proper error
/// instead of aborting the process.
///
/// # Errors
/// Returns `DeviceFileSystemError::UnexpectedUniFFICallbackError` if the callback panics.
#[inline]
pub fn try_get_user_data_directory(
    file_system: &dyn DeviceFileSystem,
) -> Result<String, DeviceFileSystemError> {
    // Use catch_unwind to guard against panics raised while lifting the foreign return.
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        file_system.get_user_data_directory()
    }))
    .map_or_else(
        |_| {
            Err(DeviceFileSystemError::UnexpectedUniFFICallbackError(
                "panic in DeviceFileSystem.get_user_data_directory callback"
                    .to_string(),
            ))
        },
        Ok,
    )
}

/// Errors that can occur during key-value store operations
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
pub enum KeyValueStoreError {
    /// The requested key was not found in the store
    #[error("key not found")]
    KeyNotFound,
    /// Failed to parse the stored value
    #[error("failed to parse value")]
    ParsingFailure,
    /// Failed to update the value in the store
    #[error("failed to update value")]
    UpdateFailure,
    /// Unexpected error in foreign callback
    #[error("unexpected error in foreign callback: {0}")]
    UnexpectedUniFFICallbackError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for KeyValueStoreError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(e.reason)
    }
}

/// A trait which is implemented by native World App to provide a key-value cache that is persisted in the device.
///
/// The key-value store can be used to cache data which is not sensitive. Android uses `SharedPreferences`
/// to store the data and iOS uses `UserDefaults`.
///
/// This is explicitly **not a secure store!** Do not store anything sensitive here. Furthermore, there are no integrity guarantees.
/// The cache may be tampered with, corrupted or otherwise modified at any time.
///
/// Only string storage is supported because Android's `SharedPreferences` doesn't support raw bytes to allow us more customization.
/// JSON may be used to serialize more complex data.
///
/// The native implementation will always prefix all keys with `oxide/` to avoid collisions with other values. This is invisible to Oxide.
#[uniffi::export(with_foreign)]
pub trait DeviceKeyValueStore: Send + Sync {
    /// Get a value from the key-value store
    ///
    /// # Errors
    /// - `KeyValueStoreError::KeyNotFound` if the key is not found
    /// - `KeyValueStoreError::ParsingFailure` if something goes wrong while parsing the value
    fn get(&self, key: String) -> Result<String, KeyValueStoreError>;

    /// Set a value in the key-value store
    ///
    /// # Errors
    /// - `KeyValueStoreError::UpdateFailure` if something goes wrong while updating the value
    fn set(&self, key: String, value: String) -> Result<(), KeyValueStoreError>;

    /// Delete a value from the key-value store
    ///
    /// # Errors
    /// - `KeyValueStoreError::KeyNotFound` if the key is not found
    /// - `KeyValueStoreError::UpdateFailure` if something goes wrong while updating the value
    fn delete(&self, key: String) -> Result<(), KeyValueStoreError>;
}

/// Test utilities for device abstractions
#[cfg(test)]
pub mod test;
