use thiserror::Error;

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
pub enum DeviceFileSystemError {
    #[error("failed to read the file")]
    ReadFileError,
    #[error("tried to read a file that doesn't exist")]
    FileDoesNotExitError,
    #[error("unexpected error in foreign callback: {0}")]
    UnexpectedUniFFICallbackError(String),
}

impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceFileSystemError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(e.reason)
    }
}

pub type Success = bool;

#[allow(clippy::missing_errors_doc)]
#[allow(clippy::module_name_repetitions)]
#[uniffi::export(with_foreign)]
pub trait DeviceFileSystem: Send + Sync {
    fn get_user_data_directory(&self) -> String;

    fn file_exists(&self, file_path: String) -> bool;

    fn read_file(&self, file_path: String) -> Result<Vec<u8>, DeviceFileSystemError>;

    fn list_files(&self, folder_path: String) -> Vec<String>;

    fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> Success;

    fn delete_file(&self, file_path: String) -> Success;
}

/// Safely call into the foreign `DeviceFileSystem.get_user_data_directory` callback.
///
/// Some foreign language implementations (e.g., Kotlin coroutines) may throw exceptions such as
/// `CancellationException` which cannot be represented in the `String` return type and can cause
/// FFI lifting to panic. This helper catches any panic that occurs during the callback invocation
/// and converts it into a `DeviceFileSystemError` so callers can propagate a proper `OxideError`
/// instead of aborting the process.
#[inline]
pub fn try_get_user_data_directory(file_system: &dyn DeviceFileSystem) -> Result<String, DeviceFileSystemError> {
    // Use catch_unwind to guard against panics raised while lifting the foreign return.
    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| file_system.get_user_data_directory())) {
        Ok(path) => Ok(path),
        Err(_) => Err(DeviceFileSystemError::UnexpectedUniFFICallbackError(
            "panic in DeviceFileSystem.get_user_data_directory callback".to_string(),
        )),
    }
}

#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
pub enum KeyValueStoreError {
    #[error("key not found")]
    KeyNotFound,
    #[error("failed to parse value")]
    ParsingFailure,
    #[error("failed to update value")]
    UpdateFailure,
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

#[cfg(test)]
pub mod test;
