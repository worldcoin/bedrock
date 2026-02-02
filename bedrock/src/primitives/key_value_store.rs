use thiserror::Error;

/// Errors that can occur when interacting with the device key-value store
#[allow(clippy::module_name_repetitions)]
#[derive(Debug, Error, uniffi::Error)]
pub enum KeyValueStoreError {
    /// The requested key was not found in the store
    #[error("key not found")]
    KeyNotFound,
    /// Failed to parse the value retrieved from the store
    #[error("failed to parse value")]
    ParsingFailure,
    /// Failed to update the value in the store
    #[error("failed to update value")]
    UpdateFailure,
    /// An unexpected error occurred in the foreign callback
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
/// In-memory implementation of `DeviceKeyValueStore` for testing purposes
pub struct InMemoryDeviceKeyValueStore {
    store: std::sync::Mutex<std::collections::HashMap<String, String>>,
}

#[cfg(test)]
impl InMemoryDeviceKeyValueStore {
    /// Creates a new empty in-memory key-value store
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
impl Default for InMemoryDeviceKeyValueStore {
    fn default() -> Self {
        Self {
            store: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

#[cfg(test)]
impl DeviceKeyValueStore for InMemoryDeviceKeyValueStore {
    fn get(&self, key: String) -> Result<String, KeyValueStoreError> {
        let value = self.store.lock().unwrap().get(&key).cloned();
        value.ok_or(KeyValueStoreError::KeyNotFound)
    }

    fn set(&self, key: String, value: String) -> Result<(), KeyValueStoreError> {
        self.store.lock().unwrap().insert(key, value);
        Ok(())
    }

    fn delete(&self, key: String) -> Result<(), KeyValueStoreError> {
        self.store.lock().unwrap().remove(&key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get() {
        let store = InMemoryDeviceKeyValueStore::new();

        store
            .set("test_key".to_string(), "test_value".to_string())
            .unwrap();
        let value = store.get("test_key".to_string()).unwrap();

        assert_eq!(value, "test_value");
    }

    #[test]
    fn test_get_nonexistent_key() {
        let store = InMemoryDeviceKeyValueStore::new();

        let result = store.get("nonexistent".to_string());

        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyValueStoreError::KeyNotFound
        ));
    }

    #[test]
    fn test_delete() {
        let store = InMemoryDeviceKeyValueStore::new();

        store
            .set("test_key".to_string(), "test_value".to_string())
            .unwrap();
        store.delete("test_key".to_string()).unwrap();

        let result = store.get("test_key".to_string());
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            KeyValueStoreError::KeyNotFound
        ));
    }

    #[test]
    fn test_overwrite_value() {
        let store = InMemoryDeviceKeyValueStore::new();

        store
            .set("test_key".to_string(), "value1".to_string())
            .unwrap();
        store
            .set("test_key".to_string(), "value2".to_string())
            .unwrap();

        let value = store.get("test_key".to_string()).unwrap();
        assert_eq!(value, "value2");
    }
}
