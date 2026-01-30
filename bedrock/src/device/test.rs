use std::collections::HashMap;
use std::sync::Mutex;

use super::*;

/// In-memory implementation of [`DeviceFileSystem`] for testing
#[allow(clippy::module_name_repetitions)]
pub struct TestInMemoryDeviceFileSystem {
    /// Files stored in memory as a HashMap
    pub files: Mutex<HashMap<String, Vec<u8>>>,
    /// Mock user data directory path returned by `get_user_data_directory`
    pub mock_get_user_data_directory: String,
}

impl TestInMemoryDeviceFileSystem {
    /// Creates a new in-memory filesystem for testing
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: Mutex::new(HashMap::new()),
            mock_get_user_data_directory: "/user/test/data_directory".to_string(),
        }
    }
}

impl Default for TestInMemoryDeviceFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl DeviceFileSystem for TestInMemoryDeviceFileSystem {
    fn file_exists(&self, file_path: String) -> bool {
        self.files.lock().unwrap().contains_key(file_path.as_str())
    }

    #[allow(clippy::significant_drop_tightening)]
    fn read_file(&self, file_path: String) -> Result<Vec<u8>, DeviceFileSystemError> {
        let files = self.files.lock().unwrap();
        let bytes = files.get(file_path.as_str());
        bytes.map_or(Err(DeviceFileSystemError::FileDoesNotExitError), |bytes| {
            Ok(bytes.clone())
        })
    }

    fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> Success {
        println!("Writing file to in-memory file system: {file_path:?}");

        if let Ok(contents_string) = String::from_utf8(file_buffer.clone()) {
            println!("Content of the file is: {contents_string:?}");
        }

        self.files.lock().unwrap().insert(file_path, file_buffer);
        true
    }

    fn get_user_data_directory(&self) -> String {
        self.mock_get_user_data_directory.clone()
    }

    fn list_files(&self, folder_path: String) -> Vec<String> {
        let mut files: Vec<String> = self
            .files
            .lock()
            .unwrap()
            .keys()
            .filter(|key| key.starts_with(&folder_path))
            .map(|key| {
                key.trim_start_matches(&format!("{folder_path}/"))
                    .to_string()
            })
            .collect();
        files.sort();
        files
    }

    fn delete_file(&self, file_path: String) -> Success {
        self.files.lock().unwrap().remove(&file_path);
        true
    }
}

////////////////////////////////////////////////////////////////////////////////
// KeyValueStore
////////////////////////////////////////////////////////////////////////////////

/// In-memory implementation of [`DeviceKeyValueStore`] for testing
pub struct InMemoryDeviceKeyValueStore {
    store: Mutex<HashMap<String, String>>,
}

impl InMemoryDeviceKeyValueStore {
    /// Creates a new in-memory key-value store for testing
    #[must_use]
    pub fn new() -> Self {
        Self {
            store: Mutex::new(HashMap::new()),
        }
    }
}

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
