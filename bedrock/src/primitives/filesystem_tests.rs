#[cfg(feature = "tooling_tests")]
use crate::primitives::filesystem::FileSystemError;
#[cfg(feature = "tooling_tests")]
use crate::{bedrock_error, bedrock_export};

/// Test error enum to verify FileSystemError is automatically included
#[cfg(feature = "tooling_tests")]
#[bedrock_error]
pub enum FileSystemTestError {
    /// Custom test error
    #[error("test error: {message}")]
    TestError {
        /// The error message
        message: String,
    },
}

/// Test struct to verify filesystem middleware injection
#[cfg(feature = "tooling_tests")]
#[derive(uniffi::Object)]
pub struct FileSystemTester;

#[cfg(feature = "tooling_tests")]
#[bedrock_export]
impl FileSystemTester {
    /// Tests writing a file using the injected filesystem middleware
    ///
    /// # Errors
    /// - `FileSystemTestError` if filesystem operations fail
    pub fn test_write_file(
        &self,
        filename: &str,
        content: &str,
    ) -> Result<bool, FileSystemTestError> {
        // _bedrock_fs is automatically injected by the macro
        // FileSystemError automatically converts to FileSystemTestError::FileSystem
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
        // FileSystemError from _bedrock_fs automatically converts to FileSystemTestError::FileSystem
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

    /// Tests getting the user data directory with prefix
    ///
    /// # Errors
    /// - `FileSystemError` if filesystem operations fail
    pub fn test_get_user_directory(&self) -> Result<String, FileSystemError> {
        _bedrock_fs.get_user_data_directory()
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
    pub fn test_delete_file(&self, filename: &str) -> Result<bool, FileSystemError> {
        _bedrock_fs.delete_file(filename)
    }
}

#[cfg(all(test, feature = "tooling_tests"))]
mod tests {
    use super::*;
    use crate::primitives::filesystem::{set_filesystem, FileSystem};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// Mock filesystem for testing
    struct MockFileSystem {
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl MockFileSystem {
        fn new() -> Self {
            Self {
                files: Arc::new(Mutex::new(HashMap::new())),
            }
        }
    }

    impl FileSystem for MockFileSystem {
        fn get_user_data_directory(&self) -> String {
            "/mock/user/data".to_string()
        }

        fn file_exists(&self, file_path: String) -> bool {
            self.files.lock().unwrap().contains_key(&file_path)
        }

        fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError> {
            println!("MockFS: Reading from path: {file_path}");
            let result = self
                .files
                .lock()
                .unwrap()
                .get(&file_path)
                .cloned()
                .ok_or(FileSystemError::FileDoesNotExist);
            if let Ok(ref data) = result {
                println!("MockFS: Found data of length: {}", data.len());
            }
            result
        }

        fn list_files(&self, folder_path: String) -> Vec<String> {
            self.files
                .lock()
                .unwrap()
                .keys()
                .filter(|k| k.starts_with(&folder_path))
                .cloned()
                .collect()
        }

        fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> bool {
            println!("MockFS: Writing to path: {file_path}");
            self.files.lock().unwrap().insert(file_path, file_buffer);
            true
        }

        fn delete_file(&self, file_path: String) -> bool {
            self.files.lock().unwrap().remove(&file_path).is_some()
        }
    }

    #[test]
    #[ignore = "This test requires exclusive access to the global filesystem"]
    fn test_filesystem_middleware_integration() {
        // Set up the mock filesystem
        set_filesystem(Arc::new(MockFileSystem::new()));

        let tester = FileSystemTester;

        // Test writing a file - should be prefixed with "FileSystemTester"
        let result = tester.test_write_file("test.txt", "Hello, World!");
        assert!(result.is_ok());

        // Test reading the file
        let content = tester.test_read_file("test.txt");
        assert!(content.is_ok());
        assert_eq!(content.unwrap(), "Hello, World!");

        // Test file exists
        let exists = tester.test_file_exists("test.txt");
        assert!(exists.is_ok());
        assert!(exists.unwrap());

        // Test user directory - should include the prefix
        let user_dir = tester.test_get_user_directory();
        assert!(user_dir.is_ok());
        assert_eq!(user_dir.unwrap(), "/mock/user/data/FileSystemTester");

        // Test delete file
        let deleted = tester.test_delete_file("test.txt");
        assert!(deleted.is_ok());
        assert!(deleted.unwrap());

        // Verify file is deleted
        let exists_after_delete = tester.test_file_exists("test.txt");
        assert!(exists_after_delete.is_ok());
        assert!(!exists_after_delete.unwrap());
    }
}
