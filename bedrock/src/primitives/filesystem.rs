use std::sync::{Arc, OnceLock};
use thiserror::Error;

/// Errors that can occur during filesystem operations
#[derive(Debug, Error, uniffi::Error)]
pub enum FileSystemError {
    /// Failed to read the file
    #[error("failed to read the file")]
    ReadFileError,
    /// Tried to read a file that doesn't exist
    #[error("tried to read a file that doesn't exist")]
    FileDoesNotExist,
    /// Failed to write file
    #[error("failed to write file")]
    WriteFileError,
    /// Failed to delete file
    #[error("failed to delete file")]
    DeleteFileError,
    /// Failed to list files
    #[error("failed to list files")]
    ListFilesError,
    /// Filesystem not initialized
    #[error("filesystem not initialized")]
    NotInitialized,
}

/// Trait representing a filesystem that can be implemented by the native side
///
/// This trait should be implemented by the platform-specific filesystem handler.
/// It is exported via `UniFFI` for use in foreign languages.
///
/// # Examples
///
/// ## Swift
/// ```swift
/// class BedrockFileSystemBridge: Bedrock.FileSystem {
///     static let shared = BedrockFileSystemBridge()
///     
///     func getUserDataDirectory() -> String {
///         // Return platform-specific user data directory
///     }
///     
///     func fileExists(filePath: String) -> Bool {
///         // Check if file exists
///     }
///     
///     func readFile(filePath: String) throws -> Data {
///         // Read file contents
///     }
///     
///     func writeFile(filePath: String, fileBuffer: Data) -> Bool {
///         // Write file contents
///     }
///     
///     func deleteFile(filePath: String) -> Bool {
///         // Delete file
///     }
///     
///     func listFiles(folderPath: String) -> [String] {
///         // List files in directory
///     }
/// }
///
/// // In app delegate
/// setupBedrockFileSystem() // Call this only once!!!
/// ```
#[uniffi::export(with_foreign)]
pub trait FileSystem: Send + Sync {
    /// Get the user data directory path
    fn get_user_data_directory(&self) -> String;

    /// Check if a file exists at the given path
    fn file_exists(&self, file_path: String) -> bool;

    /// Read file contents
    ///
    /// # Errors
    /// - `FileSystemError::ReadFileError` if the file cannot be read
    /// - `FileSystemError::FileDoesNotExist` if the file doesn't exist
    fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError>;

    /// List files in a directory
    fn list_files(&self, folder_path: String) -> Vec<String>;

    /// Write file contents
    fn write_file(&self, file_path: String, file_buffer: Vec<u8>) -> bool;

    /// Delete a file
    fn delete_file(&self, file_path: String) -> bool;
}

/// A global instance of the user-provided filesystem
static FILESYSTEM_INSTANCE: OnceLock<Arc<dyn FileSystem>> = OnceLock::new();

/// Sets the global filesystem instance
///
/// This function allows you to provide your own implementation of the `FileSystem` trait.
/// It should be called once during application initialization.
///
/// # Arguments
///
/// * `filesystem` - An `Arc` containing your filesystem implementation.
///
/// # Note
///
/// If the filesystem has already been set, this function will print a message and do nothing.
#[uniffi::export]
pub fn set_filesystem(filesystem: Arc<dyn FileSystem>) {
    match FILESYSTEM_INSTANCE.set(filesystem) {
        Ok(()) => (),
        Err(_) => println!("FileSystem already set"),
    }
}

/// Gets a reference to the global filesystem instance
///
/// # Errors
/// - `FileSystemError::NotInitialized` if the filesystem has not been initialized via `set_filesystem`
pub(crate) fn get_filesystem() -> Result<&'static Arc<dyn FileSystem>, FileSystemError>
{
    FILESYSTEM_INSTANCE
        .get()
        .ok_or(FileSystemError::NotInitialized)
}

/// Middleware wrapper that enforces path prefixing for filesystem operations
///
/// This struct is created by the `bedrock_export` macro and ensures all filesystem
/// operations are scoped to a specific prefix (typically the struct name).
pub struct FileSystemMiddleware {
    prefix: String,
}

/// Creates a filesystem middleware for a given struct name
/// This is used internally by the `bedrock_export` macro
#[must_use]
pub fn create_middleware(struct_name: &str) -> FileSystemMiddleware {
    FileSystemMiddleware::new(struct_name)
}

impl FileSystemMiddleware {
    /// Creates a new filesystem middleware with the given prefix
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }

    /// Prefixes a path with the middleware's prefix
    fn prefix_path(&self, path: &str) -> String {
        if path.starts_with(&self.prefix) {
            path.to_string()
        } else {
            format!("{}/{}", self.prefix, path.trim_start_matches('/'))
        }
    }

    /// Get the user data directory with the prefix
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    pub fn get_user_data_directory(&self) -> Result<String, FileSystemError> {
        let fs = get_filesystem()?;
        let base_dir = fs.get_user_data_directory();
        Ok(format!("{}/{}", base_dir, self.prefix))
    }

    /// Check if a file exists at the given path (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    pub fn file_exists(&self, file_path: &str) -> Result<bool, FileSystemError> {
        let fs = get_filesystem()?;
        let prefixed_path = self.prefix_path(file_path);
        Ok(fs.file_exists(prefixed_path))
    }

    /// Read file contents (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn read_file(&self, file_path: &str) -> Result<Vec<u8>, FileSystemError> {
        let fs = get_filesystem()?;
        let prefixed_path = self.prefix_path(file_path);
        fs.read_file(prefixed_path)
    }

    /// List files in a directory (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    pub fn list_files(
        &self,
        folder_path: &str,
    ) -> Result<Vec<String>, FileSystemError> {
        let fs = get_filesystem()?;
        let prefixed_path = self.prefix_path(folder_path);
        Ok(fs.list_files(prefixed_path))
    }

    /// Write file contents (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    pub fn write_file(
        &self,
        file_path: &str,
        file_buffer: Vec<u8>,
    ) -> Result<bool, FileSystemError> {
        let fs = get_filesystem()?;
        let prefixed_path = self.prefix_path(file_path);
        Ok(fs.write_file(prefixed_path, file_buffer))
    }

    /// Delete a file (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    pub fn delete_file(&self, file_path: &str) -> Result<bool, FileSystemError> {
        let fs = get_filesystem()?;
        let prefixed_path = self.prefix_path(file_path);
        Ok(fs.delete_file(prefixed_path))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockFileSystem;

    impl FileSystem for MockFileSystem {
        fn get_user_data_directory(&self) -> String {
            "/mock/user/data".to_string()
        }

        fn file_exists(&self, _file_path: String) -> bool {
            true
        }

        fn read_file(&self, _file_path: String) -> Result<Vec<u8>, FileSystemError> {
            Ok(b"mock content".to_vec())
        }

        fn list_files(&self, _folder_path: String) -> Vec<String> {
            vec!["file1.txt".to_string(), "file2.txt".to_string()]
        }

        fn write_file(&self, _file_path: String, _file_buffer: Vec<u8>) -> bool {
            true
        }

        fn delete_file(&self, _file_path: String) -> bool {
            true
        }
    }

    #[test]
    fn test_filesystem_middleware_prefixing() {
        // Set up mock filesystem
        let _ = FILESYSTEM_INSTANCE.set(Arc::new(MockFileSystem));

        let middleware = FileSystemMiddleware::new("TestModule");

        // Test that paths are properly prefixed
        assert_eq!(middleware.prefix_path("file.txt"), "TestModule/file.txt");
        assert_eq!(middleware.prefix_path("/file.txt"), "TestModule/file.txt");
        assert_eq!(
            middleware.prefix_path("TestModule/file.txt"),
            "TestModule/file.txt"
        );

        // Test get_user_data_directory includes prefix
        let user_dir = middleware.get_user_data_directory().unwrap();
        assert_eq!(user_dir, "/mock/user/data/TestModule");
    }
}
