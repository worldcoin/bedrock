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
    #[error("failed to list files: {0}")]
    ListFilesError(String),
    /// Filesystem not initialized
    #[error("filesystem not initialized")]
    NotInitialized,
    /// Unexpected UniFFI callback error
    #[error("unexpected uniffi callback error: {0}")]
    UnexpectedUniFFICallbackError(String),
}

/// Converts unexpected UniFFI callback errors to `FileSystemError`.
///
/// This implementation is required for foreign trait support. When native apps
/// (Swift/Kotlin) implement `FileSystem` and encounter unexpected
/// errors (panics, unhandled exceptions), UniFFI converts them to this error type
/// instead of causing Rust to panic.
///
/// The error reason from the foreign implementation is preserved in the
/// `UnexpectedUniFFICallbackError` variant for debugging purposes.
///
/// Without this implementation, unexpected foreign errors would panic the Rust code.
impl From<uniffi::UnexpectedUniFFICallbackError> for FileSystemError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        Self::UnexpectedUniFFICallbackError(error.reason)
    }
}

/// **This is intended exclusively for testing.**
#[derive(Debug)]
pub struct InMemoryFileSystem {
    files: std::sync::Arc<std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>>,
}

#[allow(clippy::missing_panics_doc)]
impl InMemoryFileSystem {
    /// Creates a new empty in-memory filesystem
    #[must_use]
    pub fn new() -> Self {
        Self {
            files: Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// Creates a new in-memory filesystem with some initial files for testing
    ///
    /// # Arguments
    /// * `initial_files` - A slice of tuples containing (path, content) pairs
    ///
    /// # Examples
    /// ```rust
    /// use bedrock::primitives::filesystem::InMemoryFileSystem;
    ///
    /// let fs = InMemoryFileSystem::with_files(&[
    ///     ("config.json", r#"{"test": true}"#),
    ///     ("data/users.txt", "alice\nbob\ncharlie"),
    /// ]);
    /// ```
    #[must_use]
    pub fn with_files(initial_files: &[(&str, &str)]) -> Self {
        let fs = Self::new();
        for (path, content) in initial_files {
            fs.setup_file(path, content);
        }
        fs
    }

    /// Sets up a file in the filesystem for testing
    ///
    /// This is a convenience method for test setup that doesn't return errors.
    /// Use this to prepare test data before running tests.
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `content` - The file content as a string
    pub fn setup_file(&self, path: &str, content: &str) {
        let normalized_path = Self::normalize_path(path);
        self.files
            .lock()
            .unwrap()
            .insert(normalized_path, content.as_bytes().to_vec());
    }

    /// Sets up a file in the filesystem with binary data
    ///
    /// # Arguments
    /// * `path` - The file path
    /// * `data` - The file content as bytes
    pub fn setup_file_bytes(&self, path: &str, data: &[u8]) {
        let normalized_path = Self::normalize_path(path);
        self.files
            .lock()
            .unwrap()
            .insert(normalized_path, data.to_vec());
    }

    /// Creates a directory in the filesystem
    ///
    /// In the in-memory filesystem, directories are represented by ensuring
    /// that the directory path exists in our internal tracking.
    ///
    /// # Arguments
    /// * `path` - The directory path
    pub fn setup_directory(&self, path: &str) {
        let normalized_path = Self::normalize_path(path);
        let dir_path = if normalized_path.ends_with('/') {
            normalized_path
        } else {
            format!("{normalized_path}/")
        };

        // Create a marker for the directory
        self.files
            .lock()
            .unwrap()
            .insert(format!("{dir_path}__DIR__"), Vec::new());
    }

    /// Clears all files from the filesystem
    pub fn clear(&self) {
        self.files.lock().unwrap().clear();
    }

    /// Returns the number of files in the filesystem
    #[must_use]
    pub fn file_count(&self) -> usize {
        self.files
            .lock()
            .unwrap()
            .keys()
            .filter(|k| !k.ends_with("__DIR__"))
            .count()
    }

    /// Returns all file paths currently in the filesystem
    #[must_use]
    pub fn all_file_paths(&self) -> Vec<String> {
        self.files
            .lock()
            .unwrap()
            .keys()
            .filter(|k| !k.ends_with("__DIR__"))
            .cloned()
            .collect()
    }

    /// Checks if the filesystem contains a specific file
    #[must_use]
    pub fn contains_file(&self, path: &str) -> bool {
        let normalized_path = Self::normalize_path(path);
        self.files.lock().unwrap().contains_key(&normalized_path)
    }

    /// Gets the content of a file as a string (for testing convenience)
    ///
    /// # Errors
    /// Returns `FileSystemError::FileDoesNotExist` if the file doesn't exist
    pub fn get_file_content(&self, path: &str) -> Result<String, FileSystemError> {
        let data = self.read_file(path.to_string())?;
        String::from_utf8(data).map_err(|_| FileSystemError::ReadFileError)
    }

    /// Normalizes a file path by removing leading slashes and ensuring consistency
    fn normalize_path(path: &str) -> String {
        path.trim_start_matches('/').to_string()
    }

    /// Checks if a path represents a directory
    #[allow(dead_code)]
    fn is_directory(&self, path: &str) -> bool {
        let normalized_path = Self::normalize_path(path);
        let dir_marker = if normalized_path.ends_with('/') {
            format!("{normalized_path}__DIR__")
        } else {
            format!("{normalized_path}/__DIR__")
        };

        self.files.lock().unwrap().contains_key(&dir_marker)
    }
}

impl Default for InMemoryFileSystem {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for InMemoryFileSystem {
    fn clone(&self) -> Self {
        let files = self.files.lock().unwrap().clone();
        Self {
            files: Arc::new(std::sync::Mutex::new(files)),
        }
    }
}

impl FileSystem for InMemoryFileSystem {
    fn file_exists(&self, file_path: String) -> Result<bool, FileSystemError> {
        let normalized_path = Self::normalize_path(&file_path);
        Ok(self.files.lock().unwrap().contains_key(&normalized_path))
    }

    fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError> {
        let normalized_path = Self::normalize_path(&file_path);
        self.files
            .lock()
            .unwrap()
            .get(&normalized_path)
            .cloned()
            .ok_or(FileSystemError::FileDoesNotExist)
    }

    fn list_files(&self, folder_path: String) -> Result<Vec<String>, FileSystemError> {
        let normalized_folder = Self::normalize_path(&folder_path);
        let folder_prefix = if normalized_folder.is_empty() {
            String::new()
        } else if normalized_folder.ends_with('/') {
            normalized_folder
        } else {
            format!("{normalized_folder}/")
        };

        let files: Vec<String> = self
            .files
            .lock()
            .unwrap()
            .keys()
            .filter(|path| {
                // Exclude directory markers
                !path.ends_with("__DIR__") &&
                // Include files in the specified folder
                (folder_prefix.is_empty() || path.starts_with(&folder_prefix))
            })
            .cloned()
            .collect();

        Ok(files)
    }

    fn write_file(
        &self,
        file_path: String,
        file_buffer: Vec<u8>,
    ) -> Result<bool, FileSystemError> {
        let normalized_path = Self::normalize_path(&file_path);
        self.files
            .lock()
            .unwrap()
            .insert(normalized_path, file_buffer);
        Ok(true)
    }

    fn delete_file(&self, file_path: String) -> Result<bool, FileSystemError> {
        let normalized_path = Self::normalize_path(&file_path);
        Ok(self
            .files
            .lock()
            .unwrap()
            .remove(&normalized_path)
            .is_some())
    }
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
///     func fileExists(filePath: String) throws -> Bool {
///         // Check if file exists, throw if error
///     }
///     
///     func readFile(filePath: String) throws -> Data {
///         // Read file contents
///     }
///     
///     func writeFile(filePath: String, fileBuffer: Data) throws -> Bool {
///         // Write file contents, throw if error
///     }
///     
///     func deleteFile(filePath: String) throws -> Bool {
///         // Delete file, throw if error
///     }
///     
///     func listFiles(folderPath: String) throws -> [String] {
///         // List files in directory, throw if error
///     }
/// }
///
/// // In app delegate
/// setupBedrockFileSystem() // Call this only once!!!
/// ```
#[uniffi::export(with_foreign)]
pub trait FileSystem: Send + Sync {
    /// Check if a file exists at the given path
    ///
    /// # Errors
    /// - `FileSystemError` if the operation fails
    fn file_exists(&self, file_path: String) -> Result<bool, FileSystemError>;

    /// Read file contents
    ///
    /// # Errors
    /// - `FileSystemError::ReadFileError` if the file cannot be read
    /// - `FileSystemError::FileDoesNotExist` if the file doesn't exist
    fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError>;

    /// List files in a directory
    ///
    /// # Errors
    /// - `FileSystemError::ListFilesError` if the directory cannot be listed
    fn list_files(&self, folder_path: String) -> Result<Vec<String>, FileSystemError>;

    /// Write file contents
    ///
    /// # Errors
    /// - `FileSystemError::WriteFileError` if the file cannot be written
    fn write_file(
        &self,
        file_path: String,
        file_buffer: Vec<u8>,
    ) -> Result<bool, FileSystemError>;

    /// Delete a file
    ///
    /// # Errors
    /// - `FileSystemError::DeleteFileError` if the file cannot be deleted
    fn delete_file(&self, file_path: String) -> Result<bool, FileSystemError>;
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
/// # ⚠️ WARNING
/// This function bypasses the `FileSystemMiddleware` and should only be used internally
/// by the middleware itself. Direct usage skips important path prefixing and scoping.
///
/// For normal filesystem operations, use `FileSystemMiddleware` created via `create_middleware()`.
///
/// # Errors
/// - `FileSystemError::NotInitialized` if the filesystem has not been initialized via `set_filesystem`
pub(crate) fn get_filesystem_raw(
) -> Result<&'static Arc<dyn FileSystem>, FileSystemError> {
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

    /// Check if a file exists at the given path (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn file_exists(&self, file_path: &str) -> Result<bool, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        fs.file_exists(prefixed_path)
    }

    /// Read file contents (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn read_file(&self, file_path: &str) -> Result<Vec<u8>, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        fs.read_file(prefixed_path)
    }

    /// List files in a directory (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn list_files(
        &self,
        folder_path: &str,
    ) -> Result<Vec<String>, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(folder_path);
        fs.list_files(prefixed_path)
    }

    /// Write file contents (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn write_file(
        &self,
        file_path: &str,
        file_buffer: Vec<u8>,
    ) -> Result<bool, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        fs.write_file(prefixed_path, file_buffer)
    }

    /// Delete a file (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn delete_file(&self, file_path: &str) -> Result<bool, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        fs.delete_file(prefixed_path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_filesystem_middleware_prefixing() {
        // Set up in-memory filesystem
        let _ = FILESYSTEM_INSTANCE.set(Arc::new(InMemoryFileSystem::new()));

        let middleware = FileSystemMiddleware::new("TestModule");

        // Test that paths are properly prefixed
        assert_eq!(middleware.prefix_path("file.txt"), "TestModule/file.txt");
        assert_eq!(middleware.prefix_path("/file.txt"), "TestModule/file.txt");
        assert_eq!(
            middleware.prefix_path("TestModule/file.txt"),
            "TestModule/file.txt"
        );
    }
}
