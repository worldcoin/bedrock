use std::sync::{Arc, OnceLock};
use thiserror::Error;

/// Errors that can occur during filesystem operations
#[derive(Debug, Error, uniffi::Error)]
pub enum FileSystemError {
    /// Tried to read a file that doesn't exist
    #[error("requested file does not exist")]
    FileDoesNotExist,
    /// Something went wrong with the filesystem operation
    #[error("IO failure: {0}")]
    IoFailure(String),
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

/// Trait representing a filesystem that can be implemented by the native side
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
    /// - `FileSystemError::IoFailure` if the file cannot be read
    /// - `FileSystemError::FileDoesNotExist` if the file doesn't exist
    fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError>;

    /// List files in a specific directory. No recursion and no subdirectories are returned.
    ///
    /// # Notes
    /// Files are returned without the directory path. Only the file name is returned.
    ///
    /// # Errors
    /// - `FileSystemError::IoFailure` if the directory cannot be listed
    fn list_files_at_directory(
        &self,
        folder_path: String,
    ) -> Result<Vec<String>, FileSystemError>;

    /// Read a specific byte range from a file
    ///
    /// Returns up to `max_length` bytes starting at `offset`. Returns an empty vector
    /// when `offset` is at or beyond the end of the file.
    ///
    /// # Errors
    /// - `FileSystemError::IoFailure` if the file cannot be read
    /// - `FileSystemError::FileDoesNotExist` if the file doesn't exist
    fn read_file_range(
        &self,
        file_path: String,
        offset: u64,
        max_length: u64,
    ) -> Result<Vec<u8>, FileSystemError>;

    /// Write file contents
    ///
    /// # Errors
    /// - `FileSystemError::IoFailure` if the file cannot be written, with details about the failure
    fn write_file(
        &self,
        file_path: String,
        file_buffer: Vec<u8>,
    ) -> Result<(), FileSystemError>;

    /// Delete a file
    ///
    /// # Errors
    /// - `FileSystemError::FileDoesNotExist` if the file does not exist
    /// - `FileSystemError::IoFailure` if the file cannot be deleted
    fn delete_file(&self, file_path: String) -> Result<(), FileSystemError>;
}

/// Extension helpers for `FileSystem`.
///
/// These are provided as default methods implemented for all `FileSystem`s.
pub trait FileSystemExt {
    /// Calculates the `blake3` checksum of the file at the given path.
    ///
    /// Implementations should avoid loading the entire file into memory where possible.
    /// Uses `read_file_range` in a loop to stream the file.
    ///
    /// # Errors
    /// - `FileSystemError::FileDoesNotExist` if the path does not exist
    /// - `FileSystemError::IoFailure` for unexpected underlying IO/read errors
    fn calculate_checksum_and_size(
        &self,
        file_path: &str,
    ) -> Result<([u8; 32], u64), FileSystemError>;
}

impl<T> FileSystemExt for T
where
    T: FileSystem + ?Sized,
{
    fn calculate_checksum_and_size(
        &self,
        file_path: &str,
    ) -> Result<([u8; 32], u64), FileSystemError> {
        let mut hasher = blake3::Hasher::new();
        let mut offset: u64 = 0;
        let chunk_size: u64 = 65_536; // 64 KiB (64 * 1024)
        loop {
            let chunk =
                self.read_file_range(file_path.to_string(), offset, chunk_size)?;
            if chunk.is_empty() {
                break;
            }
            hasher.update(&chunk);

            debug_assert!(
                u64::try_from(chunk.len()).is_ok(),
                "chunk.len() cannot overflow because chunk_size is set"
            );
            offset = offset.saturating_add(chunk.len() as u64);
        }
        Ok((hasher.finalize().into(), offset))
    }
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

/// Safely invoke a filesystem callback, catching any panics from UniFFI lifting.
///
/// When foreign implementations (Kotlin/Swift) throw exceptions during callbacks,
/// UniFFI may panic while lifting the return value. This helper catches those panics
/// and converts them to proper errors.
///
/// This is particularly important when Kotlin coroutines are cancelled mid-callback,
/// as the `CancellationException` cannot be properly represented in the return type
/// and causes UniFFI to panic during `RustBuffer` destruction.
fn catch_callback_panic<T, F>(operation: &str, f: F) -> Result<T, FileSystemError>
where
    F: FnOnce() -> Result<T, FileSystemError> + std::panic::UnwindSafe,
{
    std::panic::catch_unwind(f).map_or_else(
        |_| {
            Err(FileSystemError::UnexpectedUniFFICallbackError(format!(
                "panic in FileSystem.{} callback",
                operation
            )))
        },
        |result| result,
    )
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
        catch_callback_panic(
            "file_exists",
            std::panic::AssertUnwindSafe(|| fs.file_exists(prefixed_path)),
        )
    }

    /// Read file contents (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn read_file(&self, file_path: &str) -> Result<Vec<u8>, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        catch_callback_panic(
            "read_file",
            std::panic::AssertUnwindSafe(|| fs.read_file(prefixed_path)),
        )
    }

    /// Read a specific byte range from a file (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn read_file_range(
        &self,
        file_path: &str,
        offset: u64,
        max_length: u64,
    ) -> Result<Vec<u8>, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        catch_callback_panic(
            "read_file_range",
            std::panic::AssertUnwindSafe(|| {
                fs.read_file_range(prefixed_path, offset, max_length)
            }),
        )
    }

    /// List files in a directory (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - Any error from the underlying filesystem implementation
    pub fn list_files_at_directory(
        &self,
        folder_path: &str,
    ) -> Result<Vec<String>, FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(folder_path);
        catch_callback_panic(
            "list_files_at_directory",
            std::panic::AssertUnwindSafe(|| fs.list_files_at_directory(prefixed_path)),
        )
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
    ) -> Result<(), FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        catch_callback_panic(
            "write_file",
            std::panic::AssertUnwindSafe(|| fs.write_file(prefixed_path, file_buffer)),
        )
    }

    /// Delete a file (with prefix)
    ///
    /// # Errors
    /// - `FileSystemError::NotInitialized` if the filesystem has not been initialized
    /// - `FileSystemError::FileDoesNotExist` if the file does not exist
    /// - Any other error from the underlying filesystem implementation
    pub fn delete_file(&self, file_path: &str) -> Result<(), FileSystemError> {
        let fs = get_filesystem_raw()?;
        let prefixed_path = self.prefix_path(file_path);
        catch_callback_panic(
            "delete_file",
            std::panic::AssertUnwindSafe(|| fs.delete_file(prefixed_path)),
        )
    }
}

// Re-export InMemoryFileSystem for tests
#[cfg(test)]
pub use tests::InMemoryFileSystem;

#[cfg(test)]
mod tests {
    use super::*;

    /// **This is intended exclusively for testing.**
    #[derive(Debug)]
    pub struct InMemoryFileSystem {
        files: std::sync::Arc<
            std::sync::Mutex<std::collections::HashMap<String, Vec<u8>>>,
        >,
    }

    #[allow(clippy::missing_panics_doc)]
    impl InMemoryFileSystem {
        /// Creates a new empty in-memory filesystem
        #[must_use]
        pub fn new() -> Self {
            Self {
                files: Arc::new(
                    std::sync::Mutex::new(std::collections::HashMap::new()),
                ),
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
                // Use write_file directly instead of setup_file
                let _ = fs.write_file((*path).to_string(), content.as_bytes().to_vec());
            }
            fs
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

        fn list_files_at_directory(
            &self,
            folder_path: String,
        ) -> Result<Vec<String>, FileSystemError> {
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
                    if path.ends_with("__DIR__") {
                        return false;
                    }

                    if folder_prefix.is_empty() {
                        // Root listing: only items with no '/' are immediate children
                        !path.contains('/')
                    } else if path.starts_with(&folder_prefix) {
                        // Strip the prefix and ensure there is no further '/' => immediate child
                        let rest = &path[folder_prefix.len()..];
                        !rest.is_empty() && !rest.contains('/')
                    } else {
                        false
                    }
                })
                .map(|path| path.split('/').next_back().unwrap().to_string())
                .collect();

            Ok(files)
        }

        #[allow(clippy::manual_let_else)]
        fn read_file_range(
            &self,
            file_path: String,
            offset: u64,
            max_length: u64,
        ) -> Result<Vec<u8>, FileSystemError> {
            let normalized_path = Self::normalize_path(&file_path);
            let start_usize = usize::try_from(offset)
                .map_err(|_| FileSystemError::IoFailure("offset".to_string()))?;
            let end_add = offset.saturating_add(max_length);
            let result = {
                let files = self.files.lock().unwrap();
                if let Some(data) = files.get(&normalized_path) {
                    let data_len_u64 = data.len() as u64;
                    if offset >= data_len_u64 {
                        Ok(Vec::new())
                    } else {
                        let end_u64 = std::cmp::min(data_len_u64, end_add);
                        let end_usize = usize::try_from(end_u64).map_err(|_| {
                            FileSystemError::IoFailure("end_u64".to_string())
                        })?;
                        Ok(data[start_usize..end_usize].to_vec())
                    }
                } else {
                    Err(FileSystemError::FileDoesNotExist)
                }
            };
            result
        }

        fn write_file(
            &self,
            file_path: String,
            file_buffer: Vec<u8>,
        ) -> Result<(), FileSystemError> {
            let normalized_path = Self::normalize_path(&file_path);
            self.files
                .lock()
                .unwrap()
                .insert(normalized_path, file_buffer);
            Ok(())
        }

        fn delete_file(&self, file_path: String) -> Result<(), FileSystemError> {
            let normalized_path = Self::normalize_path(&file_path);
            let removed = self.files.lock().unwrap().remove(&normalized_path);
            match removed {
                Some(_) => Ok(()),
                None => Err(FileSystemError::FileDoesNotExist),
            }
        }
    }

    #[test]
    fn test_filesystem_middleware_prefixing() {
        // Set up in-memory filesystem
        let _ = FILESYSTEM_INSTANCE.set(Arc::new(InMemoryFileSystem::new()));

        // Test with snake_case prefix (as would be generated by bedrock_export macro)
        let middleware = FileSystemMiddleware::new("test_module");

        // Test that paths are properly prefixed
        assert_eq!(middleware.prefix_path("file.txt"), "test_module/file.txt");
        assert_eq!(middleware.prefix_path("/file.txt"), "test_module/file.txt");
        assert_eq!(
            middleware.prefix_path("test_module/file.txt"),
            "test_module/file.txt"
        );
    }
}
