//! Example demonstrating automatic FileSystemError support in bedrock_error macro

use crate::{bedrock_error, bedrock_export};

/// Example error enum that automatically includes FileSystemError support
#[bedrock_error]
pub enum ConfigError {
    /// Configuration parse error
    #[error("Invalid configuration format: {format}")]
    InvalidFormat {
        /// The format that was invalid
        format: String,
    },
    /// Configuration not found
    #[error("Configuration not found: {name}")]
    NotFound {
        /// Name of the missing configuration
        name: String,
    },
}

/// Example configuration manager
#[derive(uniffi::Object)]
pub struct ConfigManagerExample;

#[bedrock_export]
impl ConfigManagerExample {
    /// Load configuration from a file
    ///
    /// This demonstrates how FileSystemError automatically converts to ConfigError::FileSystem
    ///
    /// # Errors
    /// - `ConfigError::FileSystem` if the file cannot be read
    /// - `ConfigError::InvalidFormat` if the file content is not valid JSON
    pub fn load_config(&self, name: &str) -> Result<String, ConfigError> {
        // FileSystemError automatically converts to ConfigError::FileSystem
        let data = _bedrock_fs.read_file(&format!("{name}.json"))?;

        // Convert to string
        let content =
            String::from_utf8(data).map_err(|_| ConfigError::InvalidFormat {
                format: "UTF-8".to_string(),
            })?;

        // Simple JSON validation
        if !content.trim().starts_with('{') || !content.trim().ends_with('}') {
            return Err(ConfigError::InvalidFormat {
                format: "JSON".to_string(),
            });
        }

        Ok(content)
    }

    /// Save configuration to a file
    ///
    /// # Errors
    /// - `ConfigError::FileSystem` if the file cannot be written
    pub fn save_config(&self, name: &str, content: &str) -> Result<(), ConfigError> {
        // Validate JSON format
        if !content.trim().starts_with('{') || !content.trim().ends_with('}') {
            return Err(ConfigError::InvalidFormat {
                format: "JSON".to_string(),
            });
        }

        // FileSystemError automatically converts to ConfigError::FileSystem
        _bedrock_fs.write_file(&format!("{name}.json"), content.as_bytes().to_vec())?;

        Ok(())
    }

    /// Delete a configuration file
    ///
    /// # Errors
    /// - `ConfigError::FileSystem` if the file cannot be deleted
    /// - `ConfigError::NotFound` if the file doesn't exist
    pub fn delete_config(&self, name: &str) -> Result<(), ConfigError> {
        let filename = format!("{name}.json");

        // Check if file exists first
        if !_bedrock_fs.file_exists(&filename)? {
            return Err(ConfigError::NotFound {
                name: name.to_string(),
            });
        }

        // Delete the file - FileSystemError converts automatically
        _bedrock_fs.delete_file(&filename)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::filesystem::{set_filesystem, FileSystem, FileSystemError};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

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
        fn file_exists(&self, file_path: String) -> Result<bool, FileSystemError> {
            Ok(self.files.lock().unwrap().contains_key(&file_path))
        }

        fn read_file(&self, file_path: String) -> Result<Vec<u8>, FileSystemError> {
            self.files
                .lock()
                .unwrap()
                .get(&file_path)
                .cloned()
                .ok_or(FileSystemError::FileDoesNotExist)
        }

        fn list_files(
            &self,
            _folder_path: String,
        ) -> Result<Vec<String>, FileSystemError> {
            Ok(vec![])
        }

        fn write_file(
            &self,
            file_path: String,
            file_buffer: Vec<u8>,
        ) -> Result<bool, FileSystemError> {
            self.files.lock().unwrap().insert(file_path, file_buffer);
            Ok(true)
        }

        fn delete_file(&self, file_path: String) -> Result<bool, FileSystemError> {
            Ok(self.files.lock().unwrap().remove(&file_path).is_some())
        }
    }

    #[test]
    #[ignore = "This test requires exclusive access to the global filesystem"]
    fn test_filesystem_error_conversion() {
        // Set up mock filesystem
        set_filesystem(Arc::new(MockFileSystem::new()));

        // This test verifies that FileSystemError automatically converts to ConfigError
        let mgr = ConfigManagerExample;

        // Try to load a non-existent file
        let result = mgr.load_config("nonexistent");
        assert!(result.is_err());

        // The error should be ConfigError::FileSystem variant
        match result.unwrap_err() {
            ConfigError::FileSystem(_) => {
                // Success - FileSystemError was automatically converted
            }
            _ => panic!("Expected ConfigError::FileSystem variant"),
        }
    }
}
