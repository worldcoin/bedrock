# Bedrock Filesystem Middleware

The Bedrock filesystem middleware provides a secure, isolated filesystem access pattern for structs exported via the `#[bedrock_export]` macro. Each struct automatically gets its own sandboxed filesystem namespace based on the struct name.

## Key Features

- **Automatic Path Prefixing**: All filesystem operations are automatically prefixed with the struct name
- **Isolation Between Structs**: Different structs cannot access each other's files
- **Global Initialization**: The native filesystem implementation is set once globally
- **Transparent Access**: The filesystem is available as `_bedrock_fs` in all public methods

## Usage

### Native Side Setup

First, the native application must provide a filesystem implementation. See complete examples in our foreign tests:

- **Swift Implementation**: [`swift/tests/BedrockTests/BedrockFilesystemTests.swift`](../swift/tests/BedrockTests/BedrockFilesystemTests.swift)
- **Kotlin Implementation**: [`kotlin/bedrock-tests/src/test/kotlin/bedrock/BedrockFilesystemTests.kt`](../kotlin/bedrock-tests/src/test/kotlin/bedrock/BedrockFilesystemTests.kt)

These tests include both mock filesystem implementations for testing and examples of how to set up the filesystem bridge in real applications. Run the tests to verify your setup:

```bash
# Test Swift implementation
./swift/test_swift.sh

# Test Kotlin implementation
./kotlin/test_kotlin.sh
```

### Rust Side Usage

Any struct using `#[bedrock_export]` automatically gets filesystem access:

```rust
use bedrock::{bedrock_export, info};
use bedrock::primitives::filesystem::FileSystemError;

#[derive(uniffi::Object)]
pub struct ConfigManager;

#[bedrock_export]
impl ConfigManager {
    pub fn save_config(&self, name: &str, data: &str) -> Result<(), FileSystemError> {
        // _bedrock_fs is automatically available
        // This will save to "ConfigManager/configs/{name}.json"
        info!("Saving config: {}", name);

        _bedrock_fs.write_file(
            &format!("configs/{}.json", name),
            data.as_bytes().to_vec()
        )?;

        Ok(())
    }

    pub fn load_config(&self, name: &str) -> Result<String, FileSystemError> {
        // This will read from "ConfigManager/configs/{name}.json"
        let data = _bedrock_fs.read_file(&format!("configs/{}.json", name))?;
        String::from_utf8(data)
            .map_err(|_| FileSystemError::ReadFileError)
    }

    pub fn list_configs(&self) -> Result<Vec<String>, FileSystemError> {
        // List all files in "ConfigManager/configs/"
        _bedrock_fs.list_files("configs")
    }
}

// Different struct gets different namespace
#[derive(uniffi::Object)]
pub struct UserDataManager;

#[bedrock_export]
impl UserDataManager {
    pub fn save_user_data(&self, user_id: &str, data: &str) -> Result<(), FileSystemError> {
        // This saves to "UserDataManager/users/{user_id}.data"
        // Completely isolated from ConfigManager
        _bedrock_fs.write_file(
            &format!("users/{}.data", user_id),
            data.as_bytes().to_vec()
        )?;
        Ok(())
    }
}
```

## Path Isolation

The filesystem middleware automatically enforces path isolation:

- `ConfigManager` methods can only access paths under `ConfigManager/`
- `UserDataManager` methods can only access paths under `UserDataManager/`
- No struct can access another struct's files

Example paths:

```
/user/data/directory/
├── ConfigManager/
│   ├── configs/
│   │   ├── app.json
│   │   └── user.json
│   └── cache/
│       └── temp.dat
└── UserDataManager/
    └── users/
        ├── user123.data
        └── user456.data
```

## Available Operations

All operations are available through the injected `_bedrock_fs` variable:

```rust
// Get the base directory for this struct
let dir = _bedrock_fs.get_user_data_directory()?;
// Returns: "/user/data/directory/StructName"

// Check if a file exists
let exists = _bedrock_fs.file_exists("config.json")?;

// Read a file
let data = _bedrock_fs.read_file("config.json")?;

// Write a file
let success = _bedrock_fs.write_file("output.txt", b"Hello".to_vec())?;

// Delete a file
let deleted = _bedrock_fs.delete_file("temp.txt")?;

// List files in a directory
let files = _bedrock_fs.list_files("configs")?;
```

## Error Handling

The filesystem operations return `Result<T, FileSystemError>` with these possible errors:

- `FileSystemError::NotInitialized` - Filesystem not set via `set_filesystem()`
- `FileSystemError::FileDoesNotExist` - File not found
- `FileSystemError::ReadFileError` - Failed to read file
- `FileSystemError::WriteFileError` - Failed to write file
- `FileSystemError::DeleteFileError` - Failed to delete file
- `FileSystemError::ListFilesError` - Failed to list directory

### Automatic Error Conversion with `#[bedrock_error]`

When using the `#[bedrock_error]` macro, `FileSystemError` is automatically included:

```rust
use bedrock::bedrock_error;

#[bedrock_error]
pub enum MyError {
    #[error("Custom error: {message}")]
    Custom { message: String },
}

// Now you can use filesystem operations with automatic error conversion:
pub fn read_config(&self) -> Result<String, MyError> {
    // FileSystemError automatically converts to MyError::FileSystem
    let data = _bedrock_fs.read_file("config.json")?;
    Ok(String::from_utf8_lossy(&data).to_string())
}
```

The `#[bedrock_error]` macro automatically adds:

- A `FileSystem(FileSystemError)` variant
- `impl From<FileSystemError>` for automatic conversion with `?`

## Best Practices

1. **Initialize Early**: Call `set_filesystem()` once during app initialization
2. **Use Subdirectories**: Organize files into subdirectories (e.g., `configs/`, `cache/`, `users/`)
3. **Handle Errors**: Always handle filesystem errors appropriately
4. **UTF-8 Strings**: When storing strings, ensure proper UTF-8 encoding/decoding
5. **Binary Data**: Use `Vec<u8>` directly for binary data

## Testing

### Rust Unit Tests

For Rust unit tests, you can provide a mock filesystem implementation:

```rust
#[cfg(test)]
mod tests {
    use bedrock::primitives::filesystem::{set_filesystem, FileSystem, FileSystemError};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    struct MockFileSystem {
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl FileSystem for MockFileSystem {
        // Implement the trait methods...
    }

    #[test]
    fn test_my_feature() {
        set_filesystem(Arc::new(MockFileSystem::new()));

        // Your test code here
    }
}
```

### Foreign Function Interface Tests

Complete foreign tests demonstrating filesystem usage are available and can be run:

- **Swift Tests**: Run `./swift/test_swift.sh` to execute Swift filesystem tests
- **Kotlin Tests**: Run `./kotlin/test_kotlin.sh` to execute Kotlin filesystem tests

These tests validate:

- File reading/writing operations
- Directory listing and file existence checks
- Error handling and edge cases
- Path isolation between different struct namespaces
- Mock filesystem implementations for testing

The foreign tests serve as both validation of the filesystem middleware and practical examples of how to implement filesystem bridges in your applications.
