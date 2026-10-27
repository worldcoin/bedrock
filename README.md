![Banner image](./banner.png)

# Bedrock

Foundational library which powers World App's crypto wallet.

## 🧱 Local Development & Contributing

Review our [CONTRIBUTING](CONTRIBUTING.md) guide. Including details on how to run this project locally.

## 🚀 Releasing

Releases are managed through [release-plz](https://release-plz.dev/docs). To trigger a release go to the open PR with the release tag, review the changes and merge. This will trigger the process to bump the release and generate all foreign bindings.

## 🐦‍🔥 Swift Bindings

Bedrock ships with foreign bindings for native Swift. All details can be found in the [/swift](./swift/README.md) folder.

## 🧬 Kotlin Bindings

Bedrock ships with foreign bindings for native Kotlin. All details can be found in the [/kotlin](./kotlin/README.md) folder.

## 🌍 Global Configuration

Bedrock provides a global configuration system for managing environment settings across your application.

### Initialization

Install the logger first, then initialize the global configuration once at app startup, before any other Bedrock call.

**Swift:**

```swift
@_exported import Bedrock

// The directory your `FileSystem` implementation used to resolve relative paths against.
let dataDirectory = try fileSystem.applicationSupportDirectory().path

try Bedrock.setConfig(environment: .staging, os: .ios, dataDirectory: dataDirectory)
```

**Kotlin:**

```kotlin
// The directory your `FileSystem` implementation used to resolve relative paths against.
val dataDirectory = File(context.filesDir, "oxide").absolutePath

uniffi.bedrock.setConfig(BedrockEnvironment.STAGING, Os.ANDROID, dataDirectory)
```

## Backup file storage

Backup entries use disk by default. Hosts storing PCPs or credential-vault exports
elsewhere can call `set_backup_file_handlers(designators, source, sink)` once at
startup, before backup operations. Both callbacks are required for the same set
of designators. Registration is process-wide: internally created manifest,
restore, and reporting managers all use it, and it cannot be replaced. The host
must resolve the active account in its callbacks and serialize account changes
with backup operations.

Implement the UniFFI `BackupFileSource.read` callback to return the exact stored
bytes for a designator and path. The path remains the logical ID in the manifest,
CBOR payload, and tar entry; leading `./` and `/` are removed. Owned paths need
no file on disk. Missing entries and callback failures abort the operation;
Bedrock never falls back to disk. Unregistered designators retain disk storage.

Use `sync_changes` with a `Put` (or `ReplaceFiles`) for every changed entry,
including a refreshed credential-vault export. These operations recompute the
BLAKE3 checksum from the source. Other entries are read again during archive
construction and must match their manifest checksum. Keep source bytes stable
until the call returns. Neither the manifest format nor the backup format changes.

Implement `BackupFileSink.restore` to persist a batch of all restored owned
entries. Bedrock validates every path and duplicate before calling it, writes
unowned files to disk, and saves the manifest only after both succeed. On
failure, an existing manifest stays unchanged; no new manifest is written.
The sink may have committed even when restore fails later: upsert by path so
repeating restore after a failure or interruption is safe. Prefer a transaction
for the host batch; Bedrock cannot roll back host or disk writes. Return only
`BackupFileSourceError` failure classes, without paths or data in errors/logs.

## 🛠️ Error Handling & Logging Tooling

Each module should implement its own error enum. See [tooling_tests](/bedrock/src/primitives/tooling_tests.rs) for example references.

### `#[bedrock_error]` Macro

Automatically enhances error enums with UniFFI compatibility and `anyhow` integration:

```rust
#[bedrock_error]
pub enum MyError {
    #[error("Authentication failed with code: {code}")]
    AuthenticationFailed { code: u32 },
    #[error("Network timeout after {seconds} seconds")]
    NetworkTimeout { seconds: u32 },
    // Generic variant added automatically for anyhow integration
}
```

**Features:**

- Auto-derives `Debug`, `thiserror::Error`, `uniffi::Error`
- Adds `Generic { message: String }` variant automatically
- Adds `FileSystem(FileSystemError)` variant automatically for filesystem operations
- Implements `From<anyhow::Error>` for seamless error conversion
- Implements `From<FileSystemError>` for automatic filesystem error conversion
- Provides helper methods like `from_anyhow_result()` and `from_anyhow_result_with_prefix()`

This means filesystem operations automatically work with your error types:

```rust
pub fn load_config(&self) -> Result<String, MyError> {
    // FileSystemError automatically converts to MyError::FileSystem
    let data = _bedrock_fs.read_file("config.json")?;
    Ok(String::from_utf8_lossy(&data).to_string())
}
```

### `#[bedrock_export]` Macro

Wraps `#[uniffi::export]` with automatic logging context and scoped filesystem injection:

```rust
#[bedrock_export]
impl MyStruct {
    pub fn some_method(&self) -> String {
        // LogContext automatically set to "MyStruct"
        info!("This will be prefixed with [Bedrock][MyStruct]");

        // Scoped filesystem available as _bedrock_fs with automatic path prefixing
        // Files will be prefixed with snake_case version of struct name: "my_struct/"
        _bedrock_fs.write_file("data.txt", b"content").ok();

        "result".to_string()
    }
}
```

**Features:**

- Automatically injects `LogContext::new("StructName")` at the start of every public method
- Works with any `impl` block for structs or traits
- Maintains all original `#[uniffi::export]` functionality
