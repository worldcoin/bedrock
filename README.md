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
let rootPath = try fileSystem.applicationSupportDirectory().path

try Bedrock.setConfig(environment: .staging, os: .ios, rootPath: rootPath)
```

**Kotlin:**

```kotlin
// The directory your `FileSystem` implementation used to resolve relative paths against.
val rootPath = File(context.filesDir, "oxide").absolutePath

uniffi.bedrock.setConfig(BedrockEnvironment.STAGING, Os.ANDROID, rootPath)
```

> [!IMPORTANT]
> **Upgrading from `setFilesystem`.** `rootPath` replaces the base directory your
> `FileSystem` implementation applied to the relative paths Bedrock handed it. Pass that
> exact directory — a new one leaves Bedrock reading an empty tree, so the manifest reads
> as missing and every existing user reports as having no backup.

`rootPath` is a namespace Bedrock shares with the app, not a private one. Files registered
through `ManifestManager` are app-written and app-owned; Bedrock only reads and checksums
them at the relative path you register. Bedrock owns `.bedrock-staged`, which it clears at
startup, and rejects any path naming it or escaping the root with `..`.

Bedrock writes files with platform defaults, preserving an existing file's permissions when
it replaces one. Anything else the app needs — an iOS data protection class, exclusion from
iCloud backup — must be set on the root directory so new files inherit it.

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
