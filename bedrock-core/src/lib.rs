//! `bedrock-core` is the portable foundational library for World App.
//!
//! It provides backup, migration, and root key management functionality
//! with no EVM/wallet dependencies, making it suitable for identity
//! applications that do not require the full crypto wallet stack.

// Re-export the proc-macro attributes so downstream code can use them via
// `bedrock_core::bedrock_error` etc.
pub use bedrock_macros::{bedrock_error, bedrock_export};

/// Low-level primitives: filesystem, HTTP client, key-value store, logger, config.
pub mod primitives;

/// Key management for World App.
pub mod root_key;

/// Tools for storing, retrieving, encrypting and decrypting backup data and metadata.
pub mod backup;

/// Generic, reusable framework for running idempotent, resumable migrations.
pub mod migration;

// Re-export commonly used primitives at the crate root for convenience.
pub use primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};

// UniFFI scaffolding — required so that #[derive(uniffi::Object)] etc. work in this crate.
// The parent `bedrock` crate owns the FFI ABI; bedrock-core exposes its own namespace.
uniffi::setup_scaffolding!("bedrock_core");
