// Re-export HTTP client types for external use
pub use http_client::{AuthenticatedHttpClient, HttpError, HttpMethod};

/// Introduces logging functionality that can be integrated with foreign language bindings.
pub mod logger;

/// Introduces global configuration for Bedrock-core operations.
pub mod config;

/// Introduces filesystem functionality with automatic path prefixing for each exported struct.
pub mod filesystem;

/// Introduces authenticated HTTP client functionality that native applications must implement.
pub mod http_client;

/// Introduces key-value store functionality for persisting device data.
pub mod key_value_store;
