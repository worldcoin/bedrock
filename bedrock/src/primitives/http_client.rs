// Portable HTTP client primitives live in bedrock-core.
// Re-export everything so internal `crate::primitives::http_client::*` paths continue to resolve.
pub use bedrock_core::primitives::http_client::*;
