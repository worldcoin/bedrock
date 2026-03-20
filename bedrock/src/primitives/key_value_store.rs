// Portable key-value store primitives live in bedrock-core.
// Re-export everything so internal `crate::primitives::key_value_store::*` paths continue to resolve.
pub use bedrock_core::primitives::key_value_store::*;
