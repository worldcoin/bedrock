// Portable filesystem primitives live in bedrock-core.
// Re-export everything so internal `crate::primitives::filesystem::*` paths continue to resolve.
pub use bedrock_core::primitives::filesystem::*;
