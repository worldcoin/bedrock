// Portable logger primitives (structs, traits, global singleton) live in bedrock-core.
// Re-export everything so internal `crate::primitives::logger::*` paths continue to resolve.
// The log macros (info!, warn!, error!, etc.) are re-exported at the bedrock crate root in lib.rs.
pub use bedrock_core::primitives::logger::*;
