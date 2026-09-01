//! Compatibility shims for processors that became wallet migrations.
//!
//! Kept so the released FFI surface does not break. Nothing here does work.

/// Deprecated shim for the processor that installed the ERC-4337 module.
pub mod safe_4337_module_processor;
