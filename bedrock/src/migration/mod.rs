//! Migration System
//!
//! A generic, reusable framework for running idempotent, resumable migrations.
//!
//! The core migration infrastructure lives in `bedrock-core`. This module
//! re-exports everything from there and adds EVM/wallet-specific processors.

// Re-export all core migration types from bedrock-core
pub use bedrock_core::migration::{
    MigrationController, MigrationError, MigrationProcessor, MigrationRecord,
    MigrationRecordEntry, MigrationRunSummary, MigrationStatus, ProcessorResult,
};

/// EVM/wallet-specific migration processors (e.g. Permit2 approval).
pub mod processors;

/// Extends `MigrationController` with a `new_with_defaults` constructor that
/// includes EVM-specific default processors (e.g. `Permit2ApprovalProcessor`).
pub mod controller_ext;

pub use controller_ext::new_migration_controller_with_defaults;
