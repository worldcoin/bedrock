//! Migration System
//!
//! A generic, reusable framework for running idempotent, resumable migrations.
//!
//! # Overview
//!
//! The migration system consists of:
//! - [`MigrationController`]: Orchestrates migration execution
//! - [`MigrationProcessor`]: Trait for implementing individual migrations
//! - [`MigrationRecord`]: Persistent state tracking individual migration progress
//!
//! Each migration's state is stored independently in the `DeviceKeyValueStore` using
//! namespaced keys (`migration:{migration_id}`)

mod controller;
mod error;
mod processor;
mod state;

/// Example and extension processors (EVM-specific processors live in the parent `bedrock` crate)
pub mod processors;

// Public API exports
pub use controller::{MigrationController, MigrationRecordEntry, MigrationRunSummary};
pub use error::MigrationError;
pub use processor::{MigrationProcessor, ProcessorResult};
pub use state::{MigrationRecord, MigrationStatus};
