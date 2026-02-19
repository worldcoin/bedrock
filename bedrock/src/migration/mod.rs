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
//!
//! # Usage
//!
//! ```rust,ignore
//! use oxide::migration::MigrationController;
//! use std::sync::Arc;
//!
//! // Create controller (processors are registered internally)
//! let controller = MigrationController::new(kv_store);
//!
//! let summary = controller.run_migrations()?;
//! ```
//!
//! # Adding New Processors
//!
//! To add a new migration processor:
//! 1. Implement the `MigrationProcessor` trait in `processors/`
//! 2. Add it to `MigrationController::default_processors()`
//!
//! ## Versioning
//!
//! Include the version in the migration ID itself (e.g., `worldid.credentials.nfc.refresh.v1`).
//! If you need to update a migration, create a new processor with a new ID:
//!
//! ```rust,ignore
//! // Old migration
//! worldid.credentials.nfc.refresh.v1
//!
//! // Updated migration
//! worldid.credentials.nfc.refresh.v2
//! ```
//!
//! Both processors can coexist in `default_processors()`. The v1 will already be succeeded
//! for existing users, and v2 will run for those who need it. This keeps the system simple
//! with one unique identifier per migration.
//!
//! # Handling App Reinstalls
//!
//! **On app uninstall:** Both migration records (in `DeviceKeyValueStore`) and actual data are cleared.
//!
//! **On app reinstall with account recovery:** Actual data (credentials, etc.) is restored from
//! backup, but migration records remain empty since `DeviceKeyValueStore` is not backed up.
//!
//! **Why this works:** Each processor's `is_applicable()` method checks **actual restored state**
//! first, not just migration records. Example:
//!
//! ```rust,ignore
//! fn is_applicable(&self) -> Result<bool, MigrationError> {
//!     // 1. Check if migration outcome already exists (e.g., v4 credential restored from backup)
//!     if self.credential_store.has_v4_credential()? {
//!         return Ok(false);  // Skip - already have what this migration creates
//!     }
//!
//!     Ok(true)  // Run migration
//! }
//! ```
//!
//! # Synchronous Processor Interface
//!
//! `is_applicable()` and `execute()` are intentionally **synchronous** to work around a
//! known UniFFI bug with async foreign callbacks on Android/Kotlin
//! ([uniffi-rs#2624](https://github.com/mozilla/uniffi-rs/issues/2624)).
//!
//! Foreign (Kotlin/Swift) implementations that need async operations should block
//! internally (e.g., `runBlocking` in Kotlin, semaphore in Swift).

mod controller;
mod error;
mod processor;
mod state;

/// Example processors showing how to implement migrations
pub mod processors;

// Public API exports
pub use controller::{MigrationController, MigrationRunSummary};
pub use error::MigrationError;
pub use processor::{MigrationProcessor, ProcessorResult};
pub use state::{MigrationRecord, MigrationStatus};
