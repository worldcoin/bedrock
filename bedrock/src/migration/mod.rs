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
//! ## Platform Usage (Swift/Kotlin)
//!
//! ```swift
//! // 1. Create processor with dependencies
//! let processor = MyMigrationProcessor(
//!     dependency1: dep1,
//!     dependency2: dep2
//! )
//!
//! // 2. Register processor
//! registerMyProcessor(processor: processor)
//!
//! // 3. Create controller and run
//! let controller = MigrationController(kvStore: kvStore)
//! let summary = try await controller.runMigrations()
//! ```
//!
//! ```kotlin
//! // 1. Create processor with dependencies
//! val processor = MyMigrationProcessor(dep1, dep2)
//!
//! // 2. Register processor
//! registerMyProcessor(processor)
//!
//! // 3. Create controller and run
//! val controller = MigrationController(kvStore)
//! val summary = controller.runMigrations()
//! ```
//!
//! ## Adding New Migrations
//!
//! 1. **Create processor in Rust** (see `processors/poh_migration_processor.rs` as template)
//!    - Define struct with dependency fields
//!    - Add `#[uniffi::constructor]` that takes dependencies
//!    - Implement `MigrationProcessor` trait with migration logic
//!
//! 2. **Add global storage and registration** in `controller.rs`:
//!    ```rust
//!    static MY_PROCESSOR: OnceLock<Arc<dyn MigrationProcessor>> = OnceLock::new();
//!
//!    #[uniffi::export]
//!    pub fn register_my_processor(processor: Arc<MyProcessor>) {
//!        MY_PROCESSOR.set(processor).ok();
//!    }
//!    ```
//!
//! 3. **Wire into controller** - add to `run_migrations_async()`:
//!    ```rust
//!    if let Some(p) = MY_PROCESSOR.get() {
//!        processors.push(p.clone());
//!    }
//!    ```
//!
//! 4. **Platform creates and registers** with injected dependencies
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
//! async fn is_applicable(&self, record: Option<&MigrationRecord>) -> OxideResult<bool> {
//!     // 1. Check if migration outcome already exists (e.g., v4 credential restored from backup)
//!     if self.credential_store.has_v4_credential().await? {
//!         return Ok(false);  // Skip - already have what this migration creates
//!     }
//!
//!     Ok(true)  // Run migration
//! }
//! ```

mod controller;
mod error;
mod processor;
mod state;

/// Example processors showing how to implement migrations
pub mod processors;

// Public API exports
pub use controller::{
    register_poh_processor, MigrationController, MigrationRunSummary,
};
pub use error::MigrationError;
pub use processor::{MigrationProcessor, ProcessorResult};
pub use state::{MigrationRecord, MigrationStatus};
