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
//! // 1. Create processors with dependencies
//! let pohProcessor = PoHMigrationProcessor(jwtToken: token, sub: sub)
//!
//! // 2. Create controller with processors
//! let controller = MigrationController(
//!     kvStore: kvStore,
//!     pohProcessor: pohProcessor
//! )
//!
//! // 3. Run migrations
//! let summary = try await controller.runMigrations()
//!
//! // When credentials rotate, create new controller
//! let newPohProcessor = PoHMigrationProcessor(jwtToken: newToken, sub: newSub)
//! let newController = MigrationController(
//!     kvStore: kvStore,
//!     pohProcessor: newPohProcessor
//! )
//! ```
//!
//! ```kotlin
//! // 1. Create processors with dependencies
//! val pohProcessor = PoHMigrationProcessor(token, sub)
//!
//! // 2. Create controller with processors
//! val controller = MigrationController(kvStore, pohProcessor)
//!
//! // 3. Run migrations
//! val summary = controller.runMigrations()
//!
//! // When credentials rotate, create new controller
//! val newPohProcessor = PoHMigrationProcessor(newToken, newSub)
//! val newController = MigrationController(kvStore, newPohProcessor)
//! ```
//!
//! ## Adding New Migrations
//!
//! 1. **Create processor in Rust** (see `processors/poh_migration_processor.rs` as template)
//!    - Define struct with dependency fields (use `#[allow(dead_code)]` for placeholder fields)
//!    - Add `#[uniffi::constructor]` that takes dependencies
//!    - Implement `MigrationProcessor` trait with migration logic
//!
//! 2. **Add processor parameter to controller constructor** in `controller.rs`:
//!    ```rust
//!    #[uniffi::constructor]
//!    pub fn new(
//!        kv_store: Arc<dyn DeviceKeyValueStore>,
//!        poh_processor: Option<Arc<PoHMigrationProcessor>>,
//!        my_processor: Option<Arc<MyProcessor>>,  // Add new parameter
//!    ) -> Arc<Self> {
//!        let mut processors: Vec<Arc<dyn MigrationProcessor>> = vec![];
//!        if let Some(p) = poh_processor { processors.push(p); }
//!        if let Some(p) = my_processor { processors.push(p); }  // Add to list
//!        // ...
//!    }
//!    ```
//!
//! 3. **Platform creates controller with processors** - dependencies injected via constructor
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
pub use controller::{MigrationController, MigrationRunSummary};
pub use error::MigrationError;
pub use processor::{MigrationProcessor, ProcessorResult};
pub use state::{MigrationRecord, MigrationStatus};
