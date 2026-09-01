//! Migrations that run on app start to bring the app to an expected state.
//!
//! Two frameworks under one entry point, [`MigrationController`]:
//!
//! - **Native migrations** — [`MigrationProcessor`], implemented in Swift and
//!   Kotlin over FFI and owned by the platform teams.
//! - **[Wallet migrations](wallet_migration)** — Bedrock's own, for on-chain
//!   wallet operations. Fire-and-forget: work is submitted and never waited on,
//!   and only a later observation of the chain proves it landed.
//!
//! See `README.md` in this directory for the model, the state machine and the
//! rules on giving up.

mod controller;
mod error;
mod processor;
mod record_store;

mod wallet_controller;
mod wallet_migration;

/// The individual wallet migrations Bedrock owns.
pub mod wallet;

// Public API exports
pub use controller::{MigrationController, MigrationRunSummary};
pub use error::MigrationError;
pub use processor::{MigrationProcessor, ProcessorResult};
pub use record_store::{
    MigrationRecord, MigrationRecordEntry, MigrationStatus, Submission,
};
pub use wallet_controller::WalletMigrationController;
pub use wallet_migration::{WalletMigration, WalletMigrationResult};
