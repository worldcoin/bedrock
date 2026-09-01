//! Compatibility shim for the released `Safe4337ModuleProcessor`.
//!
//! The repair itself now lives in
//! [`Safe4337ModuleMigration`](crate::migration::wallet::safe_4337_module::Safe4337ModuleMigration),
//! which [`MigrationController`](crate::migration::MigrationController)
//! registers on its own. See `../README.md`.

use crate::migration::{MigrationError, MigrationProcessor, ProcessorResult};
use crate::smart_account::SafeSmartAccount;
use async_trait::async_trait;
use std::sync::Arc;

/// Repairs the ERC-4337 configuration of a Safe deployed without the module.
///
/// **Deprecated and inert.** The repair is now a wallet migration the
/// controller runs automatically, proven by on-chain state rather than by a
/// processor's own word. This type is kept only so the released FFI surface
/// does not break; registering it does nothing.
#[derive(uniffi::Object)]
pub struct Safe4337ModuleProcessor {
    /// Unused. Retained so the released constructor signature is unchanged.
    _safe_account: Arc<SafeSmartAccount>,
}

#[uniffi::export]
impl Safe4337ModuleProcessor {
    /// Creates a processor that repairs the ERC-4337 configuration of
    /// `safe_account` (on World Chain).
    ///
    /// **Deprecated and inert**, see the type docs. Nothing needs to be
    /// registered: the controller runs the repair itself.
    #[uniffi::constructor]
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Arc<Self> {
        Arc::new(Self {
            _safe_account: safe_account,
        })
    }

    /// Returns this processor as a [`MigrationProcessor`] trait object so it can
    /// be registered with
    /// [`MigrationController`](crate::migration::MigrationController) via its
    /// `additional_processors` argument.
    ///
    /// **Deprecated and inert**, see the type docs.
    #[must_use]
    pub fn as_migration_processor(self: Arc<Self>) -> Arc<dyn MigrationProcessor> {
        self
    }
}

#[async_trait]
impl MigrationProcessor for Safe4337ModuleProcessor {
    fn migration_id(&self) -> String {
        // Deliberately not the wallet migration's id, so a consumer that still
        // registers this cannot collide with the record the controller owns.
        "worldId.safe.enable4337Module.v1.deprecated".to_string()
    }

    /// Never applicable: the wallet migration owns this work now.
    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        crate::warn!(
            "migration.deprecated_processor_registered id={}",
            self.migration_id()
        );
        Ok(false)
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        Ok(ProcessorResult::Success)
    }
}
