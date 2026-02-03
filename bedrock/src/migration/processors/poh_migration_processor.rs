use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;

/// `PoH` (Proof of Humanity) credential refresh migration processor
///
/// This processor handles migrating `PoH` credentials to a new version/format.
/// Platform code provides the required dependencies via the constructor.
#[derive(uniffi::Object)]
pub struct PoHMigrationProcessor {
    // TODO: Add these dependencies when implementing the actual migration logic.
    // These should be foreign traits (with_foreign) implemented by platform code:
    // identity: Arc<dyn Identity>,
    // personal_custody_keypair: Arc<dyn PersonalCustodyKeypair>,
    // attestation_generator: Arc<dyn AttestationGenerator>,
    #[allow(dead_code)]
    jwt_token: String,
    #[allow(dead_code)]
    sub: Option<String>,
}

#[uniffi::export]
impl PoHMigrationProcessor {
    /// Create a new `PoH` migration processor with injected dependencies
    #[uniffi::constructor]
    #[must_use]
    pub fn new(jwt_token: String, sub: Option<String>) -> Arc<Self> {
        Arc::new(Self { jwt_token, sub })
    }
}

#[async_trait]
impl MigrationProcessor for PoHMigrationProcessor {
    fn migration_id(&self) -> String {
        "worldid.credentials.poh.refresh.v1".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        // TODO: Implement actual applicability check
        info!("Checking if PoH migration is applicable");

        // Placeholder: Return false to skip migration for now
        Ok(false)
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        // TODO: Implement actual migration logic
        info!("Executing PoH migration for sub");

        // Placeholder: Return success for now
        Ok(ProcessorResult::Success)
    }
}
