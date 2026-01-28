use crate::migration::error::MigrationResult;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use async_trait::async_trait;
use log::info;

/// Example processor skeleton showing how to implement a migration
///
/// This is a **template** - copy this file and customize it for your actual migration.
/// Replace `ExampleProcessor` with your processor name and update the migration_id.
///
/// For actual implementations, see the migration spec and implement processors like:
/// - `AccountBootstrapProcessor` for "worldid.account.bootstrap.v1"
/// - `PoHRefreshProcessor` for "worldid.credentials.poh.refresh.v1"
/// - `NfcRefreshProcessor` for "worldid.credentials.nfc.refresh.v1"
pub struct ExampleProcessor {
    // Add dependencies here (e.g., authenticator, config, API clients, credential store, etc.)
    // For example:
    // authenticator: Arc<Authenticator>,
    // config: Arc<Config>,
    // credential_store: Arc<CredentialStore>,
}

impl ExampleProcessor {
    /// Create a new example processor
    #[allow(dead_code)]
    #[must_use]
    pub const fn new() -> Self {
        Self {
            // Initialize dependencies
        }
    }
}

impl Default for ExampleProcessor {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl MigrationProcessor for ExampleProcessor {
    fn migration_id(&self) -> &'static str {
        // TODO: Replace with your actual migration ID
        // Format: "namespace.category.action.v1"
        // Examples:
        //   - "worldid.account.bootstrap.v1"
        //   - "worldid.credentials.poh.refresh.v1"
        //   - "worldid.credentials.nfc.refresh.v1"
        "example.migration.v1"
    }

    async fn is_applicable(&self) -> MigrationResult<bool> {
        // IMPORTANT: Check actual state, not migration records
        // This ensures idempotency and handles reinstalls gracefully.

        // Example implementation pattern:

        // 1. Check if the migration outcome already exists (e.g., v4 credential exists)
        // if self.credential_store.has_v4_credential().await? {
        //     info!("v4 credential already exists, migration not needed");
        //     return Ok(false);
        // }

        // 2. Check if the migration source exists (e.g., v3 credential to migrate from)
        // if !self.credential_store.has_v3_credential().await? {
        //     info!("No v3 credential to migrate, skipping");
        //     return Ok(false);
        // }

        // 3. Check feature flags if applicable
        // if !self.config.is_migration_enabled() {
        //     return Ok(false);
        // }

        // 4. All checks passed - migration is needed
        // Ok(true)

        // Placeholder: skip this example processor
        Ok(false)
    }

    async fn execute(&self) -> MigrationResult<ProcessorResult> {
        info!("Executing example migration");

        // TODO: Implement your migration logic here
        //
        // Example patterns:

        // SUCCESS CASE:
        // let result = self.do_migration().await?;
        // return Ok(ProcessorResult::Success);

        // RETRYABLE ERROR (network issues, temporary failures):
        // if let Err(e) = self.api_call().await {
        //     return Ok(ProcessorResult::Retryable {
        //         error_code: "NETWORK_ERROR".to_string(),
        //         error_message: format!("Failed to connect: {}", e),
        //         retry_after_ms: Some(30_000), // Optional: suggest retry delay
        //     });
        // }

        // TERMINAL ERROR (can't recover, don't retry):
        // if account_not_found {
        //     return Ok(ProcessorResult::Terminal {
        //         error_code: "ACCOUNT_NOT_FOUND".to_string(),
        //         error_message: "No account exists for this user".to_string(),
        //     });
        // }

        // BLOCKED (waiting for user action):
        // if needs_user_consent {
        //     return Ok(ProcessorResult::BlockedUserAction {
        //         reason: "User must grant permission in settings".to_string(),
        //     });
        // }

        Ok(ProcessorResult::Success)
    }
}
