//! High-level backup flows. A flow is a high-level user action that usually
//! incorporates communication with multiple systems and several steps.
//!
//! Reference: <https://docs.toolsforhumanity.com/world-app/backup/flows>

mod delete_backup;
mod remove_factor;

pub use delete_backup::DeleteBackup;
pub use remove_factor::{RemoveFactor, RemoveFactorOutcome};

use std::time::Duration;

use crate::backup::backup_service::BackupServiceClient;
use crate::backup::turnkey::{TurnkeyApiClient, TurnkeyApiError};
use crate::backup::{BackupOperationError, SyncFactor};
use crate::primitives::P256Signer;

/// Deadline for a post-commit Turnkey cleanup (best-effort; backup-service is the authority).
#[cfg(not(test))]
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(10);
/// Same, but for tests.
#[cfg(test)]
const CLEANUP_TIMEOUT: Duration = Duration::from_millis(200);

/// Shared dependencies handed to every [`BackupFlow`]: the two remote clients and
/// the caller's signers. Everything is borrowed, so the caller (and tests) own the
/// clients.
pub struct FlowContext<'a> {
    /// Bedrock-owned backup-service client.
    pub service: &'a BackupServiceClient,
    /// Per-run Turnkey client (its read cache lives for this flow only).
    pub turnkey: &'a TurnkeyApiClient,
    /// The sync-factor signer: authenticates backup-service calls and stamps the
    /// Turnkey sub-organization teardown.
    pub sync_factor: &'a P256Signer,
    /// An optional main-factor signer for privileged Turnkey writes.
    pub main_factor: Option<&'a P256Signer>,
}

/// A high-level backup operation (e.g. "Add a Main Factor", "Remove a Main Factor").
#[async_trait::async_trait]
pub trait BackupFlow {
    /// What the flow returns on success.
    type Output;

    /// Executes the flow.
    ///
    /// # Errors
    /// Returns [`BackupOperationError`] or `NeedsReauth` if applicable.
    async fn run(
        &self,
        ctx: &FlowContext<'_>,
    ) -> Result<Self::Output, BackupOperationError>;
}

/// Tears down the Turnkey sub-organization.
///
/// Callers bound this with [`CLEANUP_TIMEOUT`] as best-effort because the backup-service
/// is the authority.
async fn best_effort_delete_sub_org(
    flow: &str,
    turnkey: &TurnkeyApiClient,
    suborg_id: &str,
    sync_factor: &P256Signer,
) {
    if let Err(error) = turnkey
        .delete_sub_organization(suborg_id, SyncFactor(sync_factor))
        .await
    {
        if matches!(error, TurnkeyApiError::ActivityPollingExceeded { .. }) {
            crate::warn!(
                "{flow}.turnkey_suborg_teardown_pending suborg_id={suborg_id} err={error}"
            );
            return;
        }
        crate::critical!(
            "{flow}.turnkey_suborg_orphaned suborg_id={suborg_id} code={} err={error}",
            error.code()
        );
    }
}
