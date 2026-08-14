//! High-level backup flows. A flow is a high-level user action that usually
//! incorporates communication with multiple systems and several steps.
//!
//! Reference: <https://docs.toolsforhumanity.com/world-app/backup/flows>

mod remove_oidc_factor;

pub use remove_oidc_factor::{RemoveOidcFactor, RemoveOidcOutcome};

use crate::backup::backup_service::BackupServiceClient;
use crate::backup::turnkey::TurnkeyApiClient;
use crate::backup::BackupOperationError;
use crate::primitives::P256Signer;

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
