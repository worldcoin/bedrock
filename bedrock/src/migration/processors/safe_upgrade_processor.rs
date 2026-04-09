use async_trait::async_trait;
use log::info;
use std::sync::Arc;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::utils::poll_for_receipt;
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount};
use crate::transactions::contracts::gnosis_safe::{
    GnosisSafe, SafeWalletVersionUpgrade, SAFE_VERSION_130,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};

/// Migration processor that checks the Gnosis Safe wallet version and upgrades
/// from v1.3.0 to v1.4.1 if needed.
///
/// Uses a `delegatecall` to the `WC_MIGRATION_WALLET_UPGRADE` contract which
/// handles updating the Safe proxy's singleton address.
pub struct SafeUpgradeProcessor {
    safe_account: Arc<SafeSmartAccount>,
}

impl SafeUpgradeProcessor {
    /// Creates a new `SafeUpgradeProcessor` with the given Safe smart account.
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self { safe_account }
    }
}

#[async_trait]
impl MigrationProcessor for SafeUpgradeProcessor {
    fn migration_id(&self) -> String {
        "wallet.safe.upgrade.v1".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let safe = GnosisSafe::new(self.safe_account.wallet_address);
        let version = safe
            .fetch_version(&rpc_client)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        if version == SAFE_VERSION_130 {
            info!("Safe is on v1.3.0, upgrade to v1.4.1 needed");
            Ok(true)
        } else {
            info!("Safe is on v{version}, no upgrade needed");
            Ok(false)
        }
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        let upgrade = SafeWalletVersionUpgrade;

        let user_op_hash = match upgrade
            .sign_and_execute(
                &self.safe_account,
                Network::WorldChain,
                None,
                None,
                RpcProviderName::Any,
            )
            .await
        {
            Ok(hash) => {
                info!("Submitted Safe upgrade transaction, userOpHash: {hash:?}");
                hash
            }
            Err(e) => {
                return Ok(ProcessorResult::Retryable {
                    error_code: "RPC_ERROR".to_string(),
                    error_message: format!(
                        "Failed to submit Safe upgrade transaction: {e}"
                    ),
                });
            }
        };

        poll_for_receipt(user_op_hash, "Safe upgrade").await
    }
}
