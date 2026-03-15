use async_trait::async_trait;
use log::info;
use std::sync::Arc;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::utils::poll_for_receipt;
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount};
use crate::transactions::contracts::gnosis_safe::{
    GnosisSafe, SafeEnableModule, SAFE_4337_MODULE,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};

/// Migration processor that checks if the Safe4337Module is enabled on the wallet
/// and enables it if not.
///
/// The 4337 module is required for the wallet to process ERC-4337 UserOperations.
/// Some wallets may have been deployed without it or had it removed. This processor
/// ensures the module is enabled by checking on-chain state and calling `enableModule`
/// if needed.
pub struct Enable4337ModuleProcessor {
    safe_account: Arc<SafeSmartAccount>,
}

impl Enable4337ModuleProcessor {
    /// Creates a new `Enable4337ModuleProcessor` with the given Safe smart account.
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self { safe_account }
    }
}

#[async_trait]
impl MigrationProcessor for Enable4337ModuleProcessor {
    fn migration_id(&self) -> String {
        "wallet.safe.enable_4337_module.v1".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let safe = GnosisSafe::new(self.safe_account.wallet_address);
        let is_enabled = safe
            .is_module_enabled(&rpc_client, SAFE_4337_MODULE)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        if is_enabled {
            info!("Safe4337Module is already enabled");
        } else {
            info!("Safe4337Module is NOT enabled, migration needed");
        }

        Ok(!is_enabled)
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        let enable_module =
            SafeEnableModule::new(self.safe_account.wallet_address, SAFE_4337_MODULE);

        let user_op_hash = match enable_module
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
                info!("Submitted enableModule for 4337 module, userOpHash: {hash:?}");
                hash
            }
            Err(e) => {
                return Ok(ProcessorResult::Retryable {
                    error_code: "RPC_ERROR".to_string(),
                    error_message: format!(
                        "Failed to submit enableModule transaction: {e}"
                    ),
                });
            }
        };

        poll_for_receipt(user_op_hash, "enableModule").await
    }
}
