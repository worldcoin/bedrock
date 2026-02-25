use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::OnceCell;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount, PERMIT2_ADDRESS};
use crate::transactions::contracts::erc20::Erc20;
use crate::transactions::contracts::permit2::{
    Permit2Erc20ApprovalBatch, WORLDCHAIN_PERMIT2_TOKENS,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};

/// Migration processor that ensures the user's smart account has granted max ERC20 approval
/// to the Permit2 singleton on WorldChain for supported tokens (USDC, WETH, WBTC, WLD).
///
/// Uses a single MultiSend transaction to batch all needed approvals.
pub struct Permit2ApprovalProcessor {
    safe_account: Arc<SafeSmartAccount>,
    tokens_needing_approval: OnceCell<Vec<Address>>,
}

impl Permit2ApprovalProcessor {
    /// Creates a new `Permit2ApprovalProcessor` with the given Safe smart account.
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self {
            safe_account,
            tokens_needing_approval: OnceCell::new(),
        }
    }

    /// Queries on-chain allowance for a given token from the wallet to the Permit2 contract.
    async fn get_allowance(&self, token: Address) -> Result<U256, MigrationError> {
        let rpc_client =
            get_rpc_client().map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let call_data =
            Erc20::encode_allowance(self.safe_account.wallet_address, PERMIT2_ADDRESS);

        let result = rpc_client
            .eth_call(Network::WorldChain, token, call_data.into())
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        if result.len() < 32 {
            return Err(MigrationError::InvalidOperation(
                "eth_call returned less than 32 bytes for allowance".to_string(),
            ));
        }

        Ok(U256::from_be_slice(&result[..32]))
    }

    /// Returns the cached list of tokens that need max approval to Permit2,
    /// fetching from on-chain only on the first call.
    async fn get_tokens_needing_approval(&self) -> Result<&Vec<Address>, MigrationError> {
        self.tokens_needing_approval
            .get_or_try_init(|| async {
                let mut needs_approval = Vec::new();

                for (token, name) in &WORLDCHAIN_PERMIT2_TOKENS {
                    let allowance = self.get_allowance(*token).await?;
                    if allowance < U256::MAX {
                        info!(
                            "Token {} ({}) has allowance {} < MAX, needs approval",
                            name, token, allowance
                        );
                        needs_approval.push(*token);
                    }
                }

                Ok(needs_approval)
            })
            .await
    }
}

#[async_trait]
impl MigrationProcessor for Permit2ApprovalProcessor {
    fn migration_id(&self) -> String {
        "wallet.permit2.approval".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        let tokens = self.get_tokens_needing_approval().await?;
        Ok(!tokens.is_empty())
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        let tokens = self.get_tokens_needing_approval().await?;

        if tokens.is_empty() {
            return Ok(ProcessorResult::Success);
        }

        let batch = Permit2Erc20ApprovalBatch::new(tokens);

        match batch
            .sign_and_execute(
                &self.safe_account,
                Network::WorldChain,
                None,
                None,
                RpcProviderName::Any,
            )
            .await
        {
            Ok(user_op_hash) => {
                info!(
                    "Submitted batched ERC20 approvals for {} tokens to Permit2, userOpHash: {:?}",
                    tokens.len(),
                    user_op_hash
                );
                Ok(ProcessorResult::Success)
            }
            Err(e) => Ok(ProcessorResult::Retryable {
                error_code: "RPC_ERROR".to_string(),
                error_message: format!(
                    "Failed to submit batched ERC20 approvals to Permit2: {}",
                    e
                ),
                retry_after_ms: Some(30_000),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_migration_id() {
        let safe = SafeSmartAccount::random();
        let processor = Permit2ApprovalProcessor::new(Arc::new(safe));
        assert_eq!(processor.migration_id(), "wallet.permit2.approval");
    }

    #[test]
    fn test_encode_allowance() {
        use alloy::primitives::address;
        use alloy::sol_types::SolCall;
        use crate::transactions::contracts::erc20::IErc20;

        let owner = address!("0x4564420674EA68fcc61b463C0494807C759d47e6");
        let spender = PERMIT2_ADDRESS;

        let call_data = Erc20::encode_allowance(owner, spender);

        let expected = IErc20::allowanceCall { owner, spender }.abi_encode();
        assert_eq!(call_data, expected);
    }
}
