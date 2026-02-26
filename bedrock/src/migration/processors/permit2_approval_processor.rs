use alloy::primitives::{Address, U256};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount, PERMIT2_ADDRESS};
use crate::transactions::contracts::erc20::Erc20;
use crate::transactions::contracts::permit2::{
    Permit2Erc20ApprovalBatch, WORLDCHAIN_PERMIT2_TOKENS,
};
use crate::transactions::contracts::worldchain::USDC_ADDRESS;
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};

/// Minimum allowance threshold for USDC before re-approval is triggered.
///
/// USDC is non-standard: it decrements allowance on every `transferFrom` even when set to
/// `type(uint256).max`. Standard ERC20 tokens do not decrement allowance when it is set to
/// `type(uint256).max`, so for those tokens a simple `< U256::MAX` check suffices.
///
/// This buffer of 1,000,000 USDC (1M * 10^6 decimals = 10^12) avoids re-approving on every
/// migration run due to minor allowance decrements from normal usage.
const USDC_ALLOWANCE_BUFFER: U256 = U256::from_limbs([1_000_000_000_000u64, 0, 0, 0]);

/// Migration processor that ensures the user's smart account has granted max ERC20 approval
/// to the Permit2 singleton on `WorldChain` for supported tokens (USDC, WETH, WBTC, WLD).
///
/// Standard ERC20 tokens do not decrement allowance when set to `type(uint256).max`, so once
/// approved they remain approved indefinitely. USDC is an exception — it decrements allowance
/// on every transfer, so a buffer threshold is used to avoid unnecessary re-approvals.
///
/// Uses a single `MultiSend` transaction to batch all needed approvals.
pub struct Permit2ApprovalProcessor {
    safe_account: Arc<SafeSmartAccount>,
    tokens_needing_approval: Mutex<Vec<Address>>,
}

impl Permit2ApprovalProcessor {
    /// Creates a new `Permit2ApprovalProcessor` with the given Safe smart account.
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self {
            safe_account,
            tokens_needing_approval: Mutex::new(Vec::new()),
        }
    }

    /// Queries on-chain allowance for a given token from the wallet to the Permit2 contract.
    async fn get_allowance(&self, token: Address) -> Result<U256, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

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

    /// Fetches on-chain allowances and stores the tokens that need approval.
    async fn fetch_tokens_needing_approval(&self) -> Result<(), MigrationError> {
        let mut needs_approval = Vec::new();

        for (token, name) in &WORLDCHAIN_PERMIT2_TOKENS {
            let allowance = self.get_allowance(*token).await?;
            // USDC decrements allowance on every transfer (non-standard behavior),
            // so use a buffer to avoid re-approving after minor usage.
            // Standard ERC20 tokens skip decrement at uint256.max, so exact check is fine.
            let threshold = if *token == USDC_ADDRESS {
                U256::MAX - USDC_ALLOWANCE_BUFFER
            } else {
                U256::MAX
            };
            if allowance < threshold {
                needs_approval.push(*token);
            }
        }

        *self.tokens_needing_approval.lock().await = needs_approval;
        Ok(())
    }
}

#[async_trait]
impl MigrationProcessor for Permit2ApprovalProcessor {
    fn migration_id(&self) -> String {
        "wallet.permit2.approval".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        self.fetch_tokens_needing_approval().await?;
        let tokens = self.tokens_needing_approval.lock().await;
        if !tokens.is_empty() {
            let names: Vec<&str> = tokens
                .iter()
                .filter_map(|addr| {
                    WORLDCHAIN_PERMIT2_TOKENS
                        .iter()
                        .find(|(a, _)| a == addr)
                        .map(|(_, name)| *name)
                })
                .collect();
            info!(
                "Permit2 approval needed for {} token(s): {names:?}",
                names.len()
            );
        }
        Ok(!tokens.is_empty())
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        let tokens = self.tokens_needing_approval.lock().await.clone();

        if tokens.is_empty() {
            return Ok(ProcessorResult::Success);
        }

        let batch = Permit2Erc20ApprovalBatch::new(&tokens);

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
                    "Submitted batched ERC20 approvals for {} tokens to Permit2, userOpHash: {user_op_hash:?}",
                    tokens.len(),
                );
                Ok(ProcessorResult::Success)
            }
            Err(e) => Ok(ProcessorResult::Retryable {
                error_code: "RPC_ERROR".to_string(),
                error_message: format!(
                    "Failed to submit batched ERC20 approvals to Permit2: {e}"
                ),
                retry_after_ms: Some(10_000),
            }),
        }
    }
}
