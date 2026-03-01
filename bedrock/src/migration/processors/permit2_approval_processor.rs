use alloy::primitives::{Address, Bytes, U256};
use async_trait::async_trait;
use log::info;
use std::sync::Arc;
use tokio::sync::Mutex;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount};
use crate::transactions::contracts::erc20::Erc20;
use crate::transactions::contracts::permit2::{BatchPermit2Approval, PERMIT2_ADDRESS};
use crate::transactions::contracts::worldchain::{
    USDC_ADDRESS, WBTC_ADDRESS, WETH_ADDRESS, WLD_ADDRESS,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};

/// Token addresses on `WorldChain` that should have max ERC20 approval to Permit2.
const WORLDCHAIN_PERMIT2_TOKENS: [(Address, &str); 4] = [
    (USDC_ADDRESS, "USDC"),
    (WETH_ADDRESS, "WETH"),
    (WBTC_ADDRESS, "WBTC"),
    (WLD_ADDRESS, "WLD"),
];

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
    tokens_needing_approval: Mutex<Vec<(Address, &'static str)>>,
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

    /// Fetches on-chain allowances for all tokens concurrently and stores those that need approval.
    async fn fetch_tokens_needing_approval(&self) -> Result<(), MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let call_data =
            Erc20::encode_allowance(self.safe_account.wallet_address, PERMIT2_ADDRESS);

        let calls: Vec<_> = WORLDCHAIN_PERMIT2_TOKENS
            .iter()
            .map(|(token, _)| (*token, Bytes::from(call_data.clone())))
            .collect();

        let results = rpc_client
            .eth_call_batched(Network::WorldChain, &calls)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let mut needs_approval = Vec::new();
        for ((token, name), result) in WORLDCHAIN_PERMIT2_TOKENS.iter().zip(results) {
            if !result.success || result.returnData.len() < 32 {
                return Err(MigrationError::InvalidOperation(format!(
                    "Multicall3 allowance query failed for {name}"
                )));
            }
            let allowance = U256::from_be_slice(&result.returnData[..32]);

            // USDC decrements allowance on every transfer (non-standard behavior),
            // so use a buffer to avoid re-approving after minor usage.
            // Standard ERC20 tokens skip decrement at uint256.max, so exact check is fine.
            let threshold = if *token == USDC_ADDRESS {
                U256::MAX - USDC_ALLOWANCE_BUFFER
            } else {
                U256::MAX
            };
            if allowance < threshold {
                info!("Token {name} needs Permit2 approval");
                needs_approval.push((*token, *name));
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
        Ok(!tokens.is_empty())
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        let tokens = self.tokens_needing_approval.lock().await.clone();

        if tokens.is_empty() {
            return Ok(ProcessorResult::Success);
        }

        let addresses: Vec<Address> = tokens.iter().map(|(addr, _)| *addr).collect();
        let names: Vec<&str> = tokens.iter().map(|(_, name)| *name).collect();
        let batch = BatchPermit2Approval::new(&addresses);

        let user_op_hash = match batch
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
                info!(
                    "Submitted Permit2 approvals for {names:?}, userOpHash: {hash:?}"
                );
                hash
            }
            Err(e) => {
                return Ok(ProcessorResult::Retryable {
                    error_code: "RPC_ERROR".to_string(),
                    error_message: format!(
                        "Failed to submit batched ERC20 approvals to Permit2: {e}"
                    ),
                    retry_after_ms: Some(10_000),
                });
            }
        };

        // Wait for the user operation to be mined before marking as success.
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        let user_op_hash_hex = format!("{user_op_hash:#x}");
        let delay_ms = 4000u64;

        for attempt in 0..5 {
            let response = rpc_client
                .wa_get_user_operation_receipt(Network::WorldChain, &user_op_hash_hex)
                .await
                .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

            match response.status.as_str() {
                "mined_success" => {
                    info!(
                        "Permit2 approvals mined successfully for {names:?}, txHash: {:?}",
                        response.transaction_hash
                    );
                    return Ok(ProcessorResult::Success);
                }
                "mined_revert" | "error" => {
                    return Ok(ProcessorResult::Retryable {
                        error_code: "MINED_REVERT".to_string(),
                        error_message: format!(
                            "Permit2 approval transaction failed for {names:?}, txHash: {:?}",
                            response.transaction_hash
                        ),
                        retry_after_ms: Some(10_000),
                    });
                }
                _ => {
                    // Still pending — keep polling unless this is the last attempt
                    if attempt < 4 {
                        tokio::time::sleep(tokio::time::Duration::from_millis(
                            delay_ms,
                        ))
                        .await;
                    }
                }
            }
        }

        // Still pending after all polling attempts — retry the whole migration later
        Ok(ProcessorResult::Retryable {
            error_code: "PENDING_TIMEOUT".to_string(),
            error_message: format!(
                "Permit2 approval for {names:?} still pending after polling, will retry"
            ),
            retry_after_ms: Some(10_000),
        })
    }
}
