use crate::info;
use alloy::primitives::{Address, Bytes, U256};
use async_trait::async_trait;
use std::sync::Arc;

use crate::migration::error::MigrationError;
use crate::migration::{WalletMigration, WalletMigrationResult};
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount, TransactionTypeId};
use crate::transactions::contracts::erc20::{BatchErc20Approval, Erc20};
use crate::transactions::contracts::permit2::PERMIT2_ADDRESS;
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

/// Minimum USDC allowance before re-approval.
///
/// USDC decrements allowance on every `transferFrom` even at
/// `type(uint256).max`, so this 1M buffer avoids re-approving after minor usage.
const USDC_ALLOWANCE_BUFFER: U256 = U256::from_limbs([1_000_000_000_000u64, 0, 0, 0]);

/// Grants max ERC20 approval to Permit2 on `WorldChain`.
///
/// Covers USDC, WETH, WBTC and WLD, batched into one `MultiSend`. Standard
/// tokens stay approved; USDC does not, see [`USDC_ALLOWANCE_BUFFER`].
pub struct Permit2ApprovalMigration {
    safe_account: Arc<SafeSmartAccount>,
}

impl Permit2ApprovalMigration {
    /// Creates the migration for the given Safe smart account.
    #[must_use]
    pub const fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self { safe_account }
    }

    /// **Observe.** The one chain read: allowances for all tokens, batched,
    /// returning those that still need approval — the gap.
    async fn observe(&self) -> Result<Vec<(Address, &'static str)>, MigrationError> {
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

            // USDC decrements on every transfer, so it needs a buffer; standard
            // tokens skip the decrement at uint256.max, so an exact check does.
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

        Ok(needs_approval)
    }
}

#[async_trait]
impl WalletMigration for Permit2ApprovalMigration {
    fn migration_id(&self) -> String {
        "wallet.permit2.approval".to_string()
    }

    async fn end_state_holds(&self) -> Result<bool, MigrationError> {
        Ok(self.observe().await?.is_empty())
    }

    async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
        // The only chain read of this pass; the gap is a local, never a field.
        let tokens = self.observe().await?;
        if tokens.is_empty() {
            return Ok(WalletMigrationResult::Converged);
        }

        // Fire-and-forget: the hash is kept for log correlation only. The next
        // observation of the allowances is what proves they landed.
        let approvals: Vec<(Address, U256)> =
            tokens.iter().map(|(addr, _)| (*addr, U256::MAX)).collect();
        let names: Vec<&str> = tokens.iter().map(|(_, name)| *name).collect();

        match BatchErc20Approval::new(
            PERMIT2_ADDRESS,
            &approvals,
            TransactionTypeId::Permit2Approve,
        )
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
                Ok(WalletMigrationResult::submitted(format!("{hash:#x}")))
            }
            Err(e) => Ok(WalletMigrationResult::retry(
                "RPC_ERROR",
                format!("Failed to submit batched ERC20 approvals to Permit2: {e}"),
            )),
        }
    }
}
