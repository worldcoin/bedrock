//! Tops up the Safe's ERC-20 allowance to the TFH multi-token paymaster.
//!
//! **Staging and sandbox only.** `WalletMigrationController` is the only thing
//! that registers it, and does not on production, so there it never runs and
//! never gets a record.

use std::sync::Arc;

use alloy::primitives::{uint, Address, Bytes, U256};

use crate::migration::wallet_migration::{WalletMigration, WalletMigrationResult};
use crate::migration::MigrationError;
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount};
use crate::transactions::contracts::erc20::{BatchErc20Approval, Erc20};
use crate::transactions::contracts::worldchain::{
    TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};
use crate::{info, smart_account::TransactionTypeId};
use async_trait::async_trait;

/// 100 WLD, at 18 decimals.
const WLD_TARGET: U256 = uint!(100_000000000000000000_U256);

/// 30 USDC, at 6 decimals.
const USDC_TARGET: U256 = uint!(30_000000_U256);

/// The tokens the paymaster charges in, and the allowance each is granted.
const PAYMASTER_TOKENS: [(Address, &str, U256); 2] = [
    (WLD_ADDRESS, "WLD", WLD_TARGET),
    (USDC_ADDRESS, "USDC", USDC_TARGET),
];

/// Grants the TFH paymaster an ERC-20 allowance so it can charge for gas.
///
/// A token is topped up when the Safe holds some of it *and* its allowance has
/// fallen below half the target — the paymaster spends the allowance down, so
/// this runs again as it drains. Registered on staging and sandbox only.
pub struct TfhPaymasterApprovalMigration {
    safe_account: Arc<SafeSmartAccount>,
}

impl TfhPaymasterApprovalMigration {
    /// Creates the migration for the given Safe smart account.
    #[must_use]
    pub const fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self { safe_account }
    }

    /// **Observe.** One batched read of every token's balance and allowance,
    /// returning those that are held and under half their target — the gap.
    async fn observe(
        &self,
    ) -> Result<Vec<(Address, U256, &'static str)>, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let safe = self.safe_account.wallet_address;

        let calls: Vec<(Address, Bytes)> = PAYMASTER_TOKENS
            .iter()
            .flat_map(|(token, _, _)| {
                [
                    (*token, Erc20::encode_balance_of(safe).into()),
                    (
                        *token,
                        Erc20::encode_allowance(safe, TFH_PAYMASTER_ADDRESS).into(),
                    ),
                ]
            })
            .collect();

        let results = rpc_client
            .eth_call_batched(Network::WorldChain, &calls)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        // A short array would drop a token and read as "no gap", so refuse it.
        if results.len() != calls.len() {
            return Err(MigrationError::InvalidOperation(format!(
                "Multicall3 returned {} results for {} calls",
                results.len(),
                calls.len()
            )));
        }

        // Two calls per token, in order, so the results pair up.
        let mut gap = Vec::new();
        for ((token, name, target), pair) in
            PAYMASTER_TOKENS.iter().zip(results.chunks_exact(2))
        {
            if pair.iter().any(|r| !r.success || r.returnData.len() < 32) {
                return Err(MigrationError::InvalidOperation(format!(
                    "Multicall3 balance/allowance query failed for {name}"
                )));
            }
            let balance = U256::from_be_slice(&pair[0].returnData[..32]);
            let allowance = U256::from_be_slice(&pair[1].returnData[..32]);

            // Both conditions, per token: a WLD-only holder gets WLD alone.
            if balance.is_zero() || allowance >= *target / uint!(2_U256) {
                continue;
            }
            info!(
                token = *name,
                allowance = allowance.to_string(),
                target = target.to_string(),
                "wallet_migration.paymaster_allowance_low"
            );
            gap.push((*token, *target, *name));
        }

        Ok(gap)
    }
}

#[async_trait]
impl WalletMigration for TfhPaymasterApprovalMigration {
    fn migration_id(&self) -> String {
        "wallet.tfh_paymaster.approval.v1".to_string()
    }

    async fn end_state_holds(&self) -> Result<bool, MigrationError> {
        Ok(self.observe().await?.is_empty())
    }

    async fn reconcile(&self) -> Result<WalletMigrationResult, MigrationError> {
        // The only chain read of this pass; the gap is a local, never a field.
        let gap = self.observe().await?;
        if gap.is_empty() {
            return Ok(WalletMigrationResult::Converged);
        }

        let approvals: Vec<(Address, U256)> = gap
            .iter()
            .map(|(token, target, _)| (*token, *target))
            .collect();
        let names: Vec<&str> = gap.iter().map(|(_, _, name)| *name).collect();

        match BatchErc20Approval::new(
            TFH_PAYMASTER_ADDRESS,
            &approvals,
            TransactionTypeId::TfhPaymasterApprove,
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
                    tokens = format!("{names:?}"),
                    user_op_hash = format!("{hash:#x}"),
                    "wallet_migration.paymaster_approvals_submitted"
                );
                Ok(WalletMigrationResult::submitted(format!("{hash:#x}")))
            }
            Err(e) => Ok(WalletMigrationResult::retry(
                "RPC_ERROR",
                format!("Failed to submit paymaster approvals for {names:?}: {e}"),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_KEY: &str =
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583";
    const TEST_WALLET: &str = "0x4564420674EA68fcc61b463C0494807C759d47e6";

    fn account() -> Arc<SafeSmartAccount> {
        Arc::new(
            SafeSmartAccount::from_private_key_hex(TEST_KEY.to_string(), TEST_WALLET)
                .unwrap(),
        )
    }

    #[test]
    fn test_migration_id_is_versioned() {
        let migration = TfhPaymasterApprovalMigration::new(account());
        assert_eq!(migration.migration_id(), "wallet.tfh_paymaster.approval.v1");
    }

    /// Pins the targets to the documented human amounts and their decimals.
    #[test]
    fn test_targets_are_the_documented_amounts() {
        assert_eq!(
            WLD_TARGET,
            U256::from(100u64) * U256::from(10u64).pow(U256::from(18))
        );
        assert_eq!(
            USDC_TARGET,
            U256::from(30u64) * U256::from(10u64).pow(U256::from(6))
        );
    }

    /// The top-up trigger is half the target, so document both halves.
    #[test]
    fn test_half_target_is_the_trigger() {
        assert_eq!(
            WLD_TARGET / uint!(2_U256),
            U256::from(50u64) * U256::from(10u64).pow(U256::from(18))
        );
        assert_eq!(USDC_TARGET / uint!(2_U256), U256::from(15_000_000u64));
    }
}
