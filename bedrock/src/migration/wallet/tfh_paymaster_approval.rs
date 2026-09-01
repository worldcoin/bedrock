//! Tops up the Safe's ERC-20 allowance to the TFH multi-token paymaster.
//!
//! **Staging and sandbox only.** [`TfhPaymasterApprovalMigration::new`] returns
//! `None` on production, so the migration cannot be constructed — let alone
//! registered or submitted — there.

use std::sync::Arc;

use alloy::primitives::{Address, Bytes, U256};

use crate::migration::wallet_migration::{WalletMigration, WalletMigrationResult};
use crate::migration::MigrationError;
use crate::primitives::config::{current_environment_or_default, BedrockEnvironment};
use crate::primitives::contracts::IMulticall3;
use crate::primitives::Network;
use crate::smart_account::{Is4337Encodable, SafeSmartAccount};
use crate::transactions::contracts::erc20::{BatchErc20Approval, Erc20};
use crate::transactions::contracts::worldchain::{
    TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WLD_ADDRESS,
};
use crate::transactions::rpc::{get_rpc_client, RpcProviderName};
use crate::{info, smart_account::TransactionTypeId};
use async_trait::async_trait;

/// One token the paymaster takes payment in, and the allowance it is granted.
struct PaymasterToken {
    address: Address,
    name: &'static str,
    /// The allowance granted when topping up.
    target: U256,
}

/// 100 WLD, 18 decimals.
const WLD_TARGET: U256 = U256::from_limbs([7_766_279_631_452_241_920, 5, 0, 0]);

/// 30 USDC, 6 decimals.
const USDC_TARGET: U256 = U256::from_limbs([30_000_000, 0, 0, 0]);

/// The tokens the paymaster accepts, with the allowance each is granted.
const PAYMASTER_TOKENS: [PaymasterToken; 2] = [
    PaymasterToken {
        address: WLD_ADDRESS,
        name: "WLD",
        target: WLD_TARGET,
    },
    PaymasterToken {
        address: USDC_ADDRESS,
        name: "USDC",
        target: USDC_TARGET,
    },
];

/// Grants the TFH paymaster an ERC-20 allowance so it can charge for gas.
///
/// **Staging and sandbox only.** A token is topped up when the Safe holds some
/// of it *and* its allowance has fallen below half the target — the paymaster
/// spends the allowance down, so this runs again as it drains.
pub struct TfhPaymasterApprovalMigration {
    safe_account: Arc<SafeSmartAccount>,
}

impl TfhPaymasterApprovalMigration {
    /// Creates the migration, or `None` on production.
    ///
    /// The environment defaults to production when the config is uninitialized,
    /// so an unknown environment also declines.
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Option<Self> {
        match current_environment_or_default() {
            BedrockEnvironment::Staging | BedrockEnvironment::Sandbox => {
                Some(Self { safe_account })
            }
            BedrockEnvironment::Production => None,
        }
    }

    /// **Observe.** One batched read of every token's balance and allowance,
    /// returning those that are held and under half their target — the gap.
    async fn observe(
        &self,
    ) -> Result<Vec<(Address, U256, &'static str)>, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let safe = self.safe_account.wallet_address;

        let mut calls: Vec<(Address, Bytes)> =
            Vec::with_capacity(PAYMASTER_TOKENS.len() * 2);
        for token in &PAYMASTER_TOKENS {
            calls.push((token.address, Erc20::encode_balance_of(safe).into()));
            calls.push((
                token.address,
                Erc20::encode_allowance(safe, TFH_PAYMASTER_ADDRESS).into(),
            ));
        }

        let results = rpc_client
            .eth_call_batched(Network::WorldChain, &calls)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        // Two calls per token, in order, so the results pair up.
        let mut gap = Vec::new();
        for (token, pair) in PAYMASTER_TOKENS.iter().zip(results.chunks_exact(2)) {
            let balance = Self::word(&pair[0], token.name, "balanceOf")?;
            let allowance = Self::word(&pair[1], token.name, "allowance")?;

            // Both conditions, per token: a WLD-only holder gets WLD alone.
            if balance.is_zero() || allowance >= token.target / U256::from(2) {
                continue;
            }
            info!(
                token = token.name,
                allowance = allowance.to_string(),
                target = token.target.to_string(),
                "wallet_migration.paymaster_allowance_low"
            );
            gap.push((token.address, token.target, token.name));
        }

        Ok(gap)
    }

    /// Reads one 32-byte word out of a batched result.
    fn word(
        result: &IMulticall3::Result,
        token: &str,
        call: &str,
    ) -> Result<U256, MigrationError> {
        if !result.success || result.returnData.len() < 32 {
            return Err(MigrationError::InvalidOperation(format!(
                "Multicall3 {call} query failed for {token}"
            )));
        }
        Ok(U256::from_be_slice(&result.returnData[..32]))
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

    /// Marks the child run of [`test_production_never_constructs`].
    const PRODUCTION_CHILD_ENV: &str = "BEDROCK_TFH_PAYMASTER_PROD_CHILD";
    const PRODUCTION_TEST_NAME: &str =
        "migration::wallet::tfh_paymaster_approval::tests::test_production_never_constructs";

    fn account() -> Arc<SafeSmartAccount> {
        Arc::new(
            SafeSmartAccount::from_private_key_hex(TEST_KEY.to_string(), TEST_WALLET)
                .unwrap(),
        )
    }

    #[test]
    fn test_migration_id_is_versioned() {
        crate::primitives::filesystem::init_test_filesystem();
        let migration = TfhPaymasterApprovalMigration::new(account()).unwrap();
        assert_eq!(migration.migration_id(), "wallet.tfh_paymaster.approval.v1");
    }

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
            WLD_TARGET / U256::from(2),
            U256::from(50u64) * U256::from(10u64).pow(U256::from(18))
        );
        assert_eq!(USDC_TARGET / U256::from(2), U256::from(15_000_000u64));
    }

    /// The test process is configured as staging, so it constructs.
    #[test]
    fn test_staging_constructs() {
        crate::primitives::filesystem::init_test_filesystem();
        assert!(TfhPaymasterApprovalMigration::new(account()).is_some());
    }

    /// Production, and an uninitialized config that defaults to it, both refuse.
    ///
    /// Runs in a fresh process: the config is a process-wide `OnceLock`, so the
    /// staging value the other tests rely on cannot be replaced in place.
    #[test]
    fn test_production_never_constructs() {
        use crate::primitives::config::{set_config, Os};

        if std::env::var_os(PRODUCTION_CHILD_ENV).is_none() {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", "--nocapture", PRODUCTION_TEST_NAME])
                .env(PRODUCTION_CHILD_ENV, "1")
                .output()
                .expect("re-run this test in a child process");
            let report = String::from_utf8_lossy(&output.stdout);
            assert!(
                output.status.success(),
                "child run failed:\n{report}{}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(
                report.contains("1 passed"),
                "child did not run the test, only: {report}"
            );
            return;
        }

        // Uninitialized: the environment defaults to production, so it declines.
        assert!(
            TfhPaymasterApprovalMigration::new(account()).is_none(),
            "an uninitialized config must not construct the migration"
        );

        let root = std::env::temp_dir()
            .join(format!("bedrock-tfh-paymaster-prod-{}", std::process::id()));
        set_config(
            BedrockEnvironment::Production,
            Os::Ios,
            root.to_string_lossy().into_owned(),
        )
        .expect("configure a production test environment");

        assert!(
            TfhPaymasterApprovalMigration::new(account()).is_none(),
            "production must never construct the migration"
        );
        drop(std::fs::remove_dir_all(&root));
    }
}
