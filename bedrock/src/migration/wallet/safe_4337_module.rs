//! Migration: repair the ERC-4337 configuration of legacy Safes.

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;

use crate::migration::error::MigrationError;
use crate::migration::{Reconciled, WalletMigration};
use crate::primitives::Network;
use crate::smart_account::{SafeOperation, SafeSmartAccount, SafeTransaction};
use crate::transactions::contracts::multisend::MULTISEND_ADDRESS;
use crate::transactions::contracts::safe_module::{
    encode_is_4337_module_enabled, encode_nonce, ISafe, Safe4337Repairs,
    SAFE_FALLBACK_HANDLER_SLOT,
};
use crate::transactions::rpc::{get_rpc_client, RelaySafeTransactionRequest};

/// Repairs a Safe deployed without the [`GNOSIS_SAFE_4337_MODULE`].
///
/// Relays an owner-signed `execTransaction`, so unlike every other migration it
/// works on a Safe that cannot yet validate a userOp — hence their prerequisite.
///
/// [`GNOSIS_SAFE_4337_MODULE`]: crate::smart_account::GNOSIS_SAFE_4337_MODULE
pub struct Safe4337ModuleMigration {
    safe_account: Arc<SafeSmartAccount>,
}

impl Safe4337ModuleMigration {
    /// Creates the migration for the given Safe smart account (on World Chain).
    #[must_use]
    pub const fn new(safe_account: Arc<SafeSmartAccount>) -> Self {
        Self { safe_account }
    }

    /// **Observe.** Reads the Safe's ERC-4337 configuration on-chain and returns
    /// the repairs still needed — the gap.
    async fn repairs_needed(&self) -> Result<Safe4337Repairs, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let safe = self.safe_account.wallet_address;

        let module_bytes = rpc_client
            .eth_call(
                Network::WorldChain,
                safe,
                encode_is_4337_module_enabled().into(),
            )
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let is_module_enabled = ISafe::isModuleEnabledCall::abi_decode_returns(
            &module_bytes,
        )
        .map_err(|e| {
            MigrationError::InvalidOperation(format!(
                "failed to decode isModuleEnabled response: {e}"
            ))
        })?;

        let fallback_word = rpc_client
            .eth_get_storage_at(Network::WorldChain, safe, SAFE_FALLBACK_HANDLER_SLOT)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let fallback_handler = Address::from_word(fallback_word);

        Ok(Safe4337Repairs::from_chain_state(
            is_module_enabled,
            fallback_handler,
        ))
    }

    /// Reads the Safe's current nonce, so the `execTransaction` is valid.
    async fn safe_nonce(&self) -> Result<U256, MigrationError> {
        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let nonce_bytes = rpc_client
            .eth_call(
                Network::WorldChain,
                self.safe_account.wallet_address,
                encode_nonce().into(),
            )
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        ISafe::nonceCall::abi_decode_returns(&nonce_bytes).map_err(|e| {
            MigrationError::InvalidOperation(format!(
                "failed to decode Safe nonce: {e}"
            ))
        })
    }

    /// Builds and signs the repair `execTransaction`, or `None` if nothing needs
    /// repairing. Separate from [`Self::reconcile`] so the calldata and signing
    /// path is unit-testable without a live RPC client.
    fn build_signed_transaction(
        &self,
        repairs: Safe4337Repairs,
        nonce: U256,
    ) -> Result<Option<RelaySafeTransactionRequest>, MigrationError> {
        let safe_address = self.safe_account.wallet_address;
        let Some(bundle) = repairs.build_bundle(safe_address) else {
            return Ok(None);
        };

        // gas_price = 0 → the Safe performs no refund; the relayer's outer
        // transaction pays gas.
        let safe_tx = SafeTransaction {
            to: format!("{MULTISEND_ADDRESS:#x}"),
            value: "0x0".to_string(),
            data: format!("0x{}", hex::encode(&bundle.data)),
            operation: SafeOperation::DelegateCall,
            safe_tx_gas: "0x0".to_string(),
            base_gas: "0x0".to_string(),
            gas_price: "0x0".to_string(),
            gas_token: format!("{:#x}", Address::ZERO),
            refund_receiver: format!("{:#x}", Address::ZERO),
            nonce: format!("0x{nonce:x}"),
        };

        let signature = self
            .safe_account
            .sign_transaction(Network::WorldChain as u32, safe_tx.clone())
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        Ok(Some(RelaySafeTransactionRequest {
            safe_address: format!("{safe_address:#x}"),
            to: safe_tx.to,
            value: safe_tx.value,
            data: safe_tx.data,
            operation: safe_tx.operation as u8,
            safe_tx_gas: safe_tx.safe_tx_gas,
            base_gas: safe_tx.base_gas,
            gas_price: safe_tx.gas_price,
            gas_token: safe_tx.gas_token,
            refund_receiver: safe_tx.refund_receiver,
            nonce: safe_tx.nonce,
            signatures: signature.to_hex_string(),
        }))
    }
}

#[async_trait]
impl WalletMigration for Safe4337ModuleMigration {
    fn migration_id(&self) -> String {
        "wallet.safe.enable_4337_module.v1".to_string()
    }

    async fn end_state_holds(&self) -> Result<bool, MigrationError> {
        Ok(!self.repairs_needed().await?.any())
    }

    async fn submit(&self) -> Result<Reconciled, MigrationError> {
        let repairs = self.repairs_needed().await?;
        let nonce = self.safe_nonce().await?;
        // Race guard only — the decision to be here was made by
        // `end_state_holds`; the Safe may have been repaired since.
        let Some(request) = self.build_signed_transaction(repairs, nonce)? else {
            return Ok(Reconciled::Converged);
        };

        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let transaction_id = rpc_client
            .relay_safe_transaction(Network::WorldChain, &request)
            .await
            .map_err(|e| {
                MigrationError::InvalidOperation(format!(
                    "Failed to relay 4337 repair: {e}"
                ))
            })?;

        crate::info!(
            "Relayed Safe 4337 repair (enable_module={}, set_fallback_handler={}, transaction_id={})",
            repairs.enable_module,
            repairs.set_fallback_handler,
            transaction_id,
        );

        Ok(Reconciled::submitted(transaction_id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::contracts::multisend::IMultiSend;

    // A 1-of-1 owner key with a known wallet address, reused from the smart
    // account signing tests.
    const TEST_KEY: &str =
        "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583";
    const TEST_WALLET: &str = "0x4564420674EA68fcc61b463C0494807C759d47e6";

    const BOTH: Safe4337Repairs = Safe4337Repairs {
        enable_module: true,
        set_fallback_handler: true,
    };

    fn migration() -> Safe4337ModuleMigration {
        let safe_account = Arc::new(
            SafeSmartAccount::from_private_key_hex(TEST_KEY.to_string(), TEST_WALLET)
                .unwrap(),
        );
        Safe4337ModuleMigration::new(safe_account)
    }

    #[test]
    fn test_migration_id_is_versioned() {
        assert_eq!(
            migration().migration_id(),
            "wallet.safe.enable_4337_module.v1"
        );
    }

    #[test]
    fn test_no_repairs_builds_nothing() {
        let result = migration()
            .build_signed_transaction(Safe4337Repairs::default(), U256::ZERO)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_signed_transaction_shape() {
        let req = migration()
            .build_signed_transaction(BOTH, U256::from(7))
            .unwrap()
            .unwrap();

        assert_eq!(req.operation, SafeOperation::DelegateCall as u8);
        assert_eq!(req.value, "0x0");
        assert_eq!(req.gas_price, "0x0");
        assert_eq!(req.nonce, "0x7");
        assert_eq!(req.to.to_lowercase(), format!("{MULTISEND_ADDRESS:#x}"));
        // 0x + 65-byte ECDSA signature.
        assert_eq!(req.signatures.len(), 2 + 130);
    }

    #[test]
    fn test_module_only_repair_excludes_fallback_handler() {
        let module = *crate::smart_account::GNOSIS_SAFE_4337_MODULE;
        let req = migration()
            .build_signed_transaction(
                Safe4337Repairs {
                    enable_module: true,
                    set_fallback_handler: false,
                },
                U256::ZERO,
            )
            .unwrap()
            .unwrap();

        let data = hex::decode(req.data.trim_start_matches("0x")).unwrap();
        let packed: Vec<u8> = IMultiSend::multiSendCall::abi_decode_raw(&data[4..])
            .unwrap()
            .transactions
            .to_vec();
        let enable = ISafe::enableModuleCall { module }.abi_encode();
        let set_handler =
            ISafe::setFallbackHandlerCall { handler: module }.abi_encode();

        assert!(
            packed.windows(enable.len()).any(|w| w == enable.as_slice()),
            "missing enableModule call"
        );
        assert!(
            !packed
                .windows(set_handler.len())
                .any(|w| w == set_handler.as_slice()),
            "must not set fallback handler when only the module is missing"
        );
    }

    #[test]
    fn test_signing_is_deterministic() {
        let a = migration()
            .build_signed_transaction(BOTH, U256::from(42))
            .unwrap()
            .unwrap();
        let b = migration()
            .build_signed_transaction(BOTH, U256::from(42))
            .unwrap()
            .unwrap();
        assert_eq!(a.signatures, b.signatures);

        // A different nonce binds into the Safe tx hash → different signature.
        let c = migration()
            .build_signed_transaction(BOTH, U256::from(43))
            .unwrap()
            .unwrap();
        assert_ne!(a.signatures, c.signatures);
    }
}
