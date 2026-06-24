//! Migration: repair the ERC-4337 configuration of legacy Safes.
//!

use std::sync::Arc;

use alloy::primitives::{Address, U256};
use alloy::sol_types::SolCall;
use async_trait::async_trait;
use log::info;

use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::primitives::Network;
use crate::smart_account::{SafeOperation, SafeSmartAccount, SafeTransaction};
use crate::transactions::contracts::multisend::MULTISEND_ADDRESS;
use crate::transactions::contracts::safe_module::{
    encode_is_4337_module_enabled, encode_nonce, ISafe, Safe4337Repairs,
    SAFE_FALLBACK_HANDLER_SLOT,
};
use crate::transactions::rpc::{get_rpc_client, RelaySafeTransactionRequest};

/// Migration processor that repairs the ERC-4337 configuration of a Safe that
/// was deployed without the [`GNOSIS_SAFE_4337_MODULE`].
///
/// [`GNOSIS_SAFE_4337_MODULE`]: crate::smart_account::GNOSIS_SAFE_4337_MODULE
#[derive(uniffi::Object)]
pub struct Safe4337ModuleProcessor {
    safe_account: Arc<SafeSmartAccount>,
}

#[uniffi::export]
impl Safe4337ModuleProcessor {
    /// Creates a processor that repairs the ERC-4337 configuration of
    /// `safe_account` (on World Chain).
    #[uniffi::constructor]
    #[must_use]
    pub fn new(safe_account: Arc<SafeSmartAccount>) -> Arc<Self> {
        Arc::new(Self { safe_account })
    }

    /// Returns this processor as a [`MigrationProcessor`] trait object so it can
    /// be registered with
    /// [`MigrationController`](crate::migration::MigrationController) via its
    /// `additional_processors` argument.
    #[must_use]
    pub fn as_migration_processor(self: Arc<Self>) -> Arc<dyn MigrationProcessor> {
        self
    }
}

impl Safe4337ModuleProcessor {
    /// Reads the Safe's ERC-4337 configuration on-chain and returns the repairs
    /// needed (module enablement and/or fallback handler).
    async fn fetch_repairs(&self) -> Result<Safe4337Repairs, MigrationError> {
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

    /// Builds and signs the repair `execTransaction` for the given `repairs` and
    /// on-chain `nonce`, or `None` if nothing needs repairing.
    ///
    /// Kept separate from [`Self::execute`] so the calldata/signing path is
    /// unit-testable without a live RPC client.
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
impl MigrationProcessor for Safe4337ModuleProcessor {
    fn migration_id(&self) -> String {
        "wallet.safe.enable_4337_module.v1".to_string()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        // Always attempt — the on-chain check lives in `execute`, which is the
        // idempotent source of truth. On the first run it relays the repair and
        // stays retryable; on the next run it sees the module + fallback handler
        // in place and returns `Success`, which is what marks the migration
        // done. (Once `Succeeded`, the controller stops calling this until the
        // TTL recheck.)
        Ok(true)
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        // `execute` performs the on-chain check itself: if the Safe is already
        // configured (e.g. a repair relayed on a previous run has since mined),
        // report success; otherwise relay the repair and stay retryable so the
        // next run confirms it.
        let repairs = self.fetch_repairs().await?;
        if !repairs.any() {
            return Ok(ProcessorResult::Success);
        }

        let rpc_client = get_rpc_client()
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let safe_address = self.safe_account.wallet_address;

        // Read the Safe's current nonce so the execTransaction is valid.
        let nonce_bytes = rpc_client
            .eth_call(Network::WorldChain, safe_address, encode_nonce().into())
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;
        let nonce =
            ISafe::nonceCall::abi_decode_returns(&nonce_bytes).map_err(|e| {
                MigrationError::InvalidOperation(format!(
                    "failed to decode Safe nonce: {e}"
                ))
            })?;

        let Some(request) = self.build_signed_transaction(repairs, nonce)? else {
            return Ok(ProcessorResult::Success);
        };

        let tx_hash = match rpc_client
            .relay_safe_transaction(Network::WorldChain, &request)
            .await
        {
            Ok(tx_hash) => tx_hash,
            Err(e) => {
                return Ok(ProcessorResult::Retryable {
                    error_code: "RELAY_ERROR".to_string(),
                    error_message: format!("Failed to relay 4337 repair: {e}"),
                });
            }
        };

        info!(
            "Relayed Safe 4337 repair (enable_module={}, set_fallback_handler={}), txHash: {tx_hash}",
            repairs.enable_module, repairs.set_fallback_handler
        );

        // Not done yet: the relayed transaction may not have mined. Stay
        // retryable so the next run re-reads on-chain state (above) and settles
        // to `Success` once the repair is confirmed in place.
        Ok(ProcessorResult::Retryable {
            error_code: "REPAIR_RELAYED".to_string(),
            error_message:
                "4337 repair relayed; will confirm on the next migration run"
                    .to_string(),
        })
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

    fn processor() -> Safe4337ModuleProcessor {
        let safe_account = Arc::new(
            SafeSmartAccount::from_private_key_hex(TEST_KEY.to_string(), TEST_WALLET)
                .unwrap(),
        );
        Safe4337ModuleProcessor { safe_account }
    }

    #[test]
    fn test_migration_id_is_versioned() {
        assert_eq!(
            processor().migration_id(),
            "wallet.safe.enable_4337_module.v1"
        );
    }

    #[test]
    fn test_no_repairs_builds_nothing() {
        let result = processor()
            .build_signed_transaction(Safe4337Repairs::default(), U256::ZERO)
            .unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn test_signed_transaction_shape() {
        let req = processor()
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
        let req = processor()
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
        let a = processor()
            .build_signed_transaction(BOTH, U256::from(42))
            .unwrap()
            .unwrap();
        let b = processor()
            .build_signed_transaction(BOTH, U256::from(42))
            .unwrap()
            .unwrap();
        assert_eq!(a.signatures, b.signatures);

        // A different nonce binds into the Safe tx hash → different signature.
        let c = processor()
            .build_signed_transaction(BOTH, U256::from(43))
            .unwrap()
            .unwrap();
        assert_ne!(a.signatures, c.signatures);
    }
}
