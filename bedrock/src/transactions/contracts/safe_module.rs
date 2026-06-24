//! Helpers for enabling the ERC-4337 module on an already-deployed Safe.
//!
//! This module builds the calldata that retrofits such a Safe to match a
//! freshly-deployed account: it both `enableModule`s and `setFallbackHandler`s
//! the [`GNOSIS_SAFE_4337_MODULE`].
//!
//! Because the module is absent, this batch **cannot** be executed as a 4337
//! `UserOperation` (that is the very thing that is broken). It is encoded as a
//! Safe `execTransaction` and must be relayed on-chain by a gas-paying executor.

use alloy::{
    primitives::{b256, Address, B256, U256},
    sol,
    sol_types::SolCall,
};

use crate::smart_account::{SafeOperation, GNOSIS_SAFE_4337_MODULE};
use crate::transactions::contracts::multisend::{
    MultiSend, MultiSendBundle, MultiSendTx,
};

sol! {
    /// Subset of the Safe (v1.3.0 / v1.4.1) interface needed to detect and
    /// install the ERC-4337 module.
    ///
    /// `enableModule` and `setFallbackHandler` are both `authorized` — they
    /// revert unless `msg.sender == address(this)`, so they can only be invoked
    /// by the Safe on itself (via `execTransaction` or a `MultiSend` batch).
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/base/ModuleManager.sol>
    interface ISafe {
        function enableModule(address module) external;
        function setFallbackHandler(address handler) external;
        function isModuleEnabled(address module) external view returns (bool);
        function nonce() external view returns (uint256);
    }
}

/// Builds the calldata to read whether the [`GNOSIS_SAFE_4337_MODULE`] is
/// enabled on a Safe (`isModuleEnabled(module)`).
#[must_use]
pub fn encode_is_4337_module_enabled() -> Vec<u8> {
    ISafe::isModuleEnabledCall {
        module: *GNOSIS_SAFE_4337_MODULE,
    }
    .abi_encode()
}

/// Builds the calldata to read a Safe's current transaction nonce (`nonce()`).
#[must_use]
pub fn encode_nonce() -> Vec<u8> {
    ISafe::nonceCall {}.abi_encode()
}

/// Storage slot holding a Safe's fallback handler address:
/// `keccak256("fallback_manager.handler.address")`.
///
/// Safe (v1.3.0 / v1.4.1) has no public getter for the fallback handler, so it
/// is read directly from storage via `eth_getStorageAt`.
pub const SAFE_FALLBACK_HANDLER_SLOT: B256 =
    b256!("0x6c9a6c4a39284e37ed1cf53d337577d14212a4870fb976a4366c693b939918d5");

/// The repairs needed to bring a Safe's ERC-4337 configuration in line with a
/// freshly-deployed account.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Safe4337Repairs {
    /// The `Safe4337Module` is not enabled as a module.
    pub enable_module: bool,
    /// The fallback handler is not set to the `Safe4337Module`.
    pub set_fallback_handler: bool,
}

impl Safe4337Repairs {
    /// Derives the needed repairs from on-chain reads.
    #[must_use]
    pub fn from_chain_state(
        is_module_enabled: bool,
        fallback_handler: Address,
    ) -> Self {
        Self {
            enable_module: !is_module_enabled,
            set_fallback_handler: fallback_handler != *GNOSIS_SAFE_4337_MODULE,
        }
    }

    /// Whether any repair is required.
    #[must_use]
    pub const fn any(self) -> bool {
        self.enable_module || self.set_fallback_handler
    }

    /// Builds the `MultiSend` bundle for the needed repairs, or `None` when the
    /// Safe is already correctly configured.
    ///
    /// Each entry is a self-`Call` to the Safe (the pattern required by the
    /// `authorized` admin functions), wrapped in a single `DelegateCall` to
    /// `MultiSend`.
    #[must_use]
    pub fn build_bundle(self, safe_address: Address) -> Option<MultiSendBundle> {
        let module = *GNOSIS_SAFE_4337_MODULE;
        let mut entries = Vec::new();

        // Match the backend ordering: fallback handler first, then module.
        if self.set_fallback_handler {
            entries.push(self_call(
                safe_address,
                ISafe::setFallbackHandlerCall { handler: module }.abi_encode(),
            ));
        }
        if self.enable_module {
            entries.push(self_call(
                safe_address,
                ISafe::enableModuleCall { module }.abi_encode(),
            ));
        }

        if entries.is_empty() {
            return None;
        }
        Some(MultiSend::build_bundle(&entries))
    }
}

/// Builds a `MultiSend` entry that calls the Safe itself, as required by the
/// Safe's `authorized` (self-call) admin functions.
fn self_call(safe_address: Address, data: Vec<u8>) -> MultiSendTx {
    MultiSendTx {
        operation: SafeOperation::Call as u8,
        to: safe_address,
        value: U256::ZERO,
        data_length: U256::from(data.len()),
        data: data.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::contracts::multisend::{IMultiSend, MULTISEND_ADDRESS};
    use alloy::primitives::address;

    /// Each packed `MultiSend` entry is
    /// `operation(1) ++ to(20) ++ value(32) ++ dataLength(32) ++ data`.
    /// `enableModule(address)` / `setFallbackHandler(address)` both encode to
    /// a 4-byte selector + a 32-byte address argument = 36 bytes.
    const INNER_CALL_LEN: usize = 4 + 32;
    const ENTRY_LEN: usize = 1 + 20 + 32 + 32 + INNER_CALL_LEN;

    const SAFE: Address = address!("0x4564420674EA68fcc61b463C0494807C759d47e6");

    fn packed_entries(repairs: Safe4337Repairs) -> Vec<u8> {
        let bundle = repairs.build_bundle(SAFE).expect("repairs were needed");
        assert_eq!(bundle.to, MULTISEND_ADDRESS);
        assert_eq!(bundle.value, U256::ZERO);
        assert_eq!(bundle.operation as u8, SafeOperation::DelegateCall as u8);
        IMultiSend::multiSendCall::abi_decode_raw(&bundle.data[4..])
            .unwrap()
            .transactions
            .to_vec()
    }

    fn assert_entry(entry: &[u8], expected_inner: &[u8]) {
        assert_eq!(entry[0], SafeOperation::Call as u8); // Call
        assert_eq!(&entry[1..21], SAFE.as_slice()); // self-call
        assert_eq!(&entry[21..53], &[0u8; 32]); // value == 0
        assert_eq!(
            U256::from_be_slice(&entry[53..85]),
            U256::from(INNER_CALL_LEN)
        );
        assert_eq!(&entry[85..85 + INNER_CALL_LEN], expected_inner);
    }

    #[test]
    fn test_from_chain_state() {
        let module = *GNOSIS_SAFE_4337_MODULE;
        let other = address!("0x000000000000000000000000000000000000dEaD");

        // Correctly configured → nothing to do.
        let ok = Safe4337Repairs::from_chain_state(true, module);
        assert!(!ok.any());
        assert!(ok.build_bundle(SAFE).is_none());

        assert_eq!(
            Safe4337Repairs::from_chain_state(false, module),
            Safe4337Repairs {
                enable_module: true,
                set_fallback_handler: false
            }
        );
        assert_eq!(
            Safe4337Repairs::from_chain_state(true, other),
            Safe4337Repairs {
                enable_module: false,
                set_fallback_handler: true
            }
        );
        assert_eq!(
            Safe4337Repairs::from_chain_state(false, other),
            Safe4337Repairs {
                enable_module: true,
                set_fallback_handler: true
            }
        );
    }

    #[test]
    fn test_bundle_repairs_both_fallback_handler_first() {
        let module = *GNOSIS_SAFE_4337_MODULE;
        let packed = packed_entries(Safe4337Repairs {
            enable_module: true,
            set_fallback_handler: true,
        });
        assert_eq!(packed.len(), ENTRY_LEN * 2, "expected two entries");

        // Fallback handler first, then enableModule (matches the backend order).
        assert_entry(
            &packed[0..ENTRY_LEN],
            &ISafe::setFallbackHandlerCall { handler: module }.abi_encode(),
        );
        assert_entry(
            &packed[ENTRY_LEN..ENTRY_LEN * 2],
            &ISafe::enableModuleCall { module }.abi_encode(),
        );
    }

    #[test]
    fn test_bundle_module_only_omits_enable_module_revert() {
        // enableModule reverts (GS102) if already enabled, so when only the
        // module is missing the batch must contain *only* enableModule.
        let module = *GNOSIS_SAFE_4337_MODULE;
        let packed = packed_entries(Safe4337Repairs {
            enable_module: true,
            set_fallback_handler: false,
        });
        assert_eq!(packed.len(), ENTRY_LEN, "expected a single entry");
        assert_entry(
            &packed[0..ENTRY_LEN],
            &ISafe::enableModuleCall { module }.abi_encode(),
        );
    }

    #[test]
    fn test_bundle_fallback_only_omits_enable_module() {
        let module = *GNOSIS_SAFE_4337_MODULE;
        let packed = packed_entries(Safe4337Repairs {
            enable_module: false,
            set_fallback_handler: true,
        });
        assert_eq!(packed.len(), ENTRY_LEN, "expected a single entry");
        assert_entry(
            &packed[0..ENTRY_LEN],
            &ISafe::setFallbackHandlerCall { handler: module }.abi_encode(),
        );
    }

    #[test]
    fn test_is_module_enabled_calldata_roundtrips() {
        let data = encode_is_4337_module_enabled();
        let decoded = ISafe::isModuleEnabledCall::abi_decode_raw(&data[4..]).unwrap();
        assert_eq!(decoded.module, *GNOSIS_SAFE_4337_MODULE);
    }

    #[test]
    fn test_nonce_calldata_is_bare_selector() {
        // nonce() takes no arguments, so the calldata is exactly the 4-byte selector.
        assert_eq!(encode_nonce().len(), 4);
    }
}
