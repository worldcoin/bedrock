//! This module introduces the Morpho vault contract interface for deposits and withdrawals.
//!
//! Morpho deposits require a MultiSend to approve the token and then deposit into the vault.
//! Morpho withdrawals require a MultiSend to approve the vault token and then withdraw.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::transactions::contracts::erc20::Erc20;
use crate::transactions::contracts::multisend::{MultiSend, MultiSendTx};

// =============================================================================
// Contract Addresses
// =============================================================================

/// The Morpho vault contract address on World Chain.
pub const MORPHO_VAULT_ADDRESS: Address =
    address!("0xb1e80387ebe53ff75a89736097d34dc8d9e9045b");

// =============================================================================
// Contract ABIs
// =============================================================================

sol! {
    /// The Morpho vault contract interface.
    /// Reference: Morpho vault implementation
    #[derive(serde::Serialize)]
    interface IMorphoVault {
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
        function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
    }
}

// =============================================================================
// Morpho Transaction Types
// =============================================================================

/// Represents a Morpho vault operation (deposit or withdraw).
pub struct Morpho {
    /// The encoded call data for the operation.
    call_data: Vec<u8>,
}

impl Morpho {
    /// Creates a new deposit operation (approve token + deposit via MultiSend).
    ///
    /// # Arguments
    /// * `token_address` - The address of the token to deposit.
    /// * `amount` - The amount of tokens to deposit (in the token's smallest unit).
    /// * `receiver` - The address that will receive the vault shares.
    ///
    /// # Returns
    /// A `Morpho` struct configured for a deposit operation.
    pub fn deposit(token_address: Address, amount: U256, receiver: Address) -> Self {
        // 1. Encode the approve call (approve token to Morpho vault)
        let approve_data = Erc20::encode_approve(MORPHO_VAULT_ADDRESS, amount);

        // 2. Encode the deposit call
        let deposit_data = IMorphoVault::depositCall {
            assets: amount,
            receiver,
        }
        .abi_encode();

        // 3. Build the MultiSend bundle (approve + deposit)
        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: token_address,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: MORPHO_VAULT_ADDRESS,
                value: U256::ZERO,
                data_length: U256::from(deposit_data.len()),
                data: deposit_data.into(),
            },
        ];

        let bundle = MultiSend::build_bundle(&entries);

        Self {
            call_data: bundle.data,
        }
    }

    /// Creates a new withdraw operation (approve vault token + withdraw via MultiSend).
    ///
    /// # Arguments
    /// * `vault_token_address` - The address of the vault token to approve for withdrawal.
    /// * `amount` - The amount of tokens to withdraw (in the token's smallest unit).
    /// * `receiver` - The address that will receive the withdrawn tokens.
    /// * `owner` - The address that owns the vault shares.
    ///
    /// # Returns
    /// A `Morpho` struct configured for a withdraw operation.
    pub fn withdraw(
        vault_token_address: Address,
        amount: U256,
        receiver: Address,
        owner: Address,
    ) -> Self {
        // 1. Encode the approve call (approve vault token to Morpho vault)
        let approve_data = Erc20::encode_approve(MORPHO_VAULT_ADDRESS, amount);

        // 2. Encode the withdraw call
        let withdraw_data = IMorphoVault::withdrawCall {
            assets: amount,
            receiver,
            owner,
        }
        .abi_encode();

        // 3. Build the MultiSend bundle (approve + withdraw)
        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: vault_token_address,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: MORPHO_VAULT_ADDRESS,
                value: U256::ZERO,
                data_length: U256::from(withdraw_data.len()),
                data: withdraw_data.into(),
            },
        ];

        let bundle = MultiSend::build_bundle(&entries);

        Self {
            call_data: bundle.data,
        }
    }
}

impl Is4337Encodable for Morpho {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: crate::transactions::contracts::multisend::MULTISEND_ADDRESS,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: SafeOperation::DelegateCall as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let metadata_bytes = [0u8; 10];

        let key = NonceKeyV1::new(
            TransactionTypeId::MorphoDeposit,
            InstructionFlag::Default,
            metadata_bytes,
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;
    use crate::transactions::contracts::constants::{
        MORPHO_VAULT_WLD_TOKEN_ADDRESS, WLD_TOKEN_ADDRESS,
    };

    use super::*;

    #[test]
    fn test_morpho_deposit() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let morpho = Morpho::deposit(WLD_TOKEN_ADDRESS, U256::from(1_000_000), receiver);

        let call_data = morpho.as_execute_user_op_call_data();

        // Verify that call data is generated (non-empty)
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_withdraw() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let owner =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let morpho = Morpho::withdraw(
            MORPHO_VAULT_WLD_TOKEN_ADDRESS,
            U256::from(1_000_000),
            receiver,
            owner,
        );

        let call_data = morpho.as_execute_user_op_call_data();

        // Verify that call data is generated (non-empty)
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_deposit_preflight_user_operation_nonce_v1() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let morpho = Morpho::deposit(WLD_TOKEN_ADDRESS, U256::from(1_000_000), receiver);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = morpho.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::MorphoDeposit as u8);
        assert_eq!(be[6], 0u8); // instruction flags default

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_contract_addresses() {
        assert_eq!(
            MORPHO_VAULT_ADDRESS,
            Address::from_str("0xb1e80387ebe53ff75a89736097d34dc8d9e9045b").unwrap()
        );
    }
}
