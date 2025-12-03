//! This module introduces the Morpho vault contract interface for deposits and withdrawals.
//!
//! Morpho deposits require a MultiSend to approve the token and then deposit into the vault.
//! Morpho withdrawals require a MultiSend to approve the vault token and then withdraw.

#![allow(dead_code)]

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
use crate::transactions::contracts::constants::{
    MORPHO_VAULT_USDC_TOKEN_ADDRESS, MORPHO_VAULT_WBTC_TOKEN_ADDRESS,
    MORPHO_VAULT_WETH_TOKEN_ADDRESS, MORPHO_VAULT_WLD_TOKEN_ADDRESS,
    USDC_TOKEN_ADDRESS, WBTC_TOKEN_ADDRESS, WETH_TOKEN_ADDRESS, WLD_TOKEN_ADDRESS,
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
// Morpho Token Enum
// =============================================================================

/// Supported tokens for Morpho vault deposits and withdrawals.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::upper_case_acronyms)]
pub enum MorphoToken {
    /// Worldcoin (WLD)
    WLD,
    /// Wrapped BTC (WBTC)
    WBTC,
    /// Wrapped ETH (WETH)
    WETH,
    /// USD Coin (USDC)
    USDC,
}

impl MorphoToken {
    /// Returns the program ID for this token (used in metadata).
    /// Order: WLD=0, USDC=1, WETH=2, WBTC=3
    #[must_use]
    pub const fn program_id(&self) -> u8 {
        match self {
            Self::WLD => 0,
            Self::USDC => 1,
            Self::WETH => 2,
            Self::WBTC => 3,
        }
    }

    /// Returns the underlying token address for this Morpho token.
    #[must_use]
    pub const fn token_address(&self) -> Address {
        match self {
            Self::WLD => WLD_TOKEN_ADDRESS,
            Self::WBTC => WBTC_TOKEN_ADDRESS,
            Self::WETH => WETH_TOKEN_ADDRESS,
            Self::USDC => USDC_TOKEN_ADDRESS,
        }
    }

    /// Returns the Morpho vault token address for this token.
    #[must_use]
    pub const fn vault_token_address(&self) -> Address {
        match self {
            Self::WLD => MORPHO_VAULT_WLD_TOKEN_ADDRESS,
            Self::WBTC => MORPHO_VAULT_WBTC_TOKEN_ADDRESS,
            Self::WETH => MORPHO_VAULT_WETH_TOKEN_ADDRESS,
            Self::USDC => MORPHO_VAULT_USDC_TOKEN_ADDRESS,
        }
    }
}

// =============================================================================
// Morpho Transaction Types
// =============================================================================

/// Represents a Morpho vault operation (deposit or withdraw).
pub struct Morpho {
    /// The encoded call data for the operation.
    call_data: Vec<u8>,
    /// The token used for this operation (for metadata).
    token: MorphoToken,
}

impl Morpho {
    /// Creates a new deposit operation (approve token + deposit via MultiSend).
    ///
    /// # Arguments
    /// * `token` - The token to deposit.
    /// * `amount` - The amount of tokens to deposit (in the token's smallest unit).
    /// * `receiver` - The address that will receive the vault shares.
    ///
    /// # Returns
    /// A `Morpho` struct configured for a deposit operation.
    pub fn deposit(token: MorphoToken, amount: U256, receiver: Address) -> Self {
        let token_address = token.token_address();

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
            token,
        }
    }

    /// Creates a new withdraw operation (approve vault token + withdraw via MultiSend).
    ///
    /// # Arguments
    /// * `token` - The token to withdraw (maps to the corresponding vault token).
    /// * `amount` - The amount of tokens to withdraw (in the token's smallest unit).
    /// * `receiver` - The address that will receive the withdrawn tokens.
    /// * `owner` - The address that owns the vault shares.
    ///
    /// # Returns
    /// A `Morpho` struct configured for a withdraw operation.
    pub fn withdraw(
        token: MorphoToken,
        amount: U256,
        receiver: Address,
        owner: Address,
    ) -> Self {
        let vault_token_address = token.vault_token_address();

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
            token,
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

        // First byte contains the token program ID
        let mut metadata_bytes = [0u8; 10];
        metadata_bytes[0] = self.token.program_id();

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

    use super::*;

    #[test]
    fn test_morpho_deposit_wld() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let morpho = Morpho::deposit(MorphoToken::WLD, U256::from(1_000_000), receiver);

        let call_data = morpho.as_execute_user_op_call_data();
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_deposit_usdc() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let morpho =
            Morpho::deposit(MorphoToken::USDC, U256::from(1_000_000), receiver);

        let call_data = morpho.as_execute_user_op_call_data();
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_withdraw_wld() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let owner =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let morpho =
            Morpho::withdraw(MorphoToken::WLD, U256::from(1_000_000), receiver, owner);

        let call_data = morpho.as_execute_user_op_call_data();
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_withdraw_usdc() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let owner =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let morpho =
            Morpho::withdraw(MorphoToken::USDC, U256::from(1_000_000), receiver, owner);

        let call_data = morpho.as_execute_user_op_call_data();
        assert!(!call_data.is_empty());
    }

    #[test]
    fn test_morpho_token_addresses() {
        assert_eq!(MorphoToken::WLD.token_address(), WLD_TOKEN_ADDRESS);
        assert_eq!(MorphoToken::WBTC.token_address(), WBTC_TOKEN_ADDRESS);
        assert_eq!(MorphoToken::WETH.token_address(), WETH_TOKEN_ADDRESS);
        assert_eq!(MorphoToken::USDC.token_address(), USDC_TOKEN_ADDRESS);
    }

    #[test]
    fn test_morpho_vault_token_addresses() {
        assert_eq!(
            MorphoToken::WLD.vault_token_address(),
            MORPHO_VAULT_WLD_TOKEN_ADDRESS
        );
        assert_eq!(
            MorphoToken::WBTC.vault_token_address(),
            MORPHO_VAULT_WBTC_TOKEN_ADDRESS
        );
        assert_eq!(
            MorphoToken::WETH.vault_token_address(),
            MORPHO_VAULT_WETH_TOKEN_ADDRESS
        );
        assert_eq!(
            MorphoToken::USDC.vault_token_address(),
            MORPHO_VAULT_USDC_TOKEN_ADDRESS
        );
    }

    #[test]
    fn test_morpho_deposit_preflight_user_operation_nonce_v1() {
        let receiver =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let morpho = Morpho::deposit(MorphoToken::WLD, U256::from(1_000_000), receiver);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = morpho.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::MorphoDeposit as u8);
        assert_eq!(be[6], 0u8); // instruction flags default

        // Metadata byte 0 should contain the program ID (WLD = 0)
        assert_eq!(be[7], MorphoToken::WLD.program_id());

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_morpho_program_ids() {
        assert_eq!(MorphoToken::WLD.program_id(), 0);
        assert_eq!(MorphoToken::USDC.program_id(), 1);
        assert_eq!(MorphoToken::WETH.program_id(), 2);
        assert_eq!(MorphoToken::WBTC.program_id(), 3);
    }

    #[test]
    fn test_contract_addresses() {
        assert_eq!(
            MORPHO_VAULT_ADDRESS,
            Address::from_str("0xb1e80387ebe53ff75a89736097d34dc8d9e9045b").unwrap()
        );
    }
}
