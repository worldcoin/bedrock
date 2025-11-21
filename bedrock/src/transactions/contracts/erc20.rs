//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};

sol! {
    /// The ERC20 contract interface.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-20>
    /// Reference: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol>
    #[derive(serde::Serialize)]
    interface IErc20 {
        function transfer(address to, uint256 value) external returns (bool);
          function approve(address spender, uint256 value) external returns (bool);
    }
}

/// Enables operations with the ERC-20 token contract.
pub struct Erc20 {
    /// The inner call data for the ERC-20 `transferCall` function.
    call_data: Vec<u8>,
    /// The address of the ERC-20 token contract.
    token_address: Address,
}

impl Erc20 {
    pub fn new(token_address: Address, to: Address, value: U256) -> Self {
        let call_data = IErc20::transferCall { to, value }.abi_encode();

        Self {
            call_data,
            token_address,
        }
    }
    pub fn encode_approve(spender: Address, value: U256) -> Vec<u8> {
        IErc20::approveCall { spender, value }.abi_encode()
    }
}

/// First byte of the metadata field. Index starts at 1 as 0 is reserved for "not set"
/// NOTE: Ordering should never change, only new values should be added
#[derive(Debug, uniffi::Enum)]
#[repr(u8)]
pub enum TransferAssociation {
    None = 1,
    XmtpMessage = 2,
}

pub struct MetadataArg {
    pub association: Option<TransferAssociation>,
}

impl Is4337Encodable for Erc20 {
    type MetadataArg = MetadataArg;

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            // The token address
            to: self.token_address,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: SafeOperation::Call as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let mut metadata_bytes: [u8; 10] = [0u8; 10];
        if let Some(metadata) = metadata {
            if let Some(association) = metadata.association {
                metadata_bytes[0] = association as u8;
            }
        }

        let key = NonceKeyV1::new(
            TransactionTypeId::Transfer,
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
    use alloy::primitives::bytes;
    use std::str::FromStr;

    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;

    use super::*;

    #[test]
    fn test_erc20_transfer() {
        let erc20 = Erc20::new(
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap(),
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            U256::from(1),
        );

        let execute_user_op_call_data = erc20.as_execute_user_op_call_data();

        // generated with `chisel`
        let expected_call_data = bytes!("0x7bb374280000000000000000000000002cfc85d8e48f8eab294be644d9e25c30308630030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000");

        assert_eq!(execute_user_op_call_data, expected_call_data);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_no_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = erc20.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8); // instruction flags default

        // Empty metadata
        assert_eq!(&be[7..=16], &[0u8; 10]);

        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_with_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();

        let metadata = MetadataArg {
            association: Some(TransferAssociation::XmtpMessage),
        };

        let user_op = erc20
            .as_preflight_user_operation(wallet, Some(metadata))
            .unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();
        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8);

        // Check metadata
        assert_eq!(be[7], TransferAssociation::XmtpMessage as u8);
        assert_eq!(&be[8..=16], &[0u8; 9]);

        // sequence must be zero
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
