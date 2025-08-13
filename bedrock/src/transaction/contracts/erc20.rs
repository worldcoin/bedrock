//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    encode_nonce_v1, ISafe4337Module, InstructionFlags, Is4337Encodable, NonceKeyV1,
    SafeOperation, TransactionTypeId, UserOperation,
};

sol! {
    /// The ERC20 contract interface.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-20>
    /// Reference: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol>
    #[derive(serde::Serialize)]
    interface IErc20 {
        function transfer(address to, uint256 value) external returns (bool);
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
}

impl Is4337Encodable for Erc20 {
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
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        // Nonce v1: transfers have no subtype/metadata (all zeros)
        let key = NonceKeyV1::new(
            TransactionTypeId::Transfer,
            InstructionFlags::default(),
            [0u8; 10],
        );
        let nonce = encode_nonce_v1(key.to_bytes(), 0u64);

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
    fn test_erc20_preflight_user_operation_nonce_v1() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = erc20.as_preflight_user_operation(wallet).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();
        assert_eq!(be[0], TransactionTypeId::Transfer as u8);
        assert_eq!(&be[1..=5], b"bdrck");
        assert_eq!(be[6], 0u8); // instruction flags default
                                // transfer has no subtype/metadata (zeros)
        assert_eq!(&be[7..=16], &[0u8; 10]);
        // sequence must be zero
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
