//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::smart_account::{ISafe4337Module, Is4337Operable, SafeOperation};

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
    /// The Safe Smart Account address from where the transaction will be executed.
    wallet_address: Address,
}

impl Erc20 {
    pub fn new(
        token_address: Address,
        to: Address,
        value: U256,
        wallet_address: Address,
    ) -> Self {
        let call_data = IErc20::transferCall { to, value }.abi_encode();

        Self {
            call_data,
            token_address,
            wallet_address,
        }
    }
}

impl Is4337Operable for Erc20 {
    /// Sensible gas limit for ERC-20 transfer.
    const CALL_GAS_LIMIT: u128 = 65_000;

    fn wallet_address(&self) -> &Address {
        &self.wallet_address
    }

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
            Address::from_str("0x0000000000000000000000000000000000000000").unwrap(),
        );

        let execute_user_op_call_data = erc20.as_execute_user_op_call_data();

        // generated with `chisel`
        let expected_call_data = bytes!("0x7bb374280000000000000000000000002cfc85d8e48f8eab294be644d9e25c30308630030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000");

        assert_eq!(execute_user_op_call_data, expected_call_data);
    }
}
