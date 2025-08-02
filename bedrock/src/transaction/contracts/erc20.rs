//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::SolCall,
};

use crate::{
    primitives::PrimitiveError,
    smart_account::{ISafe4337Module, Is4337Encodable, SafeOperation, UserOperation},
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
    call_data: Vec<u8>,
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
    fn into_user_operation(self) -> Result<UserOperation, PrimitiveError> {
        let user_op_call_data = ISafe4337Module::executeUserOpCall {
            to: self.token_address,
            value: U256::ZERO,
            data: self.call_data.into(),
            operation: SafeOperation::Call as u8,
        }
        .abi_encode();

        todo!("todo");
    }
}
