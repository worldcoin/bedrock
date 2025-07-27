use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use bedrock_macros::bedrock_export;

use crate::{
    contracts::erc20::IERC20, primitives::ParseFromForeignBinding,
    smart_account::SafeTransaction,
};

mod erc20;

/// Exposes common operations for key smart contracts. This will return a `SafeTransaction` which can be then signed and executed.
#[derive(uniffi::Object)]
pub struct CommonContracts {}

/// Errors that can occur when interacting with the common contracts.
#[crate::bedrock_error]
pub enum ContractsError {
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error(transparent)]
    PrimitiveError(#[from] crate::primitives::PrimitiveError),
}

#[bedrock_export]
impl CommonContracts {
    /// Allows executing an ERC-20 token transfer.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    pub fn transfer(
        &self,
        token_address: &str,
        to_address: &str,
        amount: &str,
    ) -> Result<SafeTransaction, ContractsError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?; // TODO: see if we type tokens
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let calldata = IERC20::transferCall {
            to: to_address,
            value: amount,
        }
        .abi_encode();

        let tx = SafeTransaction::with_defaults(
            token_address.to_string(),
            format!("0x{}", hex::encode(&calldata)),
            "0".to_string(), // TODO: Implement correct nonce
        );

        Ok(tx)
    }
}
