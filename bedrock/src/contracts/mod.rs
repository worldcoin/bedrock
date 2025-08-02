use alloy::{
    primitives::{Address, U256},
    sol_types::SolCall,
};
use bedrock_macros::bedrock_export;

use crate::{
    contracts::erc20::Erc20,
    primitives::{HexEncodedData, ParseFromForeignBinding},
    smart_account::{EncodedSafeOpStruct, SafeTransaction},
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
    ) -> Result<HexEncodedData, ContractsError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?; // TODO: see if we type tokens
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        // simulated tx hash
        Ok(HexEncodedData::new("0x123456")?)
    }
}
