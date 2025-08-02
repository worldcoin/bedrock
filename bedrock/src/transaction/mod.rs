use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;

use crate::{
    primitives::{HexEncodedData, ParseFromForeignBinding},
    transaction::contracts::erc20::Erc20,
};

mod contracts;
pub mod foreign;

/// Exposes common transactions for key smart contracts.
#[derive(uniffi::Object)]
pub struct CommonTransaction {}

/// Errors that can occur when interacting with transaction operations.
#[crate::bedrock_error]
pub enum TransactionError {
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error(transparent)]
    PrimitiveError(#[from] crate::primitives::PrimitiveError),
}

#[bedrock_export]
impl CommonTransaction {
    /// Allows executing an ERC-20 token transfer.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    pub fn transfer(
        &self,
        token_address: &str,
        to_address: &str,
        amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?; // TODO: see if we type tokens
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        // simulated tx hash
        Ok(HexEncodedData::new("0x123456")?)
    }
}
