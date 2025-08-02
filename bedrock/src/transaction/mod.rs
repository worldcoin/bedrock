use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;

use crate::{
    primitives::{HexEncodedData, ParseFromForeignBinding},
    smart_account::{Is4337Encodable, SafeSmartAccount},
    transaction::contracts::erc20::Erc20,
};

mod contracts;
pub mod foreign;

/// Errors that can occur when interacting with transaction operations.
#[crate::bedrock_error]
pub enum TransactionError {
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error(transparent)]
    PrimitiveError(#[from] crate::primitives::PrimitiveError),
}

/// Extensions to SafeSmartAccount to enable high-level APIs for transactions.
#[bedrock_export]
impl SafeSmartAccount {
    /// Allows executing an ERC-20 token transfer.
    ///
    /// # Arguments
    /// - `token_address`: The address of the ERC-20 token to transfer.
    /// - `to_address`: The address of the recipient.
    /// - `amount`: The amount of tokens to transfer.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    pub fn transaction_transfer(
        &self,
        token_address: &str,
        to_address: &str,
        amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?; // TODO: see if we type tokens
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        let user_op = transaction.as_preflight_user_operation(
            self.wallet_address,
            U256::ZERO, // FIXME: compute proper nonce
            65_000,     // sensible gas limit for ERC-20 transfer
        )?;

        // TODO: next step is to send the user op to the RPC for `wa_sponsorUserOperation`
        dbg!(&user_op);

        // simulated tx hash
        Ok(HexEncodedData::new("0x123456")?)
    }
}
