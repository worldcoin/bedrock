use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;

use crate::{
    primitives::{HexEncodedData, Network, ParseFromForeignBinding},
    smart_account::{Is4337Encodable, SafeSmartAccount},
    transaction::contracts::erc20::Erc20,
};

mod contracts;
pub mod foreign;
pub mod rpc;

pub use rpc::{RpcClient, RpcError, SponsorUserOperationResponse};

/// Errors that can occur when interacting with transaction operations.
#[crate::bedrock_error]
pub enum TransactionError {
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error(transparent)]
    PrimitiveError(#[from] crate::primitives::PrimitiveError),
}

/// Extensions to `SafeSmartAccount` to enable high-level APIs for transactions.
#[bedrock_export]
impl SafeSmartAccount {
    /// Allows executing an ERC-20 token transfer on World Chain.
    ///
    /// # Arguments
    /// - `token_address`: The address of the ERC-20 token to transfer.
    /// - `to_address`: The address of the recipient.
    /// - `amount`: The amount of tokens to transfer.
    /// - `http_client`: The authenticated HTTP client for making RPC requests.
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use bedrock::smart_account::SafeSmartAccount;
    /// use bedrock::transaction::TransactionError;
    /// use bedrock::primitives::Network;
    ///
    /// # async fn example() -> Result<(), TransactionError> {
    /// // Assume we have a configured SafeSmartAccount
    /// # let safe_account = SafeSmartAccount::new("test_key".to_string(), "0x1234567890123456789012345678901234567890").unwrap();
    ///
    /// // Transfer USDC on World Chain
    /// let tx_hash = safe_account.transaction_transfer(
    ///     Network::WorldChain,
    ///     "0x79A02482A880BCE3F13E09Da970dC34DB4cD24d1", // USDC on World Chain
    ///     "0x1234567890123456789012345678901234567890",
    ///     "1000000", // 1 USDC (6 decimals)
    /// ).await?;
    ///
    /// println!("Transaction hash: {}", tx_hash.to_hex_string());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    /// - Will throw an RPC error if the transaction submission fails.
    /// - Will throw an error if the global HTTP client has not been initialized.
    pub async fn transaction_transfer(
        &self,
        network: Network,
        token_address: &str,
        to_address: &str,
        amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?;
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        // Sign and execute the transaction (uses global RPC client automatically)
        let user_op_hash = transaction
            .sign_and_execute(network, self, None)
            .await
            .map_err(|e| TransactionError::Generic {
                message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }
}
