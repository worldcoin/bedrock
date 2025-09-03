use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;

use crate::{
    primitives::{HexEncodedData, Network, ParseFromForeignBinding},
    smart_account::{Is4337Encodable, SafeSmartAccount},
    transaction::contracts::erc20::{Erc20, TransferAssociation},
};

mod contracts;
pub mod foreign;
pub mod rpc;

pub use rpc::{RpcClient, RpcError, RpcProviderName, SponsorUserOperationResponse};

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
    /// Allows executing an ERC-20 token transfer **on World Chain**.
    ///
    /// # Arguments
    /// - `token_address`: The address of the ERC-20 token to transfer.
    /// - `to_address`: The address of the recipient.
    /// - `amount`: The amount of tokens to transfer as a stringified integer with the decimals of the token (e.g. 18 for USDC or WLD)
    /// - `transfer_association`: Metadata value. The association of the transfer.
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
    ///     "0x79A02482A880BCE3F13E09Da970dC34DB4cD24d1", // USDC on World Chain
    ///     "0x1234567890123456789012345678901234567890",
    ///     "1000000", // 1 USDC (6 decimals)
    ///     None,
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
        // TODO: Use struct for transaction parameters
        token_address: &str,
        to_address: &str,
        amount: &str,
        pbh: bool,
        provider: RpcProviderName,
        transfer_association: Option<TransferAssociation>,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?;
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        let metadata = crate::transaction::contracts::erc20::MetadataArg {
            association: transfer_association,
        };

        // NOTE: We use Alchemy as the default provider for now.
        let provider = RpcProviderName::Alchemy;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, pbh, Some(metadata), provider)
            .await
            .map_err(|e| TransactionError::Generic {
                message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }
}
