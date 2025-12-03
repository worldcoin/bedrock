use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;
use rand::RngCore;
use std::sync::Arc;

use crate::{
    primitives::{HexEncodedData, Network, ParseFromForeignBinding},
    smart_account::{Is4337Encodable, SafeSmartAccount},
    transactions::{
        contracts::{
            erc20::{Erc20, TransferAssociation},
            world_campaign_manager::WorldCampaignManager,
            world_gift_manager::WorldGiftManager,
        },
        rpc::{get_rpc_client, WaGetUserOperationReceiptResponse},
    },
};

pub mod contracts;
pub use contracts::world_campaign_manager::world_campaign_manager_address;
pub mod foreign;
pub mod rpc;

pub use rpc::{RpcClient, RpcError, RpcProviderName, SponsorUserOperationResponse};

/// Errors that can occur when interacting with transaction operations.
#[crate::bedrock_error]
pub enum TransactionError {
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error("Primitive error: {0}")]
    PrimitiveError(String),
}

impl From<crate::primitives::PrimitiveError> for TransactionError {
    fn from(e: crate::primitives::PrimitiveError) -> Self {
        Self::PrimitiveError(e.to_string())
    }
}

/// Return value from the World Gift Manager methods
#[allow(missing_docs)]
#[derive(uniffi::Record, Clone, Debug)]
pub struct WorldGiftManagerResult {
    pub user_op_hash: Arc<HexEncodedData>,
    pub gift_id: Arc<HexEncodedData>,
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
    /// use bedrock::transactions::TransactionError;
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
        token_address: &str,
        to_address: &str,
        amount: &str,
        transfer_association: Option<TransferAssociation>,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?;
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let transaction = Erc20::new(token_address, to_address, amount);

        let metadata = crate::transactions::contracts::erc20::MetadataArg {
            association: transfer_association,
        };

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, Some(metadata), provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Sends a gift using the `WorldGiftManager` contract.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the provided attributes are invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_world_gift_manager_gift(
        &self,
        token_address: &str,
        to_address: &str,
        amount: &str,
    ) -> Result<WorldGiftManagerResult, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?;
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let amount = U256::parse_from_ffi(amount, "amount")?;

        let mut gift_id = [0u8; 14];
        rand::thread_rng().fill_bytes(&mut gift_id);

        let transaction =
            WorldGiftManager::gift(token_address, to_address, amount, gift_id);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(WorldGiftManagerResult {
            user_op_hash: Arc::new(HexEncodedData::new(&user_op_hash.to_string())?),
            gift_id: Arc::new(HexEncodedData::new(&hex::encode(gift_id))?),
        })
    }

    /// Reddems a gift using the `WorldGiftManager` contract.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the provided attributes are invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_world_gift_manager_redeem(
        &self,
        gift_id_str: &str,
    ) -> Result<WorldGiftManagerResult, TransactionError> {
        let gift_id = U256::parse_from_ffi(gift_id_str, "gift_id")?;

        let transaction = WorldGiftManager::redeem(gift_id);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(WorldGiftManagerResult {
            user_op_hash: Arc::new(HexEncodedData::new(&user_op_hash.to_string())?),
            gift_id: Arc::new(HexEncodedData::new(gift_id_str)?),
        })
    }

    /// Cancel a gift using the `WorldGiftManager` contract.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the provided attributes are invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_world_gift_manager_cancel(
        &self,
        gift_id_str: &str,
    ) -> Result<WorldGiftManagerResult, TransactionError> {
        let gift_id = U256::parse_from_ffi(gift_id_str, "gift_id")?;

        let transaction = WorldGiftManager::cancel(gift_id);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(WorldGiftManagerResult {
            user_op_hash: Arc::new(HexEncodedData::new(&user_op_hash.to_string())?),
            gift_id: Arc::new(HexEncodedData::new(gift_id_str)?),
        })
    }

    /// Sponsors a campaign gift using the `WorldCampaignManager` contract.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the provided attributes are invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_world_campaign_manager_sponsor(
        &self,
        campaign_id_str: &str,
        to_address: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let campaign_id = U256::parse_from_ffi(campaign_id_str, "campaign_id")?;
        let to_address = Address::parse_from_ffi(to_address, "address")?;
        let transaction = WorldCampaignManager::sponsor(campaign_id, to_address);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Claims a campaign gift using the `WorldCampaignManager` contract.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the provided attributes are invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_world_campaign_manager_claim(
        &self,
        campaign_id_str: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let campaign_id = U256::parse_from_ffi(campaign_id_str, "campaign_id")?;
        let transaction = WorldCampaignManager::claim(campaign_id);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Gets a custom user operation receipt for a given user operation hash via the global RPC client.
    ///
    /// This is a convenience wrapper around [`RpcClient::wa_get_user_operation_receipt`]
    /// that uses the globally configured HTTP client.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The global HTTP client has not been initialized.
    /// - The HTTP request fails.
    /// - The request serialization fails.
    /// - The response parsing fails.
    /// - The RPC returns an error response.
    pub async fn wa_get_user_operation_receipt(
        &self,
        user_op_hash: &str,
    ) -> Result<WaGetUserOperationReceiptResponse, RpcError> {
        let client = get_rpc_client()?;

        // Retry while the receipt status is still "pending".
        let delay_ms = 2000u64; // duration of 1 OP block

        for attempt in 0..5 {
            let response = client
                .wa_get_user_operation_receipt(Network::WorldChain, user_op_hash)
                .await?;

            if response.status != "pending" || attempt == 4 {
                return Ok(response);
            }

            tokio::time::sleep(tokio::time::Duration::from_millis(delay_ms)).await;
        }

        // This line is technically unreachable due to the for-loop logic,
        // but is required to satisfy the type checker.
        unreachable!("wa_get_user_operation_receipt retry loop exited unexpectedly")
    }
}
