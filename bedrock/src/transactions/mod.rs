use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;
use rand::RngCore;
use std::sync::Arc;

use alloy::primitives::aliases::{U160, U48};

use crate::{
    primitives::{HexEncodedData, Network, ParseFromForeignBinding},
    smart_account::{Is4337Encodable, Permit2Approve, SafeSmartAccount},
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
pub mod custom_bundler;
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

    /// Sets a Permit2 allowance for a spender on a specific token via the `IAllowanceTransfer.approve` method.
    ///
    /// This calls the Permit2 contract's `approve(token, spender, amount, expiration)` function,
    /// granting the spender permission to transfer tokens via Permit2's allowance-based mechanism.
    ///
    /// Note: The Safe must have already approved the Permit2 contract on the ERC-20 token
    /// (via a standard ERC-20 `approve`) before the spender can use the Permit2 allowance.
    ///
    /// # Arguments
    /// - `token_address`: The ERC-20 token address to set the allowance for.
    /// - `spender_address`: The address being granted permission to transfer tokens via Permit2.
    /// - `amount`: The maximum amount of tokens the spender can transfer, as a stringified `uint160`.
    /// - `expiration`: The timestamp after which the allowance expires, as a stringified `uint48`.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    /// - Will throw an RPC error if the transaction submission fails.
    /// - Will throw an error if the global HTTP client has not been initialized.
    pub async fn transaction_permit2_approve(
        &self,
        token_address: &str,
        spender_address: &str,
        amount: &str,
        expiration: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let token_address = Address::parse_from_ffi(token_address, "token_address")?;
        let spender_address =
            Address::parse_from_ffi(spender_address, "spender_address")?;
        let amount = U160::parse_from_ffi(amount, "amount")?;
        let expiration = U48::parse_from_ffi(expiration, "expiration")?;

        let transaction =
            Permit2Approve::new(token_address, spender_address, amount, expiration);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute Permit2 approve: {e}"),
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
        let transaction: WorldCampaignManager =
            WorldCampaignManager::claim(campaign_id);

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute transaction: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Deposits tokens into an ERC4626 vault on World Chain.
    ///
    /// This method uses the generic ERC4626 implementation that queries the vault's
    /// asset address and checks the user's balance before creating the transaction.
    ///
    /// # Arguments
    /// - `vault_address`: The address of the ERC4626 vault contract.
    /// - `asset_amount`: The amount of assets to deposit as a stringified integer with the asset's decimals.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if the vault address or `asset_amount` is invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_erc4626_deposit(
        &self,
        vault_address: &str,
        asset_amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let vault_address = Address::parse_from_ffi(vault_address, "vault_address")?;
        let asset_amount = U256::parse_from_ffi(asset_amount, "asset_amount")?;
        let receiver = self.wallet_address;

        // Get the RPC client and create the ERC4626 deposit transaction
        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;
        let transaction =
            crate::transactions::contracts::erc4626::Erc4626Vault::deposit(
                rpc_client,
                Network::WorldChain,
                vault_address,
                asset_amount,
                receiver,
                [0u8; 10], // metadata
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create ERC4626 deposit: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute ERC4626 deposit: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Withdraws assets from an ERC4626 vault on World Chain.
    ///
    /// This method uses the generic ERC4626 implementation that queries the vault's
    /// share balance and automatically handles share-limited scenarios by switching to redeem.
    ///
    /// # Arguments
    /// - `vault_address`: The address of the ERC4626 vault contract.
    /// - `asset_amount`: The amount of assets to withdraw as a stringified integer with the asset's decimals.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if the vault address or `asset_amount` is invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_erc4626_withdraw(
        &self,
        vault_address: &str,
        asset_amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let vault_address = Address::parse_from_ffi(vault_address, "vault_address")?;
        let asset_amount = U256::parse_from_ffi(asset_amount, "asset_amount")?;
        let receiver = self.wallet_address;

        // Get the RPC client and create the ERC4626 withdraw transaction
        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;
        let transaction =
            crate::transactions::contracts::erc4626::Erc4626Vault::withdraw(
                rpc_client,
                Network::WorldChain,
                vault_address,
                asset_amount,
                receiver,
                [0u8; 10], // metadata
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create ERC4626 withdraw: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute ERC4626 withdraw: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Redeems shares from an ERC4626 vault on World Chain.
    ///
    /// This method uses the generic ERC4626 implementation that queries the vault's
    /// share balance before creating the transaction.
    ///
    /// # Arguments
    /// - `vault_address`: The address of the ERC4626 vault contract.
    /// - `share_amount`: The amount of shares to redeem as a stringified integer.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if the vault address or `share_amount` is invalid.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    pub async fn transaction_erc4626_redeem(
        &self,
        vault_address: &str,
        share_amount: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let vault_address = Address::parse_from_ffi(vault_address, "vault_address")?;
        let share_amount = U256::parse_from_ffi(share_amount, "share_amount")?;
        let receiver = self.wallet_address;

        // Get the RPC client and create the ERC4626 redeem transaction
        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;
        let transaction =
            crate::transactions::contracts::erc4626::Erc4626Vault::redeem(
                rpc_client,
                Network::WorldChain,
                vault_address,
                share_amount,
                receiver,
                [0u8; 10], // metadata
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create ERC4626 redeem: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute ERC4626 redeem: {e}"),
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
