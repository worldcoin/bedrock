use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;
use rand::{Rng, RngCore};
use std::sync::Arc;

use alloy::primitives::aliases::{U160, U48};

use crate::{
    primitives::{ntp::now_with_ntp, HexEncodedData, Network, ParseFromForeignBinding},
    smart_account::{
        Is4337Encodable, Permit2Approve, SafeSmartAccount, UnparsedPermitTransferFrom,
        UnparsedTokenPermissions, UserOperation, ENTRYPOINT_4337,
    },
    transactions::{
        contracts::{
            erc20::{Erc20, MetadataArg, TransferAssociation},
            usd_legacy_vault::Permit2Data,
            world_gift_manager::WorldGiftManager,
        },
        rpc::{
            get_rpc_client, PmSponsorUserOperationResponse, PmSponsorshipDecline,
            SponsorshipContext, WaGetUserOperationReceiptResponse,
        },
    },
};

pub mod contracts;
pub mod custom_bundler;
pub mod foreign;
pub mod rpc;

pub use rpc::{RpcClient, RpcError, RpcProviderName, SponsorUserOperationResponse};

// One initial estimate of the approval-plus-transfer batch and up to three
// re-estimates if the fee exceeds the approval. RPC errors are not retried.
const MAX_SELF_SPONSORSHIP_ESTIMATION_ATTEMPTS: usize = 4;

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

/// An unsigned World Chain `UserOperation` prepared for review before signing.
#[derive(Debug, uniffi::Object)]
pub struct PreparedTransaction {
    user_operation: UserOperation,
    fee_details: Option<PreparedTransactionFee>,
}

/// ERC-20 fee estimate for a prepared self-sponsored operation.
#[derive(Debug, Clone, uniffi::Record)]
pub struct PreparedTransactionFee {
    /// Fee token address.
    pub token_address: String,
    /// Paymaster that charges the fee token.
    pub paymaster_address: String,
    /// Estimated fee in token base units, as a decimal integer.
    pub estimated_cost_in_token: String,
    /// Policy reason for the original sponsorship decline.
    pub decline_reason: String,
}

#[bedrock_export]
impl PreparedTransaction {
    /// Returns the final fee estimate for the completed operation, if token paid.
    #[must_use]
    pub fn fee_details(&self) -> Option<PreparedTransactionFee> {
        self.fee_details.clone()
    }
}

fn parse_fee_estimate(
    decline: &PmSponsorshipDecline,
) -> Result<U256, TransactionError> {
    let estimate =
        U256::from_str_radix(&decline.estimated_cost_in_token, 10).map_err(|e| {
            TransactionError::Generic {
                error_message: format!("Invalid self-sponsorship fee estimate: {e}"),
            }
        })?;
    if estimate == U256::ZERO {
        return Err(TransactionError::Generic {
            error_message: "Self-sponsorship fee estimate must be positive".to_string(),
        });
    }
    Ok(estimate)
}

async fn prepare_self_sponsored_transfer(
    rpc_client: &RpcClient,
    wallet_address: Address,
    transaction: &Erc20,
    transfer_association: Option<TransferAssociation>,
    decline: &PmSponsorshipDecline,
) -> Result<PreparedTransaction, TransactionError> {
    let mut approval_amount = parse_fee_estimate(decline)?;
    for _ in 0..MAX_SELF_SPONSORSHIP_ESTIMATION_ATTEMPTS {
        let operation = transaction
            .clone()
            .with_fee_approval(
                decline.token,
                decline.paymaster_address,
                approval_amount,
            )
            .build_preflight_user_operation(
                wallet_address,
                Some(MetadataArg {
                    association: transfer_association,
                }),
            )?;

        // Re-evaluate the completed callData: the first advisory only
        // priced the transfer, before its approval was added.
        let final_advisory = rpc_client
            .pm_sponsor_user_operation(
                Network::WorldChain,
                &operation,
                *ENTRYPOINT_4337,
                &SponsorshipContext::Protocol,
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to estimate completed transaction: {e}"),
            })?;
        let PmSponsorUserOperationResponse::Declined(final_decline) = final_advisory
        else {
            return Err(TransactionError::Generic {
                error_message:
                    "Completed transaction no longer requires self-sponsorship"
                        .to_string(),
            });
        };
        if final_decline.token != decline.token
            || final_decline.paymaster_address != decline.paymaster_address
        {
            return Err(TransactionError::Generic {
                error_message:
                    "Self-sponsorship fee token or paymaster changed during preparation"
                        .to_string(),
            });
        }
        let final_cost = parse_fee_estimate(&final_decline)?;
        if final_cost > approval_amount {
            approval_amount = final_cost;
            continue;
        }

        let retry = rpc_client
            .pm_sponsor_user_operation(
                Network::WorldChain,
                &operation,
                *ENTRYPOINT_4337,
                &SponsorshipContext::SelfSponsoredToken(decline.token),
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to prepare token-paid transaction: {e}"),
            })?;
        let PmSponsorUserOperationResponse::Approved(approval) = retry else {
            return Err(TransactionError::Generic {
                error_message: "Token-paid sponsorship was declined".to_string(),
            });
        };
        if approval.paymaster != Some(decline.paymaster_address)
            || approval.paymaster_data.is_none()
            || approval.paymaster_verification_gas_limit.is_none()
            || approval.paymaster_post_op_gas_limit.is_none()
        {
            return Err(TransactionError::Generic {
                error_message:
                    "Token-paid sponsorship returned incomplete paymaster fields"
                        .to_string(),
            });
        }
        return Ok(PreparedTransaction {
            user_operation: operation.with_pm_sponsorship_approval(&approval),
            fee_details: Some(PreparedTransactionFee {
                token_address: decline.token.to_string(),
                paymaster_address: decline.paymaster_address.to_string(),
                estimated_cost_in_token: final_cost.to_string(),
                decline_reason: decline.reason.to_string(),
            }),
        });
    }
    Err(TransactionError::Generic {
        error_message: "Self-sponsorship fee did not stabilize".to_string(),
    })
}

/// Extensions to `SafeSmartAccount` to enable high-level APIs for transactions.
#[bedrock_export]
impl SafeSmartAccount {
    /// Prepares an unsigned ERC-20 transfer on World Chain.
    ///
    /// # Arguments
    /// - `token_address`: The address of the ERC-20 token to transfer.
    /// - `to_address`: The address of the recipient.
    /// - `amount`: The amount of tokens to transfer as a stringified integer with the decimals of the token (e.g. 18 for USDC or WLD)
    /// - `transfer_association`: Metadata value. The association of the transfer.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    /// - Will throw an RPC error if sponsorship preparation fails.
    /// - Will throw an error if the self-sponsored retry cannot be prepared.
    /// - Will throw an error if the global HTTP client has not been initialized.
    pub async fn prepare_transaction_transfer(
        &self,
        token_address: &str,
        to_address: &str,
        amount: &str,
        transfer_association: Option<TransferAssociation>,
    ) -> Result<PreparedTransaction, TransactionError> {
        let log_failure = |stage: &str, error: &dyn std::fmt::Display| {
            crate::error!(
                transaction_type = "erc20_transfer",
                network = Network::WorldChain.network_name(),
                sender = self.wallet_address,
                outcome = "error",
                stage = stage,
                error_message = error,
                "Failed to prepare ERC-20 transfer"
            );
        };

        let token_address = Address::parse_from_ffi(token_address, "token_address")
            .inspect_err(|e| {
                log_failure("parse_token_address", e);
            })?;
        let to_address =
            Address::parse_from_ffi(to_address, "address").inspect_err(|e| {
                log_failure("parse_to_address", e);
            })?;
        let amount = U256::parse_from_ffi(amount, "amount").inspect_err(|e| {
            log_failure("parse_amount", e);
        })?;

        let transaction = Erc20::new(token_address, to_address, amount);

        let metadata = MetadataArg {
            association: transfer_association,
        };

        let user_operation = transaction
            .build_preflight_user_operation(self.wallet_address, Some(metadata))
            .inspect_err(|e| {
                log_failure("build_user_operation", e);
            })?;
        let rpc_client = get_rpc_client().map_err(|e| {
            log_failure("get_rpc_client", &e);
            TransactionError::Generic {
                error_message: format!(
                    "Failed to get RPC client for ERC-20 transfer preparation: {e}"
                ),
            }
        })?;
        let sponsorship = rpc_client
            .pm_sponsor_user_operation(
                Network::WorldChain,
                &user_operation,
                *ENTRYPOINT_4337,
                &SponsorshipContext::Protocol,
            )
            .await
            .map_err(|e| {
                crate::error!(
                    transaction_type = "erc20_transfer",
                    network = Network::WorldChain.network_name(),
                    sender = self.wallet_address,
                    outcome = "error",
                    user_operation = format!("{user_operation:?}"),
                    error_message = e,
                    "Failed to request sponsorship for ERC-20 transfer"
                );
                TransactionError::Generic {
                    error_message: format!("Failed to request sponsorship: {e}"),
                }
            })?;

        let prepared_transaction = match sponsorship {
            PmSponsorUserOperationResponse::Approved(approval) => PreparedTransaction {
                user_operation: user_operation.with_pm_sponsorship_approval(&approval),
                fee_details: None,
            },
            PmSponsorUserOperationResponse::Declined(decline) => {
                crate::info!(
                    transaction_type = "erc20_transfer",
                    network = Network::WorldChain.network_name(),
                    sender = self.wallet_address,
                    outcome = "sponsorship_declined",
                    decline_reason = decline.reason,
                    "Sponsorship declined for ERC-20 transfer"
                );
                prepare_self_sponsored_transfer(
                    rpc_client,
                    self.wallet_address,
                    &transaction,
                    transfer_association,
                    &decline,
                )
                .await?
            }
        };

        crate::debug!(
            transaction_type = "erc20_transfer",
            network = Network::WorldChain.network_name(),
            sender = self.wallet_address,
            outcome = "prepared",
            "Prepared ERC-20 transfer"
        );

        Ok(prepared_transaction)
    }

    /// Signs and submits a previously prepared transaction on World Chain.
    ///
    /// # Errors
    /// - Will throw an error if the transaction was prepared for another account.
    /// - Will throw an RPC error if signing or submission fails.
    /// - Will throw an error if the global HTTP client has not been initialized.
    pub async fn submit_prepared_transaction(
        &self,
        prepared_transaction: &PreparedTransaction,
    ) -> Result<HexEncodedData, TransactionError> {
        let log_failure = |stage: &str, error: &dyn std::fmt::Display| {
            crate::error!(
                sender = prepared_transaction.user_operation.sender,
                wallet_address = self.wallet_address,
                network = Network::WorldChain.network_name(),
                outcome = "error",
                stage = stage,
                error_message = error,
                "Failed to submit prepared transaction"
            );
        };

        crate::info!(
            sender = prepared_transaction.user_operation.sender,
            network = Network::WorldChain.network_name(),
            "Submitting prepared transaction"
        );
        if prepared_transaction.user_operation.sender != self.wallet_address {
            log_failure(
                "validate_account",
                &"Prepared transaction belongs to another account",
            );
            return Err(TransactionError::Generic {
                error_message: "Prepared transaction belongs to another account"
                    .to_string(),
            });
        }

        let mut user_operation = prepared_transaction.user_operation.clone();
        self.sign_user_operation(&mut user_operation, Network::WorldChain)
            .map_err(|e| {
                log_failure("sign", &e);
                TransactionError::Generic {
                    error_message: format!("Failed to sign transaction: {e}"),
                }
            })?;

        let rpc_client = get_rpc_client().map_err(|e| {
            log_failure("get_rpc_client", &e);
            TransactionError::Generic {
                error_message: format!(
                    "Failed to get RPC client for transaction submission: {e}"
                ),
            }
        })?;
        let user_op_hash = rpc_client
            .send_user_operation_v2(
                Network::WorldChain,
                &user_operation,
                *ENTRYPOINT_4337,
            )
            .await
            .map_err(|e| {
                crate::error!(
                    user_operation = format!("{user_operation:?}"),
                    sender = user_operation.sender,
                    network = Network::WorldChain.network_name(),
                    outcome = "error",
                    error_message = e,
                    "Failed to submit prepared transaction"
                );
                TransactionError::Generic {
                    error_message: format!("Failed to submit transaction: {e}"),
                }
            })?;

        crate::info!(
            user_op_hash = user_op_hash,
            sender = user_operation.sender,
            network = Network::WorldChain.network_name(),
            "Submitted prepared transaction"
        );

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

    /// Migrates the full redeemable share balance from one ERC4626 vault to another on World Chain.
    ///
    /// This builds one atomic bundle with:
    /// 1. `redeem(shares)` on the source vault (`shares = min(balanceOf, maxRedeem)`)
    /// 2. `approve(assets)` on the underlying token for the destination vault
    /// 3. `deposit(assets)` into the destination vault
    ///
    /// The `assets` amount is snapshotted with `previewRedeem` when building the transaction,
    /// then reduced by a 0.03% haircut (Morpho SDK default slippage) for approve + deposit.
    /// If more assets are redeemed at execution time, the remainder stays as dust in the Safe.
    /// Destination `previewDeposit` must return a non-zero share amount or building fails.
    ///
    /// If source `maxRedeem < balanceOf`, only the redeemable portion moves; remaining source
    /// shares can be migrated in a later call. Do not gate Morpho V2 destinations on
    /// `maxDeposit` / `maxRedeem` (often 0 by design).
    ///
    /// # Arguments
    /// - `from_vault_address`: The source ERC4626 vault address.
    /// - `to_vault_address`: The destination ERC4626 vault address.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any argument is invalid.
    /// - Returns [`TransactionError::Generic`] if transaction creation or submission fails.
    pub async fn transaction_erc4626_migrate(
        &self,
        from_vault_address: &str,
        to_vault_address: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let from_vault_address =
            Address::parse_from_ffi(from_vault_address, "from_vault_address")?;
        let to_vault_address =
            Address::parse_from_ffi(to_vault_address, "to_vault_address")?;
        let receiver = self.wallet_address;

        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;
        let transaction =
            crate::transactions::contracts::erc4626::Erc4626Vault::migrate(
                rpc_client,
                Network::WorldChain,
                from_vault_address,
                to_vault_address,
                receiver,
                [0u8; 10], // metadata
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create ERC4626 migrate: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute ERC4626 migrate: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Migrates assets from a `WLDVault` to an ERC4626 vault on World Chain.
    ///
    /// This method withdraws all WLD tokens from the legacy `WLDVault` and deposits the
    /// equivalent amount into a new ERC4626-compliant vault. The migration process is
    /// atomic and executed as a single transaction bundle.
    ///
    /// Note: After migration, the user may have some dust WLD tokens left due to
    /// rounding differences in the conversion process.
    ///
    /// # Arguments
    /// - `wld_vault_address`: The address of the `WLDVault` contract to migrate from.
    /// - `erc4626_vault_address`: The address of the new ERC4626 vault contract to migrate to.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the vault addresses are invalid.
    /// - Returns [`TransactionError::Generic`] if the migration transaction creation fails.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    /// - Returns [`TransactionError::Generic`] if the global HTTP client has not been initialized.
    pub async fn transaction_wld_legacy_vault_migrate(
        &self,
        legacy_vault_address: &str,
        erc4626_vault_address: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let legacy_vault_address =
            Address::parse_from_ffi(legacy_vault_address, "legacy_vault_address")?;
        let erc4626_vault_address =
            Address::parse_from_ffi(erc4626_vault_address, "erc4626_vault_address")?;

        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;
        let transaction =
            crate::transactions::contracts::wld_legacy_vault::WldLegacyVault::migrate(
                rpc_client,
                Network::WorldChain,
                legacy_vault_address,
                erc4626_vault_address,
                self.wallet_address,
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create WLDVault migration: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute WLDVault migration: {e}"),
            })?;

        Ok(HexEncodedData::new(&user_op_hash.to_string())?)
    }

    /// Migrates assets from a USD Vault to an ERC4626 vault on World Chain.
    ///
    /// This method performs a complex migration process that includes:
    /// 1. Fetching the user's sDAI balance from the USD Vault
    /// 2. Creating a Permit2 signature for secure token transfer
    /// 3. Executing a multi-step transaction bundle:
    ///    - Redeeming sDAI for USDC from the USD Vault
    ///    - Approving the new vault to spend USDC
    ///    - Depositing USDC into the new ERC4626 vault
    ///
    /// The entire process is executed atomically using a `MultiSend` transaction bundle.
    ///
    /// # Arguments
    /// - `usd_vault_address`: The address of the USD Vault contract to migrate from.
    /// - `erc4626_vault_address`: The address of the ERC4626 vault contract to migrate to.
    ///
    /// # Errors
    /// - Returns [`TransactionError::PrimitiveError`] if any of the vault addresses are invalid.
    /// - Returns [`TransactionError::Generic`] if fetching the sDAI balance fails.
    /// - Returns [`TransactionError::Generic`] if the Permit2 signature creation fails.
    /// - Returns [`TransactionError::Generic`] if the migration transaction bundle creation fails.
    /// - Returns [`TransactionError::Generic`] if the transaction submission fails.
    /// - Returns [`TransactionError::Generic`] if the global HTTP client has not been initialized.
    pub async fn transaction_usd_legacy_vault_migrate(
        &self,
        legacy_vault_address: &str,
        erc4626_vault_address: &str,
    ) -> Result<HexEncodedData, TransactionError> {
        let legacy_vault_address =
            Address::parse_from_ffi(legacy_vault_address, "legacy_vault_address")?;
        let erc4626_vault_address =
            Address::parse_from_ffi(erc4626_vault_address, "erc4626_vault_address")?;

        // Get the RPC client and create the ERC4626 deposit transaction
        let rpc_client = get_rpc_client().map_err(|e| TransactionError::Generic {
            error_message: format!("Failed to get RPC client: {e}"),
        })?;

        let (sdai_address, sdai_amount) =
            crate::transactions::contracts::usd_legacy_vault::UsdLegacyVault::fetch_sdai_balance(
                rpc_client,
                Network::WorldChain,
                legacy_vault_address,
                self.wallet_address,
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to fetch sDAI balance: {e}"),
            })?;

        if sdai_amount.is_zero() {
            return Err(TransactionError::Generic {
                error_message: "Cannot migrate with zero sDAI balance".to_string(),
            });
        }

        let permitted = UnparsedTokenPermissions {
            token: sdai_address.to_string(),
            amount: sdai_amount.to_string(),
        };

        let nonce = {
            let mut rng = rand::thread_rng();
            U256::from_be_bytes(rng.gen::<[u8; 32]>())
        };

        let deadline = now_with_ntp().timestamp() + 180; // 3 minutes from now

        let transfer = UnparsedPermitTransferFrom {
            permitted,
            spender: legacy_vault_address.to_string(),
            nonce: nonce.to_string(),
            deadline: deadline.to_string(),
        };

        let signature = self
            .sign_permit2_transfer(Network::WorldChain as u32, transfer)
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to sign permit2 transfer: {e}"),
            })?;

        let permit2_data = Permit2Data {
            signature,
            nonce,
            deadline: U256::from(deadline),
        };

        let transaction =
            crate::transactions::contracts::usd_legacy_vault::UsdLegacyVault::migrate(
                rpc_client,
                Network::WorldChain,
                legacy_vault_address,
                erc4626_vault_address,
                sdai_amount,
                self.wallet_address,
                permit2_data,
            )
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to create USDVault migration: {e}"),
            })?;

        let provider = RpcProviderName::Any;

        let user_op_hash = transaction
            .sign_and_execute(self, Network::WorldChain, None, None, provider)
            .await
            .map_err(|e| TransactionError::Generic {
                error_message: format!("Failed to execute USDVault migration: {e}"),
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
