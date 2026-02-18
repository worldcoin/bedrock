//! This module introduces USD Vault contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::transactions::contracts::{erc4626::IERC4626, multisend::{MultiSend, MultiSendTx}};
use crate::transactions::rpc::{RpcClient, RpcError};
use crate::{
    primitives::HexEncodedData,
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
};
use crate::{
    primitives::{Network, PrimitiveError},
    transactions::contracts::erc4626::Erc4626Vault,
};
use crate::{smart_account::PERMIT2_ADDRESS, transactions::contracts::erc20::Erc20};

/// Permit2 data for secure token transfers.
#[derive(Debug, Clone)]
pub struct Permit2Data {
    /// The permit2 signature for authorization.
    pub signature: HexEncodedData,
    /// The nonce for the permit2 transfer.
    pub nonce: U256,
    /// The deadline for the permit2 transfer.
    pub deadline: U256,
}

sol! {
    /// The USD Vault contract interface.
    /// Reference: <https://worldchain-mainnet.explorer.alchemy.com/address/0xB0e31149c03F1300BD9fF8C165B1fa38fDA2F0bB?tab=contract>
    #[derive(serde::Serialize)]
    interface USDVault {
        function USDC() public view returns (address);
        function SDAI() public view returns (address);

        function getDSRConversionRate() public view returns (uint256);

        function redeemSDAI(
            address recipient,
            uint256 amountIn,
            uint256 amountOutMin,
            uint256 nonce,
            uint256 deadline,
            bytes signature
        ) external;
    }
}

/// Represents a USD Vault migration transaction bundle.
#[derive(Debug)]
pub struct UsdLegacyVault {
    /// The encoded call data for the operation.
    pub call_data: Vec<u8>,
    /// The action type.
    action: TransactionTypeId,
    /// The target address for the operation.
    to: Address,
    /// The Safe operation type for the operation.
    operation: SafeOperation,
}

impl UsdLegacyVault {
    async fn fetch_conversion_rate(
        rpc_client: &RpcClient,
        network: Network,
        vault_address: Address,
    ) -> Result<U256, RpcError> {
        let call_data = USDVault::getDSRConversionRateCall {}.abi_encode();
        let result = rpc_client
            .eth_call(network, vault_address, call_data.into())
            .await?;

        // Ensure the response is exactly 32 bytes (standard ABI encoding for uint256)
        if result.len() != 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid {}() response: expected exactly 32 bytes, got {} bytes",
                    "getDSRConversionRate",
                    result.len()
                ),
            });
        }

        Ok(U256::from_be_slice(&result[..32]))
    }

    /// Fetches the user's sDAI balance from the USD Vault.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if:
    /// - The RPC call to fetch the sDAI address fails
    /// - The RPC call to fetch the user's balance fails
    pub async fn fetch_sdai_balance(
        rpc_client: &RpcClient,
        network: Network,
        usd_vault_address: Address,
        user_address: Address,
    ) -> Result<(Address, U256), RpcError> {
        let sdai_call_data = USDVault::SDAICall {}.abi_encode();
        let sdai_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            usd_vault_address,
            sdai_call_data,
        )
        .await?;

        let balance =
            Erc20::fetch_balance(rpc_client, network, sdai_address, user_address)
                .await?;
        Ok((sdai_address, balance))
    }

    /// Calculates USDC amount from sDAI amount and conversion rate.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if:
    /// - Decimal factor parsing fails
    /// - Multiplication overflow occurs
    /// - Division by zero occurs
    fn calculate_usdc_amount(sdai_amount: U256, rate: U256) -> Result<U256, RpcError> {
        let decimal_factor = U256::from_str_radix(
            "1000000000000000000000000000000000000000", // 1e39
            10,
        )
        .map_err(|e| RpcError::InvalidResponse {
            error_message: format!("Failed to parse decimal factor: {e}"),
        })?;

        sdai_amount
            .checked_mul(rate)
            .ok_or_else(|| RpcError::InvalidResponse {
                error_message: "Multiplication overflow when calculating USDC amount"
                    .to_string(),
            })?
            .checked_div(decimal_factor)
            .ok_or_else(|| RpcError::InvalidResponse {
                error_message: "Division by zero when calculating USDC amount"
                    .to_string(),
            })
    }

    /// Fetches USDC and sDAI addresses from the USD Vault.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if:
    /// - The RPC call to fetch the USDC address fails
    /// - The RPC call to fetch the sDAI address fails
    async fn fetch_vault_addresses(
        rpc_client: &RpcClient,
        network: Network,
        usd_vault_address: Address,
    ) -> Result<(Address, Address), RpcError> {
        let usdc_call_data = USDVault::USDCCall {}.abi_encode();
        let usdc_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            usd_vault_address,
            usdc_call_data,
        )
        .await?;

        let sdai_call_data = USDVault::SDAICall {}.abi_encode();
        let sdai_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            usd_vault_address,
            sdai_call_data,
        )
        .await?;

        Ok((usdc_address, sdai_address))
    }

    /// Creates a new migration operation (redeemSDAI + approve + deposit via `MultiSend`).
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if:
    /// - Any RPC call to fetch addresses fails
    /// - Asset addresses between USD Vault and ERC-4626 Vault don't match
    /// - Conversion rate fetching fails  
    /// - USDC amount calculation fails (overflow, decimal parsing, division by zero)
    /// - Permit signature is invalid
    /// - Balance fetching fails
    pub async fn migrate(
        rpc_client: &RpcClient,
        network: Network,
        usd_vault_address: Address,
        erc4626_vault_address: Address,
        sdai_amount: U256,
        user_address: Address,
        permit2_data: Permit2Data,
    ) -> Result<Self, RpcError> {
        let (usdc_address, sdai_address) =
            Self::fetch_vault_addresses(rpc_client, network, usd_vault_address).await?;

        let asset_call_data = IERC4626::assetCall {}.abi_encode();
        let asset_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            erc4626_vault_address,
            asset_call_data,
        )
        .await?;

        if usdc_address != asset_address {
            return Err(RpcError::InvalidResponse {
                error_message:
                    "Asset address mismatch between USD Vault and ERC-4626 Vault"
                        .to_string(),
            });
        }

        let rate =
            Self::fetch_conversion_rate(rpc_client, network, usd_vault_address).await?;

        let usdc_amount = Self::calculate_usdc_amount(sdai_amount, rate)?;

        let withdraw_all_data = USDVault::redeemSDAICall {
            recipient: user_address,
            amountIn: sdai_amount,
            amountOutMin: usdc_amount,
            nonce: permit2_data.nonce,
            deadline: permit2_data.deadline,
            signature: permit2_data
                .signature
                .to_vec()
                .map_err(|e| RpcError::InvalidResponse {
                    error_message: format!("Invalid permit signature: {e}"),
                })?
                .into(),
        }
        .abi_encode();

        let approve_data = Erc20::encode_approve(erc4626_vault_address, usdc_amount);

        let deposit_data = IERC4626::depositCall {
            assets: usdc_amount,
            receiver: user_address,
        }
        .abi_encode();

        let mut entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: usd_vault_address,
                value: U256::ZERO,
                data_length: U256::from(withdraw_all_data.len()),
                data: withdraw_all_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: usdc_address,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: erc4626_vault_address,
                value: U256::ZERO,
                data_length: U256::from(deposit_data.len()),
                data: deposit_data.into(),
            },
        ];

        let permit2_sdai_allowance = Erc20::fetch_allowance(
            rpc_client,
            network,
            sdai_address,
            user_address,
            PERMIT2_ADDRESS,
        )
        .await?;

        if permit2_sdai_allowance < sdai_amount {
            let approve_permit2_data =
                Erc20::encode_approve(PERMIT2_ADDRESS, U256::MAX);
            entries.insert(
                0,
                MultiSendTx {
                    operation: SafeOperation::Call as u8,
                    to: sdai_address,
                    value: U256::ZERO,
                    data_length: U256::from(approve_permit2_data.len()),
                    data: approve_permit2_data.into(),
                },
            );
        }

        let bundle = MultiSend::build_bundle(&entries);

        Ok(Self {
            call_data: bundle.data,
            action: TransactionTypeId::USDVaultMigration,
            to: crate::transactions::contracts::multisend::MULTISEND_ADDRESS,
            operation: SafeOperation::DelegateCall,
        })
    }
}

impl Is4337Encodable for UsdLegacyVault {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.to,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: self.operation as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let key = NonceKeyV1::new(self.action, InstructionFlag::Default, [0u8; 10]);
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}
