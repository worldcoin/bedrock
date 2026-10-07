//! This module defines the interface for the legacy `USDVault` contract.
//!
//! This is **not** an ERC-4626 compliant vault.
//!
//! Historically, `USDVault` existed before the introduction of ERC-4626-based
//! vault architecture. Despite its name, `USDVault` is technically not a vault.
//! It is a simple conversion contract that allows swapping for verified users:
//!
//! - USDC → sDAI
//! - sDAI → USDC
//!
//! The conversion rate is fetched from the `IDSROracle` contract.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::transactions::contracts::{
    erc4626::{is_eth_call_revert, IERC4626},
    multisend::{MultiSend, MultiSendTx},
};
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

/// The legacy `USDVault` deployments on World Chain (same interface, different limits).
pub const USD_LEGACY_VAULT_ADDRESSES: [Address; 2] = [
    address!("0xB0e31149c03F1300BD9fF8C165B1fa38fDA2F0bB"),
    address!("0x6F1D98034D3055684F989f3Ac9832eC37B3F22EC"),
];

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
    /// Reference: <https://explorer.worldchain.worldcoin.org/address/0xB0e31149c03F1300BD9fF8C165B1fa38fDA2F0bB?tab=contract>
    #[derive(serde::Serialize)]
    interface USDVault {
        function USDC() public view returns (address);
        function SDAI() public view returns (address);

        function getDSRConversionRate() public view returns (uint256);

        function LIMIT_WITHDRAWALS_TO_DEPOSITS() public view returns (bool);
        function sDAIBalances(address account) public view returns (uint256);

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
    pub call_data: Bytes,
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

    /// Checks that the vault will redeem `sdai_amount` sDAI for `user_address`.
    ///
    /// Some deployments only redeem up to what the account deposited through them
    /// (`LIMIT_WITHDRAWALS_TO_DEPOSITS`, tracked in `sDAIBalances`); redeeming more reverts on
    /// execution. A vault without that limit, or without these getters, is not restricted.
    ///
    /// # Errors
    ///
    /// Returns an `RpcError` if the deposit limit would be exceeded or an RPC call fails.
    pub async fn ensure_withdrawal_allowed(
        rpc_client: &RpcClient,
        network: Network,
        usd_vault_address: Address,
        user_address: Address,
        sdai_amount: U256,
    ) -> Result<(), RpcError> {
        let limit_call_data =
            USDVault::LIMIT_WITHDRAWALS_TO_DEPOSITSCall {}.abi_encode();
        let limited = match rpc_client
            .eth_call(network, usd_vault_address, limit_call_data.into())
            .await
        {
            Ok(result) if result.len() >= 32 => result[31] != 0,
            // No such getter: this deployment has no deposit limit.
            Ok(_) => false,
            Err(RpcError::RpcResponseError {
                code,
                error_message,
            }) if is_eth_call_revert(code, &error_message) => false,
            Err(e) => return Err(e),
        };
        if !limited {
            return Ok(());
        }

        let deposited_call_data = USDVault::sDAIBalancesCall {
            account: user_address,
        }
        .abi_encode();
        let result = rpc_client
            .eth_call(network, usd_vault_address, deposited_call_data.into())
            .await?;
        if result.len() < 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid sDAIBalances() response: expected at least 32 bytes, got {} bytes",
                    result.len()
                ),
            });
        }
        let deposited = U256::from_be_slice(&result[..32]);

        if deposited < sdai_amount {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Cannot migrate - USDVault only redeems up to the amount deposited through it (deposited={deposited}, sdai_balance={sdai_amount})"
                ),
            });
        }
        Ok(())
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
                    "Asset address mismatch between USDVault and ERC-4626 Vault"
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
            call_data: bundle.data.into(),
            action: TransactionTypeId::USDVaultMigration,
            to: crate::transactions::contracts::multisend::MULTISEND_ADDRESS,
            operation: SafeOperation::DelegateCall,
        })
    }
}

impl Is4337Encodable for UsdLegacyVault {
    type MetadataArg = ();

    fn build_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.to,
            value: U256::ZERO,
            data: self.call_data.clone(),
            operation: self.operation as u8,
        }
        .abi_encode()
        .into()
    }

    fn build_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.build_execute_user_op_call_data();

        let key = NonceKeyV1::new(self.action, InstructionFlag::Default, [0u8; 10]);
        let nonce = key.encode();

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transactions::rpc::RpcClient;
    use alloy::{
        node_bindings::{Anvil, AnvilInstance},
        primitives::utils::parse_units,
        providers::ProviderBuilder,
    };
    use std::sync::Arc;

    const VAULT: Address = address!("0xB0e31149c03F1300BD9fF8C165B1fa38fDA2F0bB");
    const USER: Address = address!("0x4564420674EA68fcc61b463C0494807C759d47e6");

    fn word(value: U256) -> String {
        format!("0x{}", hex::encode(value.to_be_bytes::<32>()))
    }

    /// Mocks the vault's limit flag and the user's recorded deposits (when given). Calls without
    /// a mock fall through to the returned anvil node, which must outlive the client.
    fn rpc_client(
        limited: Option<bool>,
        deposited: Option<U256>,
    ) -> (RpcClient, AnvilInstance) {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());
        let mut http_client = crate::test_utils::AnvilBackedHttpClient::new(provider);
        if let Some(limited) = limited {
            http_client.set_response_for_address_and_data(
                VAULT,
                format!(
                    "0x{}",
                    hex::encode(
                        USDVault::LIMIT_WITHDRAWALS_TO_DEPOSITSCall {}.abi_encode()
                    )
                ),
                word(U256::from(u8::from(limited))),
            );
        }
        if let Some(deposited) = deposited {
            http_client.set_response_for_address_and_data(
                VAULT,
                format!(
                    "0x{}",
                    hex::encode(
                        USDVault::sDAIBalancesCall { account: USER }.abi_encode()
                    )
                ),
                word(deposited),
            );
        }
        (RpcClient::new(Arc::new(http_client)), anvil)
    }

    async fn check(client: &RpcClient, sdai_amount: u64) -> Result<(), RpcError> {
        UsdLegacyVault::ensure_withdrawal_allowed(
            client,
            Network::WorldChain,
            VAULT,
            USER,
            U256::from(sdai_amount),
        )
        .await
    }

    #[tokio::test]
    async fn withdrawal_above_recorded_deposits_is_rejected() {
        let (client, _anvil) = rpc_client(Some(true), Some(U256::from(5u64)));
        let error = check(&client, 10).await.unwrap_err();
        let message = error.to_string();
        assert!(
            message.contains("Cannot migrate - USDVault only redeems up to"),
            "{message}"
        );
        assert!(message.contains("deposited=5"), "{message}");
        assert!(message.contains("sdai_balance=10"), "{message}");
    }

    #[tokio::test]
    async fn withdrawal_within_recorded_deposits_is_allowed() {
        let (client, _anvil) = rpc_client(Some(true), Some(U256::from(10u64)));
        check(&client, 10).await.unwrap();
    }

    #[tokio::test]
    async fn unlimited_vault_is_not_restricted() {
        // No `sDAIBalances` mock: it must not even be read.
        let (client, _anvil) = rpc_client(Some(false), None);
        check(&client, 10).await.unwrap();
    }

    #[tokio::test]
    async fn vault_without_the_limit_getter_is_not_restricted() {
        // No mocks: the call goes to an address without code and returns nothing.
        let (client, _anvil) = rpc_client(None, None);
        check(&client, 10).await.unwrap();
    }

    #[test]
    fn test_calculate_usdc_amount() {
        let sdai_amount = parse_units("10", 18).unwrap().into(); // 10 sDAI
        let rate = U256::from_str_radix("1172270944672187612903813109", 10).unwrap();

        let result = UsdLegacyVault::calculate_usdc_amount(sdai_amount, rate)
            .expect("Should calculate successfully");

        // Expected result: 11722709 (USDC with 6 decimals)
        let expected = U256::from(11_722_709u64);
        assert_eq!(result, expected);
    }
}
