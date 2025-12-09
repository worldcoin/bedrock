//! This module introduces a generic ERC-4626 vault contract interface.
//!
//! ERC-4626 is a standard for tokenized vaults that represent shares of a single underlying ERC-20 token.
//! This module provides a generic implementation that can be extended for specific vault protocols.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::{Network, PrimitiveError};
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::transactions::contracts::erc20::{Erc20, IErc20};
use crate::transactions::contracts::multisend::{MultiSend, MultiSendTx};
use crate::transactions::rpc::{RpcClient, RpcError};

sol! {
    /// The ERC-4626 vault contract interface.
    /// Reference: https://eips.ethereum.org/EIPS/eip-4626
    #[derive(serde::Serialize)]
    interface IERC4626 {
        // Core ERC-4626 functions
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
        function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares);
        function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);

        // View functions
        function asset() public view returns (address assetTokenAddress);
    }
}

// =============================================================================
// Generic ERC-4626 Transaction Types
// =============================================================================

/// Represents a generic ERC-4626 vault operation.
#[derive(Debug)]
pub struct Erc4626Vault {
    /// The encoded call data for the operation.
    pub call_data: Vec<u8>,
    /// The action type.
    action: TransactionTypeId,
    /// The target address for the operation.
    to: Address,
    /// The Safe operation type for the operation.
    operation: SafeOperation,
    /// The underlying asset address.
    #[allow(dead_code)]
    asset_address: Address,
    /// The vault address.
    #[allow(dead_code)]
    vault_address: Address,
    /// Metadata for nonce generation (protocol-specific).
    metadata: [u8; 10],
}

impl Erc4626Vault {
    /// Creates a new deposit operation (approve asset + deposit via `MultiSend`).
    ///
    /// This function queries the vault's underlying asset address and checks the receiver's
    /// balance before creating the approval and deposit transactions. It uses the minimum
    /// of the requested amount and the receiver's actual balance.
    ///
    /// # Arguments
    /// * `rpc_client` - The RPC client to use for queries.
    /// * `network` - The blockchain network to query.
    /// * `vault_address` - The vault contract address.
    /// * `asset_amount` - The amount of assets to deposit (in the asset's smallest unit).
    /// * `receiver` - The address that owns the asset tokens and will receive the vault shares.
    /// * `metadata` - Protocol-specific metadata for nonce generation.
    ///
    /// # Returns
    /// An `Erc4626Vault` struct configured for a deposit operation.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The asset amount is zero
    /// - The RPC call to query the asset address fails
    /// - The RPC call to query the receiver's balance fails
    pub async fn deposit(
        rpc_client: &RpcClient,
        network: Network,
        vault_address: Address,
        asset_amount: U256,
        receiver: Address,
        metadata: [u8; 10],
    ) -> Result<Self, RpcError> {
        // 1. Query the asset address from the vault contract
        let asset_call_data = IERC4626::assetCall {}.abi_encode();
        let asset_result = rpc_client
            .eth_call(network, vault_address, asset_call_data.into())
            .await?;

        // Decode the asset address from the result
        let asset_address = Address::from_slice(&asset_result[12..32]); // Last 20 bytes of 32-byte word

        // 2. Query the receiver's balance of the asset token
        let balance_call_data =
            IErc20::balanceOfCall { account: receiver }.abi_encode();
        let balance_result = rpc_client
            .eth_call(network, asset_address, balance_call_data.into())
            .await?;

        // Decode the balance from the result
        let balance = U256::from_be_slice(&balance_result);

        // 3. Use the minimum of the requested amount and the actual balance
        let actual_amount = asset_amount.min(balance);

        // 4. Validate that the actual amount is not zero (user has no balance)
        if actual_amount.is_zero() {
            return Err(RpcError::InvalidResponse {
                error_message: "Cannot deposit zero amount - user has no balance of the asset token".to_string(),
            });
        }

        // 5. Encode the approve call (approve asset to vault)
        let approve_data = Erc20::encode_approve(vault_address, actual_amount);

        // 6. Encode the deposit call
        let deposit_data = IERC4626::depositCall {
            assets: actual_amount,
            receiver,
        }
        .abi_encode();

        // 7. Build the MultiSend bundle (approve + deposit)
        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: asset_address,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: vault_address,
                value: U256::ZERO,
                data_length: U256::from(deposit_data.len()),
                data: deposit_data.into(),
            },
        ];

        let bundle = MultiSend::build_bundle(&entries);

        Ok(Self {
            call_data: bundle.data,
            action: TransactionTypeId::ERC4626Deposit,
            to: crate::transactions::contracts::multisend::MULTISEND_ADDRESS,
            operation: SafeOperation::DelegateCall,
            asset_address,
            vault_address,
            metadata,
        })
    }

    /// Creates a new withdraw operation (direct call to vault, no approval needed).
    ///
    /// # Arguments
    /// * `vault_address` - The vault contract address.
    /// * `asset_amount` - The amount of assets to withdraw.
    /// * `receiver` - The address that will receive the withdrawn assets.
    /// * `owner` - The address that owns the vault shares.
    /// * `metadata` - Protocol-specific metadata for nonce generation.
    ///
    /// # Returns
    /// An `Erc4626Vault` struct configured for a withdraw operation.
    #[must_use]
    pub fn withdraw(
        vault_address: Address,
        asset_amount: U256,
        receiver: Address,
        owner: Address,
        metadata: [u8; 10],
    ) -> Self {
        let withdraw_data = IERC4626::withdrawCall {
            assets: asset_amount,
            receiver,
            owner,
        }
        .abi_encode();

        Self {
            call_data: withdraw_data,
            action: TransactionTypeId::ERC4626Withdraw,
            to: vault_address,
            operation: SafeOperation::Call,
            asset_address: Address::ZERO, // Not needed for withdraw
            vault_address,
            metadata,
        }
    }

    /// Creates a new redeem operation (direct call to vault, no approval needed).
    ///
    /// # Arguments
    /// * `vault_address` - The vault contract address.
    /// * `share_amount` - The amount of shares to redeem.
    /// * `receiver` - The address that will receive the redeemed assets.
    /// * `owner` - The address that owns the vault shares.
    /// * `metadata` - Protocol-specific metadata for nonce generation.
    ///
    /// # Returns
    /// An `Erc4626Vault` struct configured for a redeem operation.
    #[must_use]
    pub fn redeem(
        vault_address: Address,
        share_amount: U256,
        receiver: Address,
        owner: Address,
        metadata: [u8; 10],
    ) -> Self {
        let redeem_data = IERC4626::redeemCall {
            shares: share_amount,
            receiver,
            owner,
        }
        .abi_encode();

        Self {
            call_data: redeem_data,
            action: TransactionTypeId::ERC4626Redeem,
            to: vault_address,
            operation: SafeOperation::Call,
            asset_address: Address::ZERO, // Not needed for redeem
            vault_address,
            metadata,
        }
    }
}

impl Is4337Encodable for Erc4626Vault {
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

        let key = NonceKeyV1::new(self.action, InstructionFlag::Default, self.metadata);
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use alloy::{node_bindings::Anvil, providers::ProviderBuilder};
    use std::str::FromStr;
    use std::sync::Arc;

    use crate::primitives::Network;
    use crate::transactions::rpc::RpcClient;

    use super::*;

    /// Creates a test RPC client with mocked responses for asset() and balanceOf() calls
    async fn setup_test_rpc_client(
        vault_address: Address,
        asset_address: Address,
        receiver: Address,
        balance: U256,
    ) -> RpcClient {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let mut http_client = crate::test_utils::AnvilBackedHttpClient::new(provider);

        // Set response for asset() call
        let asset_call_data = IERC4626::assetCall {}.abi_encode();
        let mut padded_asset = [0u8; 32];
        padded_asset[12..32].copy_from_slice(asset_address.as_slice());
        let asset_response = format!("0x{}", hex::encode(padded_asset));
        http_client.set_response_for_address_and_data(
            vault_address,
            format!("0x{}", hex::encode(asset_call_data)),
            asset_response,
        );

        // Set response for balanceOf() call
        let balance_call_data =
            IErc20::balanceOfCall { account: receiver }.abi_encode();
        let mut padded_balance = [0u8; 32];
        balance
            .to_be_bytes_vec()
            .iter()
            .rev()
            .enumerate()
            .for_each(|(i, &b)| {
                if i < 32 {
                    padded_balance[31 - i] = b;
                }
            });
        let balance_response = format!("0x{}", hex::encode(padded_balance));
        http_client.set_response_for_address_and_data(
            asset_address,
            format!("0x{}", hex::encode(balance_call_data)),
            balance_response,
        );

        RpcClient::new(Arc::new(http_client))
    }

    #[tokio::test]
    async fn test_erc4626_deposit() {
        let vault_address =
            Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();
        let asset_address =
            Address::from_str("0x2cfc85d8e48f8eab294be644d9e25c3030863003").unwrap();
        let receiver =
            Address::from_str("0x9bB365324EDeF7A608c316abBf1d88460c556AB0").unwrap();
        let metadata = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let deposit_amount = U256::from(10u128.pow(18)); // 1 WLD

        // Setup test RPC client that returns custom asset address and large balance
        let test_rpc_client = setup_test_rpc_client(
            vault_address,
            asset_address,
            receiver,
            deposit_amount,
        )
        .await;

        // Test deposit with test RPC client
        let vault = Erc4626Vault::deposit(
            &test_rpc_client,
            Network::WorldChain,
            vault_address,
            deposit_amount,
            receiver,
            metadata,
        )
        .await
        .unwrap();

        assert_eq!(vault.operation as u8, SafeOperation::DelegateCall as u8);
        assert_eq!(
            vault.to,
            crate::transactions::contracts::multisend::MULTISEND_ADDRESS
        );
        assert_eq!(hex::encode(vault.call_data), "8d80ff0a00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000132002cfc85d8e48f8eab294be644d9e25c303086300300000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044095ea7b3000000000000000000000000348831b46876d3df2db98bdec5e3b4083329ab9f0000000000000000000000000000000000000000000000000de0b6b3a764000000348831b46876d3df2db98bdec5e3b4083329ab9f000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000446e553f650000000000000000000000000000000000000000000000000de0b6b3a76400000000000000000000000000009bb365324edef7a608c316abbf1d88460c556ab00000000000000000000000000000");
    }

    #[tokio::test]
    async fn test_erc4626_deposit_with_zero_balance_error() {
        let vault_address =
            Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();
        let asset_address =
            Address::from_str("0x2cfc85d8e48f8eab294be644d9e25c3030863003").unwrap();
        let receiver =
            Address::from_str("0x9bB365324EDeF7A608c316abBf1d88460c556AB0").unwrap();
        let metadata = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        // Setup test RPC client where user has zero balance
        let test_rpc_client = setup_test_rpc_client(
            vault_address,
            asset_address,
            receiver,
            U256::from(0), // User has no balance
        )
        .await;

        // Test deposit should fail due to zero balance
        let result = Erc4626Vault::deposit(
            &test_rpc_client,
            Network::WorldChain,
            vault_address,
            U256::from(1_000_000),
            receiver,
            metadata,
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Cannot deposit zero amount - user has no balance"));
    }
}
