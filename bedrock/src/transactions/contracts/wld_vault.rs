use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::{Network, PrimitiveError};
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::transactions::contracts::erc20::{Erc20, IErc20};
use crate::transactions::contracts::erc4626::IERC4626;
use crate::transactions::contracts::multisend::{
    MultiSend, MultiSendTx, MULTISEND_ADDRESS,
};
use crate::transactions::rpc::{RpcClient, RpcError};

/// The WLD token address on World Chain.
pub const WLD_TOKEN_ADDRESS: Address =
    address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");

sol! {
    /// Interface for the WLD vault contract.
    #[derive(serde::Serialize)]
    interface IWldVault {
        /// Withdraws all of the caller's shares from the vault.
        function withdrawAll() external;
    }
}

// =============================================================================
// WLD Vault Migration Transaction Type
// =============================================================================

/// Represents a WLD vault migration operation.
///
/// This transaction bundles three operations:
/// 1. Withdraw all from the old WLD vault
/// 2. Approve the new vault to spend the asset
/// 3. Deposit into the new re7WLD Morpho vault
#[derive(Debug)]
pub struct WldVault {
    /// The encoded MultiSend call data for the operation.
    pub call_data: Vec<u8>,
    /// The target address for the operation (MultiSend contract).
    to: Address,
    /// The Safe operation type for the operation.
    operation: SafeOperation,
    /// Metadata for nonce generation.
    metadata: [u8; 10],
}

impl WldVault {
    /// Helper function to fetch and decode a U256 value from an RPC call.
    async fn fetch_u256(
        rpc_client: &RpcClient,
        network: Network,
        contract_address: Address,
        call_data: Vec<u8>,
        function_name: &str,
    ) -> Result<U256, RpcError> {
        let result = rpc_client
            .eth_call(network, contract_address, call_data.into())
            .await?;

        if result.len() != 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid {}() response: expected exactly 32 bytes, got {} bytes",
                    function_name,
                    result.len()
                ),
            });
        }

        Ok(U256::from_be_slice(&result[..32]))
    }

    /// Creates a new migration operation to move funds from the old WLD vault to the re7WLD Morpho vault.
    ///
    /// This operation:
    /// 1. Withdraws all from the old vault using `withdrawAll()`
    /// 2. Approves the new vault to spend the asset tokens
    /// 3. Deposits into the new re7WLD Morpho vault
    ///
    /// # Arguments
    /// * `rpc_client` - The RPC client for making blockchain queries.
    /// * `network` - The blockchain network to use.
    /// * `old_vault_address` - The address of the old WLD vault to withdraw from.
    /// * `new_vault_address` - The address of the new re7WLD Morpho vault to deposit into.
    /// * `user_address` - The address of the user performing the migration.
    /// * `metadata` - Protocol-specific metadata for nonce generation.
    ///
    /// # Returns
    /// A `WldVault` struct configured for the migration operation.
    ///
    /// # Errors
    /// Returns an error if:
    /// - The user has no shares in the old vault
    /// - The RPC calls fail
    pub async fn migrate_to_re7wld(
        rpc_client: &RpcClient,
        network: Network,
        old_vault_address: Address,
        new_vault_address: Address,
        user_address: Address,
        metadata: [u8; 10],
    ) -> Result<Self, RpcError> {
        // 1. Query the user's WLD balance in the old vault (includes accrued interest)
        let balance_call_data = IErc20::balanceOfCall {
            account: user_address,
        }
        .abi_encode();
        let wld_amount = Self::fetch_u256(
            rpc_client,
            network,
            old_vault_address,
            balance_call_data,
            "balanceOf",
        )
        .await?;

        // 2. Validate that the user has funds to migrate
        if wld_amount.is_zero() {
            return Err(RpcError::InvalidResponse {
                error_message: "Cannot migrate - user has no funds in the old vault"
                    .to_string(),
            });
        }

        // 3. Encode the withdrawAll call for the old vault
        let withdraw_all_data = IWldVault::withdrawAllCall {}.abi_encode();

        // 4. Encode the approve call (approve new vault to spend WLD)
        let approve_data = Erc20::encode_approve(new_vault_address, wld_amount);

        // 5. Encode the deposit call for the new vault
        let deposit_data = IERC4626::depositCall {
            assets: wld_amount,
            receiver: user_address,
        }
        .abi_encode();

        // 6. Build the MultiSend bundle (withdrawAll + approve + deposit)
        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: old_vault_address,
                value: U256::ZERO,
                data_length: U256::from(withdraw_all_data.len()),
                data: withdraw_all_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: WLD_TOKEN_ADDRESS,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: new_vault_address,
                value: U256::ZERO,
                data_length: U256::from(deposit_data.len()),
                data: deposit_data.into(),
            },
        ];

        let bundle = MultiSend::build_bundle(&entries);

        Ok(Self {
            call_data: bundle.data,
            to: MULTISEND_ADDRESS,
            operation: SafeOperation::DelegateCall,
            metadata,
        })
    }
}

impl Is4337Encodable for WldVault {
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

        let key = NonceKeyV1::new(
            TransactionTypeId::MorphoMigrate,
            InstructionFlag::Default,
            self.metadata,
        );
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

    /// Creates a test RPC client with mocked responses for migration queries
    fn setup_test_rpc_client(
        old_vault_address: Address,
        user_address: Address,
        wld_balance: U256,
    ) -> RpcClient {
        let anvil = Anvil::new().spawn();
        let provider = ProviderBuilder::new().connect_http(anvil.endpoint_url());

        let mut http_client = crate::test_utils::AnvilBackedHttpClient::new(provider);

        // Set response for balanceOf() call (user's WLD balance in old vault)
        let balance_call_data = IErc20::balanceOfCall {
            account: user_address,
        }
        .abi_encode();
        let mut padded_balance = [0u8; 32];
        padded_balance[..32].copy_from_slice(&wld_balance.to_be_bytes::<32>());
        let balance_response = format!("0x{}", hex::encode(padded_balance));
        http_client.set_response_for_address_and_data(
            old_vault_address,
            format!("0x{}", hex::encode(balance_call_data)),
            balance_response,
        );

        RpcClient::new(Arc::new(http_client))
    }

    #[tokio::test]
    async fn test_wld_vault_migrate_to_re7wld() {
        let old_vault_address =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let new_vault_address =
            Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();
        let user_address =
            Address::from_str("0x9bB365324EDeF7A608c316abBf1d88460c556AB0").unwrap();
        let metadata = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let wld_balance = U256::from(10u128.pow(18)); // 1 WLD

        let test_rpc_client =
            setup_test_rpc_client(old_vault_address, user_address, wld_balance);

        let migration = WldVault::migrate_to_re7wld(
            &test_rpc_client,
            Network::WorldChain,
            old_vault_address,
            new_vault_address,
            user_address,
            metadata,
        )
        .await
        .unwrap();

        assert_eq!(migration.operation as u8, SafeOperation::DelegateCall as u8);
        assert_eq!(migration.to, MULTISEND_ADDRESS);
        // Verify the call data is not empty (MultiSend bundle was created)
        assert!(!migration.call_data.is_empty());
    }

    #[tokio::test]
    async fn test_wld_vault_migrate_with_zero_balance_error() {
        let old_vault_address =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let new_vault_address =
            Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();
        let user_address =
            Address::from_str("0x9bB365324EDeF7A608c316abBf1d88460c556AB0").unwrap();
        let metadata = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

        let wld_balance = U256::from(0); // No funds

        let test_rpc_client =
            setup_test_rpc_client(old_vault_address, user_address, wld_balance);

        let result = WldVault::migrate_to_re7wld(
            &test_rpc_client,
            Network::WorldChain,
            old_vault_address,
            new_vault_address,
            user_address,
            metadata,
        )
        .await;

        assert!(result.is_err());
        let error = result.unwrap_err();
        assert!(error
            .to_string()
            .contains("Cannot migrate - user has no funds in the old vault"));
    }

    #[tokio::test]
    async fn test_wld_vault_preflight_user_operation() {
        let old_vault_address =
            Address::from_str("0x1111111111111111111111111111111111111111").unwrap();
        let new_vault_address =
            Address::from_str("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f").unwrap();
        let user_address =
            Address::from_str("0x9bB365324EDeF7A608c316abBf1d88460c556AB0").unwrap();
        let wallet_address =
            Address::from_str("0x545c97c6664e6f9c37b0e6e2b80e68954413f70b").unwrap();
        let metadata = [0u8; 10];

        let wld_balance = U256::from(10u128.pow(18));

        let test_rpc_client =
            setup_test_rpc_client(old_vault_address, user_address, wld_balance);

        let migration = WldVault::migrate_to_re7wld(
            &test_rpc_client,
            Network::WorldChain,
            old_vault_address,
            new_vault_address,
            user_address,
            metadata,
        )
        .await
        .unwrap();

        let user_op = migration
            .as_preflight_user_operation(wallet_address, None)
            .unwrap();

        // Check the nonce contains the correct transaction type
        let be: [u8; 32] = user_op.nonce.to_be_bytes();
        assert_eq!(be[5], TransactionTypeId::MorphoMigrate as u8);
    }
}
