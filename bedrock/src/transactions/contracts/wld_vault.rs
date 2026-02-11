//! This module introduces WLD Vault contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::transactions::contracts::erc20::{Erc20, IErc20};
use crate::transactions::contracts::multisend::{MultiSend, MultiSendTx};
use crate::transactions::rpc::{RpcClient, RpcError};
use crate::{
    primitives::{Network, PrimitiveError},
    transactions::contracts::erc4626::Erc4626Vault,
};

sol! {
    #[derive(serde::Serialize)]
    interface WLDVault {
        function token() public view returns (address);
        function withdrawAll() external;
    }

    /// The ERC-4626 vault contract interface.
    /// Reference: <https://eips.ethereum.org/EIPS/eip-4626>
    /// Reference: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/extensions/ERC4626.sol>
    #[derive(serde::Serialize)]
    interface IERC4626 {
        function asset() public view returns (address assetTokenAddress);
        function deposit(uint256 assets, address receiver) external returns (uint256 shares);
    }
}

/// Represents a WLD Vault migration transaction bundle.
#[derive(Debug)]
pub struct WldVault {
    /// The encoded call data for the operation.
    pub call_data: Vec<u8>,
    /// The action type.
    action: TransactionTypeId,
    /// The target address for the operation.
    to: Address,
    /// The Safe operation type for the operation.
    operation: SafeOperation,
    /// Metadata for nonce generation (protocol-specific).
    metadata: [u8; 10],
}

impl WldVault {
    /// Constructs a WLD Vault migration transaction bundle.
    pub async fn migrate(
        rpc_client: &RpcClient,
        network: Network,
        wld_vault_address: Address,
        erc4626_vault_address: Address,
        user: Address,
        metadata: [u8; 10],
    ) -> Result<Self, RpcError> {
        let token_call_data = WLDVault::tokenCall {}.abi_encode();
        let token_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            wld_vault_address,
            token_call_data,
        )
        .await?;

        let asset_call_data = IERC4626::assetCall {}.abi_encode();
        let asset_address = Erc4626Vault::fetch_asset_address(
            rpc_client,
            network,
            erc4626_vault_address,
            asset_call_data,
        )
        .await?;

        if token_address != asset_address {
            return Err(RpcError::InvalidResponse {
                error_message:
                    "Asset address mismatch between WLD Vault and ERC-4626 Vault"
                        .to_string(),
            });
        }

        let balance_call_data =
            IErc20::balanceOfCall { account: user }.abi_encode();
        let balance = Erc4626Vault::fetch_balance(
            rpc_client,
            network,
            asset_address,
            balance_call_data,
            "balanceOf",
        )
        .await?;

        if balance.is_zero() {
            return Err(RpcError::InvalidResponse {
                error_message: "Cannot deposit zero amount - user has no balance of the asset token".to_string(),
            });
        }

        let withdraw_all_data = WLDVault::withdrawAllCall {}.abi_encode();

        let approve_data = Erc20::encode_approve(erc4626_vault_address, balance);

        let deposit_data = IERC4626::depositCall {
            assets: balance,
            receiver: user,
        }
        .abi_encode();

        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: wld_vault_address,
                value: U256::ZERO,
                data_length: U256::from(withdraw_all_data.len()),
                data: withdraw_all_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: asset_address,
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

        let bundle = MultiSend::build_bundle(&entries);

        Ok(Self {
            call_data: bundle.data,
            action: TransactionTypeId::WLDVaultMigration,
            to: crate::transactions::contracts::multisend::MULTISEND_ADDRESS,
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

        let key = NonceKeyV1::new(self.action, InstructionFlag::Default, self.metadata);
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}
