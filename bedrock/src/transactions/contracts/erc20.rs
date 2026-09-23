//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};
use crate::{
    primitives::{Network, PrimitiveError},
    transactions::{RpcClient, RpcError},
};

use super::multisend::{MultiSend, MultiSendTx};

sol! {
    /// The ERC20 contract interface.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-20>
    /// Reference: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol>
    #[derive(serde::Serialize)]
    interface IErc20 {
        function transfer(address to, uint256 value) external returns (bool);
        function approve(address spender, uint256 value) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function allowance(address owner, address spender) external view returns (uint256);
    }
}

/// Enables operations with the ERC-20 token contract.
#[derive(Clone)]
pub struct Erc20 {
    /// The inner call data for the ERC-20 `transferCall` function.
    call_data: Bytes,
    /// The address of the ERC-20 token contract.
    token_address: Address,
    to: Address,
    operation: SafeOperation,
}

impl Erc20 {
    /// Creates a new ERC-20 transfer operation.
    ///
    /// # Arguments
    /// * `token_address` - The address of the ERC-20 token contract.
    /// * `to` - The recipient address.
    /// * `value` - The amount of tokens to transfer.
    #[must_use]
    pub fn new(token_address: Address, to: Address, value: U256) -> Self {
        let call_data = IErc20::transferCall { to, value }.abi_encode().into();

        Self {
            call_data,
            token_address,
            to: token_address,
            operation: SafeOperation::Call,
        }
    }

    /// Prepends a fee-token approval to this transfer in one atomic Safe operation.
    #[must_use]
    pub(crate) fn with_fee_approval(
        mut self,
        fee_token: Address,
        paymaster: Address,
        value: U256,
    ) -> Self {
        let approval = Self::encode_approve(paymaster, value);
        let entries = [
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: fee_token,
                value: U256::ZERO,
                data_length: U256::from(approval.len()),
                data: approval.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: self.token_address,
                value: U256::ZERO,
                data_length: U256::from(self.call_data.len()),
                data: self.call_data,
            },
        ];
        let bundle = MultiSend::build_bundle(&entries);
        self.call_data = bundle.data.into();
        self.to = bundle.to;
        self.operation = bundle.operation;
        self
    }

    /// Encodes an ERC-20 approve call.
    ///
    /// # Arguments
    /// * `spender` - The address to approve.
    /// * `value` - The amount of tokens to approve.
    #[must_use]
    pub fn encode_approve(spender: Address, value: U256) -> Vec<u8> {
        IErc20::approveCall { spender, value }.abi_encode()
    }

    /// Fetches the current ERC-20 allowance for a given `owner` → `spender` pair.
    ///
    /// # Returns
    /// The current allowance as a `U256` value.
    ///
    /// # Errors
    /// Returns an `RpcError` if the RPC call fails or if the response is invalid.
    pub async fn fetch_allowance(
        rpc_client: &RpcClient,
        network: Network,
        token: Address,
        owner: Address,
        spender: Address,
    ) -> Result<U256, RpcError> {
        let call_data = IErc20::allowanceCall { owner, spender }.abi_encode();
        let result = rpc_client
            .eth_call(network, token, call_data.into())
            .await?;

        if result.len() != 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid {}() response: expected exactly 32 bytes, got {} bytes",
                    "allowance",
                    result.len()
                ),
            });
        }

        Ok(U256::from_be_slice(&result[..32]))
    }

    /// Fetches the current ERC-20 balance for a given `account`.
    ///
    /// # Returns
    /// The current balance as a `U256` value.
    ///
    /// # Errors
    /// Returns an `RpcError` if the RPC call fails or if the response is invalid.
    pub async fn fetch_balance(
        rpc_client: &RpcClient,
        network: Network,
        token: Address,
        account: Address,
    ) -> Result<U256, RpcError> {
        let call_data = IErc20::balanceOfCall { account }.abi_encode();
        let result = rpc_client
            .eth_call(network, token, call_data.into())
            .await?;

        if result.len() != 32 {
            return Err(RpcError::InvalidResponse {
                error_message: format!(
                    "Invalid {}() response: expected exactly 32 bytes, got {} bytes",
                    "balanceOf",
                    result.len()
                ),
            });
        }

        Ok(U256::from_be_slice(&result[..32]))
    }

    /// Encodes an ERC-20 allowance call.
    ///
    /// # Arguments
    /// * `owner` - The token owner address.
    /// * `spender` - The spender address.
    #[must_use]
    pub fn encode_allowance(owner: Address, spender: Address) -> Vec<u8> {
        IErc20::allowanceCall { owner, spender }.abi_encode()
    }

    /// Encodes an ERC-20 `balanceOf` call.
    #[must_use]
    pub fn encode_balance_of(account: Address) -> Vec<u8> {
        IErc20::balanceOfCall { account }.abi_encode()
    }
}

/// Batched ERC-20 `approve(spender, amount)` calls via `MultiSend`.
///
/// One 4337 `UserOperation` granting `spender` a specific allowance on each
/// token. Unlike [`BatchPermit2Approval`](super::permit2::BatchPermit2Approval)
/// the spender and the per-token amounts are both callers' choice.
pub struct BatchErc20Approval {
    call_data: Bytes,
    to: Address,
    operation: SafeOperation,
    transaction_type: TransactionTypeId,
}

impl BatchErc20Approval {
    /// Batches `approve(spender, amount)` for each `(token, amount)` pair.
    ///
    /// `transaction_type` tags the nonce key, so each caller's approvals get
    /// their own transaction class.
    #[must_use]
    pub fn new(
        spender: Address,
        approvals: &[(Address, U256)],
        transaction_type: TransactionTypeId,
    ) -> Self {
        let entries: Vec<MultiSendTx> = approvals
            .iter()
            .map(|(token, amount)| {
                let data = Self::encode_approve(spender, *amount);
                MultiSendTx {
                    operation: SafeOperation::Call as u8,
                    to: *token,
                    value: U256::ZERO,
                    data_length: U256::from(data.len()),
                    data: data.into(),
                }
            })
            .collect();

        let bundle = MultiSend::build_bundle(&entries);

        Self {
            call_data: bundle.data.into(),
            to: bundle.to,
            operation: bundle.operation,
            transaction_type,
        }
    }

    fn encode_approve(spender: Address, value: U256) -> Vec<u8> {
        IErc20::approveCall { spender, value }.abi_encode()
    }
}

impl Is4337Encodable for BatchErc20Approval {
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
        let key =
            NonceKeyV1::new(self.transaction_type, InstructionFlag::Default, [0u8; 10]);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            key.encode(),
            self.build_execute_user_op_call_data(),
        ))
    }
}

/// First byte of the metadata field. Index starts at 1 as 0 is reserved for "not set".
/// NOTE: Ordering should never change, only new values should be added.
#[derive(Debug, Clone, Copy, uniffi::Enum)]
#[repr(u8)]
pub enum TransferAssociation {
    /// No association.
    None = 1,
    /// Transfer associated with an XMTP message.
    XmtpMessage = 2,
}

/// Metadata argument for ERC-20 transfer operations.
pub struct MetadataArg {
    /// Optional transfer association metadata.
    pub association: Option<TransferAssociation>,
}

impl Is4337Encodable for Erc20 {
    type MetadataArg = MetadataArg;

    fn build_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            // The token address
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
        metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.build_execute_user_op_call_data();

        let mut metadata_bytes: [u8; 10] = [0u8; 10];
        if let Some(metadata) = metadata {
            if let Some(association) = metadata.association {
                metadata_bytes[0] = association as u8;
            }
        }

        let key = NonceKeyV1::new(
            TransactionTypeId::Transfer,
            InstructionFlag::Default,
            metadata_bytes,
        );
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
    use alloy::primitives::bytes;
    use std::str::FromStr;

    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;
    use crate::transactions::contracts::multisend::{IMultiSend, MULTISEND_ADDRESS};

    use super::*;

    #[test]
    fn test_erc20_transfer() {
        let erc20 = Erc20::new(
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap(),
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            U256::from(1),
        );

        let execute_user_op_call_data = erc20.build_execute_user_op_call_data();

        // generated with `chisel`
        let expected_call_data = bytes!("0x7bb374280000000000000000000000002cfc85d8e48f8eab294be644d9e25c30308630030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000");

        assert_eq!(execute_user_op_call_data, expected_call_data);
    }

    #[test]
    fn test_fee_approval_precedes_transfer_in_one_user_operation() {
        let transfer_token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let fee_token =
            Address::from_str("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1").unwrap();
        let paymaster =
            Address::from_str("0x0000000000000039cd5e8aE05257CE51C473ddd1").unwrap();
        let recipient =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let operation = Erc20::new(transfer_token, recipient, U256::from(7))
            .with_fee_approval(fee_token, paymaster, U256::from(12));
        let call_data = operation.build_execute_user_op_call_data();
        let safe_call =
            ISafe4337Module::executeUserOpCall::abi_decode_raw(&call_data[4..])
                .unwrap();
        assert_eq!(safe_call.to, MULTISEND_ADDRESS);
        assert_eq!(safe_call.operation, SafeOperation::DelegateCall as u8);
        let batch =
            IMultiSend::multiSendCall::abi_decode_raw(&safe_call.data[4..]).unwrap();
        let approval = Erc20::encode_approve(paymaster, U256::from(12));
        let transfer = IErc20::transferCall {
            to: recipient,
            value: U256::from(7),
        }
        .abi_encode();
        let first_len = 85 + approval.len();
        assert_eq!(batch.transactions.len(), first_len + 85 + transfer.len());
        assert_eq!(&batch.transactions[1..21], fee_token.as_slice());
        assert_eq!(&batch.transactions[85..first_len], approval);
        assert_eq!(
            &batch.transactions[first_len + 1..first_len + 21],
            transfer_token.as_slice()
        );
        assert_eq!(&batch.transactions[first_len + 85..], transfer);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_no_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = erc20.build_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8); // instruction flags default

        // Empty metadata
        assert_eq!(&be[7..=16], &[0u8; 10]);

        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_with_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();

        let metadata = MetadataArg {
            association: Some(TransferAssociation::XmtpMessage),
        };

        let user_op = erc20
            .build_preflight_user_operation(wallet, Some(metadata))
            .unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();
        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8);

        // Check metadata
        assert_eq!(be[7], TransferAssociation::XmtpMessage as u8);
        assert_eq!(&be[8..=16], &[0u8; 9]);

        // sequence must be zero
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
