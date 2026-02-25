//! Permit2 contract interface and helpers for ERC20 approval batching.
//!
//! The Permit2 contract requires that each ERC20 token has granted it a max allowance
//! before Permit2-based transfers can work. This module provides helpers to batch
//! those ERC20 approvals into a single MultiSend transaction.
//!
//! Reference: <https://docs.uniswap.org/contracts/permit2/overview>

use alloy::primitives::{address, Address, Bytes, U256};
use alloy::sol_types::SolCall;

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};

use super::erc20::Erc20;
use super::multisend::{MultiSend, MultiSendTx};

/// The canonical Permit2 contract address (same across all EVM chains).
///
/// Reference: <https://docs.uniswap.org/contracts/v4/deployments#worldchain-480>
pub static PERMIT2_ADDRESS: Address =
    address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

/// Token addresses on WorldChain (chain ID 480) that should have max ERC20 approval to Permit2.
pub const WORLDCHAIN_PERMIT2_TOKENS: [(Address, &str); 4] = [
    (
        address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1"),
        "usdc",
    ),
    (
        address!("0x4200000000000000000000000000000000000006"),
        "weth",
    ),
    (
        address!("0x03c7054bcb39f7b2e5b2c7acb37583e32d70cfa3"),
        "wbtc",
    ),
    (
        address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003"),
        "wld",
    ),
];

/// Batched ERC20 `approve(PERMIT2_ADDRESS, type(uint256).max)` calls via MultiSend.
///
/// Builds a single 4337 `UserOperation` that grants the Permit2 contract max allowance
/// on each of the given token contracts. This is a prerequisite for Permit2-based transfers.
pub struct Permit2Erc20ApprovalBatch {
    call_data: Vec<u8>,
    to: Address,
    operation: SafeOperation,
}

impl Permit2Erc20ApprovalBatch {
    /// Creates a new batch of ERC20 approvals to Permit2.
    ///
    /// # Arguments
    /// * `tokens` - The ERC20 token addresses to approve.
    #[must_use]
    pub fn new(tokens: &[Address]) -> Self {
        let approve_data = Erc20::encode_approve(PERMIT2_ADDRESS, U256::MAX);

        let entries: Vec<MultiSendTx> = tokens
            .iter()
            .map(|token| MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: *token,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.clone().into(),
            })
            .collect();

        let bundle = MultiSend::build_bundle(&entries);

        Self {
            call_data: bundle.data,
            to: bundle.to,
            operation: bundle.operation,
        }
    }
}

impl Is4337Encodable for Permit2Erc20ApprovalBatch {
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
            TransactionTypeId::Permit2Approve,
            InstructionFlag::Default,
            [0u8; 10],
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
    use super::*;
    use crate::transactions::contracts::erc20::IErc20;
    use crate::transactions::contracts::multisend::MULTISEND_ADDRESS;

    #[test]
    fn test_worldchain_permit2_tokens_count() {
        assert_eq!(WORLDCHAIN_PERMIT2_TOKENS.len(), 4);
    }

    #[test]
    fn test_batch_targets_multisend_via_delegatecall() {
        let tokens = vec![
            address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1"),
            address!("0x4200000000000000000000000000000000000006"),
        ];
        let batch = Permit2Erc20ApprovalBatch::new(&tokens);

        assert_eq!(batch.to, MULTISEND_ADDRESS);
        assert!(matches!(batch.operation, SafeOperation::DelegateCall));
    }

    #[test]
    fn test_batch_execute_user_op_targets_multisend() {
        let tokens = vec![address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1")];
        let batch = Permit2Erc20ApprovalBatch::new(&tokens);

        let call_data = batch.as_execute_user_op_call_data();
        let call_data_bytes: &[u8] = &call_data;

        // executeUserOp selector is 0x7bb37428
        assert_eq!(&call_data_bytes[0..4], &[0x7b, 0xb3, 0x74, 0x28]);

        // `to` param (bytes 4..36) should be the MultiSend address
        let mut expected_to = [0u8; 32];
        expected_to[12..32].copy_from_slice(MULTISEND_ADDRESS.as_slice());
        assert_eq!(&call_data_bytes[4..36], &expected_to);
    }

    #[test]
    fn test_batch_inner_approve_calldata() {
        let expected = IErc20::approveCall {
            spender: PERMIT2_ADDRESS,
            value: U256::MAX,
        }
        .abi_encode();

        let actual = Erc20::encode_approve(PERMIT2_ADDRESS, U256::MAX);
        assert_eq!(actual, expected);
    }
}
