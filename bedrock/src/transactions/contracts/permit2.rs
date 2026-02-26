//! Permit2 contract interface and helpers for ERC20 approval batching.
//!
//! The Permit2 contract requires that each ERC20 token has granted it a max allowance
//! before Permit2-based transfers can work. This module provides helpers to batch
//! those ERC20 approvals into a single MultiSend transaction.
//!
//! Reference: <https://docs.uniswap.org/contracts/permit2/overview>

use alloy::primitives::{Address, Bytes, U256};
use alloy::sol_types::SolCall;

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};

use super::erc20::Erc20;
use super::multisend::{MultiSend, MultiSendTx};
pub use super::worldchain::{PERMIT2_ADDRESS, WORLDCHAIN_PERMIT2_TOKENS};

/// Batched ERC20 `approve(PERMIT2_ADDRESS, type(uint256).max)` calls via `MultiSend`.
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
    use alloy::primitives::address;

    #[test]
    fn test_batch_execute_user_op_calldata() {
        let usdc = address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1");
        let weth = address!("0x4200000000000000000000000000000000000006");
        let tokens = vec![usdc, weth];
        let batch = Permit2Erc20ApprovalBatch::new(&tokens);

        let call_data = batch.as_execute_user_op_call_data();
        let call_data_bytes: &[u8] = &call_data;

        // Decode the outer executeUserOp(to, value, data, operation) call
        // Skip the 4-byte selector
        let decoded =
            ISafe4337Module::executeUserOpCall::abi_decode_raw(&call_data_bytes[4..])
                .unwrap();
        assert_eq!(decoded.to, MULTISEND_ADDRESS, "should target MultiSend");
        assert_eq!(decoded.value, U256::ZERO, "should send no ETH");
        assert_eq!(
            decoded.operation,
            SafeOperation::DelegateCall as u8,
            "should use delegatecall"
        );

        // Decode the inner multiSend(transactions) call
        let multisend_call =
            super::super::multisend::IMultiSend::multiSendCall::abi_decode_raw(
                &decoded.data[4..],
            )
            .unwrap();
        let packed = multisend_call.transactions;

        // Each packed entry: 1 byte operation + 20 bytes to + 32 bytes value + 32 bytes data_length + N bytes data
        // approve(address,uint256) calldata is 4 + 32 + 32 = 68 bytes
        let approve_data = Erc20::encode_approve(PERMIT2_ADDRESS, U256::MAX);
        assert_eq!(approve_data.len(), 68);
        let entry_size = 1 + 20 + 32 + 32 + approve_data.len(); // 153

        assert_eq!(packed.len(), entry_size * 2, "should have 2 packed entries");

        // Verify each packed entry
        for (i, token) in [usdc, weth].iter().enumerate() {
            let offset = i * entry_size;
            let entry = &packed[offset..offset + entry_size];

            // operation byte (0 = Call)
            assert_eq!(entry[0], SafeOperation::Call as u8);
            // to address (20 bytes)
            assert_eq!(&entry[1..21], token.as_slice());
            // value (32 bytes, should be zero)
            assert_eq!(&entry[21..53], &[0u8; 32]);
            // data length (32 bytes, should be 68)
            let mut expected_len = [0u8; 32];
            expected_len[31] = 68;
            assert_eq!(&entry[53..85], &expected_len);
            // data (approve calldata)
            assert_eq!(&entry[85..85 + 68], &approve_data);
        }
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
