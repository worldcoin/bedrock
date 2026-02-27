//! Permit2 contract types, helpers, and batched ERC20 approvals.
//!
//! Contains the Permit2 `IAllowanceTransfer` interface, `PermitTransferFrom` / `TokenPermissions`
//! EIP-712 types, `Permit2Approve` for on-chain allowance approvals, and `BatchPermit2Approval`
//! for batching ERC20 `approve(spender, type(uint256).max)` calls via `MultiSend`.

use alloy::{
    dyn_abi::{Eip712Domain, TypedData},
    primitives::{
        aliases::{U160, U48},
        Address, Bytes, U256,
    },
    sol,
    sol_types::{eip712_domain, SolCall},
};

use crate::bedrock_sol;
use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};

use super::erc20::Erc20;
use super::multisend::{MultiSend, MultiSendTx};
pub use super::worldchain::PERMIT2_ADDRESS;

// ---------------------------------------------------------------------------
// Permit2 signature-transfer types (PermitTransferFrom / TokenPermissions)
// ---------------------------------------------------------------------------

bedrock_sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L22>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct TokenPermissions {
        // ERC20 token address
        address token;
        // Amount of tokens which can be transferred
        uint256 amount;
    }

    /// The signed permit message for a single token transfer.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L30>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct PermitTransferFrom {
        /// The token and amount details for a transfer signed in the permit transfer signature
        TokenPermissions permitted;
        /// The address that is allowed to spend the tokens. Note this is not part of the `PermitTransferFrom` struct in the contract.
        /// This is however added in the contract from `msg.sender` to compute the hash.
        /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L62>
        address spender;
        /// A unique value for every token owner's signature to prevent replays
        uint256 nonce;
        /// Deadline (timestamp) after which the signature is no longer valid
        uint256 deadline;
    }
}

impl PermitTransferFrom {
    /// Converts the `PermitTransferFrom` struct into an EIP-712 `TypedData` struct with its relevant domain.
    #[must_use]
    pub fn as_typed_data(&self, chain_id: u32) -> TypedData {
        let domain: Eip712Domain = eip712_domain!(
            name: "Permit2",
            chain_id: chain_id.into(),
            verifying_contract: PERMIT2_ADDRESS,
        );

        TypedData::from_struct(self, Some(domain))
    }
}

// ---------------------------------------------------------------------------
// Permit2 IAllowanceTransfer interface
// ---------------------------------------------------------------------------

sol! {
    /// Permit2 `IAllowanceTransfer` interface for on-chain allowance approvals.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/IAllowanceTransfer.sol#L41>
    interface IAllowanceTransfer {
        function approve(address token, address spender, uint160 amount, uint48 expiration) external;
    }
}

// ---------------------------------------------------------------------------
// Permit2Approve (single allowance approval via IAllowanceTransfer)
// ---------------------------------------------------------------------------

/// Represents a Permit2 `IAllowanceTransfer.approve` call that sets an on-chain allowance
/// on the Permit2 contract for a given token and spender.
///
/// This grants a spender permission to transfer tokens via Permit2's allowance-based transfer
/// mechanism (`transferFrom` on `IAllowanceTransfer`).
///
/// Note: This is distinct from the ERC-20 `approve` call. The ERC-20 approval grants the Permit2
/// contract itself permission to move tokens, while this Permit2 approval grants a specific spender
/// permission to use Permit2 to move tokens on the owner's behalf.
///
/// Reference: <https://docs.uniswap.org/contracts/permit2/reference/allowance-transfer#approve>
pub struct Permit2Approve {
    /// The ABI-encoded calldata for `IAllowanceTransfer.approve(token, spender, amount, expiration)`.
    call_data: Vec<u8>,
}

impl Permit2Approve {
    /// Creates a new Permit2 allowance approve operation.
    ///
    /// # Arguments
    /// * `token` - The ERC-20 token address to set the allowance for.
    /// * `spender` - The address being granted permission to transfer tokens via Permit2.
    /// * `amount` - The maximum amount of tokens the spender can transfer (`uint160`).
    /// * `expiration` - The timestamp (`uint48`) after which the allowance expires.
    #[must_use]
    pub fn new(
        token: Address,
        spender: Address,
        amount: U160,
        expiration: U48,
    ) -> Self {
        let call_data = IAllowanceTransfer::approveCall {
            token,
            spender,
            amount,
            expiration,
        }
        .abi_encode();

        Self { call_data }
    }
}

impl Is4337Encodable for Permit2Approve {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: PERMIT2_ADDRESS,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: SafeOperation::Call as u8,
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

// ---------------------------------------------------------------------------
// BatchPermit2Approval (multiple ERC20 approvals via MultiSend)
// ---------------------------------------------------------------------------

/// Batched ERC20 `approve(spender, type(uint256).max)` calls via `MultiSend`.
///
/// Builds a single 4337 `UserOperation` that grants a spender contract max allowance
/// on each of the given token contracts.
pub struct BatchPermit2Approval {
    call_data: Vec<u8>,
    to: Address,
    operation: SafeOperation,
}

impl BatchPermit2Approval {
    /// Creates a new batch of ERC20 max approvals to the Permit2 contract.
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

impl Is4337Encodable for BatchPermit2Approval {
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::primitives::{Network, BEDROCK_NONCE_PREFIX_CONST};
    use crate::transactions::contracts::erc20::IErc20;
    use crate::transactions::contracts::multisend::MULTISEND_ADDRESS;
    use alloy::primitives::{address, fixed_bytes, uint};
    use std::str::FromStr;

    #[test]
    fn test_permit2_typed_data_and_signing_hash() {
        let permitted = TokenPermissions {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U256),
        };

        let transfer_from = PermitTransferFrom {
            permitted,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            nonce: uint!(123_U256),
            deadline: uint!(1704067200_U256),
        };

        let typed_data = transfer_from
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash()
            .unwrap();

        assert_eq!(
            typed_data,
            fixed_bytes!(
                "0x22c2b928cf818940122abf8f5e7e04158c38653b9a985006e295e90f32abd351"
            )
        );
    }

    #[test]
    fn test_permit2_approve_call_data() {
        let token = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
        let spender = address!("0x1234567890123456789012345678901234567890");
        let amount = U160::MAX;
        let expiration = U48::from(1_704_067_200u64);

        let approve = Permit2Approve::new(token, spender, amount, expiration);
        let execute_user_op_call_data = approve.as_execute_user_op_call_data();

        let call_data_bytes: &[u8] = &execute_user_op_call_data;

        // executeUserOp selector is 0x7bb37428
        assert_eq!(&call_data_bytes[0..4], &[0x7b, 0xb3, 0x74, 0x28]);

        // `to` param (bytes 4..36) should be PERMIT2_ADDRESS (left-padded to 32 bytes)
        let mut expected_to = [0u8; 32];
        expected_to[12..32].copy_from_slice(PERMIT2_ADDRESS.as_slice());
        assert_eq!(&call_data_bytes[4..36], &expected_to);
    }

    #[test]
    fn test_permit2_approve_inner_calldata_encodes_correctly() {
        let token = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
        let spender = address!("0x1234567890123456789012345678901234567890");
        let amount = U160::from(1_000_000u64);
        let expiration = U48::from(1_704_067_200u64);

        let approve = Permit2Approve::new(token, spender, amount, expiration);

        let expected_inner = IAllowanceTransfer::approveCall {
            token,
            spender,
            amount,
            expiration,
        }
        .abi_encode();

        assert_eq!(approve.call_data, expected_inner);
    }

    #[test]
    fn test_permit2_approve_preflight_user_operation_nonce() {
        let token = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
        let spender = address!("0x1234567890123456789012345678901234567890");
        let amount = U160::MAX;
        let expiration = U48::from(1_704_067_200u64);

        let approve = Permit2Approve::new(token, spender, amount, expiration);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = approve.as_preflight_user_operation(wallet, None).unwrap();

        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Permit2Approve as u8);
        assert_eq!(be[6], 0u8);

        assert_eq!(&be[7..=16], &[0u8; 10]);
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_batch_execute_user_op_calldata() {
        let usdc = address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1");
        let weth = address!("0x4200000000000000000000000000000000000006");
        let tokens = vec![usdc, weth];
        let batch = BatchPermit2Approval::new(&tokens);

        let call_data = batch.as_execute_user_op_call_data();
        let call_data_bytes: &[u8] = &call_data;

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

        let multisend_call =
            super::super::multisend::IMultiSend::multiSendCall::abi_decode_raw(
                &decoded.data[4..],
            )
            .unwrap();
        let packed = multisend_call.transactions;

        let approve_data = Erc20::encode_approve(PERMIT2_ADDRESS, U256::MAX);
        assert_eq!(approve_data.len(), 68);
        let entry_size = 1 + 20 + 32 + 32 + approve_data.len();

        assert_eq!(packed.len(), entry_size * 2, "should have 2 packed entries");

        for (i, token) in [usdc, weth].iter().enumerate() {
            let offset = i * entry_size;
            let entry = &packed[offset..offset + entry_size];

            assert_eq!(entry[0], SafeOperation::Call as u8);
            assert_eq!(&entry[1..21], token.as_slice());
            assert_eq!(&entry[21..53], &[0u8; 32]);
            let mut expected_len = [0u8; 32];
            expected_len[31] = 68;
            assert_eq!(&entry[53..85], &expected_len);
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
