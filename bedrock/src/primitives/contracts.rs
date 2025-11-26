use crate::primitives::PrimitiveError;
use crate::transactions::rpc::SponsorUserOperationResponse;
use alloy::hex::FromHex;
use alloy::primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes, U128};
use alloy::sol;
use alloy::sol_types::SolValue;
use ruint::aliases::U256;
use serde::{Deserialize, Serialize};
use std::{str::FromStr, sync::LazyLock};

/// <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L53>
static SAFE_OP_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::from_hex(
        "0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f",
    )
    .expect("error initializing `SAFE_OP_TYPEHASH`")
});

/// v0.7.0 `EntryPoint` contract
/// Contract reference: <https://github.com/eth-infinitism/account-abstraction/blob/v0.7.0/contracts/core/EntryPoint.sol>
pub static ENTRYPOINT_4337: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x0000000071727De22E5E9d8BAf0edAc6f37da032")
        .expect("failed to decode ENTRYPOINT_4337")
});

/// Multichain address for the v0.3.0 `Safe4337Module`
pub static GNOSIS_SAFE_4337_MODULE: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226")
        .expect("failed to decode GNOSIS_SAFE_4337_MODULE")
});

/// The length of a 4337 `UserOperation` signature.
///
/// This is the length of a regular ECDSA signature with r,s,v (32 + 32 + 1 = 65 bytes) + 12 bytes for the validity timestamps.
const USER_OPERATION_SIGNATURE_LENGTH: usize = 77;

// --- JSON serialization helpers for ERC-4337 ---

/// Serializes Option<Address> as hex string or null.
#[allow(clippy::ref_option)]
fn serialize_option_address<S: serde::Serializer>(
    value: &Option<Address>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(addr) => serializer.serialize_str(&format!("{addr}")),
        None => serializer.serialize_none(),
    }
}

/// Serializes Option<Bytes> as hex string or null.
#[allow(clippy::ref_option)]
fn serialize_option_bytes<S: serde::Serializer>(
    value: &Option<Bytes>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(bytes) => serializer.serialize_str(&format!("{bytes}")),
        None => serializer.serialize_none(),
    }
}

/// Serializes Option<U128> using U128's default hex serialization, or null.
#[allow(clippy::ref_option)]
fn serialize_option_u128<S: serde::Serializer>(
    value: &Option<U128>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    match value {
        Some(v) => v.serialize(serializer),
        None => serializer.serialize_none(),
    }
}

/// The structure of a generic 4337 `UserOperation`.
///
/// This is an **off-chain** JSON-RPC construct used to communicate with bundlers.
///
/// For the flow of World App:
/// - A `UserOperation` is created by the user and passed to the World App RPC to request sponsorship through the `wa_sponsorUserOperation` method.
/// - The final signed `UserOperation` is then passed to the World App RPC to be executed through the standard `eth_sendUserOperation` method.
///
/// Reference: <https://eips.ethereum.org/EIPS/eip-4337#useroperation>
#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperation {
    /// The Account making the `UserOperation`
    pub sender: Address,
    /// Anti-replay protection
    pub nonce: U256,
    /// Account Factory for new Accounts OR `0x7702` flag for EIP-7702 Accounts, otherwise None
    #[serde(serialize_with = "serialize_option_address")]
    pub factory: Option<Address>,
    /// Data for the Account Factory if factory is provided OR EIP-7702 initialization data
    #[serde(serialize_with = "serialize_option_bytes")]
    pub factory_data: Option<Bytes>,
    /// The data to pass to the sender during the main execution call
    pub call_data: Bytes,
    /// Gas limit for the main execution call
    pub call_gas_limit: U128,
    /// Gas limit for the verification call
    pub verification_gas_limit: U128,
    /// Extra gas to pay the bundler
    pub pre_verification_gas: U256,
    /// Maximum fee per gas (similar to EIP-1559 `max_fee_per_gas`)
    pub max_fee_per_gas: U128,
    /// Maximum priority fee per gas (similar to EIP-1559 `max_priority_fee_per_gas`)
    pub max_priority_fee_per_gas: U128,
    /// Address of paymaster contract (None if the transaction bundler pays for gas)
    #[serde(serialize_with = "serialize_option_address")]
    pub paymaster: Option<Address>,
    /// The amount of gas to allocate for the paymaster validation code (only if paymaster exists)
    #[serde(serialize_with = "serialize_option_u128")]
    pub paymaster_verification_gas_limit: Option<U128>,
    /// The amount of gas to allocate for the paymaster post-operation code (only if paymaster exists)
    #[serde(serialize_with = "serialize_option_u128")]
    pub paymaster_post_op_gas_limit: Option<U128>,
    /// Data for paymaster (only if paymaster exists)
    #[serde(serialize_with = "serialize_option_bytes")]
    pub paymaster_data: Option<Bytes>,
    /// Data passed into the sender to verify authorization
    pub signature: Bytes,
}

sol! {
    /// Interface for the `Safe4337Module` contract.
    ///
    /// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L172>
    #[sol(all_derives)]
    interface ISafe4337Module {
        function executeUserOp(address to, uint256 value, bytes calldata data, uint8 operation) external;
    }

    /// The EIP-712 type-hash for a `SafeOp`, representing the structure of a User Operation for the Safe.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-4337#useroperation>
    #[sol(rename_all = "camelcase")]
    struct EncodedSafeOpStruct {
        bytes32 type_hash;
        address safe;
        uint256 nonce;
        bytes32 init_code_hash;
        bytes32 call_data_hash;
        uint128 verification_gas_limit;
        uint128 call_gas_limit;
        uint256 pre_verification_gas;
        uint128 max_priority_fee_per_gas;
        uint128 max_fee_per_gas;
        bytes32 paymaster_and_data_hash;
        uint48 valid_after;
        uint48 valid_until;
        address entry_point;
    }
}

impl UserOperation {
    /// Initializes a new `UserOperation` with default values.
    ///
    /// In particular, it sets default values for gas limits & fees, paymaster and sets a dummy signature.
    pub fn new_with_defaults(sender: Address, nonce: U256, call_data: Bytes) -> Self {
        Self {
            sender,
            nonce,
            call_data,
            signature: vec![0xff; USER_OPERATION_SIGNATURE_LENGTH].into(),
            ..Default::default()
        }
    }

    /// Gathers the factory+factoryData as `initCode`.
    pub fn get_init_code(&self) -> Bytes {
        let Some(factory) = self.factory else {
            return Bytes::new();
        };

        let factory_data = self.factory_data.clone().unwrap_or_default();

        let mut out = Vec::new();
        out.extend_from_slice(factory.as_slice());
        out.extend_from_slice(&factory_data);
        out.into()
    }

    /// Extract `validAfter` and `validUntil` from a signature as `U256` values.
    ///
    /// Expects at least 12 bytes additional bytes in the signature.
    ///
    /// # Errors
    /// - Returns an error if the signature is too short.
    pub fn extract_validity_timestamps(&self) -> Result<(U48, U48), PrimitiveError> {
        // timestamp validity (12 bytes) + regular ECDSA signature (65 bytes)
        if self.signature.len() != 77 {
            return Err(PrimitiveError::InvalidInput {
                attribute: "signature".to_string(),
                error_message: "signature does not have the correct length (77 bytes)"
                    .to_string(),
            });
        }

        let mut valid_after = [0u8; 6];
        let mut valid_until = [0u8; 6];

        valid_after.copy_from_slice(&self.signature[0..6]);
        valid_until.copy_from_slice(&self.signature[6..12]);

        // Extract 6-byte validAfter and validUntil slices and convert them to U256
        let valid_after = U48::from_be_bytes(valid_after);
        let valid_until = U48::from_be_bytes(valid_until);

        Ok((valid_after, valid_until))
    }

    /// Merges all paymaster related data into a single `paymasterAndData` attribute.
    pub fn get_paymaster_and_data(&self) -> Bytes {
        let Some(paymaster) = self.paymaster else {
            return Bytes::new();
        };

        let paymaster_data = self.paymaster_data.clone().unwrap_or_default();

        let mut out = Vec::new();
        // Append paymaster address (20 bytes)
        out.extend_from_slice(paymaster.as_slice());

        // Append paymasterVerificationGasLimit (16 bytes)
        let verification_gas_limit =
            self.paymaster_verification_gas_limit.unwrap_or(U128::ZERO);
        out.extend_from_slice(&verification_gas_limit.to_be_bytes::<16>());

        // Append paymasterPostOpGasLimit (16 bytes)
        let post_op_gas_limit = self.paymaster_post_op_gas_limit.unwrap_or(U128::ZERO);
        out.extend_from_slice(&post_op_gas_limit.to_be_bytes::<16>());

        // Append paymasterData
        out.extend_from_slice(&paymaster_data);

        out.into()
    }

    /// Merges paymaster data from sponsorship response into the `UserOperation`
    #[must_use]
    pub fn with_paymaster_data(
        mut self,
        sponsor_response: &SponsorUserOperationResponse,
    ) -> Self {
        self.paymaster = sponsor_response.paymaster;
        self.paymaster_data
            .clone_from(&sponsor_response.paymaster_data);
        self.paymaster_verification_gas_limit =
            Some(sponsor_response.paymaster_verification_gas_limit);
        self.paymaster_post_op_gas_limit =
            Some(sponsor_response.paymaster_post_op_gas_limit);

        // Update gas fields
        self.pre_verification_gas = sponsor_response.pre_verification_gas;
        self.verification_gas_limit = sponsor_response.verification_gas_limit;
        self.call_gas_limit = sponsor_response.call_gas_limit;
        self.max_fee_per_gas = sponsor_response.max_fee_per_gas;
        self.max_priority_fee_per_gas = sponsor_response.max_priority_fee_per_gas;

        self
    }
}

impl EncodedSafeOpStruct {
    /// Builds an `EncodedSafeOpStruct` from a `UserOperation`, injecting explicit validity timestamps.
    ///
    /// # Errors
    /// Returns `PrimitiveError` if hashing or conversions fail when deriving fields
    /// from the provided `user_op`. Currently this can occur if internal helpers
    /// on `user_op` return invalid data for hashing.
    pub fn from_user_op_with_validity(
        user_op: &UserOperation,
        valid_after: U48,
        valid_until: U48,
    ) -> Result<Self, PrimitiveError> {
        // Convert U128 to u128 for sol! struct compatibility
        let verification_gas_limit: u128 =
            user_op.verification_gas_limit.try_into().unwrap_or(0);
        let call_gas_limit: u128 = user_op.call_gas_limit.try_into().unwrap_or(0);
        let max_priority_fee_per_gas: u128 =
            user_op.max_priority_fee_per_gas.try_into().unwrap_or(0);
        let max_fee_per_gas: u128 = user_op.max_fee_per_gas.try_into().unwrap_or(0);

        Ok(Self {
            type_hash: *SAFE_OP_TYPEHASH,
            safe: user_op.sender,
            nonce: user_op.nonce,
            init_code_hash: keccak256(user_op.get_init_code()),
            call_data_hash: keccak256(&user_op.call_data),
            verification_gas_limit,
            call_gas_limit,
            pre_verification_gas: user_op.pre_verification_gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            paymaster_and_data_hash: keccak256(user_op.get_paymaster_and_data()),
            valid_after,
            valid_until,
            entry_point: *ENTRYPOINT_4337,
        })
    }

    /// computes the hash of the userOp
    #[must_use]
    pub fn into_transaction_hash(self) -> FixedBytes<32> {
        keccak256(self.abi_encode())
    }
}

sol! {
    contract IMulticall3 {
        #[derive(Default)]
        struct Call3 {
            address target;
            bool allowFailure;
            bytes callData;
        }
    }

    contract IEntryPoint {
        #[derive(Default, serde::Serialize, serde::Deserialize, Debug)]
        struct PackedUserOperation {
            address sender;
            uint256 nonce;
            bytes initCode;
            bytes callData;
            bytes32 accountGasLimits;
            uint256 preVerificationGas;
            bytes32 gasFees;
            bytes paymasterAndData;
            bytes signature;
        }

        #[derive(Default)]
        struct UserOpsPerAggregator {
            PackedUserOperation[] userOps;
            address aggregator;
            bytes signature;
        }
    }

    contract IPBHEntryPoint {
        #[derive(Default)]
        struct PBHPayload {
            uint256 root;
            uint256 pbhExternalNullifier;
            uint256 nullifierHash;
            uint256[8] proof;
        }

        function handleAggregatedOps(
            IEntryPoint.UserOpsPerAggregator[] calldata,
            address payable
        ) external;

        function pbhMulticall(
            IMulticall3.Call3[] calls,
            PBHPayload payload,
        ) external;
    }
}
