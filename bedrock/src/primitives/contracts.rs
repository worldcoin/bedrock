use crate::primitives::{HttpError, PrimitiveError};
use crate::transactions::rpc::SponsorUserOperationResponse;
use alloy::hex::FromHex;
use alloy::primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes};
use alloy::sol;
use alloy::sol_types::SolValue;
use ruint::aliases::U256;
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

fn serialize_u128_as_hex<S: serde::Serializer>(
    value: &u128,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Always hex with 0x prefix per spec
    let s = format!("0x{value:x}");
    serializer.serialize_str(&s)
}

fn serialize_u256_as_hex<S: serde::Serializer>(
    value: &U256,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let s = format!("0x{value:x}");
    serializer.serialize_str(&s)
}

sol! {

    /// Interface for the `Safe4337Module` contract.
    ///
    /// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L172>
    #[sol(all_derives)]
    interface ISafe4337Module {
        function executeUserOp(address to, uint256 value, bytes calldata data, uint8 operation) external;
    }

    /// The structure of a generic 4337 `UserOperation`.
    ///
    /// `UserOperation`s are not used on-chain, they are used by RPCs to bundle transactions as `PackedUserOperation`s.
    ///
    /// For the flow of World App:
    /// - A `UserOperation` is created by the user and passed to the World App RPC to request sponsorship through the `wa_sponsorUserOperation` method.
    /// - The final signed `UserOperation` is then passed to the World App RPC to be executed through the standard `eth_sendUserOperation` method.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-4337#useroperation>
    #[sol(rename_all = "camelcase")]
    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UserOperation {
        /// The Account making the `UserOperation`
        address sender;
        /// Anti-replay protection
        #[serde(serialize_with = "serialize_u256_as_hex")]
        uint256 nonce;
        /// Account Factory for new Accounts OR `0x7702` flag for EIP-7702 Accounts, otherwise address(0)
        address factory;
        /// Data for the Account Factory if factory is provided OR EIP-7702 initialization data, or empty array
        bytes factory_data;
        /// The data to pass to the sender during the main execution call
        bytes call_data;
        /// Gas limit for the main execution call.
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 call_gas_limit;
        /// Gas limit for the verification call
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 verification_gas_limit;
        /// Extra gas to pay the bundler
        #[serde(serialize_with = "serialize_u256_as_hex")]
        uint256 pre_verification_gas;
        /// Maximum fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) `max_fee_per_gas`)
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 max_fee_per_gas;
        /// Maximum priority fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) `max_priority_fee_per_gas`)
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 max_priority_fee_per_gas;
        /// Address of paymaster contract, (or empty, if the sender pays for gas by itself)
        address paymaster;
        /// The amount of gas to allocate for the paymaster validation code (only if paymaster exists)
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is expected as `uint128` for `paymasterAndData` validation.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 paymaster_verification_gas_limit;
        /// The amount of gas to allocate for the paymaster post-operation code (only if paymaster exists)
        /// Even though the type is `uint256`, in the `Safe4337Module` (see `EncodedSafeOpStruct`), it is expected as `uint128` for `paymasterAndData` validation.
        #[serde(serialize_with = "serialize_u128_as_hex")]
        uint128 paymaster_post_op_gas_limit;
        /// Data for paymaster (only if paymaster exists)
        bytes paymaster_data;
        /// Data passed into the sender to verify authorization
        bytes signature;
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
        // Check if `factory` is present
        if self.factory.is_zero() {
            return Bytes::new();
        }

        let mut out = Vec::new();
        out.extend_from_slice(self.factory.as_slice());
        out.extend_from_slice(&self.factory_data);
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
                attribute: "signature",
                message: "signature does not have the correct length (77 bytes)"
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
        if self.paymaster.is_zero() {
            return Bytes::new();
        }

        let mut out = Vec::new();
        // Append paymaster address (20 bytes)
        out.extend_from_slice(self.paymaster.as_slice());

        // Append paymasterVerificationGasLimit (16 bytes)
        out.extend_from_slice(&self.paymaster_verification_gas_limit.to_be_bytes());

        // Append paymasterPostOpGasLimit (16 bytes)
        out.extend_from_slice(&self.paymaster_post_op_gas_limit.to_be_bytes());

        // Append paymasterData if it exists
        if !self.paymaster_data.is_empty() {
            out.extend_from_slice(&self.paymaster_data);
        }

        out.into()
    }

    /// Merges paymaster data from sponsorship response into the `UserOperation`
    ///
    /// # Errors
    /// Returns an error if any U128 to u128 conversion fails
    pub fn with_paymaster_data(
        mut self,
        sponsor_response: SponsorUserOperationResponse,
    ) -> Result<Self, HttpError> {
        self.paymaster = sponsor_response.paymaster;
        self.paymaster_data = sponsor_response.paymaster_data;
        self.paymaster_verification_gas_limit = sponsor_response
            .paymaster_verification_gas_limit
            .try_into()
            .unwrap_or(0);
        self.paymaster_post_op_gas_limit = sponsor_response
            .paymaster_post_op_gas_limit
            .try_into()
            .unwrap_or(0);

        // Update gas fields if they were estimated by the RPC
        if self.pre_verification_gas.is_zero() {
            self.pre_verification_gas = sponsor_response.pre_verification_gas;
        }
        if self.verification_gas_limit == 0 {
            self.verification_gas_limit = sponsor_response
                .verification_gas_limit
                .try_into()
                .unwrap_or(0);
        }
        if self.call_gas_limit == 0 {
            self.call_gas_limit =
                sponsor_response.call_gas_limit.try_into().unwrap_or(0);
        }
        if self.max_fee_per_gas == 0 {
            self.max_fee_per_gas =
                sponsor_response.max_fee_per_gas.try_into().unwrap_or(0);
        }
        if self.max_priority_fee_per_gas == 0 {
            self.max_priority_fee_per_gas = sponsor_response
                .max_priority_fee_per_gas
                .try_into()
                .unwrap_or(0);
        }

        Ok(self)
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
        Ok(Self {
            type_hash: *SAFE_OP_TYPEHASH,
            safe: user_op.sender,
            nonce: user_op.nonce,
            init_code_hash: keccak256(user_op.get_init_code()),
            call_data_hash: keccak256(&user_op.call_data),
            verification_gas_limit: user_op.verification_gas_limit,
            call_gas_limit: user_op.call_gas_limit,
            pre_verification_gas: user_op.pre_verification_gas,
            max_priority_fee_per_gas: user_op.max_priority_fee_per_gas,
            max_fee_per_gas: user_op.max_fee_per_gas,
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
