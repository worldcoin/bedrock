use crate::primitives::contracts::IPBHEntryPoint::PBHPayload;
use crate::primitives::{HttpError, PrimitiveError};
use crate::transaction::rpc::SponsorUserOperationResponse;
use alloy::hex::FromHex;
use alloy::primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes};
use alloy::sol;
use alloy::sol_types::SolValue;
use ruint::aliases::U256;
use std::{str::FromStr, sync::LazyLock};
use world_chain_builder_pbh::external_nullifier::EncodedExternalNullifier;
use world_chain_builder_pbh::payload::{PBHPayload as PbhPayload, TREE_DEPTH};

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

/// Multichain address for PBH_ENTRYPOINT_4337
/// Contract reference: <https://github.com/worldcoin/world-chain/blob/main/contracts/src/PBHEntryPointImplV1.sol>
pub static PBH_ENTRYPOINT_4337: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x0000000000A21818Ee9F93BB4f2AAad305b5397C")
        .expect("failed to decode PBH_ENTRYPOINT_4337")
});

/// Multichain address for the v0.3.0 `Safe4337Module`
pub static GNOSIS_SAFE_4337_MODULE: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226")
        .expect("failed to decode GNOSIS_SAFE_4337_MODULE")
});

/// Contract reference: <https://github.com/worldcoin/world-chain/blob/main/contracts/src/PBH4337Module.sol>
pub static PBH_SAFE_4337_MODULE_SEPOLIA: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0xeA5877676caC52d51DCEc80e4Ff33898d5B0E8D9")
        .expect("failed to decode GNOSIS_SAFE_4337_MODULE")
});

pub static PBH_SAFE_4337_MODULE_MAINNET: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0xb5b2a890a5ED55B07A27d014AdaAC113A545a96c")
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

impl From<UserOperation> for EncodedSafeOpStruct {
    /// Converts a `UserOperation` into an `EncodedSafeOpStruct`.
    ///
    /// This implementation extracts validity timestamps from the UserOperation's signature.
    /// If the signature doesn't contain valid timestamps, it uses zero values as defaults.
    ///
    /// # Example
    /// ```rust
    /// use bedrock::primitives::contracts::{UserOperation, EncodedSafeOpStruct};
    ///
    /// let user_op = UserOperation::default();
    /// let encoded_safe_op: EncodedSafeOpStruct = user_op.into();
    /// ```
    fn from(user_op: UserOperation) -> Self {
        // Extract validity timestamps from the signature, or use defaults
        let (valid_after, valid_until) = user_op
            .extract_validity_timestamps()
            .unwrap_or((U48::ZERO, U48::ZERO));

        // Use the existing method to create the struct
        Self::from_user_op_with_validity(&user_op, valid_after, valid_until)
            .expect("Failed to convert UserOperation to EncodedSafeOpStruct")
    }
}

impl From<UserOperation> for IEntryPoint::PackedUserOperation {
    /// Converts a `UserOperation` into a `PackedUserOperation`.
    ///
    /// This conversion packs gas limits and fees into bytes32 fields as required by EIP-4337.
    /// - `accountGasLimits`: verification_gas_limit (upper 128 bits) + call_gas_limit (lower 128 bits)
    /// - `gasFees`: max_priority_fee_per_gas (upper 128 bits) + max_fee_per_gas (lower 128 bits)
    ///
    /// # Example
    /// ```rust
    /// use bedrock::primitives::contracts::{UserOperation, IEntryPoint::PackedUserOperation};
    ///
    /// let user_op = UserOperation::default();
    /// let packed_user_op: PackedUserOperation = user_op.into();
    /// ```
    fn from(user_op: UserOperation) -> Self {
        // Pack verification_gas_limit (upper 128 bits) + call_gas_limit (lower 128 bits) into accountGasLimits
        let verification_gas_u256 = U256::from(user_op.verification_gas_limit);
        let call_gas_u256 = U256::from(user_op.call_gas_limit);
        let account_gas_limits: U256 = (verification_gas_u256 << 128) | call_gas_u256;

        // Pack max_priority_fee_per_gas (upper 128 bits) + max_fee_per_gas (lower 128 bits) into gasFees
        let max_priority_fee_u256 = U256::from(user_op.max_priority_fee_per_gas);
        let max_fee_u256 = U256::from(user_op.max_fee_per_gas);
        let gas_fees: U256 = (max_priority_fee_u256 << 128) | max_fee_u256;

        Self {
            sender: user_op.sender,
            nonce: user_op.nonce,
            initCode: user_op.get_init_code(),
            callData: user_op.call_data.clone(),
            accountGasLimits: FixedBytes::from_slice(
                &account_gas_limits.to_be_bytes::<32>(),
            ),
            preVerificationGas: user_op.pre_verification_gas,
            gasFees: FixedBytes::from_slice(&gas_fees.to_be_bytes::<32>()),
            paymasterAndData: user_op.get_paymaster_and_data(),
            signature: user_op.signature,
        }
    }
}

impl From<&UserOperation> for IEntryPoint::PackedUserOperation {
    /// Converts a `&UserOperation` into a `PackedUserOperation`.
    ///
    /// This conversion packs gas limits and fees into bytes32 fields as required by EIP-4337.
    /// This implementation works with borrowed UserOperations to avoid unnecessary moves.
    ///
    /// # Example
    /// ```rust
    /// use bedrock::primitives::contracts::{UserOperation, IEntryPoint::PackedUserOperation};
    ///
    /// let user_op = UserOperation::default();
    /// let packed_user_op: PackedUserOperation = (&user_op).into();
    /// // user_op is still available for use
    /// ```
    fn from(user_op: &UserOperation) -> Self {
        // Pack verification_gas_limit (upper 128 bits) + call_gas_limit (lower 128 bits) into accountGasLimits
        let verification_gas_u256 = U256::from(user_op.verification_gas_limit);
        let call_gas_u256 = U256::from(user_op.call_gas_limit);
        let account_gas_limits: U256 = (verification_gas_u256 << 128) | call_gas_u256;

        // Pack max_priority_fee_per_gas (upper 128 bits) + max_fee_per_gas (lower 128 bits) into gasFees
        let max_priority_fee_u256 = U256::from(user_op.max_priority_fee_per_gas);
        let max_fee_u256 = U256::from(user_op.max_fee_per_gas);
        let gas_fees: U256 = (max_priority_fee_u256 << 128) | max_fee_u256;

        Self {
            sender: user_op.sender,
            nonce: user_op.nonce,
            initCode: user_op.get_init_code(),
            callData: user_op.call_data.clone(),
            accountGasLimits: FixedBytes::from_slice(
                &account_gas_limits.to_be_bytes::<32>(),
            ),
            preVerificationGas: user_op.pre_verification_gas,
            gasFees: FixedBytes::from_slice(&gas_fees.to_be_bytes::<32>()),
            paymasterAndData: user_op.get_paymaster_and_data(),
            signature: user_op.signature.clone(),
        }
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

impl From<PbhPayload> for PBHPayload {
    fn from(val: PbhPayload) -> Self {
        let p0 = val.proof.0 .0 .0;
        let p1 = val.proof.0 .0 .1;
        let p2 = val.proof.0 .1 .0[0];
        let p3 = val.proof.0 .1 .0[1];
        let p4 = val.proof.0 .1 .1[0];
        let p5 = val.proof.0 .1 .1[1];
        let p6 = val.proof.0 .2 .0;
        let p7 = val.proof.0 .2 .1;

        Self {
            root: val.root,
            pbhExternalNullifier: EncodedExternalNullifier::from(
                val.external_nullifier,
            )
            .0,
            nullifierHash: val.nullifier_hash,
            proof: [p0, p1, p2, p3, p4, p5, p6, p7],
        }
    }
}
