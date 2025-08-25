//! The `transaction_4337` module enables 4337 transaction crafting.
//!
//! A transaction can be initialized through a `UserOperation` struct.
//!

use crate::primitives::{HttpError, Network, PrimitiveError};
use crate::smart_account::SafeSmartAccountSigner;
use crate::transaction::rpc::{RpcError, SponsorUserOperationResponse};

use alloy::hex::FromHex;
use alloy::{
    primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes},
    sol,
    sol_types::SolValue,
};
use chrono::{Duration, Utc};
use ruint::aliases::U256;
use std::{str::FromStr, sync::LazyLock};

use serde::Serializer;

/// <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L53>
static SAFE_OP_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::from_hex(
        "0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f",
    )
    .expect("error initializing `SAFE_OP_TYPEHASH`")
});

/// v0.7 `EntryPoint`
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

/// The default validity duration for 4337 `UserOperation` signatures.
///
/// Operations are valid for this duration from the time they are signed.
const USER_OPERATION_VALIDITY_DURATION_HOURS: i64 = 12;

/// Identifies a transaction that can be encoded, signed and executed as a 4337 `UserOperation`.
#[allow(async_fn_in_trait)]
pub trait Is4337Encodable {
    /// Each implementation can define its own metadata argument struct used when
    /// constructing a preflight `UserOperation`.
    type MetadataArg;

    /// Converts the object into a `callData` for the `executeUserOp` method. This is the inner-most `calldata`.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    fn as_execute_user_op_call_data(&self) -> Bytes;

    /// Converts the object into a preflight `UserOperation` for use with the `Safe4337Module`.
    ///
    /// A preflight operation is defined as having empty gas & paymaster data and a dummy signature.
    ///
    /// The preflight operation is sent to the RPC to request sponsorship.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError>;

    /// Signs and executes a 4337 `UserOperation` by:
    /// 1. Creating a preflight `UserOperation`
    /// 2. Requesting sponsorship via `wa_sponsorUserOperation`
    /// 3. Merging paymaster data into the `UserOperation`
    /// 4. Signing the `UserOperation`
    /// 5. Submitting via `eth_sendUserOperation`
    ///
    /// Uses the global RPC client automatically.
    ///
    /// # Arguments
    /// * `network` - The network to use for the operation
    /// * `safe_account` - The Safe Smart Account to sign with
    /// * `self_sponsor_token` - Optional token address for self-sponsorship
    ///
    /// # Returns
    /// * `Result<FixedBytes<32>, RpcError>` - The `userOpHash` on success
    ///
    /// # Errors
    /// * Returns `RpcError` if any RPC operation fails
    /// * Returns `RpcError` if signing fails
    /// * Returns `RpcError` if the global HTTP client has not been initialized
    async fn sign_and_execute(
        &self,
        network: Network,
        safe_account: &crate::smart_account::SafeSmartAccount,
        self_sponsor_token: Option<Address>,
        metadata: Option<Self::MetadataArg>,
    ) -> Result<FixedBytes<32>, RpcError> {
        // Get the global RPC client
        let rpc_client = crate::transaction::rpc::get_rpc_client()?;

        // 1. Create preflight UserOperation using default metadata for this implementation
        let mut user_operation =
            self.as_preflight_user_operation(safe_account.wallet_address, metadata)?;

        // Inject validity timestamps into the preflight signature so sponsorship evaluates a realistic op
        // validAfter = 0 (immediately valid)
        let preflight_valid_after_bytes: [u8; 6] = [0u8; 6];
        // validUntil = now + configured duration
        let preflight_valid_until_seconds = (Utc::now()
            + Duration::hours(USER_OPERATION_VALIDITY_DURATION_HOURS))
        .timestamp();
        let preflight_valid_until_seconds: u64 =
            preflight_valid_until_seconds.try_into().unwrap_or(0);
        let preflight_valid_until_bytes_full =
            preflight_valid_until_seconds.to_be_bytes();
        let preflight_valid_until_bytes: &[u8] =
            &preflight_valid_until_bytes_full[2..8];
        // Compose dummy ECDSA part (65 bytes of 0xff) but keep real validity prefix (12 bytes)
        let mut preflight_signature = Vec::with_capacity(77);
        preflight_signature.extend_from_slice(&preflight_valid_after_bytes);
        preflight_signature.extend_from_slice(preflight_valid_until_bytes);
        preflight_signature.extend([0xff; 65]);
        user_operation.signature = preflight_signature.into();

        // 2. Request sponsorship
        let sponsor_response = rpc_client
            .sponsor_user_operation(
                network,
                &user_operation,
                *ENTRYPOINT_4337,
                self_sponsor_token,
            )
            .await?;

        // 3. Merge paymaster data
        user_operation = user_operation.with_paymaster_data(sponsor_response)?;

        // 4. Compute validity timestamps
        // validAfter = 0 (immediately valid)
        let valid_after_u48 = U48::from(0u64);
        let valid_after_bytes: [u8; 6] = [0u8; 6];

        // Set validUntil to the configured duration from now
        let valid_until_seconds = (Utc::now()
            + Duration::hours(USER_OPERATION_VALIDITY_DURATION_HOURS))
        .timestamp();
        let valid_until_seconds: u64 = valid_until_seconds.try_into().unwrap_or(0);
        let valid_until_u48 = U48::from(valid_until_seconds);
        let valid_until_bytes_full = valid_until_seconds.to_be_bytes();
        let valid_until_bytes: &[u8] = &valid_until_bytes_full[2..8]; // 48-bit timestamp

        // Build EncodedSafeOpStruct using explicit validity (no dependency on user_operation.signature)
        let encoded_safe_op = EncodedSafeOpStruct::from_user_op_with_validity(
            &user_operation,
            valid_after_u48,
            valid_until_u48,
        )?;

        let signature = safe_account.sign_digest(
            encoded_safe_op.into_transaction_hash(),
            network as u32,
            Some(*GNOSIS_SAFE_4337_MODULE),
        )?;

        // Compose the final signature once (timestamps + actual 65-byte signature)
        let mut full_signature = Vec::with_capacity(77);
        full_signature.extend_from_slice(&valid_after_bytes);
        full_signature.extend_from_slice(valid_until_bytes);
        full_signature.extend_from_slice(&signature.as_bytes()[..]);

        user_operation.signature = full_signature.into();

        // 5. Submit UserOperation
        let user_op_hash = rpc_client
            .send_user_operation(network, &user_operation, *ENTRYPOINT_4337)
            .await?;

        Ok(user_op_hash)
    }
}

sol! {

    /// Interface for the `Safe4337Module` contract.
    ///
    /// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L172>
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

// --- JSON serialization helpers for ERC-7769 ---

fn serialize_u128_as_hex<S: Serializer>(
    value: &u128,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    // Always hex with 0x prefix per spec
    let s = format!("0x{value:x}");
    serializer.serialize_str(&s)
}

fn serialize_u256_as_hex<S: Serializer>(
    value: &U256,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    let s = format!("0x{value:x}");
    serializer.serialize_str(&s)
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, U128};

    use super::*;
    use crate::{
        smart_account::SafeSmartAccount, transaction::foreign::UnparsedUserOperation,
    };

    #[test]
    fn test_hash_user_op() {
        let user_op = UnparsedUserOperation {
        sender:"0xf1390a26bd60d83a4e38c7be7be1003c616296ad".to_string(),
        nonce: "0xb14292cd79fae7d79284d4e6304fb58e21d579c13a75eed80000000000000000".to_string(),
        call_data:  "0x7bb3742800000000000000000000000079a02482a880bce3f13e09da970dc34db4cd24d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000ce2111f9ab8909b71ebadc9b6458daefe069eda4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000".to_string(),
        signature:  "0x000012cea6000000967a7600ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
        call_gas_limit: "0xabb8".to_string(),
        verification_gas_limit: "0xfa07".to_string(),
        pre_verification_gas: "0x8e4d78".to_string(),
        max_fee_per_gas: "0x1af6f".to_string(),
        max_priority_fee_per_gas: "0x1adb0".to_string(),
        paymaster: Some("0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B".to_string()),
        paymaster_verification_gas_limit: "0x7415".to_string(),
        paymaster_post_op_gas_limit: "0x".to_string(),
        paymaster_data: Some("000000000000000067789a97c4af0f8ae7acc9237c8f9611a0eb4662009d366b8defdf5f68fed25d22ca77be64b8eef49d917c3f8642ca539571594a84be9d0ee717c099160b79a845bea2111b".to_string()),
        factory: None,
        factory_data: None,
    };

        let user_op: UserOperation = user_op.try_into().unwrap();

        let (valid_after, valid_until) = user_op.extract_validity_timestamps().unwrap();
        let encoded_safe_op = EncodedSafeOpStruct::from_user_op_with_validity(
            &user_op,
            valid_after,
            valid_until,
        )
        .unwrap();
        let hash = encoded_safe_op.into_transaction_hash();

        let smart_account = SafeSmartAccount::random();

        let safe_tx_hash = smart_account.eip_712_hash(
            hash,
            Network::WorldChain as u32,
            Some(*GNOSIS_SAFE_4337_MODULE),
        );

        let expected_hash =
            "f56239eeacb960d469a19f397dd6dce1b0ca6c9553aeff6fc72100cbddbfdb1a";
        assert_eq!(hex::encode(safe_tx_hash), expected_hash);
    }

    #[test]
    fn test_get_init_code_allows_no_factory() {
        let user_op_no_factory = UserOperation {
            factory: Address::ZERO,
            factory_data: Bytes::new(),
            ..Default::default()
        };
        let code = user_op_no_factory.get_init_code();
        assert!(
            code.is_empty(),
            "Expected empty init code when factory=None"
        );
    }

    #[test]
    fn test_get_init_code_parse_valid_factory_no_data() {
        let user_op_valid_factory = UserOperation {
            factory: address!("0x1111111111111111111111111111111111111111"),
            factory_data: Bytes::new(),
            ..Default::default()
        };
        let code = user_op_valid_factory.get_init_code();
        assert_eq!(
            code.len(),
            20,
            "Should have exactly 20 bytes from the address"
        );
    }

    #[test]
    fn test_get_init_code_parse_valid_factory_and_data() {
        let user_op_with_data = UserOperation {
            factory: address!("0x2222222222222222222222222222222222222222"),
            factory_data: Bytes::from_str("0x1234abcd").unwrap(),
            ..Default::default()
        };
        let code = user_op_with_data.get_init_code();
        assert_eq!(
            code.len(),
            20 + 4,
            "Should be 20 bytes + length of factory_data"
        );
        // The last 4 bytes should match 0x12, 0x34, 0xab, 0xcd
        assert_eq!(&code[20..24], &[0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_with_paymaster_data() {
        let mut user_op = UserOperation::new_with_defaults(
            address!("0x1111111111111111111111111111111111111111"),
            U256::ZERO,
            Bytes::from_str("0x1234").unwrap(),
        );

        // Set some initial values
        user_op.call_gas_limit = 100;
        user_op.verification_gas_limit = 200;

        let sponsor_response = SponsorUserOperationResponse {
            paymaster: address!("0x2222222222222222222222222222222222222222"),
            paymaster_data: Bytes::from_str("0xabcd").unwrap(),
            pre_verification_gas: U256::from(300),
            verification_gas_limit: U128::from(400),
            call_gas_limit: U128::from(500),
            paymaster_verification_gas_limit: U128::from(600),
            paymaster_post_op_gas_limit: U128::from(700),
            max_priority_fee_per_gas: U128::from(800),
            max_fee_per_gas: U128::from(900),
        };

        let result = user_op.with_paymaster_data(sponsor_response);
        assert!(result.is_ok());

        let updated_user_op = result.unwrap();
        assert_eq!(
            updated_user_op.paymaster,
            address!("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(
            updated_user_op.paymaster_data,
            Bytes::from_str("0xabcd").unwrap()
        );
        assert_eq!(updated_user_op.pre_verification_gas, U256::from(300));
        assert_eq!(updated_user_op.paymaster_verification_gas_limit, 600);
        assert_eq!(updated_user_op.paymaster_post_op_gas_limit, 700);
        assert_eq!(updated_user_op.max_priority_fee_per_gas, 800);
        assert_eq!(updated_user_op.max_fee_per_gas, 900);
    }

    #[test]
    fn test_with_paymaster_data_does_not_overwrite_existing_gas_values() {
        let mut user_op = UserOperation::new_with_defaults(
            address!("0x1111111111111111111111111111111111111111"),
            U256::ZERO,
            Bytes::from_str("0x1234").unwrap(),
        );

        // Set existing non-zero values that should NOT be overwritten
        user_op.pre_verification_gas = U256::from(1000);
        user_op.verification_gas_limit = 2000;
        user_op.call_gas_limit = 3000;
        user_op.max_fee_per_gas = 4000;
        user_op.max_priority_fee_per_gas = 5000;

        let sponsor_response = SponsorUserOperationResponse {
            paymaster: address!("0x2222222222222222222222222222222222222222"),
            paymaster_data: Bytes::from_str("0xabcd").unwrap(),
            pre_verification_gas: U256::from(300),
            verification_gas_limit: U128::from(400),
            call_gas_limit: U128::from(500),
            paymaster_verification_gas_limit: U128::from(600),
            paymaster_post_op_gas_limit: U128::from(700),
            max_priority_fee_per_gas: U128::from(800),
            max_fee_per_gas: U128::from(900),
        };

        let result = user_op.with_paymaster_data(sponsor_response);
        assert!(result.is_ok());

        let updated_user_op = result.unwrap();

        // Paymaster fields should always be updated
        assert_eq!(
            updated_user_op.paymaster,
            address!("0x2222222222222222222222222222222222222222")
        );
        assert_eq!(
            updated_user_op.paymaster_data,
            Bytes::from_str("0xabcd").unwrap()
        );
        assert_eq!(updated_user_op.paymaster_verification_gas_limit, 600);
        assert_eq!(updated_user_op.paymaster_post_op_gas_limit, 700);

        // Existing non-nil values should NOT be overwritten
        assert_eq!(updated_user_op.pre_verification_gas, U256::from(1000));
        assert_eq!(updated_user_op.verification_gas_limit, 2000);
        assert_eq!(updated_user_op.call_gas_limit, 3000);
        assert_eq!(updated_user_op.max_fee_per_gas, 4000);
        assert_eq!(updated_user_op.max_priority_fee_per_gas, 5000);
    }

    #[test]
    fn test_get_paymaster_and_data_no_paymaster() {
        let user_op = UserOperation {
            paymaster: Address::ZERO,
            ..Default::default()
        };
        let data = user_op.get_paymaster_and_data();
        assert!(
            data.is_empty(),
            "Expected empty data when paymaster is zero"
        );
    }

    #[test]
    fn test_get_paymaster_and_data_with_paymaster_when_there_is_no_additional_paymaster_data(
    ) {
        let user_op = UserOperation {
            paymaster: address!("0x1111111111111111111111111111111111111111"),
            paymaster_verification_gas_limit: 1000,
            paymaster_post_op_gas_limit: 2000,
            paymaster_data: Bytes::new(),
            ..Default::default()
        };
        let data = user_op.get_paymaster_and_data();

        // Should be 20 bytes (address) + 16 bytes (verification gas) + 16 bytes (post-op gas) = 52 bytes
        assert_eq!(data.len(), 52);

        // First 20 bytes should be the paymaster address
        assert_eq!(
            &data[0..20],
            address!("0x1111111111111111111111111111111111111111").as_slice()
        );

        // Next 16 bytes should be verification gas limit (1000 as big-endian u128)
        let expected_verification_gas = 1000u128.to_be_bytes();
        assert_eq!(&data[20..36], &expected_verification_gas);

        // Last 16 bytes should be post-op gas limit (2000 as big-endian u128)
        let expected_post_op_gas = 2000u128.to_be_bytes();
        assert_eq!(&data[36..52], &expected_post_op_gas);
    }

    #[test]
    fn test_get_paymaster_and_data_full() {
        let paymaster_data = Bytes::from_str("0x1234abcd").unwrap();
        let user_op = UserOperation {
            paymaster: address!("0x2222222222222222222222222222222222222222"),
            paymaster_verification_gas_limit: 3000,
            paymaster_post_op_gas_limit: 4000,
            paymaster_data,
            ..Default::default()
        };
        let data = user_op.get_paymaster_and_data();

        // Should be 20 bytes (address) + 16 bytes (verification gas) + 16 bytes (post-op gas) + 4 bytes (data) = 56 bytes
        assert_eq!(data.len(), 56);

        // First 20 bytes should be the paymaster address
        assert_eq!(
            &data[0..20],
            address!("0x2222222222222222222222222222222222222222").as_slice()
        );

        // Next 16 bytes should be verification gas limit
        let expected_verification_gas = 3000u128.to_be_bytes();
        assert_eq!(&data[20..36], &expected_verification_gas);

        // Next 16 bytes should be post-op gas limit
        let expected_post_op_gas = 4000u128.to_be_bytes();
        assert_eq!(&data[36..52], &expected_post_op_gas);

        // Last 4 bytes should be the paymaster data
        assert_eq!(&data[52..56], &[0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_extract_validity_timestamps_valid_signature() {
        let mut signature = Vec::with_capacity(77);

        // Add validAfter (6 bytes)
        #[allow(clippy::unreadable_literal)]
        let valid_after_timestamp: u64 = 1704067200;
        let valid_after_bytes = valid_after_timestamp.to_be_bytes();
        signature.extend_from_slice(&valid_after_bytes[2..8]);

        // Add validUntil (6 bytes)
        #[allow(clippy::unreadable_literal)]
        let valid_until_timestamp: u64 = 1735689600;
        let valid_until_bytes = valid_until_timestamp.to_be_bytes();
        signature.extend_from_slice(&valid_until_bytes[2..8]);

        // Add dummy ECDSA signature
        signature.extend_from_slice(&[0xff; 65]);

        let user_op = UserOperation {
            signature: signature.into(),
            ..Default::default()
        };

        let (valid_after, valid_until) = user_op.extract_validity_timestamps().unwrap();

        assert_eq!(valid_after, U48::from(valid_after_timestamp));
        assert_eq!(valid_until, U48::from(valid_until_timestamp));
    }

    #[test]
    fn test_extract_validity_timestamps_invalid_signature_length() {
        let user_op = UserOperation {
            signature: vec![0xFF; 65].into(), // Too short - missing timestamp data
            ..Default::default()
        };

        let result = user_op.extract_validity_timestamps();
        assert!(result.is_err());

        if let Err(PrimitiveError::InvalidInput { attribute, message }) = result {
            assert_eq!(attribute, "signature");
            assert!(message.contains("signature does not have the correct length"));
        } else {
            panic!("Expected InvalidInput error");
        }
    }
}
