//! The `transaction_4337` module enables 4337 transaction crafting.
//!
//! A transaction can be initialized through a `UserOperation` struct.
//!

use crate::primitives::{ParseFromForeignBinding, PrimitiveError};

use super::SafeSmartAccountError;
use alloy::hex::FromHex;
use alloy::{
    primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes},
    sol,
    sol_types::SolValue,
};
use ruint::aliases::{U128, U256};
use std::{str::FromStr, sync::LazyLock};

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

pub trait Is4337Encodable {
    /// Converts the object into an `UserOperation` for use with the `Safe4337Module`.
    ///
    /// # Errors
    /// - Will throw a parsing error if any of the provided attributes are invalid.
    fn into_user_operation(self) -> Result<UserOperation, PrimitiveError>;
}

sol! {

    /// Interface for the `Safe4337Module` contract.
    ///
    /// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L172>
    interface ISafe4337Module {
        function executeUserOp(address to, uint256 value, bytes calldata data, uint8 operation) external;
    }

    /// The structure of a generic 4337 UserOperation.
    ///
    /// `UserOperation`s are not used on-chain, they are used by RPCs to bundle transactions as `PackedUserOperation`s.
    ///
    /// For the flow of World App:
    /// - A `UserOperation` is created by the user and passed to the World App RPC to request sponsorship through the `wa_sponsorUserOperation` method.
    /// - The final signed `UserOperation` is then passed to the World App RPC to be executed through the standard `eth_sendUserOperation` method.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-4337#useroperation
    #[sol(rename_all = "camelcase")]
    #[derive(Default)]
    struct UserOperation {
        /// The Account making the UserOperation
        address sender;
        /// Anti-replay protection
        uint256 nonce;
        /// Account Factory for new Accounts OR `0x7702` flag for EIP-7702 Accounts, otherwise address(0)
        address factory;
        /// Data for the Account Factory if factory is provided OR EIP-7702 initialization data, or empty array
        bytes factory_data;
        /// The data to pass to the sender during the main execution call
        bytes call_data;
        /// Gas limit for the main execution call.
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        uint128 call_gas_limit;
        /// Gas limit for the verification call
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        uint128 verification_gas_limit;
        /// Extra gas to pay the bundler
        uint256 pre_verification_gas;
        /// Maximum fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) max_fee_per_gas)
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        uint128 max_fee_per_gas;
        /// Maximum priority fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559) max_priority_fee_per_gas)
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is `uint128`. We enforce `uint128` to avoid overflows.
        uint128 max_priority_fee_per_gas;
        /// Address of paymaster contract, (or empty, if the sender pays for gas by itself)
        address paymaster;
        /// The amount of gas to allocate for the paymaster validation code (only if paymaster exists)
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is expected as `uint128` for paymasterAndData validation.
        uint128 paymaster_verification_gas_limit;
        /// The amount of gas to allocate for the paymaster post-operation code (only if paymaster exists)
        /// Even though the type is `uint256`, in the Safe4337Module (see `EncodedSafeOpStruct`), it is expected as `uint128` for paymasterAndData validation.
        uint128 paymaster_post_op_gas_limit;
        /// Data for paymaster (only if paymaster exists)
        bytes paymaster_data;
        /// Data passed into the sender to verify authorization
        bytes signature;
    }

    /// The EIP-712 type-hash for a SafeOp, representing the structure of a User Operation for the Safe.
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
    pub fn new_with_defaults(
        sender: Address,
        nonce: U256,
        call_data: Bytes,
        call_gas_limit: u128,
    ) -> Result<Self, SafeSmartAccountError> {
        Ok(Self {
            sender,
            nonce,
            call_data,
            call_gas_limit,
            signature: vec![0xff; 77].into(),
            ..Default::default()
        })
    }
}

impl TryFrom<&UserOperation> for EncodedSafeOpStruct {
    type Error = PrimitiveError;

    fn try_from(user_op: &UserOperation) -> Result<Self, Self::Error> {
        let (valid_after, valid_until) =
            extract_validity_timestamps(&user_op.signature)?;

        Ok(Self {
            type_hash: *SAFE_OP_TYPEHASH,
            safe: user_op.sender,
            nonce: user_op.nonce,
            init_code_hash: keccak256(get_init_code(user_op)),
            call_data_hash: keccak256(&user_op.call_data),
            verification_gas_limit: user_op.verification_gas_limit,
            call_gas_limit: user_op.call_gas_limit,
            pre_verification_gas: user_op.pre_verification_gas,
            max_priority_fee_per_gas: user_op.max_priority_fee_per_gas,
            max_fee_per_gas: user_op.max_fee_per_gas,
            paymaster_and_data_hash: keccak256(get_paymaster_and_data(&user_op)),
            valid_after,
            valid_until,
            entry_point: *ENTRYPOINT_4337,
        })
    }
}

impl EncodedSafeOpStruct {
    /// computes the hash of the userOp
    #[must_use]
    pub fn into_transaction_hash(self) -> FixedBytes<32> {
        keccak256(self.abi_encode())
    }
}

/// Extract validAfter and validUntil from a signature as `U256` values.
/// Expects at least 12 bytes in the signature. Returns an error if the signature is too short.
fn extract_validity_timestamps(signature: &[u8]) -> Result<(U48, U48), PrimitiveError> {
    // timestamp validity (12 bytes) + regular ECDSA signature (65 bytes)
    if signature.len() != 77 {
        return Err(PrimitiveError::InvalidInput {
            attribute: "signature",
            message: "signature does not have the correct length (77 bytes)"
                .to_string(),
        });
    }

    let mut valid_after = [0u8; 6];
    let mut valid_until = [0u8; 6];

    valid_after.copy_from_slice(&signature[0..6]);
    valid_until.copy_from_slice(&signature[6..12]);

    // Extract 6-byte validAfter and validUntil slices and convert them to U256
    let valid_after = U48::from_be_bytes(valid_after);
    let valid_until = U48::from_be_bytes(valid_until);

    Ok((valid_after, valid_until))
}

/// Gathers the factory+factoryData as `initCode`.
fn get_init_code(user_op: &UserOperation) -> Bytes {
    // Check if `factory` is present
    if user_op.factory.is_zero() {
        return Bytes::new();
    }

    let mut out = Vec::new();
    out.extend_from_slice(user_op.factory.as_slice());
    out.extend_from_slice(&user_op.factory_data);
    out.into()
}

/// Merges Paymaster related data
fn get_paymaster_and_data(user_op: &UserOperation) -> Bytes {
    if user_op.paymaster.is_zero() {
        return Bytes::new();
    }

    let mut out = Vec::new();
    // Append paymaster address (20 bytes)
    out.extend_from_slice(user_op.paymaster.as_slice());

    // Append paymasterVerificationGasLimit (16 bytes)
    out.extend_from_slice(&user_op.paymaster_verification_gas_limit.to_be_bytes());

    // Append paymasterPostOpGasLimit (16 bytes)
    out.extend_from_slice(&user_op.paymaster_post_op_gas_limit.to_be_bytes());

    // Append paymasterData if it exists
    if !user_op.paymaster_data.is_empty() {
        out.extend_from_slice(&user_op.paymaster_data);
    }

    out.into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_account::SafeSmartAccount;

    // #[test]
    // fn test_hash_user_op() {
    //     let user_op = UserOperation {
    //     sender:"0xf1390a26bd60d83a4e38c7be7be1003c616296ad".to_string(),
    //     nonce: "0xb14292cd79fae7d79284d4e6304fb58e21d579c13a75eed80000000000000000".to_string(),
    //     call_data:  "0x7bb3742800000000000000000000000079a02482a880bce3f13e09da970dc34db4cd24d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000ce2111f9ab8909b71ebadc9b6458daefe069eda4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000".to_string(),
    //     signature:  "0x000012cea6000000967a7600ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
    //     call_gas_limit: "0xabb8".to_string(),
    //     verification_gas_limit: "0xfa07".to_string(),
    //     pre_verification_gas: "0x8e4d78".to_string(),
    //     max_fee_per_gas: "0x1af6f".to_string(),
    //     max_priority_fee_per_gas: "0x1adb0".to_string(),
    //     paymaster: Some("0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B".to_string()),
    //     paymaster_verification_gas_limit: "0x7415".to_string(),
    //     paymaster_post_op_gas_limit: "0x".to_string(),
    //     paymaster_data: Some("000000000000000067789a97c4af0f8ae7acc9237c8f9611a0eb4662009d366b8defdf5f68fed25d22ca77be64b8eef49d917c3f8642ca539571594a84be9d0ee717c099160b79a845bea2111b".to_string()),
    //     factory: None,
    //     factory_data: None,
    // };

    //     let encoded_safe_op = EncodedSafeOpStruct::try_from(&user_op).unwrap();
    //     let hash = encoded_safe_op.into_transaction_hash();

    //     let smart_account = SafeSmartAccount::random();

    //     let safe_tx_hash =
    //         smart_account.eip_712_hash(hash, 480, Some(*GNOSIS_SAFE_4337_MODULE));

    //     let expected_hash =
    //         "f56239eeacb960d469a19f397dd6dce1b0ca6c9553aeff6fc72100cbddbfdb1a";
    //     assert_eq!(hex::encode(safe_tx_hash), expected_hash);
    // }

    // // Helper function to fill in the other fields of UserOperation so the test compiles
    // fn dummy_user_op() -> UserOperation {
    //     UserOperation {
    //         sender: "0x0".into(),
    //         nonce: "0".into(),
    //         call_data: String::new(),
    //         call_gas_limit: "0".into(),
    //         verification_gas_limit: "0".into(),
    //         pre_verification_gas: "0".into(),
    //         max_fee_per_gas: "0".into(),
    //         max_priority_fee_per_gas: "0".into(),
    //         paymaster: None,
    //         paymaster_verification_gas_limit: "0".into(),
    //         paymaster_post_op_gas_limit: "0".into(),
    //         paymaster_data: None,
    //         signature: String::new(),
    //         factory: None,
    //         factory_data: None,
    //     }
    // }

    // #[test]
    // fn test_get_init_code_allows_no_factory() {
    //     let user_op_no_factory = UserOperation {
    //         factory: None,
    //         factory_data: None,
    //         ..dummy_user_op()
    //     };
    //     let code = get_init_code(&user_op_no_factory).unwrap();
    //     assert!(
    //         code.is_empty(),
    //         "Expected empty init code when factory=None"
    //     );
    // }

    // #[test]
    // fn test_get_init_code_allows_0x_factory() {
    //     let user_op_0x_factory = UserOperation {
    //         factory: Some("0x".to_string()),
    //         factory_data: None,
    //         ..dummy_user_op()
    //     };
    //     let code = get_init_code(&user_op_0x_factory).unwrap();
    //     assert!(
    //         code.is_empty(),
    //         "Expected empty init code when factory='0x'"
    //     );
    // }

    // #[test]
    // fn test_get_init_code_parse_valid_factory_no_data() {
    //     let user_op_valid_factory = UserOperation {
    //         factory: Some("0x1111111111111111111111111111111111111111".to_string()),
    //         factory_data: None,
    //         ..dummy_user_op()
    //     };
    //     let code = get_init_code(&user_op_valid_factory).unwrap();
    //     // Should be exactly 20 bytes of the parsed address.
    //     assert_eq!(
    //         code.len(),
    //         20,
    //         "Should have exactly 20 bytes from the address"
    //     );
    // }

    // #[test]
    // fn test_get_init_code_parse_valid_factory_and_data() {
    //     let user_op_with_data = UserOperation {
    //         factory: Some("0x2222222222222222222222222222222222222222".to_string()),
    //         factory_data: Some("0x1234abcd".to_string()),
    //         ..dummy_user_op()
    //     };
    //     let code = get_init_code(&user_op_with_data).unwrap();
    //     assert_eq!(
    //         code.len(),
    //         20 + 4,
    //         "Should be 20 bytes + length of factory_data"
    //     );
    //     // The last 4 bytes should match 0x12,0x34,0xab,0xcd
    //     assert_eq!(&code[20..24], &[0x12, 0x34, 0xab, 0xcd]);
    // }

    // #[test]
    // fn test_get_init_code_invalid_factory() {
    //     let user_op_invalid_factory = UserOperation {
    //         factory: Some("0xZZZZZ...".to_string()), // obviously not valid hex
    //         factory_data: None,
    //         ..dummy_user_op()
    //     };
    //     let err = get_init_code(&user_op_invalid_factory).unwrap_err();
    //     match err {
    //         SafeSmartAccountError::InvalidInput { attribute, .. } => {
    //             assert_eq!(attribute, "factory");
    //         }
    //         _ => panic!("Expected SafeSmartAccountError::InvalidInput"),
    //     }
    // }
}
