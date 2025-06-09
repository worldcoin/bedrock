//! The `transaction_4337` module enables 4337 transaction crafting.
//!
//! A transaction can be initialized through a `UserOperation` struct.
//!

use super::SafeSmartAccountError;
use alloy::hex::FromHex;
use alloy::{
    primitives::{aliases::U48, keccak256, Address, Bytes, FixedBytes},
    sol,
    sol_types::SolValue,
};
use ruint::aliases::{U128, U256};
use std::{str::FromStr, sync::LazyLock};

/// A pseudo-transaction object for EIP-4337. Used to execute transactions through the Safe Smart Account.
///
/// This object is expected to be initialized from foreign languages.
///
/// Reference: <https://www.erc4337.io/docs/understanding-ERC-4337/user-operation>
///
/// Note the types of this struct are types that can be lifted from foreign languages to be then parsed and validated.
#[derive(uniffi::Record, Clone, Debug)]
pub struct UserOperation {
    /// The address of the smart contract account (Solidity type: `address`)
    pub sender: String,
    /// Anti-replay protection; also used as the salt for first-time account creation (Solidity type: `uint256`)
    pub nonce: String,
    /// Data that's passed to the sender for execution (Solidity type: `bytes`)
    pub call_data: String,
    /// Gas limit for execution phase (Solidity type: `uint128`)
    pub call_gas_limit: String,
    /// Gas limit for verification phase (Solidity type: `uint128`)
    pub verification_gas_limit: String,
    /// Gas to compensate the bundler (Solidity type: `uint256`)
    pub pre_verification_gas: String,
    /// Maximum fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)'s `max_fee_per_gas`) (Solidity type: `uint256`)
    pub max_fee_per_gas: String,
    /// Maximum priority fee per gas (Solidity type: `uint128`)
    pub max_priority_fee_per_gas: String,
    /// Paymaster contact address (Solidity type: `address`)
    pub paymaster: Option<String>,
    /// Paymaster verification gas limit (Solidity type: `uint128`)
    pub paymaster_verification_gas_limit: String,
    /// Paymaster post-operation gas limit (Solidity type: `uint128`)
    pub paymaster_post_op_gas_limit: String,
    /// Paymaster additional data for verification (Solidity type: `bytes`)
    pub paymaster_data: Option<String>,
    /// Used to validate a `UserOperation` along with the nonce during verification (Solidity type: `bytes`)
    pub signature: String,
    /// Factory address (Solidity type: `address`)
    pub factory: Option<String>,
    /// Factory data (Solidity type: `bytes`)
    pub factory_data: Option<String>,
}

/// <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L53>
static SAFE_OP_TYPEHASH: LazyLock<FixedBytes<32>> = LazyLock::new(|| {
    FixedBytes::from_hex(
        "0xc03dfc11d8b10bf9cf703d558958c8c42777f785d998c62060d85a4f0ef6ea7f",
    )
    .expect("error initializing `SAFE_OP_TYPEHASH`")
});

/// v0.7 `EntryPoint`
static ENTRYPOINT_4337: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x0000000071727De22E5E9d8BAf0edAc6f37da032")
        .expect("failed to decode ENTRYPOINT_4337")
});

/// Multichain address for the v0.3.0 `Safe4337Module`
pub static GNOSIS_SAFE_4337_MODULE: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x75cf11467937ce3f2f357ce24ffc3dbf8fd5c226")
        .expect("failed to decode GNOSIS_SAFE_4337_MODULE")
});

sol! {
    /// The EIP-712 type-hash for a SafeOp, representing the structure of a User Operation for the Safe.
    ///
    /// Reference: <https://github.com/safe-global/safe-modules/blob/4337/v0.3.0/modules/4337/contracts/Safe4337Module.sol#L58>
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

impl TryFrom<&UserOperation> for EncodedSafeOpStruct {
    type Error = SafeSmartAccountError;

    fn try_from(user_op: &UserOperation) -> Result<Self, Self::Error> {
        let sender = Address::from_str(&user_op.sender).map_err(|e| {
            SafeSmartAccountError::InvalidInput {
                attribute: "sender",
                message: e.to_string(),
            }
        })?;

        let nonce = U256::from_str(&user_op.nonce).map_err(|e| {
            SafeSmartAccountError::InvalidInput {
                attribute: "nonce",
                message: e.to_string(),
            }
        })?;

        let call_data = hex::decode(
            user_op
                .call_data
                .strip_prefix("0x")
                .unwrap_or(&user_op.call_data),
        )
        .map_err(|e| SafeSmartAccountError::InvalidInput {
            attribute: "call_data",
            message: e.to_string(),
        })?;

        let verification_gas_limit = U128::from_str(&user_op.verification_gas_limit)
            .map_err(|e| SafeSmartAccountError::InvalidInput {
                attribute: "verification_gas_limit",
                message: e.to_string(),
            })?
            .to::<u128>();

        let call_gas_limit = U128::from_str(&user_op.call_gas_limit)
            .map_err(|e| SafeSmartAccountError::InvalidInput {
                attribute: "call_gas_limit",
                message: e.to_string(),
            })?
            .to::<u128>();

        let pre_verification_gas = U256::from_str(&user_op.pre_verification_gas)
            .map_err(|e| SafeSmartAccountError::InvalidInput {
                attribute: "pre_verification_gas",
                message: e.to_string(),
            })?;

        let max_priority_fee_per_gas =
            U128::from_str(&user_op.max_priority_fee_per_gas)
                .map_err(|e| SafeSmartAccountError::InvalidInput {
                    attribute: "max_priority_fee_per_gas",
                    message: e.to_string(),
                })?
                .to::<u128>();

        let max_fee_per_gas = U128::from_str(&user_op.max_fee_per_gas)
            .map_err(|e| SafeSmartAccountError::InvalidInput {
                attribute: "max_fee_per_gas",
                message: e.to_string(),
            })?
            .to::<u128>();

        let paymaster_and_data = get_paymaster_and_data(user_op)?;

        let signature = hex::decode(
            user_op
                .signature
                .strip_prefix("0x")
                .unwrap_or(&user_op.signature),
        )
        .map_err(|_| SafeSmartAccountError::InvalidInput {
            attribute: "signature",
            message: "not validly encoded hex-data".to_string(),
        })?;

        let (valid_after, valid_until) = extract_validity_timestamps(&signature)?;

        Ok(Self {
            type_hash: *SAFE_OP_TYPEHASH,
            safe: sender,
            nonce,
            init_code_hash: keccak256(&get_init_code(user_op)?),
            call_data_hash: keccak256(&call_data),
            verification_gas_limit,
            call_gas_limit,
            pre_verification_gas,
            max_priority_fee_per_gas,
            max_fee_per_gas,
            paymaster_and_data_hash: keccak256(&paymaster_and_data),
            valid_after,
            valid_until,
            entry_point: *ENTRYPOINT_4337,
        })
    }
}

impl EncodedSafeOpStruct {
    pub fn into_transaction_hash(self) -> FixedBytes<32> {
        keccak256(self.abi_encode())
    }
}

/// Extract validAfter and validUntil from a signature as `U256` values.
/// Expects at least 12 bytes in the signature. Returns an error if the signature is too short.
fn extract_validity_timestamps(
    signature: &[u8],
) -> Result<(U48, U48), SafeSmartAccountError> {
    // timestamp validity (12 bytes) + regular ECDSA signature (65 bytes)
    if signature.len() != 77 {
        return Err(SafeSmartAccountError::InvalidInput {
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
fn get_init_code(user_op: &UserOperation) -> Result<Bytes, SafeSmartAccountError> {
    // Check if `factory` is present. If None, or "0x", or empty string -> treat as no factory.
    let factory_str = match user_op.factory.as_deref() {
        None | Some("0x" | "") => {
            // No factory -> return empty bytes
            return Ok(Bytes::new());
        }
        Some(addr) => addr,
    };

    // At this point, we have a non-empty factory string that is not just "0x"
    let factory_addr = Address::from_str(factory_str).map_err(|e| {
        SafeSmartAccountError::InvalidInput {
            attribute: "factory",
            message: e.to_string(),
        }
    })?;

    let mut out = Vec::new();
    out.extend_from_slice(factory_addr.as_slice());

    // If factory_data is present and not empty, parse it as hex and append
    if let Some(factory_data) = &user_op.factory_data {
        if !factory_data.is_empty() && factory_data != "0x" {
            let raw_factory_data =
                hex::decode(factory_data.strip_prefix("0x").unwrap_or(factory_data))
                    .map_err(|e| SafeSmartAccountError::InvalidInput {
                        attribute: "factory_data",
                        message: e.to_string(),
                    })?;
            out.extend_from_slice(&raw_factory_data);
        }
    }

    Ok(out.into())
}

/// Merges Paymaster related data
fn get_paymaster_and_data(
    user_op: &UserOperation,
) -> Result<Bytes, SafeSmartAccountError> {
    user_op.paymaster.as_ref().map_or_else(
        || Ok(Bytes::new()),
        |pm| {
            let mut out = Vec::new();

            // Append paymaster address (20 bytes)
            out.extend_from_slice(
                Address::from_str(pm)
                    .map_err(|e| SafeSmartAccountError::InvalidInput {
                        attribute: "paymaster",
                        message: e.to_string(),
                    })?
                    .as_slice(),
            );

            // Append paymasterVerificationGasLimit (16 bytes)
            let paymaster_verification_gas_limit = U128::from_str(
                &user_op.paymaster_verification_gas_limit,
            )
            .map_err(|e| SafeSmartAccountError::InvalidInput {
                attribute: "paymaster_verification_gas_limit",
                message: e.to_string(),
            })?;
            out.extend_from_slice(
                &paymaster_verification_gas_limit.to_be_bytes::<16>(),
            );

            // Append paymasterPostOpGasLimit (16 bytes)
            let paymaster_post_op_gas_limit =
                U128::from_str(&user_op.paymaster_post_op_gas_limit).map_err(|e| {
                    SafeSmartAccountError::InvalidInput {
                        attribute: "paymaster_post_op_gas_limit",
                        message: e.to_string(),
                    }
                })?;
            out.extend_from_slice(&paymaster_post_op_gas_limit.to_be_bytes::<16>());

            // Append paymasterData if it exists
            if let Some(data) = &user_op.paymaster_data {
                out.extend_from_slice(
                    &hex::decode(data.strip_prefix("0x").unwrap_or(data)).map_err(
                        |e| SafeSmartAccountError::InvalidInput {
                            attribute: "paymaster_data",
                            message: e.to_string(),
                        },
                    )?,
                );
            }

            Ok(out.into())
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smart_account::SafeSmartAccount;

    #[test]
    fn test_hash_user_op() {
        let user_op = UserOperation {
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

        let encoded_safe_op = EncodedSafeOpStruct::try_from(&user_op).unwrap();
        let hash = encoded_safe_op.into_transaction_hash();

        let smart_account = SafeSmartAccount::random();

        let safe_tx_hash =
            smart_account.eip_712_hash(hash, 480, Some(*GNOSIS_SAFE_4337_MODULE));

        let expected_hash =
            "f56239eeacb960d469a19f397dd6dce1b0ca6c9553aeff6fc72100cbddbfdb1a";
        assert_eq!(hex::encode(safe_tx_hash), expected_hash);
    }

    // Helper function to fill in the other fields of UserOperation so the test compiles
    fn dummy_user_op() -> UserOperation {
        UserOperation {
            sender: "0x0".into(),
            nonce: "0".into(),
            call_data: String::new(),
            call_gas_limit: "0".into(),
            verification_gas_limit: "0".into(),
            pre_verification_gas: "0".into(),
            max_fee_per_gas: "0".into(),
            max_priority_fee_per_gas: "0".into(),
            paymaster: None,
            paymaster_verification_gas_limit: "0".into(),
            paymaster_post_op_gas_limit: "0".into(),
            paymaster_data: None,
            signature: String::new(),
            factory: None,
            factory_data: None,
        }
    }

    #[test]
    fn test_get_init_code_allows_no_factory() {
        let user_op_no_factory = UserOperation {
            factory: None,
            factory_data: None,
            ..dummy_user_op()
        };
        let code = get_init_code(&user_op_no_factory).unwrap();
        assert!(
            code.is_empty(),
            "Expected empty init code when factory=None"
        );
    }

    #[test]
    fn test_get_init_code_allows_0x_factory() {
        let user_op_0x_factory = UserOperation {
            factory: Some("0x".to_string()),
            factory_data: None,
            ..dummy_user_op()
        };
        let code = get_init_code(&user_op_0x_factory).unwrap();
        assert!(
            code.is_empty(),
            "Expected empty init code when factory='0x'"
        );
    }

    #[test]
    fn test_get_init_code_parse_valid_factory_no_data() {
        let user_op_valid_factory = UserOperation {
            factory: Some("0x1111111111111111111111111111111111111111".to_string()),
            factory_data: None,
            ..dummy_user_op()
        };
        let code = get_init_code(&user_op_valid_factory).unwrap();
        // Should be exactly 20 bytes of the parsed address.
        assert_eq!(
            code.len(),
            20,
            "Should have exactly 20 bytes from the address"
        );
    }

    #[test]
    fn test_get_init_code_parse_valid_factory_and_data() {
        let user_op_with_data = UserOperation {
            factory: Some("0x2222222222222222222222222222222222222222".to_string()),
            factory_data: Some("0x1234abcd".to_string()),
            ..dummy_user_op()
        };
        let code = get_init_code(&user_op_with_data).unwrap();
        assert_eq!(
            code.len(),
            20 + 4,
            "Should be 20 bytes + length of factory_data"
        );
        // The last 4 bytes should match 0x12,0x34,0xab,0xcd
        assert_eq!(&code[20..24], &[0x12, 0x34, 0xab, 0xcd]);
    }

    #[test]
    fn test_get_init_code_invalid_factory() {
        let user_op_invalid_factory = UserOperation {
            factory: Some("0xZZZZZ...".to_string()), // obviously not valid hex
            factory_data: None,
            ..dummy_user_op()
        };
        let err = get_init_code(&user_op_invalid_factory).unwrap_err();
        match err {
            SafeSmartAccountError::InvalidInput { attribute, .. } => {
                assert_eq!(attribute, "factory");
            }
            _ => panic!("Expected SafeSmartAccountError::InvalidInput"),
        }
    }
}
