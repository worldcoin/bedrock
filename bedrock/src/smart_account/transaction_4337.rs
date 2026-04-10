//! The `transaction_4337` module enables 4337 transaction crafting.
//!
//! A transaction can be initialized through a `UserOperation` struct.
//!

use crate::primitives::contracts::{EncodedSafeOpStruct, IEntryPoint, UserOperation};
use crate::primitives::{Network, PrimitiveError};
use crate::smart_account::{SafeSmartAccount, SafeSmartAccountSigner};
use crate::transactions::rpc::{RpcError, RpcProviderName};

use alloy::primitives::{aliases::{U192, U48}, Address, Bytes, FixedBytes, U256};
use alloy::sol_types::SolCall;
use chrono::{Duration, Utc};

use crate::primitives::contracts::{ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE};

/// The default validity duration for 4337 `UserOperation` signatures.
///
/// Operations are valid for this duration from the time they are signed.
pub const USER_OPERATION_VALIDITY_DURATION_MINUTES: i64 = 30;

/// The backdating window applied to 4337 `UserOperation` signatures.
///
/// This matches app-backend's validity window construction to avoid edge cases
/// around clock skew between sponsorship and submission.
pub const USER_OPERATION_VALIDITY_BACKDATE_MINUTES: i64 = 10;

pub(crate) fn validity_window_seconds() -> (u64, u64) {
    let now = Utc::now();
    let valid_after = (now - Duration::minutes(USER_OPERATION_VALIDITY_BACKDATE_MINUTES))
        .timestamp()
        .try_into()
        .unwrap_or(0);
    let valid_until = (now + Duration::minutes(USER_OPERATION_VALIDITY_DURATION_MINUTES))
        .timestamp()
        .try_into()
        .unwrap_or(0);
    (valid_after, valid_until)
}

fn timestamp_to_u48_and_bytes(seconds: u64) -> (U48, [u8; 6]) {
    let bytes = seconds.to_be_bytes();
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes[2..8]);
    (U48::from(seconds), out)
}

impl SafeSmartAccount {
    /// Signs a `UserOperation` with the provided validity timestamps and sets the
    /// composed 77-byte signature (`validAfter` + `validUntil` + ECDSA) on the operation.
    ///
    /// # Errors
    /// * Returns `RpcError` if the `EncodedSafeOpStruct` cannot be built from the operation
    /// * Returns `RpcError` if the signing process fails
    pub(crate) fn sign_user_operation(
        &self,
        user_operation: &mut UserOperation,
        network: Network,
        valid_after_seconds: u64,
        valid_until_seconds: u64,
    ) -> Result<(), RpcError> {
        let (valid_after_u48, valid_after_bytes) =
            timestamp_to_u48_and_bytes(valid_after_seconds);
        let (valid_until_u48, valid_until_bytes) =
            timestamp_to_u48_and_bytes(valid_until_seconds);

        let encoded_safe_op = EncodedSafeOpStruct::from_user_op_with_validity(
            user_operation,
            valid_after_u48,
            valid_until_u48,
        )?;

        let signature = self.sign_digest(
            encoded_safe_op.into_transaction_hash(),
            network as u32,
            Some(*GNOSIS_SAFE_4337_MODULE),
        )?;

        // Compose the final signature: validAfter (6 bytes) + validUntil (6 bytes) + ECDSA (65 bytes) = 77 bytes
        let mut full_signature = Vec::with_capacity(77);
        full_signature.extend_from_slice(&valid_after_bytes);
        full_signature.extend_from_slice(&valid_until_bytes);
        full_signature.extend_from_slice(&signature.as_bytes()[..]);

        user_operation.signature = full_signature.into();

        Ok(())
    }
}

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
    /// # Returns
    /// * `Result<FixedBytes<32>, RpcError>` - The `userOpHash` on success
    ///
    /// # Errors
    /// * Returns `RpcError` if any RPC operation fails
    /// * Returns `RpcError` if signing fails
    /// * Returns `RpcError` if the global HTTP client has not been initialized
    async fn sign_and_execute(
        &self,
        safe_account: &SafeSmartAccount,
        network: Network,
        self_sponsor_token: Option<Address>,
        metadata: Option<Self::MetadataArg>,
        provider: RpcProviderName,
    ) -> Result<FixedBytes<32>, RpcError> {
        // 0. Get the global RPC client
        let rpc_client = crate::transactions::rpc::get_rpc_client()?;

        // 1. Create preflight UserOperation using default metadata for this implementation
        let mut user_operation =
            self.as_preflight_user_operation(safe_account.wallet_address, metadata)?;

        // Match app-backend semantics by resolving the current sequence from EntryPoint
        // for the operation's nonce key and by using a real validity window in the
        // placeholder signature during sponsorship.
        let nonce_key = {
            let nonce_bytes = user_operation.nonce.to_be_bytes::<32>();
            let mut key_bytes = [0u8; 24];
            key_bytes.copy_from_slice(&nonce_bytes[..24]);
            U192::from_be_bytes(key_bytes)
        };
        let nonce_call = IEntryPoint::getNonceCall {
            sender: user_operation.sender,
            key: nonce_key,
        };
        let nonce_result = rpc_client
            .eth_call(network, *ENTRYPOINT_4337, nonce_call.abi_encode().into())
            .await?;
        let resolved_nonce: U256 = IEntryPoint::getNonceCall::abi_decode_returns(&nonce_result)
            .map_err(|e| RpcError::InvalidResponse {
                error_message: format!("Failed to decode EntryPoint.getNonce response: {e}"),
            })?;
        user_operation.nonce = resolved_nonce;

        let (valid_after_seconds, valid_until_seconds) = validity_window_seconds();
        let (_, valid_after_bytes) = timestamp_to_u48_and_bytes(valid_after_seconds);
        let (_, valid_until_bytes) = timestamp_to_u48_and_bytes(valid_until_seconds);
        let mut placeholder_signature = Vec::with_capacity(77);
        placeholder_signature.extend_from_slice(&valid_after_bytes);
        placeholder_signature.extend_from_slice(&valid_until_bytes);
        placeholder_signature.extend_from_slice(&[0xff; 65]);
        user_operation.signature = placeholder_signature.into();

        // 2. Request sponsorship
        let sponsor_response = rpc_client
            .sponsor_user_operation(
                network,
                &user_operation,
                *ENTRYPOINT_4337,
                self_sponsor_token,
                provider,
            )
            .await?;

        // 3. Merge paymaster data
        user_operation = user_operation.with_paymaster_data(&sponsor_response);

        // 4. Sign the UserOperation with fresh validity timestamps
        safe_account.sign_user_operation(
            &mut user_operation,
            network,
            valid_after_seconds,
            valid_until_seconds,
        )?;

        // 5. Submit UserOperation
        let user_op_hash = rpc_client
            .send_user_operation(
                network,
                &user_operation,
                *ENTRYPOINT_4337,
                sponsor_response.provider_name,
            )
            .await?;

        Ok(user_op_hash)
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, U128};
    use ruint::aliases::U256;
    use std::str::FromStr;

    use super::*;
    use crate::{
        smart_account::SafeSmartAccount,
        transactions::{foreign::UnparsedUserOperation, SponsorUserOperationResponse},
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
        paymaster_verification_gas_limit: Some("0x7415".to_string()),
        paymaster_post_op_gas_limit: Some("0x".to_string()),
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
            factory: None,
            factory_data: None,
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
            factory: Some(address!("0x1111111111111111111111111111111111111111")),
            factory_data: Some(Bytes::new()),
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
            factory: Some(address!("0x2222222222222222222222222222222222222222")),
            factory_data: Some(Bytes::from_str("0x1234abcd").unwrap()),
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
        user_op.call_gas_limit = U128::from(100);
        user_op.verification_gas_limit = U128::from(200);

        let sponsor_response = SponsorUserOperationResponse {
            paymaster: Some(address!("0x2222222222222222222222222222222222222222")),
            paymaster_data: Some(Bytes::from_str("0xabcd").unwrap()),
            pre_verification_gas: U256::from(300),
            verification_gas_limit: U128::from(400),
            call_gas_limit: U128::from(500),
            paymaster_verification_gas_limit: Some(U128::from(600)),
            paymaster_post_op_gas_limit: Some(U128::from(700)),
            max_priority_fee_per_gas: U128::from(800),
            max_fee_per_gas: U128::from(900),
            provider_name: RpcProviderName::Pimlico,
        };

        let updated_user_op = user_op.with_paymaster_data(&sponsor_response);
        assert_eq!(
            updated_user_op.paymaster,
            Some(address!("0x2222222222222222222222222222222222222222"))
        );
        assert_eq!(
            updated_user_op.paymaster_data,
            Some(Bytes::from_str("0xabcd").unwrap())
        );
        assert_eq!(updated_user_op.pre_verification_gas, U256::from(300));
        assert_eq!(
            updated_user_op.paymaster_verification_gas_limit,
            Some(U128::from(600))
        );
        assert_eq!(
            updated_user_op.paymaster_post_op_gas_limit,
            Some(U128::from(700))
        );
        assert_eq!(updated_user_op.max_priority_fee_per_gas, U128::from(800));
        assert_eq!(updated_user_op.max_fee_per_gas, U128::from(900));
    }

    #[test]
    fn test_get_paymaster_and_data_no_paymaster() {
        let user_op = UserOperation {
            paymaster: None,
            paymaster_data: None,
            ..Default::default()
        };
        let data = user_op.get_paymaster_and_data();
        assert!(
            data.is_empty(),
            "Expected empty data when paymaster is None"
        );
    }

    #[test]
    fn test_get_paymaster_and_data_with_paymaster_when_there_is_no_additional_paymaster_data(
    ) {
        let user_op = UserOperation {
            paymaster: Some(address!("0x1111111111111111111111111111111111111111")),
            paymaster_verification_gas_limit: Some(U128::from(1000)),
            paymaster_post_op_gas_limit: Some(U128::from(2000)),
            paymaster_data: Some(Bytes::new()),
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
            paymaster: Some(address!("0x2222222222222222222222222222222222222222")),
            paymaster_verification_gas_limit: Some(U128::from(3000)),
            paymaster_post_op_gas_limit: Some(U128::from(4000)),
            paymaster_data: Some(paymaster_data),
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

        if let Err(PrimitiveError::InvalidInput {
            attribute,
            error_message,
        }) = result
        {
            assert_eq!(attribute, "signature");
            assert!(
                error_message.contains("signature does not have the correct length")
            );
        } else {
            panic!("Expected InvalidInput error");
        }
    }

    #[test]
    fn test_as_bundler_sponsored_zeros_fee_and_paymaster_fields() {
        let user_op = UserOperation {
            sender: address!("0x1111111111111111111111111111111111111111"),
            nonce: U256::from(42),
            call_data: Bytes::from_str("0x1234").unwrap(),
            call_gas_limit: U128::from(100_000),
            verification_gas_limit: U128::from(200_000),
            pre_verification_gas: U256::from(50_000),
            max_fee_per_gas: U128::from(1_000_000_000),
            max_priority_fee_per_gas: U128::from(500_000_000),
            paymaster: Some(address!("0x2222222222222222222222222222222222222222")),
            paymaster_verification_gas_limit: Some(U128::from(30_000)),
            paymaster_post_op_gas_limit: Some(U128::from(40_000)),
            paymaster_data: Some(Bytes::from_str("0xabcd").unwrap()),
            signature: vec![0xff; 77].into(),
            factory: None,
            factory_data: None,
        };

        let sponsored = user_op.as_bundler_sponsored();

        // Core fields should be preserved
        assert_eq!(
            sponsored.sender,
            address!("0x1111111111111111111111111111111111111111")
        );
        assert_eq!(sponsored.nonce, U256::from(42));
        assert_eq!(sponsored.call_data, Bytes::from_str("0x1234").unwrap());
        assert_eq!(sponsored.call_gas_limit, U128::from(100_000));
        assert_eq!(sponsored.verification_gas_limit, U128::from(200_000));

        // Fee fields should be zeroed
        assert_eq!(sponsored.pre_verification_gas, U256::ZERO);
        assert_eq!(sponsored.max_fee_per_gas, U128::ZERO);
        assert_eq!(sponsored.max_priority_fee_per_gas, U128::ZERO);

        // Paymaster fields should be cleared/zeroed
        assert_eq!(sponsored.paymaster, None);
        assert_eq!(sponsored.paymaster_verification_gas_limit, None);
        assert_eq!(sponsored.paymaster_post_op_gas_limit, None);
        assert_eq!(sponsored.paymaster_data, None);
    }

    #[test]
    fn test_sign_user_operation_produces_valid_77_byte_signature() {
        let safe = SafeSmartAccount::new(
            "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
                .to_string(),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();

        let (valid_after_seconds, valid_until_seconds) = validity_window_seconds();

        let mut user_op = UserOperation::new_with_defaults(
            address!("0x4564420674EA68fcc61b463C0494807C759d47e6"),
            U256::ZERO,
            Bytes::from_str("0x1234").unwrap(),
        );

        safe.sign_user_operation(
            &mut user_op,
            Network::WorldChain,
            valid_after_seconds,
            valid_until_seconds,
        )
        .unwrap();

        // Signature should be exactly 77 bytes (6 + 6 + 65)
        assert_eq!(user_op.signature.len(), 77);

        // validAfter (first 6 bytes) should be populated with the expected backdated timestamp
        assert_ne!(&user_op.signature[0..6], &[0u8; 6]);

        // validUntil (next 6 bytes) should be non-zero (30 minutes from now)
        let valid_until_bytes = &user_op.signature[6..12];
        assert_ne!(valid_until_bytes, &[0u8; 6]);

        // The timestamps should be extractable from the signed operation
        let (valid_after, valid_until) = user_op.extract_validity_timestamps().unwrap();
        assert_eq!(valid_after, U48::from(valid_after_seconds));
        assert_eq!(valid_until, U48::from(valid_until_seconds));
    }
}
