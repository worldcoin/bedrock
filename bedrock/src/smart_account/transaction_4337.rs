//! The `transaction_4337` module enables 4337 transaction crafting.
//!
//! A transaction can be initialized through a `UserOperation` struct.
//!

use crate::primitives::contracts::{PBH_ENTRYPOINT_4337, PBH_ENTRYPOINT_4337_MAINNET, PBH_ENTRYPOINT_4337_SEPOLIA};
use crate::primitives::contracts::{
    EncodedSafeOpStruct, IEntryPoint::PackedUserOperation, IPBHEntryPoint::PBHPayload,
    UserOperation, ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE,
};
use crate::primitives::{Network, PrimitiveError};
use crate::smart_account::SafeSmartAccountSigner;
use crate::transaction::rpc::{RpcError, RpcProviderName};

use alloy::primitives::{aliases::U48, Address, Bytes, FixedBytes};
use alloy::sol_types::SolValue;
use chrono::{Duration, Utc};
use eyre;
use futures::future;
use reqwest::Client;
use semaphore_rs::identity::Identity;
use semaphore_rs::{hash_to_field, Field};
use serde::{Deserialize, Serialize};
use world_chain_builder_pbh::external_nullifier::{
    EncodedExternalNullifier, ExternalNullifier,
};
use world_chain_builder_pbh::payload::{PBHPayload as PbhPayload, Proof};

/// The default validity duration for 4337 `UserOperation` signatures.
///
/// Operations are valid for this duration from the time they are signed.
const USER_OPERATION_VALIDITY_DURATION_HOURS: i64 = 12;

#[derive(Debug, Serialize, Deserialize)]
pub struct SerializableIdentity {
    pub nullifier: Field,
    pub trapdoor: Field,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    pub root: Field,
    pub proof: semaphore_rs::poseidon_tree::Proof,
}

impl From<&Identity> for SerializableIdentity {
    fn from(identity: &Identity) -> Self {
        Self {
            nullifier: identity.nullifier,
            trapdoor: identity.trapdoor,
        }
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
        pbh: bool,
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
        pbh: bool,
        provider: RpcProviderName,
    ) -> Result<FixedBytes<32>, RpcError> {
        // Get the global RPC client
        let rpc_client = crate::transaction::rpc::get_rpc_client()?;

        // 1. Create preflight UserOperation using default metadata for this implementation
        let mut user_operation = self.as_preflight_user_operation(
            safe_account.wallet_address,
            metadata,
            pbh,
        )?;

        let entrypoint = if pbh {
            *PBH_ENTRYPOINT_4337
        } else {
            *ENTRYPOINT_4337
        };

        // 2. Request sponsorship
        let sponsor_response = rpc_client
            .sponsor_user_operation(
                network,
                &user_operation,
                entrypoint,
                self_sponsor_token,
                provider,
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
        let mut full_signature = Vec::new();
        full_signature.extend_from_slice(&valid_after_bytes);
        full_signature.extend_from_slice(valid_until_bytes);
        full_signature.extend_from_slice(&signature.as_bytes()[..]);

        // // PBH Logic
        if pbh {
            let pbh_payload = Self::generate_pbh_proof(&user_operation).await;
            full_signature.extend_from_slice(
                PBHPayload::from(pbh_payload.clone()).abi_encode().as_ref(),
            );
        }

        user_operation.signature = full_signature.into();

        // 5. Submit UserOperation
        let user_op_hash = rpc_client
            .send_user_operation(network, &user_operation, entrypoint, provider)
            .await?;

        Ok(user_op_hash)
    }

    /// Generates a PBH proof for a given user operation.
    async fn generate_pbh_proof(user_op: &UserOperation) -> PbhPayload {
        // Convert from UserOperation to PackedUserOperation
        // TODO: Fix this
        let packed_user_op: PackedUserOperation = PackedUserOperation::from(user_op);

        let signal = Self::hash_user_op(&packed_user_op);

        let external_nullifier = ExternalNullifier::v1(8, 2025, 0);

        // TODO: Autotmatically find an unused one
        let encoded_external_nullifier =
            EncodedExternalNullifier::from(external_nullifier);

        let identities: Vec<SerializableIdentity> = serde_json::from_reader(
            std::fs::File::open("test_identities.json").unwrap(),
        )
        .unwrap();
        let identities: Vec<Identity> = identities
            .into_iter()
            .map(|identity| Identity {
                nullifier: identity.nullifier,
                trapdoor: identity.trapdoor,
            })
            .collect();

        let proofs =
            futures::future::try_join_all(identities.iter().map(|identity| async {
                Self::fetch_inclusion_proof(
                    "https://signup-orb-ethereum.stage-crypto.worldcoin.dev", // Staging
                    identity,
                )
                .await
            }))
            .await
            .unwrap();

        let identity = identities[0].clone();
        let inclusion_proof = proofs[0].clone();

        let proof: semaphore_rs_proof::Proof = semaphore_rs::protocol::generate_proof(
            &identity,
            &inclusion_proof.proof,
            encoded_external_nullifier.0,
            signal,
        )
        .expect("Failed to generate semaphore proof");
        let nullifier_hash = semaphore_rs::protocol::generate_nullifier_hash(
            &identity,
            encoded_external_nullifier.0,
        );

        let proof = Proof(proof);

        PbhPayload {
            external_nullifier,
            nullifier_hash,
            root: inclusion_proof.root,
            proof,
        }
    }

    /// Fetches an inclusion proof for a given identity from the signup sequencer.
    ///
    /// This function sends a request to the sequencer to fetch the inclusion proof for a given identity.
    ///
    /// # Arguments
    /// * `url` - The URL of the sequencer
    /// * `identity` - The identity to fetch the proof for
    async fn fetch_inclusion_proof(
        url: &str,
        identity: &Identity,
    ) -> eyre::Result<InclusionProof> {
        let client = Client::new();

        let commitment = identity.commitment();
        let response = client
            .post(format!("{}/inclusionProof", url))
            .json(&serde_json::json! {{
                "identityCommitment": commitment,
            }})
            .send()
            .await?
            .error_for_status()?;

        let proof: InclusionProof = response.json().await?;

        Ok(proof)
    }

    /// Computes a ZK-friendly hash of a PackedUserOperation.
    ///
    /// This function extracts key fields (sender, nonce, callData) from a PackedUserOperation,
    /// encodes them using ABI packed encoding, and converts the result to a Field element
    /// suitable for use in zero-knowledge proof circuits.
    ///
    /// # Arguments
    /// * `user_op` - The PackedUserOperation to hash
    ///
    /// # Returns
    /// A Field element representing the hash of the user operation
    fn hash_user_op(user_op: &PackedUserOperation) -> Field {
        let hash = SolValue::abi_encode_packed(&(
            &user_op.sender,
            &user_op.nonce,
            &user_op.callData,
        ));
        hash_to_field(hash.as_slice())
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
        transaction::{foreign::UnparsedUserOperation, SponsorUserOperationResponse},
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

    #[test]
    fn test_user_operation_to_encoded_safe_op_struct_conversion() {
        use alloy::primitives::{address, U256};
        use std::str::FromStr;

        // Create a UserOperation with valid signature containing timestamps
        let mut signature = Vec::with_capacity(77);

        // Add validAfter (6 bytes) - timestamp 1704067200
        let valid_after_timestamp: u64 = 1704067200;
        let valid_after_bytes = valid_after_timestamp.to_be_bytes();
        signature.extend_from_slice(&valid_after_bytes[2..8]);

        // Add validUntil (6 bytes) - timestamp 1735689600
        let valid_until_timestamp: u64 = 1735689600;
        let valid_until_bytes = valid_until_timestamp.to_be_bytes();
        signature.extend_from_slice(&valid_until_bytes[2..8]);

        // Add dummy ECDSA signature (65 bytes)
        signature.extend_from_slice(&[0xff; 65]);

        let user_op = UserOperation {
            sender: address!("0x1111111111111111111111111111111111111111"),
            nonce: U256::from(42),
            call_data: Bytes::from_str("0x1234abcd").unwrap(),
            signature: signature.into(),
            call_gas_limit: 100000,
            verification_gas_limit: 50000,
            pre_verification_gas: U256::from(30000),
            max_fee_per_gas: 2000000000,
            max_priority_fee_per_gas: 1000000000,
            ..Default::default()
        };

        // Test the From trait conversion
        let encoded_safe_op: EncodedSafeOpStruct = user_op.clone().into();

        // Verify the conversion worked correctly
        assert_eq!(encoded_safe_op.safe, user_op.sender);
        assert_eq!(encoded_safe_op.nonce, user_op.nonce);
        assert_eq!(encoded_safe_op.call_gas_limit, user_op.call_gas_limit);
        assert_eq!(
            encoded_safe_op.verification_gas_limit,
            user_op.verification_gas_limit
        );
        assert_eq!(
            encoded_safe_op.pre_verification_gas,
            user_op.pre_verification_gas
        );
        assert_eq!(encoded_safe_op.max_fee_per_gas, user_op.max_fee_per_gas);
        assert_eq!(
            encoded_safe_op.max_priority_fee_per_gas,
            user_op.max_priority_fee_per_gas
        );
        assert_eq!(
            encoded_safe_op.valid_after,
            U48::from(valid_after_timestamp)
        );
        assert_eq!(
            encoded_safe_op.valid_until,
            U48::from(valid_until_timestamp)
        );
        assert_eq!(encoded_safe_op.entry_point, *ENTRYPOINT_4337);
        assert_eq!(
            encoded_safe_op.call_data_hash,
            keccak256(&user_op.call_data)
        );
        assert_eq!(
            encoded_safe_op.init_code_hash,
            keccak256(user_op.get_init_code())
        );
        assert_eq!(
            encoded_safe_op.paymaster_and_data_hash,
            keccak256(user_op.get_paymaster_and_data())
        );
    }

    #[test]
    fn test_user_operation_to_encoded_safe_op_struct_with_invalid_signature() {
        use alloy::primitives::{address, U256};
        use std::str::FromStr;

        // Create a UserOperation with invalid signature (too short)
        let user_op = UserOperation {
            sender: address!("0x1111111111111111111111111111111111111111"),
            nonce: U256::from(42),
            call_data: Bytes::from_str("0x1234abcd").unwrap(),
            signature: vec![0xff; 65].into(), // Invalid length
            ..Default::default()
        };

        // Test the From trait conversion with invalid signature
        let encoded_safe_op: EncodedSafeOpStruct = user_op.clone().into();

        // Should use default timestamps (zero) when signature is invalid
        assert_eq!(encoded_safe_op.valid_after, U48::ZERO);
        assert_eq!(encoded_safe_op.valid_until, U48::ZERO);
        assert_eq!(encoded_safe_op.safe, user_op.sender);
        assert_eq!(encoded_safe_op.nonce, user_op.nonce);
    }
}
