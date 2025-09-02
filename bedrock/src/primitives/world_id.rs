use alloy::sol_types::SolValue;
use chrono::{Datelike, Utc};
use reqwest::{Client, Url};
use semaphore_rs::identity::Identity;
use semaphore_rs::{hash_to_field, Field};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use world_chain_builder_pbh::{
    external_nullifier::{EncodedExternalNullifier, ExternalNullifier},
    payload::{PBHPayload as PbhPayload, Proof},
};

use crate::primitives::contracts::{IPBHEntryPoint, PBH_ENTRYPOINT_4337};
use crate::primitives::Network;
use crate::transaction::rpc::get_rpc_client;
use crate::{
    primitives::contracts::IEntryPoint::PackedUserOperation,
    smart_account::UserOperation,
};

use alloy::primitives::U256;
use alloy::providers::{Provider, ProviderBuilder};

const STAGING_SEQUENCER_URL: &str =
    "https://signup-orb-ethereum.stage-crypto.worldcoin.dev";
const PRODUCTION_SEQUENCER_URL: &str =
    "https://signup-orb-ethereum.crypto.worldcoin.org";

const STAGING_MAX_NONCE: u16 = u16::MAX;
// TODO: UPDATE THIS ONCE SET IN PRODUCTION
// const PRODUCTION_MAX_NONCE: u16 = 9000;

/// Inclusion proof for a given identity.
///
/// This struct contains the root of the Merkle tree and the proof for a given identity.
///
/// # Fields
/// * `root` - The root of the Merkle tree
/// * `proof` - The proof for the given identity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InclusionProof {
    /// The root of the Merkle tree
    pub root: Field,
    /// The proof for the given identity
    pub proof: semaphore_rs::poseidon_tree::Proof,
}

/// Global World ID identity instance for Bedrock operations
static WORLD_ID_IDENTITY_INSTANCE: OnceLock<Arc<Identity>> = OnceLock::new();

/// Sets the World ID identity.
///
/// This function sets the World ID identity for Bedrock operations.
///
/// # Arguments
/// * `identity` - The World ID identity to set
///
/// # Returns
/// true if the World ID identity was set successfully, false otherwise.
///
/// # Errors
/// This function will return false if the World ID identity is already initialized.
pub fn set_world_id_identity(identity: Arc<Identity>) -> bool {
    if WORLD_ID_IDENTITY_INSTANCE.set(identity).is_err() {
        crate::warn!("World ID identity already initialized, ignoring");
        false
    } else {
        crate::info!("World ID identity initialized successfully");
        true
    }
}

/// Gets the World ID identity.
///
/// # Returns
/// The World ID identity if it has been initialized, None otherwise.
pub fn get_world_id_identity() -> Option<Arc<Identity>> {
    WORLD_ID_IDENTITY_INSTANCE.get().cloned()
}

/// Checks if the World ID identity has been initialized.
///
/// # Returns
/// true if the World ID identity has been initialized, false otherwise.
pub fn is_world_id_identity_initialized() -> bool {
    WORLD_ID_IDENTITY_INSTANCE.get().is_some()
}

/// Generates a PBH proof for a given user operation.
pub async fn generate_pbh_proof(
    user_op: &UserOperation,
    network: Network,
) -> PbhPayload {
    // Convert from UserOperation to PackedUserOperation
    // TODO: Clean this up
    let packed_user_op: PackedUserOperation = PackedUserOperation::from(user_op);

    let signal = hash_user_op(&packed_user_op);

    // TODO: Fix me
    let external_nullifier =
        find_unused_nullifier_hash("https://worldchain-sepolia.gateway.tenderly.co")
            .await
            .unwrap();

    let encoded_external_nullifier = EncodedExternalNullifier::from(external_nullifier);

    let identity = get_world_id_identity().unwrap();

    let inclusion_proof = fetch_inclusion_proof(
        match network {
            Network::WorldChain => PRODUCTION_SEQUENCER_URL,
            Network::WorldChainSepolia => STAGING_SEQUENCER_URL,
            _ => panic!("Invalid network for World ID"),
        },
        &identity,
    )
    .await
    .unwrap();

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

/// Finds the first unused nullifier hash for the current World ID identity.
pub async fn find_unused_nullifier_hash(
    provider_url: &str,
) -> Result<ExternalNullifier, Box<dyn std::error::Error>> {
    let identity = get_world_id_identity().unwrap();
    let now = Utc::now();
    let current_year = now.year() as u16;
    let current_month = now.month() as u16;

    // TODO: get this from global
    let provider: alloy::providers::fillers::FillProvider<
        alloy::providers::fillers::JoinFill<
            alloy::providers::Identity,
            alloy::providers::fillers::JoinFill<
                alloy::providers::fillers::GasFiller,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::BlobGasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::NonceFiller,
                        alloy::providers::fillers::ChainIdFiller,
                    >,
                >,
            >,
        >,
        alloy::providers::RootProvider,
    > = ProviderBuilder::new().connect_http(Url::parse(provider_url).unwrap());
    let contract: IPBHEntryPoint::IPBHEntryPointInstance<
        alloy::providers::fillers::FillProvider<
            alloy::providers::fillers::JoinFill<
                alloy::providers::Identity,
                alloy::providers::fillers::JoinFill<
                    alloy::providers::fillers::GasFiller,
                    alloy::providers::fillers::JoinFill<
                        alloy::providers::fillers::BlobGasFiller,
                        alloy::providers::fillers::JoinFill<
                            alloy::providers::fillers::NonceFiller,
                            alloy::providers::fillers::ChainIdFiller,
                        >,
                    >,
                >,
            >,
            alloy::providers::RootProvider,
        >,
    > = IPBHEntryPoint::new(*PBH_ENTRYPOINT_4337, provider);

    // TODO: Batching and env switch
    for nonce in 0..STAGING_MAX_NONCE {
        let external_nullifier =
            ExternalNullifier::v1(current_month as u8, current_year, nonce as u16);
        let encoded_external_nullifier =
            EncodedExternalNullifier::from(external_nullifier.clone());

        let nullifier_hash = semaphore_rs::protocol::generate_nullifier_hash(
            &identity,
            encoded_external_nullifier.0,
        );

        let vec = vec![U256::from_be_bytes(nullifier_hash.to_be_bytes::<32>())];

        let first_unused_index =
            contract.getFirstUnspentNullifierHash(vec).call().await?;

        if first_unused_index.as_i64() != -1 {
            println!("Month: {:?}", current_month);
            println!("Year: {:?}", current_year);
            println!("Nonce: {:?}", nonce);

            return Ok(external_nullifier);
        }
    }

    return Err("No PBH transactions remaining".into());
}

/// Fetches an inclusion proof for a given identity from the signup sequencer.
///
/// This function sends a request to the sequencer to fetch the inclusion proof for a given identity.
///
/// # Arguments
/// * `url` - The URL of the sequencer
/// * `identity` - The identity to fetch the proof for
pub async fn fetch_inclusion_proof(
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
pub fn hash_user_op(user_op: &PackedUserOperation) -> Field {
    let hash = SolValue::abi_encode_packed(&(
        &user_op.sender,
        &user_op.nonce,
        &user_op.callData,
    ));
    hash_to_field(hash.as_slice())
}
