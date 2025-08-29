use alloy::sol_types::SolValue;
use reqwest::Client;
use semaphore_rs::identity::Identity;
use semaphore_rs::{hash_to_field, Field};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use world_chain_builder_pbh::{
    external_nullifier::{EncodedExternalNullifier, ExternalNullifier},
    payload::{PBHPayload as PbhPayload, Proof},
};

use crate::{
    primitives::contracts::IEntryPoint::PackedUserOperation,
    smart_account::UserOperation,
};

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
pub async fn generate_pbh_proof(user_op: &UserOperation) -> PbhPayload {
    // Convert from UserOperation to PackedUserOperation
    // TODO: Fix this
    let packed_user_op: PackedUserOperation = PackedUserOperation::from(user_op);

    let signal = hash_user_op(&packed_user_op);

    let external_nullifier = ExternalNullifier::v1(8, 2025, 1);

    // TODO: Autotmatically find an unused one
    let encoded_external_nullifier = EncodedExternalNullifier::from(external_nullifier);

    let identity = get_world_id_identity().unwrap();

    let inclusion_proof = fetch_inclusion_proof(
        // TODO: Handle different envs
        "https://signup-orb-ethereum.stage-crypto.worldcoin.dev", // Staging
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
