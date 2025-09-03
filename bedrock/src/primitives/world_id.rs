use alloy::sol_types::{SolCall, SolValue};

use alloy::primitives::Bytes;
use alloy_primitives::I256;
use chrono::{Datelike, Utc};
use reqwest::Client;
use semaphore_rs::identity::Identity;
use semaphore_rs::poseidon_tree::Proof as PoseidonTreeProof;
use semaphore_rs::protocol::{generate_nullifier_hash, generate_proof, ProofError};
use semaphore_rs::{hash_to_field, Field};
use semaphore_rs_proof::Proof as SemaphoreProof;
use serde::{Deserialize, Serialize};
use std::sync::{Arc, OnceLock};
use world_chain_builder_pbh::{
    external_nullifier::{EncodedExternalNullifier, ExternalNullifier},
    payload::{
        PBHPayload as WorldchainBuilderPBHPayload, Proof as WorldchainBuilderProof,
    },
};

use crate::primitives::contracts::{IPBHEntryPoint, PBH_ENTRYPOINT_4337};
use crate::primitives::Network;
use crate::transaction::rpc::get_rpc_client;
use crate::transaction::RpcError;
use crate::{
    primitives::contracts::IEntryPoint::PackedUserOperation,
    smart_account::UserOperation,
};

use alloy::primitives::U256;

const STAGING_SEQUENCER_URL: &str =
    "https://signup-orb-ethereum.stage-crypto.worldcoin.dev";
const PRODUCTION_SEQUENCER_URL: &str =
    "https://signup-orb-ethereum.crypto.worldcoin.org";

const STAGING_MAX_NONCE: u16 = u16::MAX;
// TODO: UPDATE THIS ONCE SET IN PRODUCTION
const PRODUCTION_MAX_NONCE: u16 = 9000;

const MAX_NONCE_BATCH_SIZE: u16 = 100;

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
    pub proof: PoseidonTreeProof,
}

/// Errors that can occur when interacting with RPC operations.
#[crate::bedrock_error]
#[derive(Debug, Deserialize)]
pub enum WorldIdError {
    /// WorldID identity has not been initialized
    #[error("WorldID identity not initialized. Call set_world_id_identity() first.")]
    WorldIdIdentityNotInitialized,
    /// Failed to fetch inclusion proof from sequencer
    #[error("Inclusion proof error: {0}")]
    InclusionProofError(String),
    /// User has no more PBH transactions remaining
    #[error("No PBH transactions remaining")]
    NoPBHTransactionsRemaining,
    /// Invalid network for World ID
    #[error("Invalid network for World ID: {0}")]
    InvalidNetworkError(String),
    /// Proof error
    #[error("Proof error: {0}")]
    ProofError(#[from] ProofError),
    /// RPC error
    #[error("RPC error: {0}")]
    RpcError(#[from] RpcError),
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
pub fn set_world_id_identity(identity: Arc<Identity>) {
    if WORLD_ID_IDENTITY_INSTANCE.set(identity).is_err() {
        crate::warn!("World ID identity already initialized, ignoring");
    } else {
        crate::info!("World ID identity initialized successfully");
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
    user_op: UserOperation,
    network: Network,
) -> Result<WorldchainBuilderPBHPayload, WorldIdError> {
    let packed_user_op: PackedUserOperation = PackedUserOperation::from(user_op);
    let signal = hash_user_op(&packed_user_op);
    let external_nullifier = find_unused_nullifier_hash(network).await?;
    let encoded_external_nullifier = EncodedExternalNullifier::from(external_nullifier);
    let identity =
        get_world_id_identity().ok_or(WorldIdError::WorldIdIdentityNotInitialized)?;

    let inclusion_proof = fetch_inclusion_proof(
        match network {
            Network::WorldChain => PRODUCTION_SEQUENCER_URL,
            Network::WorldChainSepolia => STAGING_SEQUENCER_URL,
            _ => return Err(WorldIdError::InvalidNetworkError(network.to_string())),
        },
        (*identity).clone(),
    )
    .await
    .map_err(|e| {
        WorldIdError::InclusionProofError(format!(
            "Failed to fetch inclusion proof: {e}"
        ))
    })?;

    let proof: SemaphoreProof = generate_proof(
        &identity,
        &inclusion_proof.proof,
        encoded_external_nullifier.0,
        signal,
    )?;

    let nullifier_hash =
        generate_nullifier_hash(&identity, encoded_external_nullifier.0);

    let proof = WorldchainBuilderProof(proof);

    Ok(WorldchainBuilderPBHPayload {
        external_nullifier,
        nullifier_hash,
        root: inclusion_proof.root,
        proof,
    })
}

/// Finds the first unused nullifier hash for the current World ID identity in batches
pub async fn find_unused_nullifier_hash(
    network: Network,
) -> Result<ExternalNullifier, WorldIdError> {
    let identity =
        get_world_id_identity().ok_or(WorldIdError::WorldIdIdentityNotInitialized)?;

    let rpc_client: &'static crate::transaction::RpcClient = get_rpc_client()
        .map_err(|_| WorldIdError::RpcError(RpcError::HttpClientNotInitialized))?;

    let now = Utc::now();
    let current_year = now.year() as u16;
    let current_month = now.month() as u16;

    let max_nonce = match network {
        Network::WorldChain => PRODUCTION_MAX_NONCE,
        Network::WorldChainSepolia => STAGING_MAX_NONCE,
        _ => return Err(WorldIdError::InvalidNetworkError(network.to_string())),
    };

    // Process nonces in batches
    for batch_start in (0..max_nonce).step_by(MAX_NONCE_BATCH_SIZE as usize) {
        let batch_end = std::cmp::min(batch_start + MAX_NONCE_BATCH_SIZE, max_nonce);
        let mut batch_hashes = Vec::new();
        let mut batch_external_nullifiers = Vec::new();

        // Generate a batch of nullifier hashes
        for nonce in batch_start..batch_end {
            let external_nullifier =
                ExternalNullifier::v1(current_month as u8, current_year, nonce);
            let encoded_external_nullifier =
                EncodedExternalNullifier::from(external_nullifier);

            let nullifier_hash =
                generate_nullifier_hash(&identity, encoded_external_nullifier.0);

            batch_hashes.push(U256::from_be_bytes(nullifier_hash.to_be_bytes::<32>()));
            batch_external_nullifiers.push(external_nullifier);
        }

        // Call contract with batch of hashes
        let call = IPBHEntryPoint::getFirstUnspentNullifierHashCall {
            hashes: batch_hashes,
        };

        // Try the RPC call, but continue to next batch if this one fails
        let result = match rpc_client
            .eth_call(
                network,
                *PBH_ENTRYPOINT_4337,
                Bytes::from(call.abi_encode()),
            )
            .await
        {
            Ok(result) => result,
            Err(e) => {
                crate::warn!("Failed to fetch first unused nullifier hash for batch. Continuing to next batch. {e}");
                continue;
            }
        };

        let unsigned_value = U256::from_be_slice(&result);
        let signed_from_slice = I256::from_raw(unsigned_value);

        // If result is not -1, we found an unused nullifier hash
        if signed_from_slice != I256::MINUS_ONE {
            let index = unsigned_value.to::<usize>();
            let actual_nonce = batch_start + index as u16;

            println!("Found unused nullifier!");
            println!("Month: {current_month:?}");
            println!("Year: {current_year:?}");
            println!("Actual nonce: {actual_nonce:?}");

            // Return the external nullifier for the found index
            return Ok(batch_external_nullifiers[index]);
        }
    }

    Err(WorldIdError::NoPBHTransactionsRemaining)
}

/// Fetches an inclusion proof for a given identity from the signup sequencer.
///
/// This function sends a request to the sequencer to fetch the inclusion proof for a given identity.
///
/// # Arguments
/// * `url` - The URL of the sequencer
/// * `identity` - The identity to fetch the proof for
///
/// # Errors
/// Returns `WorldIdError::InclusionProofError` if the request fails or response cannot be parsed.
pub async fn fetch_inclusion_proof(
    url: &str,
    identity: Identity,
) -> Result<InclusionProof, WorldIdError> {
    let client = Client::new();
    let commitment = identity.commitment();

    // Make the HTTP request and map all errors to WorldIdError::InclusionProofError
    let response = client
        .post(format!("{url}/inclusionProof"))
        .json(&serde_json::json! {{
            "identityCommitment": commitment,
        }})
        .send()
        .await
        .map_err(|e| {
            WorldIdError::InclusionProofError(format!("HTTP request failed: {e}"))
        })?
        .error_for_status()
        .map_err(|e| {
            WorldIdError::InclusionProofError(format!("HTTP status error: {e}"))
        })?;

    // Parse the JSON response and map parsing errors
    let proof: InclusionProof = response.json().await.map_err(|e| {
        WorldIdError::InclusionProofError(format!("Failed to parse response: {e}"))
    })?;

    Ok(proof)
}

/// Computes a ZK-friendly hash of a `PackedUserOperation`.
///
/// This function extracts key fields (sender, nonce, callData) from a `PackedUserOperation`,
/// encodes them using ABI packed encoding, and converts the result to a Field element
/// suitable for use in zero-knowledge proof circuits.
///
/// # Arguments
/// * `user_op` - The `PackedUserOperation` to hash
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
