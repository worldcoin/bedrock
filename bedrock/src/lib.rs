#![deny(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    missing_docs,
    dead_code
)]

//! `bedrock` is the foundational library which powers World App's crypto wallet
//! It enables operations with the Ethereum-based wallet.
//!
//! More info about World App can be found here: <https://www.toolsforhumanity.com/world-app>

// Import and re-export the macros globally
pub use bedrock_macros::{bedrock_error, bedrock_export, bedrock_sol};

/// Introduces low level operations with the [Safe Smart Account](https://safe.global/), including
/// signing user operations (ERC-4337), messages (ERC-191) and typed data (EIP-712).
///
/// Reference: <https://github.com/safe-global/safe-smart-account>
pub mod smart_account;

/// A high level API to perform transactions from the crypto wallet.
///
/// We call this transactions for the sake of clarity, but all transactions are executed as ERC-4337 user operations.
///
/// Examples include: ERC-20 token transfers, swaps, etc.
pub mod transactions;

/// Introduces low level primitives for the crypto wallet, including logging functionality.
pub mod primitives;

/// Tools for storing, retrieving, encrypting and decrypting backup data and metadata.
/// See `backup::BackupManager` for the high-level API.
pub mod backup;

/// Introduces low level operations for interacting with a Nitro Enclave.
pub mod nitro_enclave;

// Re-export commonly used primitives at the crate root for convenience
pub use primitives::{AuthenticatedHttpClient, HttpError, HttpMethod};

/// Key management for World App.
mod root_key;

/// Test utilities for unit and integration tests
#[cfg(any(test, feature = "test-utils"))]
pub mod test_utils;

uniffi::setup_scaffolding!("bedrock");
