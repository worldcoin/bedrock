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
pub use bedrock_macros::{bedrock_error, bedrock_export};

/// Introduces low level operations with the [Safe Smart Account](https://safe.global/), including
/// signing messages (ERC-191) and typed data (EIP-712).
///
/// Reference: <https://github.com/safe-global/safe-smart-account>
pub mod smart_account;

/// Introduces low level primitives for the crypto wallet, including logging functionality.
pub mod primitives;

uniffi::setup_scaffolding!("bedrock");
