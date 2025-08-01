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

/// Module for signing messages, transactions and typed data on behalf of the Safe Smart Account.
pub mod smart_account;

// Re-export the unparsed types for uniffi
pub use smart_account::{UnparsedPermitTransferFrom, UnparsedTokenPermissions};

/// Introduces low level primitives for the crypto wallet, including logging functionality.
pub mod primitives;

uniffi::setup_scaffolding!("bedrock");
