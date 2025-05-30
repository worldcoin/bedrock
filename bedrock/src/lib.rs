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

// Import and re-export the bedrock_error macro globally
pub use bedrock_error_macros::bedrock_error;

/// Demonstrates different error handling patterns for `UniFFI` exports.
/// This module explores both strongly typed enum errors and flexible interface-based errors.
mod error_demos;

/// Introduces low level operations with the [Safe Smart Account](https://safe.global/), including
/// signing messages (ERC-191) and typed data (EIP-712).
///
/// Reference: <https://github.com/safe-global/safe-smart-account>
pub mod smart_account;

uniffi::setup_scaffolding!("bedrock");
