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

/// Introduces low level operations with the [Safe Smart Account](https://safe.global/), including
/// signing messages (ERC-191) and typed data (EIP-712).
///
/// Reference: <https://github.com/safe-global/safe-smart-account>
mod smart_account;

/// A canonical chain is a chain that is **natively** supported by World App.
///
/// This does not include chains supported by Mini Apps.
#[repr(u32)]
#[derive(Debug, uniffi::Enum)]
pub enum CanonicalChain {
    /// Blockchain for real humans. Reference: <https://world.org/world-chain>
    WorldChain = 480,
}

uniffi::setup_scaffolding!("bedrock");
