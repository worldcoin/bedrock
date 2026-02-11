//! This module introduces contract definitions for all the smart contracts
//! that power the common transactions for the crypto wallet.
pub mod erc20;
/// Generic ERC-4626 vault contract interface and implementation.
pub mod erc4626;
/// Utilities for batching multiple transactions via the Safe `MultiSend` contract.
pub mod multisend;
pub mod world_campaign_manager;
pub mod world_gift_manager;
pub mod wld_vault;
