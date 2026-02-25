//! This module introduces contract definitions for all the smart contracts
//! that power the common transactions for the crypto wallet.
pub mod erc20;
/// Generic ERC-4626 vault contract interface and implementation.
pub mod erc4626;
/// Utilities for batching multiple transactions via the Safe `MultiSend` contract.
pub mod multisend;
/// Permit2 contract helpers for batching ERC20 approvals.
pub mod permit2;
pub mod world_campaign_manager;
pub mod world_gift_manager;
