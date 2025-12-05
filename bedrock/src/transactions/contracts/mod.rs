//! This module introduces contract definitions for all the smart contracts
//! that power the common transactions for the crypto wallet.

pub mod constants;
pub mod erc20;
pub mod morpho;
/// Utilities for batching multiple transactions via the Safe `MultiSend` contract.
pub mod multisend;
pub mod world_campaign_manager;
pub mod world_gift_manager;
