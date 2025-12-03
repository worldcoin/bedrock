//! Common token and contract addresses used across transaction types.

use alloy::primitives::{address, Address};

// =============================================================================
// Supported Token Addresses (World Chain)
// =============================================================================

/// Worldcoin (WLD) token address.
pub const WLD_TOKEN_ADDRESS: Address =
    address!("0x2cfc85d8e48f8eab294be644d9e25c3030863003");

/// Wrapped BTC (WBTC) token address.
pub const WBTC_TOKEN_ADDRESS: Address =
    address!("0x03c7054bcb39f7b2e5b2c7acb37583e32d70cfa3");

/// Wrapped ETH (WETH) token address.
pub const WETH_TOKEN_ADDRESS: Address =
    address!("0x4200000000000000000000000000000000000006");

/// USD Coin (USDC) token address.
pub const USDC_TOKEN_ADDRESS: Address =
    address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1");

// =============================================================================
// Morpho Vault Token Addresses (World Chain)
// =============================================================================

/// Morpho vault token for WLD deposits.
pub const MORPHO_VAULT_WLD_TOKEN_ADDRESS: Address =
    address!("0x348831b46876d3dF2Db98BdEc5E3B4083329Ab9f");

/// Morpho vault token for WBTC deposits.
pub const MORPHO_VAULT_WBTC_TOKEN_ADDRESS: Address =
    address!("0xBC8C37467c5Df9D50B42294B8628c25888BECF61");

/// Morpho vault token for WETH deposits.
pub const MORPHO_VAULT_WETH_TOKEN_ADDRESS: Address =
    address!("0x0Db7E405278c2674F462aC9D9eb8b8346D1c1571");

/// Morpho vault token for USDC deposits.
pub const MORPHO_VAULT_USDC_TOKEN_ADDRESS: Address =
    address!("0xb1E80387EbE53Ff75a89736097D34dC8D9E9045B");
