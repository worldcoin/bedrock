//! WorldChain (chain ID 480) contract addresses and token constants.

use alloy::primitives::{address, Address};

/// The canonical Permit2 contract address (same across all EVM chains).
///
/// Reference: <https://docs.uniswap.org/contracts/v4/deployments#worldchain-480>
pub static PERMIT2_ADDRESS: Address =
    address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

/// USDC token address on WorldChain.
pub static USDC_ADDRESS: Address =
    address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1");

/// WETH token address on WorldChain.
pub static WETH_ADDRESS: Address =
    address!("0x4200000000000000000000000000000000000006");

/// WBTC token address on WorldChain.
pub static WBTC_ADDRESS: Address =
    address!("0x03c7054bcb39f7b2e5b2c7acb37583e32d70cfa3");

/// WLD token address on WorldChain.
pub static WLD_ADDRESS: Address =
    address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");

/// Token addresses on WorldChain that should have max ERC20 approval to Permit2.
pub const WORLDCHAIN_PERMIT2_TOKENS: [(Address, &str); 4] = [
    (USDC_ADDRESS, "usdc"),
    (WETH_ADDRESS, "weth"),
    (WBTC_ADDRESS, "wbtc"),
    (WLD_ADDRESS, "wld"),
];
