//! The individual wallet migrations.
//!
//! Each implements [`WalletMigration`](super::WalletMigration); the framework
//! they run under is in `wallet_migration.rs` and `wallet_controller.rs`.

/// Grants max ERC20 approval to Permit2 on `WorldChain` for supported tokens.
pub mod permit2_approval;

/// Installs the ERC-4337 module on legacy Safes that lack it.
pub mod safe_4337_module;

/// Tops up the paymaster's ERC-20 allowance. Staging and sandbox only.
pub mod tfh_paymaster_approval;
