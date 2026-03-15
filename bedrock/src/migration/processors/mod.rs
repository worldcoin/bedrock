/// Example migration processors
///
/// This module contains skeleton implementations of migration processors
/// that can be used as templates for actual migrations.
mod example_processor;

/// Processor that checks if the Safe4337Module is enabled and enables it if not.
pub mod enable_4337_module_processor;

/// Processor that ensures max ERC20 approval to Permit2 on `WorldChain` for supported tokens.
pub mod permit2_approval_processor;

/// Processor that upgrades Safe wallets from v1.3.0 to v1.4.1.
pub mod safe_upgrade_processor;
