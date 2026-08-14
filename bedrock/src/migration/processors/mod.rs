/// Example migration processors
///
/// This module contains skeleton implementations of migration processors
/// that can be used as templates for actual migrations.
mod example_processor;

/// Processor that ensures max ERC20 approval to Permit2 on `WorldChain` for supported tokens.
pub mod permit2_approval_processor;

/// Processor that installs the ERC-4337 module on legacy Safes that lack it.
pub mod safe_4337_module_processor;
