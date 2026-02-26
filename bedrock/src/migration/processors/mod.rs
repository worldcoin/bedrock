/// Example migration processors
///
/// This module contains skeleton implementations of migration processors
/// that can be used as templates for actual migrations.
mod example_processor;

/// Processor that ensures max ERC20 approval to Permit2 on WorldChain for supported tokens.
mod permit2_approval_processor;

pub use permit2_approval_processor::Permit2ApprovalProcessor;