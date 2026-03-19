//! Extension helpers that wire `bedrock`-specific (EVM/wallet) processors into
//! the core `MigrationController` from `bedrock-core`.

use crate::migration::processors::permit2_approval_processor::Permit2ApprovalProcessor;
use crate::migration::MigrationController;
use bedrock_core::migration::MigrationProcessor;
use bedrock_core::primitives::key_value_store::DeviceKeyValueStore;
use crate::smart_account::SafeSmartAccount;
use std::sync::Arc;

/// Create a [`MigrationController`] pre-loaded with the default wallet processors.
///
/// Default processors:
/// - [`Permit2ApprovalProcessor`]: Ensures max ERC20 approval to Permit2 on `WorldChain`.
///
/// Additional processors passed via `additional_processors` are appended after the defaults.
#[must_use]
pub fn new_migration_controller_with_defaults(
    kv_store: Arc<dyn DeviceKeyValueStore>,
    safe_account: Arc<SafeSmartAccount>,
    additional_processors: Vec<Arc<dyn MigrationProcessor>>,
) -> Arc<MigrationController> {
    let mut processors: Vec<Arc<dyn MigrationProcessor>> =
        vec![Arc::new(Permit2ApprovalProcessor::new(safe_account))];
    processors.extend(additional_processors);
    MigrationController::with_processors(kv_store, processors)
}
