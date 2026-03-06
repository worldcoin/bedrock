//! Shared utilities for migration processors.

use alloy::primitives::FixedBytes;
use log::info;

use crate::migration::error::MigrationError;
use crate::migration::processor::ProcessorResult;
use crate::primitives::Network;
use crate::transactions::rpc::get_rpc_client;

/// Number of polling attempts before giving up.
const POLL_ATTEMPTS: u32 = 5;

/// Delay between polling attempts in milliseconds.
const POLL_DELAY_MS: u64 = 4000;

/// Polls `wa_getUserOperationReceipt` on WorldChain until the operation is mined
/// or the maximum number of attempts is exhausted.
///
/// # Arguments
/// * `user_op_hash` - The hash returned by `sign_and_execute`.
/// * `label` - A human-readable label for log messages (e.g. `"enableModule"`).
///
/// # Returns
/// - `ProcessorResult::Success` if the operation was mined successfully.
/// - `ProcessorResult::Retryable` if the operation reverted, errored, or is still pending.
///
/// # Errors
/// Returns a `MigrationError` if the RPC client cannot be obtained or an RPC call fails.
pub async fn poll_for_receipt(
    user_op_hash: FixedBytes<32>,
    label: &str,
) -> Result<ProcessorResult, MigrationError> {
    let rpc_client = get_rpc_client()
        .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

    let user_op_hash_hex = format!("{user_op_hash:#x}");

    for attempt in 0..POLL_ATTEMPTS {
        let response = rpc_client
            .wa_get_user_operation_receipt(Network::WorldChain, &user_op_hash_hex)
            .await
            .map_err(|e| MigrationError::InvalidOperation(e.to_string()))?;

        match response.status.as_str() {
            "mined_success" => {
                info!(
                    "{label} mined successfully, txHash: {:?}",
                    response.transaction_hash
                );
                return Ok(ProcessorResult::Success);
            }
            "mined_revert" | "error" => {
                return Ok(ProcessorResult::Retryable {
                    error_code: "MINED_REVERT".to_string(),
                    error_message: format!(
                        "{label} transaction reverted, txHash: {:?}",
                        response.transaction_hash
                    ),
                });
            }
            _ => {
                if attempt < POLL_ATTEMPTS - 1 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        POLL_DELAY_MS,
                    ))
                    .await;
                }
            }
        }
    }

    Ok(ProcessorResult::Retryable {
        error_code: "PENDING_TIMEOUT".to_string(),
        error_message: format!(
            "{label} still pending after polling, will retry"
        ),
    })
}
