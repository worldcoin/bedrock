use crate::migration::MigrationError;
use async_trait::async_trait;

/// Result of executing a migration processor
#[derive(Debug, uniffi::Enum)]
pub enum ProcessorResult {
    /// Migration succeeded
    Success,

    /// Migration submitted asynchronous work (e.g. an on-chain transaction) in a
    /// fire-and-forget manner. The migration stays `InProgress`; completion is
    /// detected on the next run when [`MigrationProcessor::is_applicable`] observes
    /// the desired end state and the migration is promoted to `Succeeded`.
    Pending {
        /// Reference to the submitted work (e.g. the userOp hash), persisted on the
        /// migration record. On the next run the controller passes it to
        /// [`MigrationProcessor::check_pending_work`] so the outcome of the previous
        /// submission can be resolved before re-executing.
        user_op_hash: Option<String>,
    },

    /// Migration failed but can be retried
    Retryable {
        /// Error code for categorizing the failure
        error_code: String,
        /// Human-readable error message
        error_message: String,
    },

    /// Migration failed with terminal error (won't retry)
    Terminal {
        /// Error code for categorizing the failure
        error_code: String,
        /// Human-readable error message
        error_message: String,
    },
}

/// Status of previously submitted fire-and-forget work, as resolved by
/// [`MigrationProcessor::check_pending_work`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PendingWorkStatus {
    /// The submitted work landed successfully. The controller proceeds to
    /// re-check `is_applicable` and promotes the migration to `Succeeded` if the
    /// desired end state holds.
    Mined,
    /// The submitted work reverted or errored on-chain. The migration is marked
    /// `FailedRetryable` with a `MINED_REVERT` error code and re-executed on the
    /// next run.
    Reverted,
    /// The submitted work has not been mined yet. The migration is skipped this
    /// run (no duplicate submission) and re-checked on the next run.
    StillPending,
    /// The processor cannot determine the outcome (e.g. it does not track
    /// submissions, or the receipt is unavailable). The controller falls back to
    /// the `is_applicable` end-state recheck.
    Unknown,
}

/// Trait that all migration processors must implement
///
/// # Timeouts and Cancellation Safety
///
/// Both [`is_applicable`](Self::is_applicable) and [`execute`](Self::execute) are subject to timeouts
/// (20 seconds in production). When a timeout occurs, the future is dropped and the migration
/// is marked as failed (for `execute`) or skipped (for `is_applicable`).
///
/// **IMPORTANT**: Implementations MUST be cancellation-safe:
///
/// - **DO NOT** spawn background tasks using `tokio::spawn`, `std::thread::spawn`, or similar
///   that will continue running after the timeout
/// - **DO NOT** use blocking operations or FFI calls without proper cleanup
/// - **ENSURE** all work stops when the future is dropped (cooperative cancellation)
/// - **MAKE** migrations idempotent so partial execution can be safely retried
///
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait MigrationProcessor: Send + Sync {
    /// Unique identifier for this migration (e.g., "worldid.account.bootstrap.v1")
    /// The version should be included in the ID itself (e.g., ".v1", ".v2")
    fn migration_id(&self) -> String;

    /// Check if this migration is applicable
    ///
    /// This method should check **actual state** (e.g., does v4 credential exist?)
    /// to determine if the migration needs to run. This ensures the system is
    /// truly idempotent and handles edge cases gracefully.
    ///
    /// # Returns
    /// - `Ok(true)` if the migration should run
    /// - `Ok(false)` if the migration should be skipped
    /// - `Err(_)` if unable to determine (migration will be skipped with error logged)
    ///
    /// # Contract for previously attempted migrations
    ///
    /// For a migration that is `InProgress` or `FailedRetryable`, the controller
    /// interprets `Ok(false)` as **"the desired end state now holds"** and promotes
    /// the migration to `Succeeded` (fire-and-forget completion detection). If your
    /// `is_applicable` can return `false` for reasons other than completion (e.g. a
    /// feature flag turned off, source data missing), gate those checks so they do
    /// not fire for previously attempted migrations, or the record will be falsely
    /// marked `Succeeded`.
    async fn is_applicable(&self) -> Result<bool, MigrationError>;

    /// Execute the migration
    async fn execute(&self) -> Result<ProcessorResult, MigrationError>;

    /// Resolve the outcome of previously submitted fire-and-forget work.
    ///
    /// Called by the controller before re-executing an `InProgress` migration whose
    /// last run returned [`ProcessorResult::Pending`] with a `user_op_hash`. This
    /// lets the controller distinguish "still mining" (skip, no duplicate
    /// submission), "reverted" (record the failure and retry), and "mined"
    /// (verify the end state via [`is_applicable`](Self::is_applicable)).
    ///
    /// Processors that never return [`ProcessorResult::Pending`] should return
    /// [`PendingWorkStatus::Unknown`], which falls back to the `is_applicable`
    /// end-state recheck. (uniffi-exported traits cannot carry a default
    /// implementation, so this must be implemented explicitly.)
    ///
    /// # Errors
    /// - `Err(_)` if the status lookup fails (e.g. RPC unavailable); the controller
    ///   falls back to the `is_applicable` end-state recheck.
    async fn check_pending_work(
        &self,
        user_op_hash: String,
    ) -> Result<PendingWorkStatus, MigrationError>;
}
