use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a single migration
#[derive(Clone, Debug, Default, Serialize, Deserialize, uniffi::Enum)]
pub enum MigrationStatus {
    /// Migration has not been started yet
    #[default]
    NotStarted,
    /// Migration is currently in progress
    InProgress,
    /// Migration completed successfully
    Succeeded,
    /// Migration failed but can be retried
    FailedRetryable,
    /// Migration failed with terminal error (won't retry)
    FailedTerminal,
}

/// Record of a single migration's execution state
/// e.g. this could be the `PoH` refresh migration stage.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Current status
    pub status: MigrationStatus,

    /// Number of attempts
    pub attempts: i32,

    /// Timestamp when migration was first started
    pub started_at: Option<DateTime<Utc>>,

    /// Timestamp of last attempt
    pub last_attempted_at: Option<DateTime<Utc>>,

    /// Last error code (if any)
    pub last_error_code: Option<String>,

    /// Last error message (if any)
    pub last_error_message: Option<String>,

    /// Timestamp when migration completed successfully
    pub completed_at: Option<DateTime<Utc>>,

    /// Next time to recheck a succeeded migration's applicability.
    /// Set to `now + TTL` on success/re-check.
    pub recheck_at: Option<DateTime<Utc>>,

    /// Reference to outstanding fire-and-forget work (e.g. a userOp hash) from the
    /// most recent `Pending` execution. Checked via
    /// `MigrationProcessor::check_pending_work` on the next run and cleared once
    /// the work is resolved (mined, reverted, or superseded by a new attempt).
    #[serde(default)]
    pub pending_user_op_hash: Option<String>,

    /// Number of fire-and-forget submissions that reverted on-chain. Reset on
    /// success; when it reaches the controller's cap the migration is marked
    /// `FailedTerminal` instead of resubmitting indefinitely.
    #[serde(default)]
    pub revert_count: i32,
}
