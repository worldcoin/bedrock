use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Status of a single migration
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum MigrationStatus {
    /// Migration has not been started yet
    NotStarted,
    /// Migration is currently in progress
    InProgress,
    /// Migration completed successfully
    Succeeded,
    /// Migration failed but can be retried
    FailedRetryable,
    /// Migration failed with terminal error (won't retry)
    FailedTerminal,
    /// Migration blocked pending user action
    BlockedUserAction,
}

/// Record of a single migration's execution state
/// e.g. this could be the `PoH` refresh migration stage.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Current status
    pub status: MigrationStatus,

    /// Number of attempts
    pub attempts: i32,

    /// Timestamp when migration was first started
    pub started_at: Option<DateTime<Utc>>,

    /// Timestamp of last attempt
    pub last_attempted_at: Option<DateTime<Utc>>,

    /// Timestamp when to retry next
    /// Included so migrations are not spammed on each app open.
    pub next_attempt_at: Option<DateTime<Utc>>,

    /// Last error code (if any)
    pub last_error_code: Option<String>,

    /// Last error message (if any)
    pub last_error_message: Option<String>,

    /// Timestamp when migration completed successfully
    pub completed_at: Option<DateTime<Utc>>,
}

impl MigrationRecord {
    /// Creates a new migration record with default values
    #[must_use]
    pub const fn new() -> Self {
        Self {
            status: MigrationStatus::NotStarted,
            attempts: 0,
            started_at: None,
            last_attempted_at: None,
            next_attempt_at: None,
            last_error_code: None,
            last_error_message: None,
            completed_at: None,
        }
    }
}

impl Default for MigrationRecord {
    fn default() -> Self {
        Self::new()
    }
}
