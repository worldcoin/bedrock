use crate::migration::MigrationError;
use async_trait::async_trait;

/// Result of executing a migration processor
#[derive(uniffi::Enum)]
pub enum ProcessorResult {
    /// Migration succeeded
    Success,

    /// Migration failed but can be retried
    Retryable {
        /// Error code for categorizing the failure
        error_code: String,
        /// Human-readable error message
        error_message: String,
        /// Optional delay in milliseconds before retrying
        retry_after_ms: Option<i64>,
    },

    /// Migration failed with terminal error (won't retry)
    Terminal {
        /// Error code for categorizing the failure
        error_code: String,
        /// Human-readable error message
        error_message: String,
    },
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
    async fn is_applicable(&self) -> Result<bool, MigrationError>;

    /// Execute the migration
    async fn execute(&self) -> Result<ProcessorResult, MigrationError>;
}
