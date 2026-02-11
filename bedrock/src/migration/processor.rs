use crate::migration::MigrationError;

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

    /// Migration blocked pending user action
    BlockedUserAction {
        /// Reason why the migration is blocked
        reason: String,
    },
}

/// Trait that all migration processors must implement.
///
/// # Synchronous Interface
///
/// These methods are intentionally **synchronous** to avoid a known UniFFI bug with
/// async foreign callbacks on Android/Kotlin
/// ([uniffi-rs#2624](https://github.com/mozilla/uniffi-rs/issues/2624)).
///
/// **For foreign (Kotlin/Swift) implementors:** If your migration logic requires async
/// operations (network calls, database access, etc.), use a blocking wrapper internally.
/// 
/// **Caller requirement:** `run_migrations()` must be called from a background context. 
/// These sync callbacks will block the calling thread for the duration of each migration.
/// Calling from the main/UI thread will cause UI freezes.
#[uniffi::export(with_foreign)]
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
    /// # Synchronous
    ///
    /// This method is sync to work around a UniFFI async callback bug on Android.
    /// Foreign implementations needing async work should block internally
    /// (e.g., `runBlocking` in Kotlin).
    ///
    /// # Returns
    /// - `Ok(true)` if the migration should run
    /// - `Ok(false)` if the migration should be skipped
    /// - `Err(_)` if unable to determine (migration will be skipped with error logged)
    fn is_applicable(&self) -> Result<bool, MigrationError>;

    /// Execute the migration
    ///
    /// Called by the controller when the migration is ready to run.
    ///
    /// # Synchronous
    ///
    /// This method is sync to work around a UniFFI async callback bug on Android.
    /// Foreign implementations needing async work should block internally
    /// (e.g., `runBlocking` in Kotlin).
    fn execute(&self) -> Result<ProcessorResult, MigrationError>;
}
