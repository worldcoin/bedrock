use crate::migration::MigrationError;
use async_trait::async_trait;

/// Result of executing a [`MigrationProcessor`].
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
    },

    /// Migration failed with terminal error (won't retry)
    Terminal {
        /// Error code for categorizing the failure
        error_code: String,
        /// Human-readable error message
        error_message: String,
    },
}

/// A migration implemented by the host platform, in Swift or Kotlin.
///
/// # Blocking and idempotency
///
/// Nothing bounds how long these may take. The run is off the app-start path,
/// but it holds the migration lock, so a slow method stalls the whole run and
/// every migration sharing its task. Implementations:
///
/// - MUST NOT block the thread or call FFI without cleanup
/// - MUST NOT spawn work that outlives the returned future
/// - MUST be idempotent, since partial work is retried
#[uniffi::export(with_foreign)]
#[async_trait]
pub trait MigrationProcessor: Send + Sync {
    /// Unique identifier, version included (e.g. `"worldid.account.bootstrap.v1"`).
    fn migration_id(&self) -> String;

    /// Should this migration run? Check **actual state**, so the decision stays
    /// idempotent. `Err` skips the migration with the error logged.
    async fn is_applicable(&self) -> Result<bool, MigrationError>;

    /// Execute the migration
    async fn execute(&self) -> Result<ProcessorResult, MigrationError>;
}
