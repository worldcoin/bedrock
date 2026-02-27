use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::processors::permit2_approval_processor::Permit2ApprovalProcessor;
use crate::migration::state::{MigrationRecord, MigrationStatus};
use crate::primitives::key_value_store::{DeviceKeyValueStore, KeyValueStoreError};
use crate::smart_account::SafeSmartAccount;
use chrono::{Duration, Utc};
use futures::future::join_all;
use log::warn;
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

const MIGRATION_KEY_PREFIX: &str = "migration:";
const DEFAULT_RETRY_DELAY_MS: i64 = 60_000; // 1 minute
const MAX_RETRY_DELAY_MS: i64 = 86_400_000; // 1 day
const MIGRATION_SUCCESS_TTL_DAYS: i64 = 30; // Re-check succeeded migrations after 30 days

/// Global lock to prevent concurrent migration runs across all controller instances.
/// This is a process-wide coordination mechanism that ensures only one migration
/// can execute at a time, regardless of how many [`MigrationController`] instances exist.
///
/// **Application-level Requirements:**
/// The calling application should ensure only one [`MigrationController`] instance is
/// instantiated at a time. While this process-wide lock provides thread-safety within
/// a single process, applications should use app-level constructs (singletons, dependency
/// injection, etc.) to prevent multiple controller instances as an additional safeguard.
static MIGRATION_LOCK: Lazy<Mutex<()>> = Lazy::new(|| Mutex::new(()));

/// Summary of a migration run
#[derive(Debug, Default, uniffi::Record)]
pub struct MigrationRunSummary {
    /// Total number of migrations attempted
    pub total: i32,
    /// Number of migrations that succeeded
    pub succeeded: i32,
    /// Number of migrations that failed but can be retried
    pub failed_retryable: i32,
    /// Number of migrations that failed with terminal errors (won't retry)
    pub failed_terminal: i32,
    /// Number of migrations that were skipped (already completed or not applicable)
    pub skipped: i32,
}

/// Controller that orchestrates migration execution
///
/// ## Storage Architecture
///
/// Each migration's state is stored independently in the [`DeviceKeyValueStore`](crate::device::DeviceKeyValueStore) using
/// a namespaced key pattern: `migration:{migration_id}`.
///
/// For example:
/// - `migration:worldId.credentials.poh.refresh.v1`
/// - `migration:worldId.credentials.nfc.refresh.v1`
///
/// This approach ensures:
/// - **Scalability**: No size limits on the total number of migrations
/// - **Isolation**: Each migration's state is independent and can be managed separately
/// - **Platform compatibility**: Avoids hitting single-key size limits in `SharedPreferences` (Android) and `UserDefaults` (iOS)
///
/// Each key stores a JSON-serialized `MigrationRecord` containing execution state,
/// timestamps, and error information.
#[derive(uniffi::Object)]
pub struct MigrationController {
    kv_store: Arc<dyn DeviceKeyValueStore>,
    processors: Vec<Arc<dyn MigrationProcessor>>,
}

#[uniffi::export(async_runtime = "tokio")]
impl MigrationController {
    /// Create a new [`MigrationController`] with default processors and optional additional ones.
    ///
    /// Default processors (loaded automatically):
    /// - [`Permit2ApprovalProcessor`]: Ensures max ERC20 approval to Permit2 on `WorldChain`
    ///
    /// Additional processors passed via `additional_processors` are appended after the defaults.
    #[uniffi::constructor]
    pub fn new(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        safe_account: Arc<SafeSmartAccount>,
        additional_processors: Vec<Arc<dyn MigrationProcessor>>,
    ) -> Arc<Self> {
        let mut processors = Self::default_processors(safe_account);
        processors.extend(additional_processors);
        Self::with_processors(kv_store, processors)
    }

    /// Run all registered migrations
    ///
    /// This is an async call that may take several seconds depending on network
    /// conditions and the number of migrations to process.
    ///
    /// UniFFI handles the async runtime automatically via the `async_runtime = "tokio"` attribute.
    ///
    /// # Concurrency
    ///
    /// This method is **thread-safe** with fail-fast behavior. A global lock ensures only one
    /// migration run can execute at a time across all `MigrationController` instances in the process.
    ///
    /// If another migration is already in progress when this method is called, it will return
    /// immediately with an `InvalidOperation` error rather than waiting.
    ///
    /// # Errors
    ///
    /// Returns `MigrationError::InvalidOperation` if another migration run is already in progress.
    /// Returns other errors for migration execution failures (see `MigrationRunSummary` for details).
    pub async fn run_migrations(&self) -> Result<MigrationRunSummary, MigrationError> {
        // Try to acquire the global lock. If another migration is running, fail immediately.
        let _guard = MIGRATION_LOCK.try_lock().map_err(|_| {
            MigrationError::InvalidOperation(
                "Migration is already in progress. Please wait for the current migration to complete.".to_string(),
            )
        })?;

        // Lock acquired - we have exclusive access to run migrations
        self.run_migrations_async().await
        // Lock automatically released when _guard is dropped
    }

    /// Delete all migration records from the key-value store.
    ///
    /// **Developer/testing use only.** This resets all migration state so that
    /// migrations will run again from scratch on the next `run_migrations` call.
    ///
    /// Records that don't exist yet are silently skipped.
    ///
    /// # Errors
    ///
    /// Returns `MigrationError::InvalidOperation` if a migration run is currently in progress.
    /// Returns `MigrationError::DeviceKeyValueStoreError` if the underlying store fails.
    ///
    /// # Concurrency
    ///
    /// Acquires the global migration lock to prevent deleting records while
    /// migrations are in progress.
    pub fn delete_all_records(&self) -> Result<i32, MigrationError> {
        let _guard = MIGRATION_LOCK.try_lock().map_err(|_| {
            MigrationError::InvalidOperation(
                "Migration is already in progress. Please wait for the current migration to complete.".to_string(),
            )
        })?;

        let mut deleted = 0;
        for processor in &self.processors {
            let key = format!("{MIGRATION_KEY_PREFIX}{}", processor.migration_id());
            match self.kv_store.delete(key) {
                Ok(()) => deleted += 1,
                Err(KeyValueStoreError::KeyNotFound) => {} // No record to delete
                Err(e) => return Err(e.into()),
            }
        }

        crate::info!(
            "migration_records.deleted count={} total_processors={} timestamp={}",
            deleted,
            self.processors.len(),
            Utc::now().to_rfc3339()
        );

        Ok(deleted)
    }
}

impl MigrationController {
    /// Returns the default set of migration processors.
    fn default_processors(
        safe_account: Arc<SafeSmartAccount>,
    ) -> Vec<Arc<dyn MigrationProcessor>> {
        vec![Arc::new(Permit2ApprovalProcessor::new(safe_account))]
    }

    /// Create a controller with processors injected in
    pub fn with_processors(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        processors: Vec<Arc<dyn MigrationProcessor>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            kv_store,
            processors,
        })
    }

    /// Internal async implementation of `run_migrations`
    async fn run_migrations_async(
        &self,
    ) -> Result<MigrationRunSummary, MigrationError> {
        // Store start time for duration tracking
        let run_start_time = Utc::now();

        crate::info!(
            "migration_run.started total_processors={} timestamp={}",
            self.processors.len(),
            run_start_time.to_rfc3339()
        );

        // Run all processors in parallel
        let futures: Vec<_> = self
            .processors
            .iter()
            .map(|processor| self.run_single_processor(processor.as_ref()))
            .collect();

        let results = join_all(futures).await;

        // Aggregate per-processor summaries
        let mut summary = MigrationRunSummary {
            total: i32::try_from(self.processors.len()).unwrap_or(i32::MAX),
            succeeded: 0,
            failed_retryable: 0,
            failed_terminal: 0,
            skipped: 0,
        };
        for s in results {
            summary.succeeded += s.succeeded;
            summary.failed_retryable += s.failed_retryable;
            summary.failed_terminal += s.failed_terminal;
            summary.skipped += s.skipped;
        }

        let run_duration_ms = (Utc::now() - run_start_time).num_milliseconds();

        crate::info!(
            "migration_run.completed total={} succeeded={} failed_retryable={} failed_terminal={} skipped={} duration_ms={} timestamp={}",
            summary.total,
            summary.succeeded,
            summary.failed_retryable,
            summary.failed_terminal,
            summary.skipped,
            run_duration_ms,
            Utc::now().to_rfc3339()
        );

        Ok(summary)
    }

    /// Run a single migration processor through its full lifecycle.
    #[allow(clippy::too_many_lines)]
    async fn run_single_processor(
        &self,
        processor: &dyn MigrationProcessor,
    ) -> MigrationRunSummary {
        let migration_id = processor.migration_id();

        // Load the current record for this migration (or create new one if first time)
        let mut record = match self.load_record(&migration_id) {
            Ok(r) => r,
            Err(e) => {
                return {
                    crate::error!(
                        "migration.storage_error error={:?} timestamp={}",
                        e,
                        Utc::now().to_rfc3339()
                    );
                    MigrationRunSummary {
                        failed_retryable: 1,
                        ..MigrationRunSummary::default()
                    }
                }
            }
        };

        // Determine if this migration should be attempted based on its current status
        let should_attempt = match record.status {
            MigrationStatus::Succeeded => {
                // Check TTL: if completed_at + TTL has elapsed, re-check applicability
                let ttl_expired = record.completed_at.is_some_and(|completed| {
                    Utc::now() - completed > Duration::days(MIGRATION_SUCCESS_TTL_DAYS)
                });

                if ttl_expired {
                    crate::info!(
                        "migration.ttl_expired id={} completed_at={} timestamp={}",
                        migration_id,
                        record
                            .completed_at
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_default(),
                        Utc::now().to_rfc3339()
                    );
                    // Re-check applicability below
                    true
                } else {
                    false
                }
            }

            MigrationStatus::FailedTerminal => {
                // Terminal state - migration failed permanently
                crate::info!(
                    "migration.skipped id={} reason=terminal_failure timestamp={}",
                    migration_id,
                    Utc::now().to_rfc3339()
                );
                false
            }

            MigrationStatus::InProgress | MigrationStatus::FailedRetryable => {
                // Check retry timing (exponential backoff)
                // No retry time set = attempt immediately
                record.next_attempt_at.is_none_or(|next_attempt| {
                    if Utc::now() < next_attempt {
                        crate::info!(
                            "migration.skipped id={} reason=retry_backoff next_attempt={} timestamp={}",
                            migration_id,
                            next_attempt.to_rfc3339(),
                            Utc::now().to_rfc3339()
                        );
                        false
                    } else {
                        true // Ready to retry
                    }
                })
            }

            MigrationStatus::NotStarted => {
                // First time attempting this migration
                true
            }
        };

        if !should_attempt {
            return MigrationRunSummary {
                skipped: 1,
                ..MigrationRunSummary::default()
            };
        }

        // Check if migration is applicable based on actual state (e.g., on-chain allowances).
        if !matches!(processor.is_applicable().await, Ok(true)) {
            return MigrationRunSummary {
                skipped: 1,
                ..MigrationRunSummary::default()
            };
        }

        // For TTL-expired succeeded migrations, reset record before re-executing
        if matches!(record.status, MigrationStatus::Succeeded) {
            record = MigrationRecord::new();
        }

        // Execute the migration
        crate::info!(
            "migration.started id={} attempt={} timestamp={}",
            migration_id,
            record.attempts + 1,
            Utc::now().to_rfc3339()
        );

        // Update record for execution
        if record.started_at.is_none() {
            record.started_at = Some(Utc::now());
        }
        record.status = MigrationStatus::InProgress;
        record.attempts += 1;
        record.last_attempted_at = Some(Utc::now());

        // Save record before execution so we don't lose progress if the app crashes mid-migration
        if let Err(e) = self.save_record(&migration_id, &record) {
            return {
                crate::error!(
                    "migration.storage_error error={:?} timestamp={}",
                    e,
                    Utc::now().to_rfc3339()
                );
                MigrationRunSummary {
                    failed_retryable: 1,
                    ..MigrationRunSummary::default()
                }
            };
        }

        let execute_start = Utc::now();

        let outcome = match processor.execute().await {
            Ok(ProcessorResult::Success) => {
                let duration_ms = (Utc::now() - execute_start).num_milliseconds();
                crate::info!(
                    "migration.succeeded id={} attempt={} duration_ms={} timestamp={}",
                    migration_id,
                    record.attempts,
                    duration_ms,
                    Utc::now().to_rfc3339()
                );
                record.status = MigrationStatus::Succeeded;
                record.completed_at = Some(Utc::now());
                record.last_error_code = None;
                record.last_error_message = None;
                record.next_attempt_at = None;
                MigrationRunSummary {
                    succeeded: 1,
                    ..MigrationRunSummary::default()
                }
            }
            Ok(ProcessorResult::Retryable {
                error_code,
                error_message,
                retry_after_ms,
            }) => {
                let retry_delay_ms = retry_after_ms
                    .unwrap_or_else(|| calculate_backoff_delay(record.attempts));
                record.next_attempt_at =
                    Some(Utc::now() + Duration::milliseconds(retry_delay_ms));
                let duration_ms = (Utc::now() - execute_start).num_milliseconds();
                crate::warn!(
                    "migration.failed_retryable id={} attempt={} duration_ms={} error_code={} error_message={} retry_delay_ms={} next_attempt={} timestamp={}",
                    migration_id, record.attempts, duration_ms, error_code, error_message, retry_delay_ms,
                    record.next_attempt_at.map(|t| t.to_rfc3339()).unwrap_or_default(), Utc::now().to_rfc3339()
                );
                record.status = MigrationStatus::FailedRetryable;
                record.last_error_code = Some(error_code);
                record.last_error_message = Some(error_message);
                MigrationRunSummary {
                    failed_retryable: 1,
                    ..MigrationRunSummary::default()
                }
            }
            Ok(ProcessorResult::Terminal {
                error_code,
                error_message,
            }) => {
                let duration_ms = (Utc::now() - execute_start).num_milliseconds();
                crate::error!(
                    "migration.failed_terminal id={} attempt={} duration_ms={} error_code={} error_message={} timestamp={}",
                    migration_id, record.attempts, duration_ms, error_code, error_message, Utc::now().to_rfc3339()
                );
                record.status = MigrationStatus::FailedTerminal;
                record.last_error_code = Some(error_code);
                record.last_error_message = Some(error_message);
                record.next_attempt_at = None;
                MigrationRunSummary {
                    failed_terminal: 1,
                    ..MigrationRunSummary::default()
                }
            }
            Err(e) => {
                let duration_ms = (Utc::now() - execute_start).num_milliseconds();
                crate::error!(
                    "migration.failed_unexpected id={} attempt={} duration_ms={} error={:?} timestamp={}",
                    migration_id, record.attempts, duration_ms, e, Utc::now().to_rfc3339()
                );
                record.status = MigrationStatus::FailedRetryable;
                record.last_error_code = Some("UNEXPECTED_ERROR".to_string());
                record.last_error_message = Some(format!("{e:?}"));
                let retry_delay_ms = calculate_backoff_delay(record.attempts);
                record.next_attempt_at =
                    Some(Utc::now() + Duration::milliseconds(retry_delay_ms));
                MigrationRunSummary {
                    failed_retryable: 1,
                    ..MigrationRunSummary::default()
                }
            }
        };

        // Save the final result (success/failure) to storage
        if let Err(e) = self.save_record(&migration_id, &record) {
            return {
                crate::error!(
                    "migration.storage_error error={:?} timestamp={}",
                    e,
                    Utc::now().to_rfc3339()
                );
                MigrationRunSummary {
                    failed_retryable: 1,
                    ..MigrationRunSummary::default()
                }
            };
        }

        outcome
    }

    /// Load a single migration record from the [`DeviceKeyValueStore`](crate::device::DeviceKeyValueStore)
    /// Each migration is stored under its own key: `"migration:{migration_id}"`
    ///
    /// # Corruption Handling
    ///
    /// If the stored JSON is corrupted or invalid, this method treats it as a reset
    /// and returns a new `MigrationRecord`. This prevents one corrupted record from
    /// blocking all migrations permanently.
    fn load_record(
        &self,
        migration_id: &str,
    ) -> Result<MigrationRecord, MigrationError> {
        let key = format!("{MIGRATION_KEY_PREFIX}{migration_id}");
        match self.kv_store.get(key) {
            Ok(json) => {
                match serde_json::from_str(&json) {
                    Ok(record) => Ok(record),
                    Err(e) => {
                        // JSON is corrupted - treat as reset and let migration re-run
                        warn!("Migration {migration_id} has corrupted JSON data, resetting: {e:?}");
                        Ok(MigrationRecord::new())
                    }
                }
            }
            Err(KeyValueStoreError::KeyNotFound) => {
                // First time running this migration, return new record
                Ok(MigrationRecord::new())
            }
            Err(KeyValueStoreError::ParsingFailure) => {
                // Storage layer couldn't parse the value - treat as reset
                warn!("Migration {migration_id} has corrupted storage data, resetting");
                Ok(MigrationRecord::new())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Save a single migration record to persistent storage
    /// Each migration is stored under its own key: `"migration:{migration_id}"`
    fn save_record(
        &self,
        migration_id: &str,
        record: &MigrationRecord,
    ) -> Result<(), MigrationError> {
        let key = format!("{MIGRATION_KEY_PREFIX}{migration_id}");
        let json = serde_json::to_string(record)?;
        self.kv_store.set(key, json)?;
        Ok(())
    }
}

/// Calculate exponential backoff delay based on number of attempts
fn calculate_backoff_delay(attempts: i32) -> i64 {
    // attempts: 1 => base, 2 => 2x, 3 => 4x, ...
    let exp = (attempts.saturating_sub(1)).clamp(0, 16).cast_unsigned(); // cap exponent
    let factor = 1_i64.checked_shl(exp).unwrap_or(i64::MAX);
    (DEFAULT_RETRY_DELAY_MS.saturating_mul(factor)).min(MAX_RETRY_DELAY_MS)
}

#[cfg(test)]
mod tests {
    //! Tests for the migration controller's locking behavior.
    //!
    //! **Note:** These tests share a global `MIGRATION_LOCK` and must run serially.
    //! The `#[serial]` attribute ensures they don't interfere with each other.

    use super::*;
    use crate::primitives::key_value_store::InMemoryDeviceKeyValueStore;
    use async_trait::async_trait;
    use serial_test::serial;
    use std::sync::atomic::{AtomicU32, Ordering};
    use tokio::time::{sleep, Duration};

    /// Test processor that can be controlled for timing tests
    struct TestProcessor {
        id: String,
        delay_ms: u64,
        should_fail: bool,
        execution_count: Arc<AtomicU32>,
    }

    impl TestProcessor {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                delay_ms: 0,
                should_fail: false,
                execution_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn with_delay(mut self, delay_ms: u64) -> Self {
            self.delay_ms = delay_ms;
            self
        }

        fn execution_count(&self) -> u32 {
            self.execution_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MigrationProcessor for TestProcessor {
        fn migration_id(&self) -> String {
            self.id.clone()
        }

        async fn is_applicable(&self) -> Result<bool, MigrationError> {
            Ok(true)
        }

        async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
            self.execution_count.fetch_add(1, Ordering::SeqCst);
            if self.delay_ms > 0 {
                sleep(Duration::from_millis(self.delay_ms)).await;
            }
            if self.should_fail {
                Ok(ProcessorResult::Retryable {
                    error_code: "TEST_ERROR".to_string(),
                    error_message: "Test error".to_string(),
                    retry_after_ms: None,
                })
            } else {
                Ok(ProcessorResult::Success)
            }
        }
    }

    /// Test processor where is_applicable returns false
    struct NotApplicableProcessor {
        id: String,
        execution_count: Arc<AtomicU32>,
    }

    impl NotApplicableProcessor {
        fn new(id: &str) -> Self {
            Self {
                id: id.to_string(),
                execution_count: Arc::new(AtomicU32::new(0)),
            }
        }

        fn execution_count(&self) -> u32 {
            self.execution_count.load(Ordering::SeqCst)
        }
    }

    #[async_trait]
    impl MigrationProcessor for NotApplicableProcessor {
        fn migration_id(&self) -> String {
            self.id.clone()
        }

        async fn is_applicable(&self) -> Result<bool, MigrationError> {
            Ok(false)
        }

        async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
            self.execution_count.fetch_add(1, Ordering::SeqCst);
            Ok(ProcessorResult::Success)
        }
    }

    /// Test key-value store that fails on all operations
    struct FailingKvStore;

    impl DeviceKeyValueStore for FailingKvStore {
        fn get(&self, _key: String) -> Result<String, KeyValueStoreError> {
            Err(KeyValueStoreError::KeyNotFound)
        }

        fn set(&self, _key: String, _value: String) -> Result<(), KeyValueStoreError> {
            Err(KeyValueStoreError::UpdateFailure)
        }

        fn delete(&self, _key: String) -> Result<(), KeyValueStoreError> {
            Err(KeyValueStoreError::UpdateFailure)
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_single_migration_run_succeeds() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(processor.execution_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_concurrent_migrations_fail_fast() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // Create a processor with a delay so the first migration holds the lock
        let processor =
            Arc::new(TestProcessor::new("test.migration.v1").with_delay(100));
        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        // Clone controller for concurrent access
        let controller_clone = controller.clone();

        // Start first migration (will hold lock for 100ms)
        let handle1 = tokio::spawn(async move { controller.run_migrations().await });

        // Give first migration time to acquire lock
        sleep(Duration::from_millis(10)).await;

        // Try to start second migration while first is running
        let handle2 =
            tokio::spawn(async move { controller_clone.run_migrations().await });

        // Wait for both to complete
        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // First should succeed
        assert!(result1.is_ok());
        assert_eq!(result1.unwrap().succeeded, 1);

        // Second should fail with InvalidOperation
        assert!(result2.is_err());
        match result2.unwrap_err() {
            MigrationError::InvalidOperation(msg) => {
                assert!(msg.contains("already in progress"));
            }
            e => panic!("Expected InvalidOperation error, got: {e:?}"),
        }

        // Processor should only have executed once (first migration)
        assert_eq!(processor.execution_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_sequential_migrations_succeed() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        // First migration
        let result1 = controller.run_migrations().await;
        assert!(result1.is_ok());

        // Second migration should succeed (first is complete)
        let result2 = controller.run_migrations().await;
        assert!(result2.is_ok());

        // Migration already succeeded, so second run should skip it
        let summary2 = result2.unwrap();
        assert_eq!(summary2.skipped, 1);
        assert_eq!(summary2.succeeded, 0);

        // Processor should only execute once (second run skipped)
        assert_eq!(processor.execution_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_lock_released_on_error() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // Create a processor that will cause storage errors by using
        // an invalid KV store that errors on save
        let failing_kv = Arc::new(FailingKvStore);
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller1 =
            MigrationController::with_processors(failing_kv, vec![processor.clone()]);

        // First migration completes but with storage errors counted as failed_retryable
        let result1 = controller1.run_migrations().await;
        assert!(result1.is_ok());
        let summary1 = result1.unwrap();
        assert_eq!(summary1.failed_retryable, 1);

        // Create another controller with working KV store
        let controller2 = MigrationController::with_processors(
            kv_store,
            vec![Arc::new(TestProcessor::new("test.migration.v2"))],
        );

        // Second migration should succeed (lock was released)
        let result2 = controller2.run_migrations().await;
        assert!(result2.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_multiple_controller_instances_share_lock() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // Create two separate controller instances
        let processor1 =
            Arc::new(TestProcessor::new("test.migration1.v1").with_delay(100));
        let controller1 = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor1.clone()],
        );

        let processor2 = Arc::new(TestProcessor::new("test.migration2.v1"));
        let controller2 =
            MigrationController::with_processors(kv_store, vec![processor2.clone()]);

        // Start first controller's migration
        let handle1 = tokio::spawn(async move { controller1.run_migrations().await });

        // Give first migration time to acquire lock
        sleep(Duration::from_millis(10)).await;

        // Try second controller's migration while first is running
        let handle2 = tokio::spawn(async move { controller2.run_migrations().await });

        let result1 = handle1.await.unwrap();
        let result2 = handle2.await.unwrap();

        // First should succeed
        assert!(result1.is_ok());

        // Second should fail with InvalidOperation (same global lock)
        assert!(result2.is_err());
        match result2.unwrap_err() {
            MigrationError::InvalidOperation(msg) => {
                assert!(msg.contains("already in progress"));
            }
            e => panic!("Expected InvalidOperation error, got: {e:?}"),
        }
    }

    #[tokio::test]
    #[serial]
    async fn test_individual_key_storage() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor1 = Arc::new(TestProcessor::new("test.migration1.v1"));
        let processor2 = Arc::new(TestProcessor::new("test.migration2.v1"));

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor1, processor2],
        );

        // Run migrations
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().succeeded, 2);

        // Verify individual keys are stored correctly
        let key1 = format!("{MIGRATION_KEY_PREFIX}test.migration1.v1");
        let key2 = format!("{MIGRATION_KEY_PREFIX}test.migration2.v1");

        // Both keys should exist in the KV store
        let record1_json = kv_store.get(key1).expect("Migration 1 record should exist");
        let record2_json = kv_store.get(key2).expect("Migration 2 record should exist");

        // Verify they can be deserialized
        let record1: MigrationRecord =
            serde_json::from_str(&record1_json).expect("Should deserialize");
        let record2: MigrationRecord =
            serde_json::from_str(&record2_json).expect("Should deserialize");

        // Both should be in Succeeded status
        assert!(matches!(record1.status, MigrationStatus::Succeeded));
        assert!(matches!(record2.status, MigrationStatus::Succeeded));
    }

    #[tokio::test]
    #[serial]
    async fn test_corrupted_record_does_not_block_migrations() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Manually insert corrupted JSON for this migration
        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        kv_store
            .set(key.clone(), "{invalid json!!!".to_string())
            .expect("Should store corrupted data");

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Migration should still run despite corrupted record
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed_retryable, 0);

        // Verify the corrupted data was overwritten with valid JSON
        let updated_json = kv_store.get(key).expect("Record should exist");
        let record: MigrationRecord =
            serde_json::from_str(&updated_json).expect("Should be valid JSON now");
        assert!(matches!(record.status, MigrationStatus::Succeeded));
    }

    #[test]
    fn test_load_record_handles_parsing_failure() {
        // Test that ParsingFailure is handled gracefully like JSON corruption
        struct ParsingFailureKvStore;

        impl DeviceKeyValueStore for ParsingFailureKvStore {
            fn get(&self, _key: String) -> Result<String, KeyValueStoreError> {
                Err(KeyValueStoreError::ParsingFailure)
            }

            fn set(
                &self,
                _key: String,
                _value: String,
            ) -> Result<(), KeyValueStoreError> {
                Ok(())
            }

            fn delete(&self, _key: String) -> Result<(), KeyValueStoreError> {
                Ok(())
            }
        }

        let kv_store = Arc::new(ParsingFailureKvStore);
        let controller = MigrationController::with_processors(kv_store, vec![]);

        // Should return a new record instead of erroring
        let result = controller.load_record("test.migration.v1");
        assert!(result.is_ok());

        let record = result.unwrap();
        assert_eq!(record.attempts, 0);
        assert!(matches!(record.status, MigrationStatus::NotStarted));
    }

    #[tokio::test]
    #[serial]
    async fn test_many_concurrent_attempts_only_one_succeeds() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor =
            Arc::new(TestProcessor::new("test.migration.v1").with_delay(50));
        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        // Launch 10 concurrent attempts
        let mut handles = vec![];
        for _ in 0..10 {
            let controller_clone = controller.clone();
            handles.push(tokio::spawn(async move {
                controller_clone.run_migrations().await
            }));
        }

        // Collect results
        let mut success_count = 0;
        let mut failure_count = 0;

        for handle in handles {
            let result = handle.await.unwrap();
            match result {
                Ok(_) => success_count += 1,
                Err(MigrationError::InvalidOperation(_)) => failure_count += 1,
                Err(e) => panic!("Unexpected error: {e:?}"),
            }
        }

        // Exactly one should succeed
        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 9);

        // Processor should only execute once
        assert_eq!(processor.execution_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_in_progress_retries_immediately() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create an InProgress record (e.g., app crashed mid-migration)
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::InProgress;
        record.attempts = 1;
        record.last_attempted_at = Some(Utc::now());

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // InProgress is retried immediately
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(processor.execution_count(), 1);

        // Verify final status is Succeeded with incremented attempt counter
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
        assert_eq!(updated_record.attempts, 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_succeeded_state_is_terminal_and_skipped() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Manually create a Succeeded record
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::Succeeded;
        record.completed_at = Some(Utc::now());

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - should skip
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.succeeded, 0);

        // Verify is_applicable() was NOT called (processor was never executed)
        assert_eq!(processor.execution_count(), 0);

        // Verify status is still Succeeded
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
    }

    #[tokio::test]
    #[serial]
    async fn test_failed_terminal_state_is_permanent_and_skipped() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Manually create a FailedTerminal record
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::FailedTerminal;
        record.last_error_code = Some("TERMINAL_ERROR".to_string());
        record.last_error_message = Some("Permanent failure".to_string());

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations multiple times - should always skip
        for _ in 0..3 {
            let result = controller.run_migrations().await;
            assert!(result.is_ok());

            let summary = result.unwrap();
            assert_eq!(summary.skipped, 1);
            assert_eq!(summary.succeeded, 0);
        }

        // Verify processor was never executed
        assert_eq!(processor.execution_count(), 0);

        // Verify status is still FailedTerminal
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(
            updated_record.status,
            MigrationStatus::FailedTerminal
        ));
    }

    #[tokio::test]
    #[serial]
    async fn test_not_started_state_checks_applicability_and_executes() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - NotStarted should check is_applicable and execute
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);

        // Verify processor was executed
        assert_eq!(processor.execution_count(), 1);

        // Verify status transitioned to Succeeded
        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let record_json = kv_store.get(key).expect("Record should exist");
        let record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(record.status, MigrationStatus::Succeeded));
        assert_eq!(record.attempts, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_failed_retryable_respects_backoff_timing() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create FailedRetryable record with retry scheduled for future
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::FailedRetryable;
        record.attempts = 1;
        record.last_error_code = Some("NETWORK_ERROR".to_string());
        record.next_attempt_at = Some(Utc::now() + chrono::Duration::hours(1)); // 1 hour in future

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - should skip due to retry timing
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.succeeded, 0);

        // Verify processor was NOT executed
        assert_eq!(processor.execution_count(), 0);

        // Verify status is still FailedRetryable
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(
            updated_record.status,
            MigrationStatus::FailedRetryable
        ));
        assert_eq!(updated_record.attempts, 1); // Attempts should not increment
    }

    #[tokio::test]
    #[serial]
    async fn test_failed_retryable_retries_when_backoff_expires() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create FailedRetryable record with retry scheduled for past
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::FailedRetryable;
        record.attempts = 1;
        record.last_error_code = Some("NETWORK_ERROR".to_string());
        record.next_attempt_at = Some(Utc::now() - chrono::Duration::minutes(5)); // 5 minutes ago

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - should retry and succeed
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.skipped, 0);

        // Verify processor was executed
        assert_eq!(processor.execution_count(), 1);

        // Verify status transitioned to Succeeded
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
        assert_eq!(updated_record.attempts, 2); // Should increment from 1 to 2
    }

    #[tokio::test]
    #[serial]
    async fn test_failed_retryable_without_retry_time_executes_immediately() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create FailedRetryable record without next_attempt_at
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::FailedRetryable;
        record.attempts = 2;
        record.next_attempt_at = None; // No retry time set

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - should execute immediately
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.succeeded, 1);

        // Verify processor was executed
        assert_eq!(processor.execution_count(), 1);

        // Verify status transitioned to Succeeded
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
    }

    #[tokio::test]
    #[serial]
    async fn test_in_progress_without_timestamp_retries() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create InProgress record without last_attempted_at timestamp
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::InProgress;
        record.attempts = 1;
        record.last_attempted_at = None;

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().succeeded, 1);
        assert_eq!(processor.execution_count(), 1);

        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
    }

    #[tokio::test]
    #[serial]
    async fn test_state_based_execution_order() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // Create 5 processors with different states
        let processor1 = Arc::new(TestProcessor::new("test.succeeded.v1"));
        let processor2 = Arc::new(TestProcessor::new("test.terminal.v1"));
        let processor3 = Arc::new(TestProcessor::new("test.retryable.v1"));
        let processor4 = Arc::new(TestProcessor::new("test.in_progress.v1"));
        let processor5 = Arc::new(TestProcessor::new("test.not_started.v1"));

        // Set up initial states
        let mut succeeded = MigrationRecord::new();
        succeeded.status = MigrationStatus::Succeeded;
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.succeeded.v1"),
                serde_json::to_string(&succeeded).unwrap(),
            )
            .unwrap();

        let mut terminal = MigrationRecord::new();
        terminal.status = MigrationStatus::FailedTerminal;
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.terminal.v1"),
                serde_json::to_string(&terminal).unwrap(),
            )
            .unwrap();

        let mut retryable = MigrationRecord::new();
        retryable.status = MigrationStatus::FailedRetryable;
        retryable.next_attempt_at = Some(Utc::now() - chrono::Duration::minutes(1)); // Ready to retry
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.retryable.v1"),
                serde_json::to_string(&retryable).unwrap(),
            )
            .unwrap();

        let mut in_progress = MigrationRecord::new();
        in_progress.status = MigrationStatus::InProgress;
        in_progress.last_attempted_at = Some(Utc::now());
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.in_progress.v1"),
                serde_json::to_string(&in_progress).unwrap(),
            )
            .unwrap();

        // NotStarted doesn't need setup - it's the default

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![
                processor1.clone(),
                processor2.clone(),
                processor3.clone(),
                processor4.clone(),
                processor5.clone(),
            ],
        );

        // Run migrations
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 5);
        assert_eq!(summary.succeeded, 3); // retryable + in_progress + not_started
        assert_eq!(summary.skipped, 2); // succeeded + terminal

        // Verify execution counts
        assert_eq!(processor1.execution_count(), 0); // Succeeded - skipped
        assert_eq!(processor2.execution_count(), 0); // Terminal - skipped
        assert_eq!(processor3.execution_count(), 1); // Retryable - executed
        assert_eq!(processor4.execution_count(), 1); // InProgress - retried
        assert_eq!(processor5.execution_count(), 1); // NotStarted - executed
    }

    #[tokio::test]
    #[serial]
    async fn test_succeeded_migration_re_runs_after_ttl_expires() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Set up a succeeded record with completed_at older than TTL
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::Succeeded;
        record.completed_at =
            Some(Utc::now() - chrono::Duration::days(MIGRATION_SUCCESS_TTL_DAYS + 1));
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.migration.v1"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();

        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        // TTL has expired and is_applicable returns true → should re-execute
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.succeeded, 1);
        assert_eq!(processor.execution_count(), 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_succeeded_migration_skipped_within_ttl() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Set up a succeeded record with recent completed_at (within TTL)
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::Succeeded;
        record.completed_at = Some(Utc::now() - chrono::Duration::days(1));
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.migration.v1"),
                serde_json::to_string(&record).unwrap(),
            )
            .unwrap();

        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        // Within TTL → should skip
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.skipped, 1);
        assert_eq!(processor.execution_count(), 0);
    }

    #[test]
    #[serial]
    fn test_delete_all_records_removes_existing_records() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor1 = Arc::new(TestProcessor::new("test.migration1.v1"));
        let processor2 = Arc::new(TestProcessor::new("test.migration2.v1"));

        // Seed records into the store
        let record = MigrationRecord::new();
        let json = serde_json::to_string(&record).unwrap();
        kv_store
            .set(
                format!("{MIGRATION_KEY_PREFIX}test.migration1.v1"),
                json.clone(),
            )
            .unwrap();
        kv_store
            .set(format!("{MIGRATION_KEY_PREFIX}test.migration2.v1"), json)
            .unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor1, processor2],
        );

        let deleted = controller.delete_all_records().unwrap();
        assert_eq!(deleted, 2);

        // Verify records are gone
        assert!(matches!(
            kv_store.get(format!("{MIGRATION_KEY_PREFIX}test.migration1.v1")),
            Err(KeyValueStoreError::KeyNotFound)
        ));
        assert!(matches!(
            kv_store.get(format!("{MIGRATION_KEY_PREFIX}test.migration2.v1")),
            Err(KeyValueStoreError::KeyNotFound)
        ));
    }

    #[test]
    #[serial]
    fn test_delete_all_records_succeeds_with_no_existing_records() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // No records seeded - store is empty
        let controller =
            MigrationController::with_processors(kv_store, vec![processor]);

        // Should not error even when no records exist
        let result = controller.delete_all_records();
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[serial]
    async fn test_delete_all_records_allows_migrations_to_rerun() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - should succeed
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().succeeded, 1);
        assert_eq!(processor.execution_count(), 1);

        // Second run - should skip (already succeeded)
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().skipped, 1);
        assert_eq!(processor.execution_count(), 1);

        // Delete all records
        let deleted = controller.delete_all_records().unwrap();
        assert_eq!(deleted, 1);

        // Third run - should execute again (record was deleted)
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap().succeeded, 1);
        assert_eq!(processor.execution_count(), 2);
    }

    #[test]
    #[serial]
    fn test_delete_all_records_propagates_store_errors() {
        let kv_store = Arc::new(FailingKvStore);
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller =
            MigrationController::with_processors(kv_store, vec![processor]);

        let result = controller.delete_all_records();
        assert!(result.is_err());
    }

    #[tokio::test]
    #[serial]
    async fn test_parallel_execution_runs_concurrently() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // Two processors each with 100ms delay
        let processor1 =
            Arc::new(TestProcessor::new("test.migration1.v1").with_delay(100));
        let processor2 =
            Arc::new(TestProcessor::new("test.migration2.v1").with_delay(100));

        let controller = MigrationController::with_processors(
            kv_store,
            vec![processor1.clone(), processor2.clone()],
        );

        let start = std::time::Instant::now();
        let result = controller.run_migrations().await;
        let elapsed = start.elapsed();

        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.succeeded, 2);
        assert_eq!(processor1.execution_count(), 1);
        assert_eq!(processor2.execution_count(), 1);

        // If parallel, ~100ms total. If sequential, ~200ms.
        // Use 180ms as threshold to confirm parallelism.
        assert!(
            elapsed.as_millis() < 180,
            "Expected parallel execution (<180ms), but took {}ms",
            elapsed.as_millis()
        );
    }

    #[tokio::test]
    #[serial]
    async fn test_ttl_expired_not_applicable_skips_without_executing() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(NotApplicableProcessor::new("test.migration.v1"));

        // Set up a succeeded record with expired TTL
        let mut record = MigrationRecord::new();
        record.status = MigrationStatus::Succeeded;
        record.completed_at =
            Some(Utc::now() - chrono::Duration::days(MIGRATION_SUCCESS_TTL_DAYS + 1));

        let key = format!("{MIGRATION_KEY_PREFIX}test.migration.v1");
        kv_store
            .set(key.clone(), serde_json::to_string(&record).unwrap())
            .unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // TTL expired, is_applicable returns false → skipped, no execution
        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.skipped, 1);
        assert_eq!(processor.execution_count(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_not_applicable_processor_is_skipped() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(NotApplicableProcessor::new("test.migration.v1"));

        let controller =
            MigrationController::with_processors(kv_store, vec![processor.clone()]);

        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.skipped, 1);
        assert_eq!(summary.succeeded, 0);
        assert_eq!(processor.execution_count(), 0);
    }

    #[tokio::test]
    #[serial]
    async fn test_parallel_mixed_results() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());

        // One succeeds, one fails, one not applicable
        let success_proc = Arc::new(TestProcessor::new("test.success.v1"));
        let mut fail_proc = TestProcessor::new("test.fail.v1");
        fail_proc.should_fail = true;
        let fail_proc = Arc::new(fail_proc);
        let skip_proc = Arc::new(NotApplicableProcessor::new("test.skip.v1"));

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![success_proc.clone(), fail_proc.clone(), skip_proc.clone()],
        );

        let result = controller.run_migrations().await;
        assert!(result.is_ok());
        let summary = result.unwrap();
        assert_eq!(summary.total, 3);
        assert_eq!(summary.succeeded, 1);
        assert_eq!(summary.failed_retryable, 1);
        assert_eq!(summary.skipped, 1);

        assert_eq!(success_proc.execution_count(), 1);
        assert_eq!(fail_proc.execution_count(), 1);
        assert_eq!(skip_proc.execution_count(), 0);
    }
}
