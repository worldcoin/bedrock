use crate::device::{DeviceKeyValueStore, KeyValueStoreError};
use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::state::{MigrationRecord, MigrationStatus};
use chrono::{Duration, Utc};
use log::{error, info, warn};
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

const MIGRATION_KEY_PREFIX: &str = "migration:";
const DEFAULT_RETRY_DELAY_MS: i64 = 60_000; // 1 minute
const MAX_RETRY_DELAY_MS: i64 = 86_400_000; // 1 day

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
#[derive(Debug, uniffi::Record)]
pub struct MigrationRunSummary {
    /// Total number of migrations attempted
    pub total: i32,
    /// Number of migrations that succeeded
    pub succeeded: i32,
    /// Number of migrations that failed but can be retried
    pub failed_retryable: i32,
    /// Number of migrations that failed with terminal errors (won't retry)
    pub failed_terminal: i32,
    /// Number of migrations blocked pending user action
    pub blocked: i32,
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
    /// Create a new [`MigrationController`]
    /// Processors are registered internally
    #[uniffi::constructor]
    pub fn new(kv_store: Arc<dyn DeviceKeyValueStore>) -> Arc<Self> {
        Self::with_processors(kv_store, Self::default_processors())
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
}

impl MigrationController {
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

    /// Get the default list of processors to run
    /// Add new processors here as they're implemented
    fn default_processors() -> Vec<Arc<dyn MigrationProcessor>> {
        vec![
            // Add actual processors here as they're implemented:
            // Arc::new(AccountBootstrapProcessor::new()),
            // Arc::new(PoHRefreshProcessor::new()),
            // Arc::new(NfcRefreshProcessor::new()),
        ]
    }

    /// Internal async implementation of `run_migrations`
    #[allow(clippy::too_many_lines)]
    async fn run_migrations_async(
        &self,
    ) -> Result<MigrationRunSummary, MigrationError> {
        info!("Migration run started");

        // Summary of this migration run for analytics. Not stored.
        let mut summary = MigrationRunSummary {
            total: i32::try_from(self.processors.len()).unwrap_or(i32::MAX),
            succeeded: 0,
            failed_retryable: 0,
            failed_terminal: 0,
            blocked: 0,
            skipped: 0,
        };

        // Execute each processor sequentially
        for processor in &self.processors {
            let migration_id = processor.migration_id();

            // Load the current record for this migration (or create new one if first time)
            let mut record = self.load_record(migration_id)?;

            // Skip if already succeeded
            if matches!(record.status, MigrationStatus::Succeeded) {
                info!("Migration {migration_id} already succeeded, skipping");
                summary.skipped += 1;
                continue;
            }

            // Skip if terminal failure (non-retryable)
            if matches!(record.status, MigrationStatus::FailedTerminal) {
                info!("Migration {migration_id} failed terminally, skipping");
                summary.skipped += 1;
                continue;
            }

            // Check if we should retry (based on next_attempt_at)
            if let Some(next_attempt) = record.next_attempt_at {
                let now = Utc::now();
                if now < next_attempt {
                    info!("Migration {migration_id} scheduled for retry at {next_attempt}, skipping");
                    summary.skipped += 1;
                    continue;
                }
            }

            // Check if migration is applicable and should run, based on processor defined logic.
            // This checks actual state (e.g., "does v4 credential exist?") to ensure idempotency
            // even if migration record is deleted (reinstall scenario).
            match processor.is_applicable().await {
                Ok(false) => {
                    info!("Migration {migration_id} not applicable, skipping");
                    summary.skipped += 1;
                    continue;
                }
                Err(e) => {
                    error!("Failed to check applicability for {migration_id}: {e:?}");
                    summary.skipped += 1;
                    continue;
                }
                Ok(true) => {
                    // Continue with execution. Fall through to the execution block below.
                }
            }

            // Execute the migration
            info!(
                "Starting migration: {} (attempt {})",
                migration_id,
                record.attempts + 1
            );

            // Update record for execution
            if record.started_at.is_none() {
                record.started_at = Some(Utc::now());
            }
            record.status = MigrationStatus::InProgress;
            record.attempts += 1;
            record.last_attempted_at = Some(Utc::now());

            // Save record before execution so we don't lose progress if the app crashes mid-migration
            self.save_record(migration_id, &record)?;

            // Execute
            match processor.execute().await {
                Ok(ProcessorResult::Success) => {
                    info!("Migration {migration_id} succeeded");
                    record.status = MigrationStatus::Succeeded;
                    record.completed_at = Some(Utc::now());
                    record.last_error_code = None;
                    record.last_error_message = None;
                    record.next_attempt_at = None; // Clear retry time
                    summary.succeeded += 1;
                }
                Ok(ProcessorResult::Retryable {
                    error_code,
                    error_message,
                    retry_after_ms,
                }) => {
                    warn!("Migration {migration_id} failed (retryable): {error_code} - {error_message}");
                    record.status = MigrationStatus::FailedRetryable;
                    record.last_error_code = Some(error_code);
                    record.last_error_message = Some(error_message);

                    // Retry time is calculated according to exponential backoff and set on the
                    // record.next_attempt_at field. When the app is next opened and the
                    // migration is run again; the controller will check whether to run the
                    // migration again based on the record.next_attempt_at field.
                    let retry_delay_ms = retry_after_ms
                        .unwrap_or_else(|| calculate_backoff_delay(record.attempts));
                    record.next_attempt_at =
                        Some(Utc::now() + Duration::milliseconds(retry_delay_ms));

                    summary.failed_retryable += 1;
                }
                Ok(ProcessorResult::Terminal {
                    error_code,
                    error_message,
                }) => {
                    error!("Migration {migration_id} failed (terminal): {error_code} - {error_message}");
                    record.status = MigrationStatus::FailedTerminal;
                    record.last_error_code = Some(error_code);
                    record.last_error_message = Some(error_message);
                    record.next_attempt_at = None; // Clear retry time
                    summary.failed_terminal += 1;
                }
                Ok(ProcessorResult::BlockedUserAction { reason }) => {
                    warn!("Migration {migration_id} blocked: {reason}");
                    record.status = MigrationStatus::BlockedUserAction;
                    record.last_error_message = Some(reason);
                    record.next_attempt_at = None; // Clear retry time
                    summary.blocked += 1;
                }
                Err(e) => {
                    error!("Migration {migration_id} threw error: {e:?}");
                    record.status = MigrationStatus::FailedRetryable;
                    record.last_error_code = Some("UNEXPECTED_ERROR".to_string());
                    record.last_error_message = Some(format!("{e:?}"));

                    // Schedule retry with backoff
                    let retry_delay_ms = calculate_backoff_delay(record.attempts);
                    record.next_attempt_at =
                        Some(Utc::now() + Duration::milliseconds(retry_delay_ms));

                    summary.failed_retryable += 1;
                }
            }

            // Save the final result (success/failure) to storage
            self.save_record(migration_id, &record)?;
        }

        info!(
            "Migration run completed: {} succeeded, {} retryable, {} terminal, {} blocked, {} skipped",
            summary.succeeded, summary.failed_retryable, summary.failed_terminal, summary.blocked, summary.skipped
        );

        Ok(summary)
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
    use crate::device::test::InMemoryDeviceKeyValueStore;
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
        fn migration_id(&self) -> &str {
            &self.id
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
            e => panic!("Expected InvalidOperation error, got: {:?}", e),
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

        // Create a processor that will cause the migration to fail by using
        // an invalid KV store that errors on save
        struct FailingKvStore;
        impl DeviceKeyValueStore for FailingKvStore {
            fn get(&self, _key: String) -> Result<String, KeyValueStoreError> {
                Err(KeyValueStoreError::KeyNotFound)
            }
            fn set(
                &self,
                _key: String,
                _value: String,
            ) -> Result<(), KeyValueStoreError> {
                Err(KeyValueStoreError::UpdateFailure)
            }
            fn delete(&self, _key: String) -> Result<(), KeyValueStoreError> {
                Err(KeyValueStoreError::UpdateFailure)
            }
        }

        let failing_kv = Arc::new(FailingKvStore);
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));
        let controller1 =
            MigrationController::with_processors(failing_kv, vec![processor.clone()]);

        // First migration fails
        let result1 = controller1.run_migrations().await;
        assert!(result1.is_err());

        // Create another controller with working KV store
        let controller2 = MigrationController::with_processors(
            kv_store,
            vec![Arc::new(TestProcessor::new("test.migration.v2"))],
        );

        // Second migration should succeed (lock was released despite error)
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
            e => panic!("Expected InvalidOperation error, got: {:?}", e),
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
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        // Exactly one should succeed
        assert_eq!(success_count, 1);
        assert_eq!(failure_count, 9);

        // Processor should only execute once
        assert_eq!(processor.execution_count(), 1);
    }
}
