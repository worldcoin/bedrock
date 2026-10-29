use crate::bedrock_export;
use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::record_store::RecordStore;
use crate::migration::record_store::{
    MigrationRecord, MigrationRecordEntry, MigrationStatus,
};
use crate::migration::wallet_controller::WalletMigrationController;
use crate::primitives::key_value_store::DeviceKeyValueStore;
use crate::smart_account::SafeSmartAccount;
use chrono::{Duration, Utc};
use futures::future::join_all;
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Namespace for native migration records.
const NATIVE_KEY_PREFIX: &str = "migration:";
const MIGRATION_SUCCESS_TTL_DAYS: i64 = 30; // Re-check succeeded migrations after 30 days

/// Process-wide: only one migration run at a time, however many
/// [`MigrationController`]s exist. Callers should still keep to one instance.
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
    /// Number of migrations that submitted fire-and-forget work and remain in
    /// progress; completion is proven on a later run by re-reading on-chain state
    pub pending: i32,
}

impl MigrationRunSummary {
    /// Add another summary's per-outcome counts into this one. `total` is not
    /// merged — the caller sets it from the number of registered migrations.
    pub(crate) const fn merge_counts(&mut self, other: &Self) {
        self.succeeded += other.succeeded;
        self.failed_retryable += other.failed_retryable;
        self.failed_terminal += other.failed_terminal;
        self.skipped += other.skipped;
        self.pending += other.pending;
    }

    /// Merge another controller's whole summary in, `total` included.
    pub(crate) const fn merge(&mut self, other: &Self) {
        self.total += other.total;
        self.merge_counts(other);
    }

    pub(crate) fn skipped() -> Self {
        Self {
            skipped: 1,
            ..Self::default()
        }
    }

    pub(crate) fn succeeded() -> Self {
        Self {
            succeeded: 1,
            ..Self::default()
        }
    }

    pub(crate) fn pending() -> Self {
        Self {
            pending: 1,
            ..Self::default()
        }
    }

    pub(crate) fn failed_retryable() -> Self {
        Self {
            failed_retryable: 1,
            ..Self::default()
        }
    }

    pub(crate) fn failed_terminal() -> Self {
        Self {
            failed_terminal: 1,
            ..Self::default()
        }
    }
}

/// Orchestrates migration execution, one `RecordStore` key per migration.
///
/// See `record_store.rs` for the storage layout, `README.md` for the model.
#[derive(uniffi::Object)]
pub struct MigrationController {
    records: RecordStore,
    /// Foreign (Swift/Kotlin) processors, plus any injected in tests.
    processors: Vec<Arc<dyn MigrationProcessor>>,
    /// Bedrock's own wallet migrations. Runs alongside `processors` under the
    /// same lock; see [`crate::migration::wallet`] for why it is a separate
    /// framework rather than more processors.
    wallet: WalletMigrationController,
}

#[bedrock_export]
impl MigrationController {
    /// Create a new [`MigrationController`].
    ///
    /// Runs the `additional_processors` passed in plus Bedrock's own
    /// [wallet migrations](crate::migration::wallet), which need `safe_account`.
    #[uniffi::constructor]
    pub fn new(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        safe_account: Option<Arc<SafeSmartAccount>>,
        additional_processors: Vec<Arc<dyn MigrationProcessor>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            wallet: WalletMigrationController::new(Arc::clone(&kv_store), safe_account),
            records: RecordStore::new(kv_store, NATIVE_KEY_PREFIX),
            processors: additional_processors,
        })
    }

    /// Run all registered migrations. May take seconds; network-bound.
    ///
    /// Thread-safe and fail-fast: a concurrent run errors immediately rather
    /// than waiting on the process-wide lock.
    ///
    /// # Errors
    ///
    /// `InvalidOperation` if another run is already in progress.
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

    /// Delete all migration records, so everything runs again from scratch.
    ///
    /// **Developer/testing use only.** Takes the lock; absent records are
    /// skipped.
    ///
    /// # Errors
    ///
    /// `InvalidOperation` if a run is in progress, or the store failed.
    pub fn delete_all_records(&self) -> Result<i32, MigrationError> {
        let _guard = MIGRATION_LOCK.try_lock().map_err(|_| {
            MigrationError::InvalidOperation(
                "Migration is already in progress. Please wait for the current migration to complete.".to_string(),
            )
        })?;

        let mut deleted = 0;
        for processor in &self.processors {
            if self.records.delete(&processor.migration_id())? {
                deleted += 1;
            }
        }

        deleted += self.wallet.delete_records()?;

        crate::info!(
            "migration_records.deleted count={} total_processors={} timestamp={}",
            deleted,
            self.processors.len() + self.wallet.len(),
            Utc::now().to_rfc3339()
        );

        Ok(deleted)
    }

    /// One [`MigrationRecordEntry`] per registered migration, under the lock so
    /// the snapshot is consistent. Never-attempted ones read as `NotStarted`.
    ///
    /// # Errors
    ///
    /// `InvalidOperation` if a run is in progress, or the store failed.
    pub fn list_all_records(
        &self,
    ) -> Result<Vec<MigrationRecordEntry>, MigrationError> {
        let _guard = MIGRATION_LOCK.try_lock().map_err(|_| {
            MigrationError::InvalidOperation(
                "Migration is already in progress. Please wait for the current migration to complete.".to_string(),
            )
        })?;

        let mut entries = Vec::new();
        for processor in &self.processors {
            let migration_id = processor.migration_id();
            let record = self.load_record(&migration_id)?;
            entries.push(record.into_entry(migration_id));
        }
        entries.extend(self.wallet.list_records()?);

        Ok(entries)
    }
}

impl MigrationController {
    /// Create a controller with foreign processors injected and no on-chain
    /// migrations. Test helper.
    pub fn with_processors(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        processors: Vec<Arc<dyn MigrationProcessor>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            wallet: WalletMigrationController::with_migrations(
                Arc::clone(&kv_store),
                vec![],
            ),
            records: RecordStore::new(kv_store, NATIVE_KEY_PREFIX),
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
            self.processors.len() + self.wallet.len(),
            run_start_time.to_rfc3339()
        );

        // Foreign processors and wallet migrations run concurrently. They
        // share nothing but this lock and the summary.
        let foreign = async {
            let results = join_all(
                self.processors
                    .iter()
                    .map(|processor| self.run_single_processor(processor.as_ref())),
            )
            .await;

            let mut summary = MigrationRunSummary {
                total: i32::try_from(self.processors.len()).unwrap_or(i32::MAX),
                ..MigrationRunSummary::default()
            };
            for s in results {
                summary.merge_counts(&s);
            }
            summary
        };

        let (mut summary, wallet) = futures::join!(foreign, self.wallet.run());
        summary.merge(&wallet);

        let run_duration_ms = (Utc::now() - run_start_time).num_milliseconds();

        crate::info!(
            "migration_run.completed total={} succeeded={} failed_retryable={} failed_terminal={} skipped={} duration_ms={} timestamp={} pending={}",
            summary.total,
            summary.succeeded,
            summary.failed_retryable,
            summary.failed_terminal,
            summary.skipped,
            run_duration_ms,
            Utc::now().to_rfc3339(),
            summary.pending
        );

        Ok(summary)
    }

    /// Run a single migration processor through its full lifecycle.
    #[expect(clippy::too_many_lines)]
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
                // Check if it's time to recheck applicability via recheck_at.
                let recheck_due = record
                    .recheck_at
                    .is_some_and(|recheck_at| Utc::now() >= recheck_at);

                if recheck_due {
                    crate::info!(
                        "migration.recheck_due id={} recheck_at={} timestamp={}",
                        migration_id,
                        record
                            .recheck_at
                            .map(|t| t.to_rfc3339())
                            .unwrap_or_default(),
                        Utc::now().to_rfc3339()
                    );
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

            MigrationStatus::NotStarted
            | MigrationStatus::InProgress
            | MigrationStatus::FailedRetryable => {
                // NotStarted: first time attempting this migration
                // InProgress/FailedRetryable: retry on every app open
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
        let is_applicable = match processor.is_applicable().await {
            Ok(applicable) => applicable,
            Err(e) => {
                crate::error!(
                    "migration.is_applicable_error id={} error={:?} timestamp={}",
                    migration_id,
                    e,
                    Utc::now().to_rfc3339()
                );
                false
            }
        };

        if !is_applicable {
            // For TTL-expired succeeded migrations, renew recheck_at to avoid
            // calling is_applicable on every app open.
            if matches!(record.status, MigrationStatus::Succeeded) {
                record.recheck_at =
                    Some(Utc::now() + Duration::days(MIGRATION_SUCCESS_TTL_DAYS));
                let _ = self.save_record(&migration_id, &record);
            }
            return MigrationRunSummary {
                skipped: 1,
                ..MigrationRunSummary::default()
            };
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
                record.recheck_at =
                    Some(Utc::now() + Duration::days(MIGRATION_SUCCESS_TTL_DAYS));
                record.last_error_code = None;
                record.last_error_message = None;
                MigrationRunSummary {
                    succeeded: 1,
                    ..MigrationRunSummary::default()
                }
            }
            Ok(ProcessorResult::Retryable {
                error_code,
                error_message,
                ..
            }) => {
                let duration_ms = (Utc::now() - execute_start).num_milliseconds();
                crate::warn!(
                    "migration.failed_retryable id={} attempt={} duration_ms={} error_code={} error_message={} timestamp={}",
                    migration_id, record.attempts, duration_ms, error_code, error_message, Utc::now().to_rfc3339()
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

    /// Load one record; corrupt or missing data reads as a reset, so a single
    /// bad record cannot block every migration.
    fn load_record(
        &self,
        migration_id: &str,
    ) -> Result<MigrationRecord, MigrationError> {
        self.records.load(migration_id)
    }

    /// Save a single migration record to persistent storage
    /// Each migration is stored under its own key: `"migration:{migration_id}"`
    fn save_record(
        &self,
        migration_id: &str,
        record: &MigrationRecord,
    ) -> Result<(), MigrationError> {
        self.records.save(migration_id, record)
    }
}

#[cfg(test)]
mod tests {
    //! Tests for the migration controller's locking behavior.
    //!
    //! **Note:** These tests share a global `MIGRATION_LOCK` and must run serially.
    //! The `#[serial]` attribute ensures they don't interfere with each other.

    use super::*;
    use crate::primitives::key_value_store::{
        InMemoryDeviceKeyValueStore, KeyValueStoreError,
    };
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
                })
            } else {
                Ok(ProcessorResult::Success)
            }
        }
    }

    /// Test processor where `is_applicable` returns false
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
        let key1 = format!("{NATIVE_KEY_PREFIX}test.migration1.v1");
        let key2 = format!("{NATIVE_KEY_PREFIX}test.migration2.v1");

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
        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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
        let record = MigrationRecord {
            status: MigrationStatus::InProgress,
            attempts: 1,
            last_attempted_at: Some(Utc::now()),
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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
        let record = MigrationRecord {
            status: MigrationStatus::Succeeded,
            completed_at: Some(Utc::now()),
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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
        let record = MigrationRecord {
            status: MigrationStatus::FailedTerminal,
            last_error_code: Some("TERMINAL_ERROR".to_string()),
            last_error_message: Some("Permanent failure".to_string()),
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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
        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
        let record_json = kv_store.get(key).expect("Record should exist");
        let record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(record.status, MigrationStatus::Succeeded));
        assert_eq!(record.attempts, 1);
    }

    #[tokio::test]
    #[serial]
    async fn test_failed_retryable_retries_on_next_run() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create FailedRetryable record
        let record = MigrationRecord {
            status: MigrationStatus::FailedRetryable,
            attempts: 1,
            last_error_code: Some("NETWORK_ERROR".to_string()),
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
        let json = serde_json::to_string(&record).unwrap();
        kv_store.set(key.clone(), json).unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor.clone()],
        );

        // Run migrations - FailedRetryable should retry immediately on next app open
        let result = controller.run_migrations().await;
        assert!(result.is_ok());

        let summary = result.unwrap();
        assert_eq!(summary.total, 1);
        assert_eq!(summary.succeeded, 1);

        // Verify processor was executed
        assert_eq!(processor.execution_count(), 1);

        // Verify status transitioned to Succeeded with incremented attempts
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(matches!(updated_record.status, MigrationStatus::Succeeded));
        assert_eq!(updated_record.attempts, 2);
    }

    #[tokio::test]
    #[serial]
    async fn test_in_progress_without_timestamp_retries() {
        let kv_store = Arc::new(InMemoryDeviceKeyValueStore::new());
        let processor = Arc::new(TestProcessor::new("test.migration.v1"));

        // Create InProgress record without last_attempted_at timestamp
        let record = MigrationRecord {
            status: MigrationStatus::InProgress,
            attempts: 1,
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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
        let succeeded = MigrationRecord {
            status: MigrationStatus::Succeeded,
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.succeeded.v1"),
                serde_json::to_string(&succeeded).unwrap(),
            )
            .unwrap();

        let terminal = MigrationRecord {
            status: MigrationStatus::FailedTerminal,
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.terminal.v1"),
                serde_json::to_string(&terminal).unwrap(),
            )
            .unwrap();

        let retryable = MigrationRecord {
            status: MigrationStatus::FailedRetryable,
            last_error_code: Some("NETWORK_ERROR".to_string()),
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.retryable.v1"),
                serde_json::to_string(&retryable).unwrap(),
            )
            .unwrap();

        let in_progress = MigrationRecord {
            status: MigrationStatus::InProgress,
            last_attempted_at: Some(Utc::now()),
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.in_progress.v1"),
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

        // Set up a succeeded record with recheck_at in the past (TTL expired)
        let record = MigrationRecord {
            status: MigrationStatus::Succeeded,
            completed_at: Some(
                Utc::now() - chrono::Duration::days(MIGRATION_SUCCESS_TTL_DAYS + 1),
            ),
            recheck_at: Some(Utc::now() - chrono::Duration::days(1)),
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.migration.v1"),
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
        let record = MigrationRecord {
            status: MigrationStatus::Succeeded,
            completed_at: Some(Utc::now() - chrono::Duration::days(1)),
            ..MigrationRecord::default()
        };
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.migration.v1"),
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
        let record = MigrationRecord::default();
        let json = serde_json::to_string(&record).unwrap();
        kv_store
            .set(
                format!("{NATIVE_KEY_PREFIX}test.migration1.v1"),
                json.clone(),
            )
            .unwrap();
        kv_store
            .set(format!("{NATIVE_KEY_PREFIX}test.migration2.v1"), json)
            .unwrap();

        let controller = MigrationController::with_processors(
            kv_store.clone(),
            vec![processor1, processor2],
        );

        let deleted = controller.delete_all_records().unwrap();
        assert_eq!(deleted, 2);

        // Verify records are gone
        assert!(matches!(
            kv_store.get(format!("{NATIVE_KEY_PREFIX}test.migration1.v1")),
            Err(KeyValueStoreError::KeyNotFound)
        ));
        assert!(matches!(
            kv_store.get(format!("{NATIVE_KEY_PREFIX}test.migration2.v1")),
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

        // Set up a succeeded record with recheck_at in the past (TTL expired)
        let record = MigrationRecord {
            status: MigrationStatus::Succeeded,
            completed_at: Some(
                Utc::now() - chrono::Duration::days(MIGRATION_SUCCESS_TTL_DAYS + 1),
            ),
            recheck_at: Some(Utc::now() - chrono::Duration::days(1)),
            ..MigrationRecord::default()
        };

        let key = format!("{NATIVE_KEY_PREFIX}test.migration.v1");
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

        // Verify recheck_at was set to prevent repeated is_applicable calls
        let record_json = kv_store.get(key).expect("Record should exist");
        let updated_record: MigrationRecord =
            serde_json::from_str(&record_json).expect("Should deserialize");
        assert!(
            updated_record.recheck_at.is_some(),
            "recheck_at should be set after skipping a TTL-expired migration"
        );
        let recheck_at = updated_record.recheck_at.unwrap();
        let expected_min =
            Utc::now() + chrono::Duration::days(MIGRATION_SUCCESS_TTL_DAYS - 1);
        assert!(
            recheck_at > expected_min,
            "recheck_at should be ~{MIGRATION_SUCCESS_TTL_DAYS} days in the future"
        );
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
