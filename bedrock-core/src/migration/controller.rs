use crate::migration::error::MigrationError;
use crate::migration::processor::{MigrationProcessor, ProcessorResult};
use crate::migration::state::{MigrationRecord, MigrationStatus};
use crate::primitives::key_value_store::{DeviceKeyValueStore, KeyValueStoreError};
use chrono::{Duration, Utc};
use futures::future::join_all;
use log::warn;
use once_cell::sync::Lazy;
use std::sync::Arc;
use tokio::sync::Mutex;

const MIGRATION_KEY_PREFIX: &str = "migration:";
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

/// A single migration record entry returned by [`MigrationController::list_all_records`].
///
/// FFI-facing view of a migration's persisted execution state, combining the
/// processor's migration ID with the fields from [`MigrationRecord`] that are
/// relevant to external consumers.
///
#[derive(Debug, Clone, uniffi::Record)]
pub struct MigrationRecordEntry {
    /// The migration identifier (e.g. `"worldId.credentials.nfc.refresh.v2"`).
    pub migration_id: String,
    /// Current execution status.
    pub status: MigrationStatus,
    /// Number of execution attempts so far.
    pub attempts: i32,
    /// ISO 8601 timestamp when the migration was first started, if any.
    pub started_at: Option<String>,
    /// ISO 8601 timestamp of the most recent attempt, if any.
    pub last_attempted_at: Option<String>,
    /// Error code from the most recent failed attempt, if any.
    pub last_error_code: Option<String>,
    /// Error message from the most recent failed attempt, if any.
    pub last_error_message: Option<String>,
    /// ISO 8601 timestamp when the migration completed successfully, if any.
    pub completed_at: Option<String>,
}

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
/// Each migration's state is stored independently in the [`DeviceKeyValueStore`] using
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
    /// Create a new [`MigrationController`] with an explicit list of processors.
    ///
    /// Unlike the `bedrock` crate's version, this constructor does not include any
    /// default processors (those require EVM/wallet dependencies). Pass all desired
    /// processors via `processors`.
    #[uniffi::constructor]
    pub fn new(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        processors: Vec<Arc<dyn MigrationProcessor>>,
    ) -> Arc<Self> {
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

    /// List the current record for every registered processor.
    ///
    /// Returns one [`MigrationRecordEntry`] per registered processor. Processors
    /// that have never been attempted are included with status
    /// [`MigrationStatus::NotStarted`] and zero attempts. Corrupted or missing
    /// store entries are treated as a reset rather than an error.
    ///
    /// # Errors
    ///
    /// Returns `MigrationError::InvalidOperation` if a migration run is currently in progress.
    /// Returns `MigrationError::DeviceKeyValueStoreError` only for unexpected store failures;
    /// missing keys and parse errors are treated as resets and do not propagate.
    ///
    /// # Concurrency
    ///
    /// Acquires the global migration lock to ensure a consistent snapshot is
    /// returned while no migration is actively modifying the records.
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
            entries.push(MigrationRecordEntry {
                migration_id,
                status: record.status,
                attempts: record.attempts,
                started_at: record.started_at.map(|t| t.to_rfc3339()),
                last_attempted_at: record.last_attempted_at.map(|t| t.to_rfc3339()),
                last_error_code: record.last_error_code,
                last_error_message: record.last_error_message,
                completed_at: record.completed_at.map(|t| t.to_rfc3339()),
            });
        }

        Ok(entries)
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

    /// Load a single migration record from the [`DeviceKeyValueStore`]
    /// Each migration is stored under its own key: `"migration:{migration_id}"`
    ///
    /// # Corruption Handling
    ///
    /// If the stored JSON is corrupted or invalid, this method treats it as a reset
    /// and returns a new `MigrationRecord`. This prevents one corrupted record from
    /// blocking all migrations permanently.
    pub fn load_record(
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
                        Ok(MigrationRecord::default())
                    }
                }
            }
            Err(KeyValueStoreError::KeyNotFound) => {
                // First time running this migration, return new record
                Ok(MigrationRecord::default())
            }
            Err(KeyValueStoreError::ParsingFailure) => {
                // Storage layer couldn't parse the value - treat as reset
                warn!("Migration {migration_id} has corrupted storage data, resetting");
                Ok(MigrationRecord::default())
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
