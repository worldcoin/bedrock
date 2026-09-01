//! Migration records: the type, its FFI view, and its persistence.
//!
//! Shared by both migration frameworks; the key prefix keeps them apart.

use crate::migration::error::MigrationError;
use crate::primitives::key_value_store::{DeviceKeyValueStore, KeyValueStoreError};
use crate::warn;
use chrono::{DateTime, Utc};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::sync::Arc;

/// Status of a single migration.
#[derive(
    Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize, uniffi::Enum,
)]
pub enum MigrationStatus {
    /// Never attempted.
    #[default]
    NotStarted,

    /// In progress. For a wallet migration: submitted, not yet seen on chain.
    InProgress,

    /// Done. For a wallet migration: the end state was observed this launch,
    /// which can drift back — unlike a processor's own word, taken on trust.
    Succeeded,

    /// Failed; retried next launch.
    FailedRetryable,

    /// Failed terminally. Never attempted again.
    FailedTerminal,
}

/// Persisted state of one migration, under `{prefix}{migration_id}`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct MigrationRecord {
    /// Current status.
    pub status: MigrationStatus,

    /// Attempts made. Wallet migrations only count accepted submissions, so a
    /// failed or offline pass never advances it toward the give-up cap.
    pub attempts: i32,

    /// When the first attempt was made.
    pub started_at: Option<DateTime<Utc>>,

    /// When the most recent pass ran.
    pub last_attempted_at: Option<DateTime<Utc>>,

    /// Error code from the most recent failed pass.
    pub last_error_code: Option<String>,

    /// Error message from the most recent failed pass.
    pub last_error_message: Option<String>,

    /// When the migration first completed.
    pub completed_at: Option<DateTime<Utc>>,

    /// Next recheck of a succeeded migration's applicability, `now + TTL`.
    /// Native only; wallet migrations re-observe every launch instead.
    #[serde(default)]
    pub recheck_at: Option<DateTime<Utc>>,

    /// Most recent submission reference (userOp hash or relay id). Wallet only,
    /// diagnostics only — never read for control flow.
    #[serde(default)]
    pub last_submission: Option<String>,
}

impl MigrationRecord {
    /// The FFI view, timestamps rendered as ISO 8601.
    #[must_use]
    pub fn into_entry(self, migration_id: String) -> MigrationRecordEntry {
        MigrationRecordEntry {
            migration_id,
            status: self.status,
            attempts: self.attempts,
            started_at: self.started_at.map(|t| t.to_rfc3339()),
            last_attempted_at: self.last_attempted_at.map(|t| t.to_rfc3339()),
            last_error_code: self.last_error_code,
            last_error_message: self.last_error_message,
            completed_at: self.completed_at.map(|t| t.to_rfc3339()),
        }
    }
}

/// FFI-facing view of a [`MigrationRecord`], keyed by migration ID.
///
/// Internal-only fields (`recheck_at`, `last_submission`) are not exposed.
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

/// Per-migration record storage, namespaced by prefix.
///
/// One key per migration: no ceiling on how many can exist, no single-key size
/// limit to hit, and no way for one bad record to block the rest.
pub struct RecordStore {
    kv_store: Arc<dyn DeviceKeyValueStore>,
    prefix: &'static str,
}

impl RecordStore {
    pub const fn new(
        kv_store: Arc<dyn DeviceKeyValueStore>,
        prefix: &'static str,
    ) -> Self {
        Self { kv_store, prefix }
    }

    /// Load a record, or the default if there is none.
    ///
    /// Corrupt data reads as a reset, not an error: a migration decides by
    /// looking at the world, so the worst case is one redundant pass.
    ///
    /// # Errors
    /// Only unexpected store failures.
    pub fn load<T: DeserializeOwned + Default>(
        &self,
        id: &str,
    ) -> Result<T, MigrationError> {
        match self.kv_store.get(self.key(id)) {
            Ok(json) => Ok(serde_json::from_str(&json).unwrap_or_else(|e| {
                warn!("Migration {id} has corrupted JSON data, resetting: {e:?}");
                T::default()
            })),
            Err(KeyValueStoreError::KeyNotFound) => Ok(T::default()),
            Err(KeyValueStoreError::ParsingFailure) => {
                warn!("Migration {id} has corrupted storage data, resetting");
                Ok(T::default())
            }
            Err(e) => Err(e.into()),
        }
    }

    /// # Errors
    /// If the record cannot be serialized or the store rejects the write.
    pub fn save<T: Serialize>(
        &self,
        id: &str,
        record: &T,
    ) -> Result<(), MigrationError> {
        self.kv_store
            .set(self.key(id), serde_json::to_string(record)?)?;
        Ok(())
    }

    /// Delete a record, reporting whether one was there.
    ///
    /// # Errors
    /// If the store fails for a reason other than a missing key.
    pub fn delete(&self, id: &str) -> Result<bool, MigrationError> {
        match self.kv_store.delete(self.key(id)) {
            Ok(()) => Ok(true),
            Err(KeyValueStoreError::KeyNotFound) => Ok(false),
            Err(e) => Err(e.into()),
        }
    }

    fn key(&self, id: &str) -> String {
        format!("{}{id}", self.prefix)
    }
}
