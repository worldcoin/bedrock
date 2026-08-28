use crate::migration::error::MigrationError;
use crate::primitives::key_value_store::{DeviceKeyValueStore, KeyValueStoreError};
use crate::warn;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

/// Per-migration record storage, namespaced by prefix.
///
/// Each migration gets its own key (`{prefix}{migration_id}`) so there is no
/// ceiling on how many can exist, no single-key size limit to hit in
/// `SharedPreferences`/`UserDefaults`, and no way for one bad record to block
/// the rest.
///
/// Shared by both migration frameworks; the prefix is what keeps their records
/// apart.
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
    /// Corrupt data reads as a reset rather than an error: a migration decides
    /// what to do by looking at the world, so the worst case is one redundant
    /// pass. Only an unexpected store failure propagates.
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
