//! Types for the backup-service.

use serde::{Deserialize, Serialize};

use crate::backup::TurnkeyMeta;

/// Backup metadata as returned by the backup service
#[derive(Debug, Clone, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct BackupMetadata {
    /// The backup id.
    pub id: String,
    /// Hex-encoded hash of the current backup manifest.
    pub manifest_hash: String,
    /// Encryption keys that can decrypt the backup (PRF, iCloud, Turnkey).
    pub keys: Vec<BackupEncryptionKey>,
    /// Main factors (passkeys, OIDC accounts) that can recover or modify the backup.
    pub factors: Vec<BackupFactor>,
    /// Sync factors, used to update metadata and view/delete factors.
    pub sync_factors: Vec<BackupFactor>,
}

/// A single factor within the backup metadata.
#[derive(Debug, Clone, Deserialize, uniffi::Record)]
#[serde(rename_all = "camelCase")]
pub struct BackupFactor {
    /// Unique identifier for the factor.
    pub id: String,
    /// Unix timestamp (seconds) when the factor was created.
    pub created_at: i64,
    /// The kind of factor and its associated metadata.
    pub kind: BackupFactorKind,
}

/// The kind of a backup factor.
#[derive(Debug, Clone, Deserialize, uniffi::Enum)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupFactorKind {
    /// A `WebAuthn` passkey, `registration` blob is intentionally omitted.
    #[serde(rename_all = "camelCase")]
    Passkey {
        /// Base64url-encoded (no padding) credential id.
        credential_id: String,
        /// Human-readable label shown to the user.
        label: String,
    },
    /// An OIDC account (Google or Apple) backed by a Turnkey OAuth provider.
    #[serde(rename_all = "camelCase")]
    OidcAccount {
        /// Which provider and its masked email.
        account: BackupOidcAccount,
        /// The Turnkey OAuth provider id backing this factor.
        turnkey_provider_id: String,
    },
    /// An elliptic-curve keypair (a sync factor).
    #[serde(rename_all = "camelCase")]
    EcKeypair {
        /// Base64-encoded SEC1 public key.
        public_key: String,
    },
}

/// Which OIDC provider backs a factor, with the user's masked email.
#[derive(Debug, Clone, Deserialize, uniffi::Enum)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupOidcAccount {
    /// A Google account.
    #[serde(rename_all = "camelCase")]
    Google {
        /// The user's masked email (e.g. `j***@gmail.com`).
        masked_email: String,
    },
    /// An Apple account.
    #[serde(rename_all = "camelCase")]
    Apple {
        /// The user's masked email.
        masked_email: String,
    },
}

/// A backup encryption key. NOTE this only contains factor-secret-encrypted keys.
#[derive(Debug, Clone, Serialize, Deserialize, uniffi::Enum)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BackupEncryptionKey {
    /// Key encrypted with the user's passkey PRF.
    #[serde(rename_all = "camelCase")]
    Prf {
        /// The encrypted backup key.
        encrypted_key: String,
    },
    /// Key encrypted with the user's iCloud Keychain.
    #[serde(rename_all = "camelCase")]
    Icloud {
        /// The encrypted backup key.
        encrypted_key: String,
    },
    /// Key encrypted with a private key stored in the user's Turnkey account.
    #[serde(rename_all = "camelCase")]
    Turnkey {
        /// The encrypted backup key.
        encrypted_key: String,
        /// The Turnkey sub-organization id.
        turnkey_account_id: String,
        /// The Turnkey user id (`auth_user_main`).
        turnkey_user_id: String,
        /// The Turnkey private key id backing the encryption key.
        turnkey_private_key_id: String,
    },
}

impl BackupMetadata {
    /// Finds a main factor by id.
    pub(in crate::backup) fn factor(&self, factor_id: &str) -> Option<&BackupFactor> {
        self.factors.iter().find(|factor| factor.id == factor_id)
    }

    /// Number of main factors. When this is 1, removing that factor deletes the
    /// entire backup.
    pub(in crate::backup) const fn main_factor_count(&self) -> usize {
        self.factors.len()
    }

    /// Number of OIDC main factors. When this is 1, removing that OIDC factor tears
    /// down the Turnkey sub-organization rather than a single provider.
    pub(in crate::backup) fn oidc_factor_count(&self) -> usize {
        self.factors
            .iter()
            .filter(|factor| {
                matches!(factor.kind, BackupFactorKind::OidcAccount { .. })
            })
            .count()
    }

    /// Number of passkey main factors.
    pub(in crate::backup) fn passkey_factor_count(&self) -> usize {
        self.factors
            .iter()
            .filter(|factor| matches!(factor.kind, BackupFactorKind::Passkey { .. }))
            .count()
    }

    /// The Turnkey or `None` unless there is exactly one.
    pub(in crate::backup) fn turnkey_account(
        &self,
    ) -> Option<(TurnkeyMeta, &BackupEncryptionKey)> {
        let mut turnkey_keys = self.keys.iter().filter_map(|key| match key {
            BackupEncryptionKey::Turnkey {
                turnkey_account_id,
                turnkey_user_id,
                ..
            } => Some((
                key,
                TurnkeyMeta {
                    id: turnkey_account_id.clone(),
                    auth_user_main_id: turnkey_user_id.clone(),
                },
            )),
            _ => None,
        });

        let (key, meta) = turnkey_keys.next()?;

        if turnkey_keys.next().is_some() {
            crate::critical!("backup_metadata.multiple_turnkey_keys");
            return None;
        }

        Some((meta, key))
    }

    /// The single PRF encryption key, or `None` unless there is exactly one. A
    /// passkey removal drops this key. Invariant, only one passkey is allowed in the backup.
    pub(in crate::backup) fn single_prf_key(&self) -> Option<&BackupEncryptionKey> {
        let mut prf_keys = self
            .keys
            .iter()
            .filter(|key| matches!(key, BackupEncryptionKey::Prf { .. }));
        let key = prf_keys.next()?;
        prf_keys.next().is_none().then_some(key)
    }
}

/// The scope of the factor being deleted. OIDC factors are `Main`.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum FactorScope {
    /// A main factor (recovery method).
    Main,
}

/// Request authorization proving control of a factor by signing a server challenge.
/// Only the sync-factor keypair form is produced here.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE")]
pub(super) enum Authorization {
    /// An EC keypair authorization: an uncompressed SEC1 public key and a DER
    /// signature over the challenge, both base64-encoded.
    #[serde(rename_all = "camelCase")]
    EcKeypair {
        /// Base64-encoded uncompressed (65-byte) SEC1 P-256 public key.
        public_key: String,
        /// Base64-encoded DER ECDSA signature of the challenge.
        signature: String,
    },
}

/// Request body for `POST /v1/delete-factor`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteFactorRequest {
    /// Sync-factor authorization over the delete-factor challenge.
    pub authorization: Authorization,
    /// The challenge token bound to `factor_id`.
    pub challenge_token: String,
    /// The factor to delete.
    pub factor_id: String,
    /// The Turnkey encryption key to drop, sent only when removing the last OIDC
    /// factor.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_key: Option<BackupEncryptionKey>,
    /// Scope of the factor being deleted.
    pub scope: FactorScope,
}

/// Request body for `POST /v1/delete-backup`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct DeleteBackupRequest {
    /// Sync-factor authorization over the delete-backup challenge.
    pub authorization: Authorization,
    /// The delete-backup challenge token.
    pub challenge_token: String,
}

/// Request body for `POST /v1/retrieve-metadata`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct RetrieveMetadataRequest {
    /// Sync-factor authorization over the retrieve-metadata challenge.
    pub authorization: Authorization,
    /// The retrieve-metadata challenge token.
    pub challenge_token: String,
    /// The backup id (derived from the root key).
    pub backup_id: String,
}

/// Response body for the keypair challenge endpoints.
#[derive(Debug, Deserialize)]
pub(super) struct ChallengeResponse {
    /// Base64-encoded 32-byte random challenge to sign.
    pub challenge: String,
    /// Opaque challenge token echoed back on the follow-up request.
    pub token: String,
}

/// Response body for `POST /v1/delete-factor`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeleteFactorResponse {
    /// Whether removing the factor deleted the entire backup (last main factor).
    pub backup_deleted: bool,
    /// The refreshed metadata, absent when the backup was deleted.
    pub backup_metadata: Option<BackupMetadata>,
}

/// Error body returned by the backup service on a non-2xx response.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct ServiceErrorBody {
    /// The machine-readable error code and message.
    pub error: ServiceErrorObject,
}

/// The `error` object within [`ServiceErrorBody`].
#[derive(Debug, Deserialize)]
pub(super) struct ServiceErrorObject {
    /// Machine-readable error code, e.g. `factor_not_found`, `unauthorized_factor`.
    pub code: String,
}
