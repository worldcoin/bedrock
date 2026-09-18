# Backup migration: design

This is the overall design to migrate all logic related to the new login (prev. backup & restore) logic to Bedrock. This document outlines the whole plan. **Breaking changes** are introduced by design, we're removing all the old stuff. The plan is made to one-shot all functionality into Bedrock in one pass (multiple PRs, single release).

## Structure

```text
Native UI / account lifecycle
  └─ BackupManager                  only public backup flow object
       ├─ BackupServiceClient       private HTTP, challenges, attestation, wire types
       ├─ TurnkeyApiClient          private activities, sessions, polling, policies
       ├─ manifest + backup_format private file inventory, packing, validation
       └─ migrations               existing plan/apply functions
```

The Native App implements the following:

1. Calls Bedrock's `BackupManager` to perform all operations on the backup.
2. **Trait**. `MainFactorCeremonyHandler` allows Bedrock to trigger passkey or OIDC ceremonies.
3. **Trait**. `P256Signer` so native handles keychain & Secure Enclave key management.
4. **Trait**. Attestation, app backend HTTP client.

## Important Flows

1. **Logging in**.
   - Native calls `BackupManager::login()` which executes the Main Factor log in, backup retrieval, decryption, and all validations, the root secret is given back to Native for storage.
   - Native stores the `root_secret` in the keychain.
   - Native calls `BackupManager::finalize_login()` to finalize the execution of the login. The decrypted backup files get fully unpacked and the new `SyncFactor` is registered.

   > **Rationale**: Both native and Bedrock need to perform sequential operations to log in. A separate `finalize_login` is more concurrency-safe than callback traits which could have re-entrancy or deadlocks.
2. **Checking for updates**. Native calls `check_for_remote_updates` once after startup initialization. If the `RemoteAhead` error shows up, native shows the screen to prompt for an update download. Native must define the priority for this blocking screen.
3. **Initializing `BackupManager`**. The provided root key is consumed to compute and cache the `backupAccountId`. On a `login()`, this is derived automatically, no need to call `init()` again. Native MUST treat this as a unique signer, there must not be multiple signers at the same time (i.e. single `SyncFactor` at any time).

## Public surface

```rust
pub use backup_service_types::{BackupStatusResponse, OidcProvider}; // Remote UniFFI bindings.

#[derive(uniffi::Object)]
pub struct BackupManager {
    account_id: Option<String>,
    sync_signer: Option<P256Signer>,
    main_factor_ceremony: MainFactorCeremonyHandler,
    // Private clients, one operation mutex, and an optional pending recovery; never a root key.
}

#[bedrock_export]
impl BackupManager {
    #[uniffi::constructor]
    pub fn new(main_factor_ceremony: MainFactorCeremonyHandler) -> Self;
    /// Initializes once a backup is available. Derives the account ID, and retains the device signer.
    pub fn init(root: SiegelSession, sync: P256Signer);

    /// Returns available factor kinds without device authorization; None means no backup exists.
    pub async fn status() -> Option<BackupStatusResponse>;
    // Retrieves the backup metadata, does not enforce the RemoteStaleAhead gate.
    pub async fn metadata() -> BackupMetadata;
    // Separate from metadata() because metadata is needed to render the factor list
    pub async fn check_for_remote_updates();
    pub async fn list_files_in_backup(designator: BackupFileDesignator)
        -> Vec<String>;
    pub async fn sync(root: SiegelSession, encryption_public_key: String,
                  changes: Vec<BackupFileChange>);

    // Return the backup encryption public key for native to persist and supply on sync.
    pub async fn create(factor: FactorRegistration, root: SiegelSession,
                     files: Vec<BackupFileChange>) -> String;
    // Fetches the backup, decrypts it and stages retrieved files. Operations are read-only or staged changes.
    pub async fn login(authentication: FactorAuthentication, sync_factor: P256Signer,
                   purpose: RetrievalPurpose, expected_backup_id: Option<String>)
        -> RetrievedBackup;
    // Executes the login. Enroll the Sync Factor, removes staged files, and commit the restored manifest.
    pub async fn finalize_login(recovery_id: String);
    // Abandons a login before committing (opposite to `finalize_login`). Generally only expected on the edge case
    // of saving the root secret failing.
    pub fn cancel_login(recovery_id: String);
    // Authorize and register a new `SyncFactor`.
    pub async fn reauthorize(login: FactorAuthentication, sync: P256Signer);

    pub async fn add_factor(factor: FactorRegistration, existing: FactorAuthentication)
        -> BackupMetadata;
    pub async fn remove_factor(id: String, reauth: Option<FactorAuthentication>,
                           confirm_backup_deletion: bool)
        -> RemoveFactorOutcome;
    // Clear local backup state, optionally revoking the bound device key first.
    pub async fn logout();
    pub async fn delete_backup();
    // Performs the backup full `/reset`. Used when a user loses access to all their Main Factors.
    pub async fn reset(root: SiegelSession);
    pub async fn run_migrations(reauth: Option<FactorAuthentication>)
        -> TurnkeyMigrationOutcome;
}

/// Configuration for enrolling a Main Factor
#[derive(uniffi::Enum)]
pub enum FactorRegistration {
    Passkey { username: Option<String>, wallet_address: String },
    Oidc { provider: OidcProvider },
}

/// Initialize a login with a specific type of Main Factor
#[derive(uniffi::Enum)]
pub enum FactorAuthentication {
    Passkey,
    Oidc { provider: OidcProvider },
    IcloudKeychain { key_id: String },
}
#[derive(uniffi::Enum)]
pub enum RetrievalPurpose { Login, DownloadUpdates }

#[derive(uniffi::Record)]
pub struct RetrievedBackup {
    pub recovery_id: String,
    pub root_secret: SiegelSession,
    pub backup_keypair_public_key: String,
    pub files: Vec<RetrievedFile>,
    pub metadata: BackupMetadata,
    pub requires_app_update: bool,
}
#[derive(uniffi::Record)]
pub struct RetrievedFile {
    pub designator: BackupFileDesignator,
    pub path: String,
    pub staged_path: String,
}
```

1. Primarily reusing service types from the `backup-service` crate (e.g. `OidcProvider`).
2. File changes in the backup are declared atomically through the `BackupFileChange` enum (i.e. multiple changes can be carried out in a single `sync` call).
3. `status` requires an initialized account and calls public `/v1/backup/status` with the cached account ID. Reuse the service response and its nested `ExportedFactorSlim` through remote UniFFI bindings so native can distinguish supported login factors from unsupported-only backups. Only backup-not-found maps to `None`; this does not report device authorization or sync health.
4. All network failures are explicitly handled, either retried if appropriate or an error propagates. A network error never translates into a defined result (e.g. in `status` a network error is an error, not an `Ok(None)`).
5. Whenever performing backup `sync`s (or device authorization), Bedrock compares the local manifest hash and verified encryption public key with their corresponding remote values. If either differs, sync is blocked and native must prompt the user to download and restore the remote backup.

## Native callbacks and secrets

```rust
/// Enables Bedrock to trigger passkey or OIDC authentication or set up, i.e. a factor ceremony.
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait MainFactorCeremonyHandler: Send + Sync {
    async fn create_passkey(options_json: String) -> PasskeyResponse;
    async fn authenticate_passkey(options_json: String) -> PasskeyResponse;
    async fn oidc_token(provider: OidcProvider, nonce: String) -> SiegelSession;
    async fn authenticate_icloud(key_id: String) -> SiegelSession;
}

#[derive(uniffi::Record)]
pub struct PasskeyResponse {
    pub credential_json: String,
    pub prf: Option<SiegelSession>,
    pub legacy_prf: Option<SiegelSession>,
}
```

1. Options and credential JSON are WebAuthn wire objects. Bedrock builds all of them, including passkey name.
2. When a user selects a factor to use in the UI, Native calls `login()` or `reauthorize()`. Bedrock will then craft the passkey/OIDC request and trigger it through `MainFactorCeremonyHandler`. Native must update the UI after the user selects the factor (e.g. disabled buttons, loading state), and then handle the presentation of OIDC login screen (or dismissal on error). Importantly, these methods MUST NOT callback into Bedrock.
3. Bedrock computes the passkey name for consistency. The passkey name will be "World ID App MMM DD HH::MM", dropping the username/wallet address.
4. Bedrock configures the passkey RP (`keys.world.app`) and the PRF salt (`world-app-backup`). Bedrock will handle Android's legacy second-salt derivation when the primary cannot unwrap the backup key. This will also log a `critical!` error to track for migration.
5. No changes to `P256Signer` (native signs arbitrary digest outputs).

## Local state and concurrency

1. Store all backup information under `backup_manager/<account_id_segment>/` where `account_id_segment` is the `backup_account_id mod 2^8` to both segment the backup information and avoid collisions from state clearing issues (e.g. at logout), but also to avoid logging the `backup_account_id` accidentally.
2. Importantly, all state from `BackupManager` is local per client. It is not shared between clients (i.e. World ID App and World Money App).
3. With the introduction of these changes, migrate files from their current location on first app run (atomically with staged files). The migration must validate the local state with the remote state before executing or raise a `RemoteAhead` error.
4. Any mutation on the backup state is done through a concurrency lock. Concurrent calls error with `Busy`. Native must generally not perform concurrent updates on the backup.
5. `logout` revokes the `SyncFactor` from both the backup-service and Turnkey, then clears up all of Bedrock's local state (manifest, staged files, etc.). Native must then clear the `SyncFactor` from the secure storage.

## Backup Content Management

1. Syncing the backup (i.e. adding, removing or replacing any file) follows this pattern. Importantly, multiple updates must be batched together:
  ```
  Oxide file change / WalletKit vault change / referral change
  → native backup adapter prepares one batch
  → native asks to materialize the vault export if needed (WalletKit)
  → BackupManager.sync(..., changes) -> Bedrock will read the bytes from the filesystem from the `path` of each `V0BackupFile`
  → native deletes temporary exports (e.g. WalletKit vault)
  ```
  - If an unsupported `designator` is found in a remote backup, it is skipped and an `UpdateRequired` error is surfaced. This usually signals that a new type of file has been added to the backup that this client does not recognize.
  - If the specific designator has been marked for retirement, then the file is actually removed.
2. **Major Change**. Before this update, the `path` in `V0BackupFile` determined both the **source** of the file that was added to the backup **and the destination** where it would be unpacked. With this update now, the `path` will no longer determine where the file gets unpacked to. This is for both security and increased resilience. Instead, unpacking the backup will work as follows:
  ```
  Native calls BackupManager.login(...)
  → Bedrock retrieves and decrypts the backup
  → Bedrock validates the archive and unpacks data into isolated staging files validating checksum and size (archive keys never become destination paths)
  → Bedrock returns the root secret and staged file paths
  → native securely stores the root for a new login
  → native routes file paths to Oxide / WalletKit / referral consumers
  → consumers validate their keys and contents before any live data changes (e.g. Oxide checks for a valid PCP)
  → consumers import into their own storage, choosing their own destinations
  → native calls BackupManager.finalize_login(...)
  → Bedrock registers the sync factor and acknowledges the restored inventory
  → Bedrock removes disposable staging; native reloads consumers and completes login
  ```
  - The above permits each module to determine integrity of their recovery (e.g. WalletKit can ensure a correct credential vault, or Oxide a correct PCP). Malicious, corrupted or fake files are not persisted and cannot replace other files in the filesystem.
3. **Oxide changes:** add backup validation/import operations for orb, document, and face packages. Oxide validates its own keys, package formats, and identity bindings, then chooses destinations within its owned storage. Import must resume safely with the same  recovery ID; native should only invoke these operations and reload Oxide afterward.
4. Explicit limits on backup sizes and unpacking: 15 MiB sealed, 32 MiB per entry, 128 MiB expanded, and 128 entries.

## Other Notes

1. Rename `RemoteStaleAhead` to `RemoteAhead` errors everywhere.
2. Add a `last_used_date` property to main and sync factors in the `backup-service` to track the last used date. Any auth with such factor updates the date. This is useful to remove stale sync factors and surface `MainFactor` usage information to the user.
3. All sensitive secrets/tokens (e.g. OIDC tokens, unwrapped keys, PRF output, ...) are zeroized after use. All are handled only in `Siegel` sessions or `secrecy` boxes. Root secrets in particular MUST never linger in-memory, they are one-time used from their retrieval from the keychain.
4. **High Impact**. Different native clients (i.e. World Money and World ID App) MUST NOT use the same `SyncFactor`s. Each must be authorized independently. When opening the other client for the first time, the user will be prompted to authorize their new client. This not only ensures proper key separation, but also ensures the user has access to their Main Factors.


## Future Improvements
1. Log in reminders.
2. Introduce flow to delete legacy iCloud / Google Drive backup.
2. Introduce a `V1BackupFile` enum and replace `path` with a proper `entry_id`.
3. Backup authentication.
