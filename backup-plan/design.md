# Backup migration: design

This is the overall design to migrate all logic related to the new login (prev. backup & restore) logic to Bedrock. This document outlines the whole plan. **Breaking changes** are introduced by design. This plan is designed so that all functionality can be incorporated into Bedrock in one pass (multiple PRs, single release), including removing all the legacy functionality where Bedrock exposed low-level utility functions.

## Ownership

```text
Native UI / account lifecycle
  └─ BackupManager                  only public backup flow object
       ├─ BackupServiceClient       private HTTP, challenges, attestation, wire types
       ├─ TurnkeyApiClient          private activities, sessions, polling, policies
       ├─ manifest + backup_format private file inventory, packing, validation
       └─ migrations               existing plan/apply functions

Native implements: MainFactorCeremony + existing P256Signer
Existing shared bridges: authenticated app-backend HTTP, attestation, filesystem
```

## Public surface

```rust
pub use backup_service_types::OidcProvider;

struct BackupManager {
    account_id: Option<String>,
    sync_signer: Option<P256Signer>,
    main_factor_ceremony: MainFactorCeremony,
    // Private clients, one operation mutex, and an optional pending recovery; never a root key.
}

impl BackupManager {
    fn new(main_factor_ceremony: MainFactorCeremony) -> Self;
    // Derive the account ID, release the root, and retain the device signer.
    fn bind(root: SiegelSession, sync: P256Signer);

    async fn has_backup() -> bool;
    // Retrieves the backup metadata, does not enforce the RemoteAhead gate.
    async fn metadata() -> BackupMetadata;
    // Separate from metadata() because metadata is needed to render the factor list
    async fn check_for_remote_updates();
    async fn list_files_in_backup(designator: BackupFileDesignator)
        -> Vec<String>;
    async fn sync(root: SiegelSession, encryption_public_key: String,
                  changes: Vec<BackupFileChange>);

    // Return the backup encryption public key for native to persist and supply on sync.
    async fn create(factor: FactorRegistration, root: SiegelSession,
                     files: Vec<BackupFileChange>) -> String;
    // Stage validated files; only Login mode returns the root.
    async fn login(authentication: FactorAuthentication, sync_factor: P256Signer, mode: RecoveryMode,
                      expected_backup_id: Option<String>) -> RecoveredBackup;
    // Enroll the signer, install staged files, and commit the restored manifest.
    async fn finalize_login(recovery_id: String,
                                reauth: Option<FactorAuthentication>,
                                replace_device: Option<String>);
    // Cancel before registration; native blocks cancellation once ReplaceLocal import starts.
    fn cancel_recovery(recovery_id: String);
    // Authorize device access without importing files or returning a root.
    async fn reauthorize(login: FactorAuthentication,
                          replace_device: Option<String>);

    async fn add_factor(factor: FactorRegistration, existing: FactorAuthentication)
        -> BackupMetadata;
    async fn remove_factor(id: String, reauth: Option<FactorAuthentication>,
                           confirm_backup_deletion: bool)
        -> RemoveFactorOutcome;
    // Clear local backup state, optionally revoking the bound device key first.
    async fn logout(revoke_device: bool);
    async fn delete_backup();
    // Performs the backup full `/reset`
    async fn reset(root: SiegelSession);
    async fn run_migrations(reauth: Option<FactorAuthentication>)
        -> TurnkeyMigrationOutcome;
}

/// Configuration for enrolling a Main Factor
enum FactorRegistration {
    Passkey { name: String, display_name: String },
    Oidc { provider: OidcProvider },
}

/// Initialize a login with a specific type of Main Factor
enum FactorAuthentication {
    Passkey,
    Oidc { provider: OidcProvider },
    IcloudKeychain { key_id: String },
}
enum RecoveryMode { Login, ReplaceLocal, ResumeSync }

struct RecoveredBackup {
    recovery_id: String,
    root: Option<SiegelSession>,
    backup_keypair_public_key: String,
    files: Vec<RecoveredFile>,
    metadata: BackupMetadata,
    requires_app_update: bool,
}
struct RecoveredFile { designator: BackupFileDesignator, path: String, staged_path: String }
```

Primarily reusing service types from the `backup-service` crate and expose the shared `OidcProvider` through UniFFI so
native can do relevant high-level calls. The internal `backup_service_types::Authorization` contains
completed proofs.

File changes in the bcakup are declared as `Put { designator, path }`, `Remove { path }`, and `ReplaceFiles { designator,
paths }`. `list_files_in_backup` is used by the Oxide bridge and returns files in the backup,
after checking the remote state is in sync. Remove/ReplaceFiles changes the backup inventory, it does not change the actual
files; removing an absent path is a no-op. Put/ReplaceFiles validate the same file policy before
filesystem access or packing.

`RemoveFactorOutcome` keeps its two existing meanings. Bedrock logs secondary registration and
remote cleanup failures internally; they do not change a committed operation's native result.
Primary operation failures and actionable local-state errors still propagate. Preserve the existing
`TurnkeyMigrationOutcome`: Completed or MainFactorRequired with description-valued pending entries;
failures remain Result errors. Extend `BackupOperationError` with `UpdateRequired`, `RemoteAhead`,
`CommitUncertain`, `Busy`, `RecoveryPending { recovery_id: String, mode: RecoveryMode }`, `Capacity
{ factors: Vec<BackupFactor> }`, and `Cancelled`. Keep existing reauth/confirmation failures:
rejected/missing sync keys map to `NeedsReauth(SyncFactorInvalid)`, never a network retry. Use
`NeedsReauth(BackupKeyUnverified)` when existing metadata has no verified encryption public key.
Invalid local state or malformed archives use one contextual local-data error; do not export
internal transport/codec error enums. `has_backup` requires binding and calls public
`/v1/backup/status` with the cached account ID; it reports remote existence, not sync health.
Network failure is an error, never `false`. Add optional `last_used_at` to the existing
BackupFactor, from service metadata. Capacity UI shows creation/last-active dates and the
current-device marker.

Native calls `check_for_remote_updates` once after startup binding. Bedrock compares
authenticated metadata with its acknowledged head and returns `RemoteAhead` or `UpdateRequired` when
recovery is needed. Network/authentication failure preserves local state. Reuse this head check in
sync and file queries; `metadata` remains available for factor management while sync is blocked.
Native controls the prompt.

A head check compares both the manifest hash and `BackupMetadata.encryption_public_key`. The key is
immutable for one backup; recreating the same account and file inventory can change it. Recovery
verifies it against the unwrapped key. Reauthorization never silently replaces a cached key: a
mismatch requires explicit recovery. Existing metadata without this field needs main-factor key
unwrapping; initialize it through the existing main-authorized sync-registration flow, without an
archive import. Never infer it from an old native key just because manifest hashes match.

## Native callbacks and secrets

```rust
/// Enables Bedrock to trigger passkey or OIDC authentication or set up, i.e. a factor ceremony.
trait MainFactorCeremony {
    async fn register_passkey(options_json: String) -> PasskeyResponse;
    async fn authenticate_passkey(options_json: String) -> PasskeyResponse;
    async fn oidc_token(provider: OidcProvider, nonce: String) -> SiegelSession;
    async fn icloud_factor(key_id: String) -> SiegelSession;
}
struct PasskeyResponse {
    credential_json: String,
    prf: Option<SiegelSession>,
    legacy_prf: Option<SiegelSession>,
}
```

Options and credential JSON are WebAuthn wire objects, not new native domain models. Bedrock
constructs options, nonce bindings, and Turnkey stamps; native only invokes the OS/provider. Native
supplies localized passkey name/display-name strings for create/add; Bedrock maps its existing
configured OS into the service platform field, preserving Android's registration path. Bedrock
generates and retains a per-attempt UUID for creation's `sessionId` body field, matching iOS's
existing semantics. The authenticated HTTP bridge supplies identity, not that UUID. The response
JSON excludes PRF results. Request PRF only when unwrapping/wrapping a backup key. Registration
requires a usable PRF before any remote backup commit. Cancellation maps to the existing operation
error enum; callback exceptions never unwind across FFI.

Use `keys.world.app` and the current `world-app-backup` PRF salt. Preserve Android's legacy
second-salt derivation and try its result only when the primary cannot unwrap the backup key. New
factors use only the primary salt. Bedrock chooses the fallback; native returns requested results.

`P256Signer` stays the reusable hardware boundary: compressed SEC1 public key; sign an already
hashed 32-byte digest; DER ECDSA output, normalized in Bedrock. Never ask for its private key. Keep
existing key-storage compatibility until the separate hardware rollout. Verify a replacement key is
usable before removing the old value.

`bind(root, sync)` consumes the root, derives the account ID, and retains the signer capability.
Normal startup and creation bind with the available root. Login takes the persisted pending signer
directly, derives the account ID from the validated recovered root, and retains the signer for
finalization; no preliminary bind is needed. Subsequent flows use the stored signer. Neither bind
nor login registers a key; login registration waits for finalization.
Reset derives/checks the account ID from its root and needs neither prior binding nor a signer.
Local-only `logout(false)` also needs neither signer nor account. Create requires prior binding;
Login mode can establish the account itself. Other account operations require an ID;
signer-using operations also require a bound signer. Missing state is a contextual local-state
error. Root arguments must match an existing ID before any mutation. The break-glass public key is
already encoded in that ID.

A signer instance always identifies one fixed key; native must not implement it as a mutable
"current key" lookup. Same-account rebinding may replace the signer while idle. Preserve an
unresolved sync manifest so the new signer can reconcile its outcome after authorization. Binding
cannot switch accounts, change a key during a mutation, or replace the key of an unresolved
creation/authorization/recovery. Login enforces the same account/key replacement restrictions as
bind. After restart native passes the same persisted pending key to login for recovery, or to bind
with the root for creation/reauthorization. Bedrock checks it against the pending operation's key
before resuming. Account
switching destroys the manager. Recovery establishes the ID before the one-use Login root handoff;
no second root transfer to bind is needed. Logout and successful backup deletion/reset release the
signer together with the account binding. Native owns key storage and erasure; retaining the
callback does not export the private key.

Root, OIDC tokens, PRF, unwrapped backup keys, and ephemeral Turnkey session keys are zeroized when
no longer needed. Pending recovery may hold its five-minute main session and one-use sync token in
memory until completion/cancellation/expiry; a deadline wipes them even if native never finishes
recovery. Neither is persisted. The root is never retained by the manager. Root is supplied
explicitly for sync and reset; there is no root-provider callback. Native keeps the backup
encryption **public** key in its existing store and passes it to every `sync`. Creation returns
that key; recovery returns it with the staged result, and native promotes it after completion.
Bedrock records the verified key with its acknowledged manifest for consistency checks. Before
sealing a sync, the supplied key must match that record and authenticated remote metadata; a
mismatch fails without uploading. Supplying a key cannot initialize a missing verified remote key.

During Login, Bedrock decrypts the existing root secret from the backup and returns it to native for
wallet restoration and secure storage. That needs a one-use Rust → native transfer through Siegel;
its current bridge only supports native → Rust. Bedrock does not generate a new root. ReplaceLocal
and ResumeSync keep the recovered root inside Bedrock.

## Local state and concurrency

Persist under `backup_manager/<account_id>/`: acknowledged manifest/public key/compatibility, a
pending manifest for an upload whose outcome is unresolved, and any staged recovery.
Bedrock already owns the global manifest. Migrate it internally on the first authenticated state
load: check the remote account ID against the binding and the old manifest hash against the remote
head, then record the verified remote encryption public key with the inventory before removing the
old manifest. Missing verified remote keys require reauthorization as above. The old manifest has no
account field. If it is absent, initialize only when the remote inventory is canonically empty.
Otherwise preserve existing state, return `RemoteAhead`, and block writes until explicit recovery.
Native keeps its existing encryption public key and supplies it to sync; no public adoption call.

Android cross-app transport reads the device key and backup encryption public key from native
storage and retains the imported-from-peer marker. Remove the cached Turnkey sync-user ID from
`BackupSyncData` and its native consumers; Bedrock resolves the user from the authenticated signer
when needed. Handoff needs no BackupManager getter or separate metadata object. The receiver binds
normally, retains the imported public key for sync, and uses the startup head check. Today's handoff
has no manifest: a fresh receiver of a nonempty backup must complete a main-factor `ReplaceLocal`
recovery before
syncing, with confirmation because transferred local data may differ. Retain its imported data and
key while blocked; do not treat deprecated Drive upload callbacks as inventory. Remove duplicate
native runtime account state; retain the key transport DTO and decoder. Replacing shared keys with
separate hardware-backed keys remains a separate rollout.

One manager per active account. A concurrent mutation returns `Busy`; no unbounded queue or
background debounce. The native file adapter batches one logical change and may retry Busy once
after the active call finishes, using fresh exports; otherwise return a visible unsynced result. An
on-disk recovery returns RecoveryPending, not Busy. Startup with a persisted root restores the same
signer through bind. Binding installs the matching capability but reports RecoveryPending with
ID/mode; native surfaces resume/cancel before enabling mutations. Before Login has persisted a root,
restart resumes through login with the same persisted pending signer, without calling bind. Only
completion/cancel/resume may mutate pending recovery. Do not time-expire staged data that may
already have been imported into the vault; explicit cancellation follows the flow contract. Reads do
not observe half-published state. This does not replace backup-service's remote conditional writes;
another device is a real concurrent writer.

`logout(true)` revokes this device and clears Bedrock's manifest/staging state, signer, and account
binding. `logout(false)` clears only that local state; Android uses its existing imported-key marker
to select this path, and native local-reset callers use it too. Wallet files and native keys remain
native-owned. Share the private local-clear helper with delete/reset. The [logout
contract](flows.md#delete-reset-logout) defines ordering and errors.

## Restore file contract

Allow **designator + relative path**, in Bedrock code, from actual writers. No caller-supplied
directory wildcard and no allowlist inside the backup. Initial accepted paths:

| Designator | Paths relative to Bedrock data directory |
| --- | --- |
| `orb_pkg` | `<hex commitment>/pcp_packages/pcp_lookup_table.json`; same directory's `encrypted-package-*.dat` |
| `document_pkg` | `document-passport-v1.tar.gz.encrypted`; `document-personal-custody-<version>.tar.gz.encrypted` |
| `face_pkg` | `face_pcp/face-pcp-v<digits>.tar.gz` |
| `credential_vault` | `credential_vault/vault_export.bin` |
| `anonymized_third_party_analytics` | `third-party-requests.json`; `ThirdPartyReferrals/third-party-referrals.json` |

Bind dynamic segments to the existing Oxide filename grammar, with iOS and Android fixtures; `*`
above is a basename suffix, never a slash or directory escape. Recognize the observed optional `0x`
commitment prefix. Do not restrict document versions to the three iOS examples: Android already
accepts versions such as `mnc-1.0`. Unknown future names are unsupported, not automatically retired.

Both referral paths are legitimate and have different JSON schemas. Never rename one into the other
or translate fields speculatively. Install both into these fixed, private paths; each native store
reads only its own format. Sync preserves an unchanged foreign-platform file byte-for-byte. Referral
writers use `Put` for their own path, never `ReplaceFiles` for the entire designator.

The root/version tar entries are format fields, never filesystem destinations. Require exactly one
valid root and supported version. Reject links/special files, duplicate normalized or case-folded
paths, mismatched tar/CBOR paths, traversal, absolute paths, and symlink ancestors. Never write
`backup_manager/manifest.json` from archive contents. Validate all entries/checksums and limits
before publishing files; derive and compare the root's account ID with service metadata. Start with
the server's 15 MiB sealed-size cap, 32 MiB per tar entry, and 128 MiB expanded/4096 entries;
validate these against representative real fixtures before enabling enforcement.

Decode raw designator strings at the archive boundary; the public enum remains closed. Hash the
**full original inventory**, including unsupported/retired entries, with the existing V0 algorithm,
and persist that full inventory as acknowledged. Its hash is not the hash of the installed subset.
Change the existing internal V0BackupFile and V0BackupManifestEntry designator fields to String;
classify into the public enum only for accepted operations. No second raw-manifest DTO.

Classify entries as accepted, explicitly retired, or unsupported. Retirement rules live beside the
allowlist and initially contain no invented obsolete filenames. Remove a retired local file only
through a known owned path rule, never an arbitrary path from the old manifest. On next login,
install accepted entries and remove retired files; on next successful sync, drop retired entries
from the remote archive. Removing an allowlist entry alone means unsupported, not retirement.

`RecoveredBackup.requires_app_update` is true exactly when unsupported entries remain. Recovery
still returns supported data; completion persists `UpdateRequired` and blocks **all** archive
rewrites, including empty/retirement-only syncs. Startup checks report that persisted state even
when the remote head matches. Preserve the remote bytes. Clear the block only after a compatible
client downloads and validates the complete archive. This deliberately avoids an encrypted
opaque-entry cache. Native must show that backup updates are paused; recovering a wallet is not
evidence that its new changes are being backed up.
