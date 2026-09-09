# Backup migration: design

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
    main_factor_ceremony: MainFactorCeremony,
    // Private clients, one operation mutex, and an optional pending recovery; never a root key.
}

impl BackupManager {
    fn new(main_factor_ceremony: MainFactorCeremony) -> Self;
    // Initializes the BackupManager for a specific backup. Derives the account ID and stores it.
    // Separate from `new` because login can initialize the manager before there's a root secret.
    fn bind(root: SiegelSession);
    // Adopt native backup state only after its account, encryption key, and head match.
    async fn adopt_existing_backup(sync: P256Signer, encryption_public_key: String,
                                    turnkey_sync_user_id: Option<String>);

    async fn has_backup() -> bool;
    // Retrieves the backup metadata, does not enforce the RemoteAhead gate.
    async fn metadata(sync: P256Signer) -> BackupMetadata;
    // Separate from metadata() because metadata is needed to render the factor list
    async fn check_for_remote_updates(sync: P256Signer);
    async fn list_files_in_backup(sync: P256Signer, designator: BackupFileDesignator)
        -> Vec<String>;
    async fn sync(root: SiegelSession, sync: P256Signer, changes: Vec<BackupFileChange>);

    async fn create(factor: FactorRegistration, root: SiegelSession,
                     sync: P256Signer, files: Vec<BackupFileChange>);
    // Stage validated files; only Login returns the root, and registration waits for completion.
    async fn recover(login: FactorAuthentication, mode: RecoveryMode,
                      expected_backup_id: Option<String>) -> RecoveredBackup;
    // Acknowledge required native restore work, then enroll the signer and publish staged state.
    async fn complete_recovery(recovery_id: String, sync: P256Signer,
                                reauth: Option<FactorAuthentication>,
                                replace_device: Option<String>)
        -> TurnkeyStatus;
    // Cancel before registration; native blocks cancellation once ReplaceLocal import starts.
    fn cancel_recovery(recovery_id: String);
    // Authorize device access without importing files or returning a root.
    async fn reauthorize(login: FactorAuthentication, sync: P256Signer,
                          replace_device: Option<String>) -> TurnkeyStatus;

    async fn add_factor(factor: FactorRegistration, existing: FactorAuthentication,
                         sync: P256Signer) -> BackupMetadata;
    async fn remove_factor(id: String, sync: P256Signer,
                            reauth: Option<FactorAuthentication>, confirm_backup_deletion: bool)
        -> RemoveFactorOutcome;
    // Processes app logout: clears local backup state and unregisters the supplied Sync Factor.
    async fn logout(sync: Option<P256Signer>);
    async fn delete_backup(sync: P256Signer) -> TurnkeyStatus;
    // Performs the backup full `/reset`
    async fn reset(root: SiegelSession) -> TurnkeyStatus;
    async fn run_migrations(sync: P256Signer, reauth: Option<FactorAuthentication>)
        -> TurnkeyMigrationOutcome;
    // Read cached public metadata for offline cross-app handoff.
    fn cross_app_metadata() -> CrossAppBackupMetadata;
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
enum TurnkeyStatus { Complete, Incomplete }

struct RecoveredBackup {
    recovery_id: String,
    root: Option<SiegelSession>,
    files: Vec<RecoveredFile>,
    metadata: BackupMetadata,
    requires_app_update: bool,
}
struct RecoveredFile { designator: BackupFileDesignator, path: String, staged_path: String }
struct CrossAppBackupMetadata {
    backup_keypair_public_key: String,
    turnkey_sync_user_id: Option<String>,
}
```

Reuse service types at the wire boundary and expose the shared `OidcProvider` through UniFFI.
`FactorRegistration` and `FactorAuthentication` are ceremony inputs; wire `Authorization` contains
completed proofs, and registered-factor metadata requires fields unavailable before authentication.
Keep those roles distinct; [shared type wiring](execution.md#shared-type-wiring) defines reuse and
compilation checks.

File changes are `Put { designator, path }`, `Remove { path }`, and `ReplaceFiles { designator,
paths }`. `ReplaceFiles` replaces that designator's inventory, not unrelated files.
`list_files_in_backup` is used by the Oxide bridge and returns only installed, accepted paths
after the same remote-head check as sync. Remove/ReplaceFiles change inventory, not wallet
files; removing an absent path is a no-op. Put/ReplaceFiles validate the same file policy before
filesystem access or packing.

`RemoveFactorOutcome` keeps its two existing meanings; attach `TurnkeyStatus` to each so a committed
removal with failed Turnkey cleanup cannot appear fully cleaned up. Preserve the existing
`TurnkeyMigrationOutcome`: Completed or MainFactorRequired with description-valued pending entries;
failures remain Result errors. Extend `BackupOperationError` with `UpdateRequired`, `RemoteAhead`,
`CommitUncertain`, `Busy`, `RecoveryPending { recovery_id: String, mode: RecoveryMode }`, `Capacity
{ factors: Vec<BackupFactor> }`, and `Cancelled`. Keep existing reauth/confirmation failures:
rejected/missing sync keys map to `NeedsReauth(SyncFactorInvalid)`, never a network retry. Use
`NeedsReauth(BackupKeyUnverified)` when adopting metadata whose encryption key is not yet verified.
Invalid local state or malformed archives use one contextual local-data error; do not export
internal transport/codec error enums. `has_backup` requires binding and calls public
`/v1/backup/status` with the cached account ID; it reports remote existence, not sync health.
Network failure is an error, never `false`. Add optional `last_used_at` to the existing
BackupFactor, from service metadata. Capacity UI shows creation/last-active dates and the
current-device marker.

Native calls `check_for_remote_updates` once after startup binding/adoption. Bedrock compares
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

`bind` consumes the root once, derives `backup_account_<compressed secp256k1 public key>`, and drops
it. A second bind may only confirm the same ID; account switching destroys the manager.
Create/recover/reset can establish the binding themselves. Other account operations require it; an
unbound call returns the contextual local-state error. Recovery derives/binds the ID internally
before the one-use Login root handoff; native does not call bind again with that consumed handle.
Root arguments to sync/reset/create must match an existing binding before any mutation. The public
key for break-glass registration is already encoded in that ID; migration needs no root.

Root, OIDC tokens, PRF, unwrapped backup keys, and ephemeral Turnkey session keys are zeroized when
no longer needed. Pending recovery may hold its five-minute main session and one-use sync token in
memory until completion/cancellation/expiry; a deadline wipes them even if native never finishes
recovery. Neither is persisted. The root is never retained by the manager. Root is supplied
explicitly for sync and reset; there is no root-provider callback. The local backup encryption
**public** key is persisted by Bedrock with the manifest, not in a second native account record.

During Login, Bedrock decrypts the existing root secret from the backup and returns it to native for
wallet restoration and secure storage. That needs a one-use Rust → native transfer through Siegel;
its current bridge only supports native → Rust. Bedrock does not generate a new root. ReplaceLocal
and ResumeSync keep the recovered root inside Bedrock.

## Local state and concurrency

Persist under `backup_manager/<account_id>/`: acknowledged manifest/public key/compatibility, a
pending manifest for an upload whose outcome is unresolved, and any staged recovery.
`adopt_existing_backup` is the one-time upgrade/import flow: after bind, native passes its existing
encryption public key and signer. Check authenticated metadata ID against the binding, the public
key against the verified remote key, and the old global manifest hash against the remote head;
atomically adopt the inventory/public key, then remove the old manifest. The legacy manifest has no
account field: do not pretend otherwise. If the old manifest is absent, initialize only when the
remote inventory is canonically empty. Otherwise preserve all old state, return `RemoteAhead`, and
disable writes until explicit recovery; never auto-overwrite or guess a candidate from files alone.

Android cross-app transport retains its existing `BackupSyncData` format and imported-from-peer
marker; changing that contract belongs to the separate handoff rollout. `CrossAppBackupMetadata` is
only the two public fields needed to populate that existing wire format, not another account object;
`cross_app_metadata` reads local state only, preserving offline handoff. Cache the optional
current-key Turnkey user ID after registration/reconciliation and seed it from native metadata
during adoption. It is not authority for remote operations. None means no known mapping; only the
legacy wire adapter handles its existing null/empty representation. The receiver uses
`adopt_existing_backup` with the imported signer/public key. Today's handoff has no manifest: a
fresh receiver of a nonempty backup must complete a main-factor `ReplaceLocal` recovery before
syncing, with confirmation because transferred local data may differ. Retain its imported data and
key while blocked; do not treat deprecated Drive upload callbacks as inventory. Remove duplicate
native runtime account state, but do not remove this wire DTO or its decoder until the separate
cross-app/hardware rollout supplies a replacement.

One manager per active account. A concurrent mutation returns `Busy`; no unbounded queue or
background debounce. The native file adapter batches one logical change and may retry Busy once
after the active call finishes, using fresh exports; otherwise return a visible unsynced result. An
on-disk recovery returns RecoveryPending, not Busy. Startup with a persisted root binds but returns
that error with ID/mode; native surfaces resume/cancel before enabling backup mutations. Before
Login has transferred/persisted a root, restart resumes through recover, without calling bind. Only
completion/cancel/resume may mutate pending recovery. Do not time-expire staged data that may
already have been imported into the vault; explicit cancellation follows the flow contract. Reads do
not observe half-published state. This does not replace backup-service's remote conditional writes;
another device is a real concurrent writer.

`logout(Some(sync))` revokes this device and clears Bedrock's manifest/staging state and binding.
`logout(None)` clears only that local state; Android uses its existing imported-key marker to select
this path, and native local-reset callers use it too. Wallet files and native keys remain
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
