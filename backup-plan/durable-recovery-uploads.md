# Durable recovery uploads and pending edits on iOS and Android

**Status:** Proposed

**Updated:** 2026-10-14

## TLDR

The [resumable restore proposal](https://github.com/worldcoin/bedrock/pull/478)
explains how to finish an interrupted restore safely. This proposal covers what
happens next: uploading later edits without losing them when an upload is
interrupted or finishes after another edit.

Bedrock remembers the acknowledged backup and one pending encrypted upload. Mobile
clients separately persist which local revisions still need backing up. Each upload
uses a fixed snapshot and acknowledges only its captured revisions. Newer edits stay
queued across crashes. Restore finishes before normal editing and uploading resume.
Both platforms use this contract with their existing storage and job systems.

## Scope and foundations

Follow the backup migration [design](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/design.md)
and [flows](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/flows.md).
`BackupManager` owns service calls, archive validation, hashes, encryption, remote
checks, and recovery. Mobile clients own data revisions, snapshots, scheduling,
secure storage, and UI. World ID and World Money retain separate client state and
independently authorized signers on both platforms.

Use the proposed `BackupManager.sync` interface. No second ciphertext queue,
mobile-client manifest hashing, upload-status endpoint, or automatic merge is needed.
`finalize_login` acknowledges downloaded inventory; it does not upload. Account
activity and uploads remain gated until recovery and local completion finish.

This proposal requires one change to the [Bedrock backup migration design](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/design.md)
and its [detailed backup flows](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/flows.md): condition uploads on a unique archive revision as well as hash/key. This needs Bedrock and backup-service agreement before
implementation. All new behavior here is proposed; the archive format and
cryptographic construction remain unchanged.

Existing foundations:

- iOS [BackupSyncCoordinator](https://github.com/worldcoin/world-app-ios/blob/0924c2d15835e442c7a9b7680a28e2df24c50d8f/Sources/WorldAppCrypto/Sources/WLDBedrock/BackupSyncCoordinator.swift)
  already serializes vault, Oxide, and referral backup writes, prepares vault exports,
  and retains recovery/deletion markers. Extend it and reuse JobScheduling.
- Android [BackupRecoveryState](https://github.com/worldcoin/wld-android/blob/bdaee7d29ace9d4c1b79b76cb938b7ad88ad1ded/bedrockSdk/src/main/java/com/worldcoin/bedrockSdk/backupManifest/BackupRecoveryState.kt)
  blocks writes during restore. Its [vault coordinator](https://github.com/worldcoin/wld-android/blob/bdaee7d29ace9d4c1b79b76cb938b7ad88ad1ded/walletKit/impl/src/main/java/com/world/walletkit/impl/CredentialVaultBackupSyncCoordinator.kt)
  keeps follow-up state in memory; replace that source of truth and retain WorkManager.
- Android's [referral store](https://github.com/worldcoin/wld-android/blob/bdaee7d29ace9d4c1b79b76cb938b7ad88ad1ded/data/src/main/java/com/worldcoin/data/worldId/credentialPresentation/backup/ThirdPartyReferralsInitialBackupStore.kt)
  clears only a matching persistent generation. Reuse that semantic, but require
  atomic data/revision commits rather than separate asynchronous preferences writes.
  Its [worker](https://github.com/worldcoin/wld-android/blob/bdaee7d29ace9d4c1b79b76cb938b7ad88ad1ded/data/src/main/java/com/worldcoin/data/worldId/credentialPresentation/backup/ThirdPartyReferralsBackupWorker.kt)
  already retains pending intent after retry exhaustion.

Sources are pinned in those links. The [Bedrock backup migration design](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/design.md) was read at
`92709b74b0ad9583839252ce97500a393c763c72`; the restore proposal at
`2cb68af780f1eb0e850b5e02b8124245ce320572`, checked on 2026-10-14.
These foundations do not establish that the proposed contracts have shipped.

## Prevent stale remote writes

Hash/key equality cannot distinguish an old publication from a later one with the
same contents. If A-to-B is delayed while another client publishes A-to-C-to-A,
the old B can pass a hash-only check and overwrite the later decision.

Require a non-repeating **archive revision** on every archive publication, including
recreation of a deleted backup. The immutable selected-object identifier can serve
as the revision if old identifiers are never republished. Factor-only updates retain
it. Creation keeps the absent-account precondition and retry protocol in the
[detailed backup flows](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/flows.md), and assigns a fresh revision on publication.

Read revision, manifest hash, key, and selected-object pointer as one authenticated
metadata tuple. Upload a new immutable object, then conditionally publish its pointer,
hash, key, and revision together against the expected previous revision/hash/key.
Failure leaves the selected backup readable. Object cleanup must preserve selected
objects and objects still being read.

Metadata/authentication failures propagate; they do not imply a missing or divergent
backup. Bedrock reconciles a pending candidate before accepting another batch:

- Remote content hash/key matches the candidate: acknowledge equivalent data and
  persist the observed revision. This proves the data is backed up, not which request
  published it.
- Remote matches the exact previous revision/hash/key: retry the saved ciphertext
  against that same precondition, then confirm the result.
- Otherwise: retain the candidate and return `RemoteAhead`.

Ordinary remote checks also compare the acknowledged revision. Equal contents alone
cannot silently rebase a client without a pending candidate. Each new sync checks
again before conditional publication. One previous revision authorizes at most one
publication, although transport retries and unselected objects may repeat.

The [detailed backup flows](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/flows.md)
currently specify hash/key checks only. Add revision fields and
client support compatibly, then require revision checks for **every admitted writer**,
including legacy requests. Keep rollout blocked if a supported writer can bypass the
check. Reader compatibility and writer admission are separate requirements.

For legacy local state, validate its hash/key against one authenticated tuple before
persisting the initial acknowledged revision and removing the legacy copy. Never
invent the prior revision of an uncertain upload: acknowledge equivalent remote
candidate data, or retain it and require recovery instead of replaying an unfenced write.

## Persist uploaded state separately from edits

Bedrock privately persists the acknowledged manifest/key/revision, at most one encrypted
candidate and its expected previous tuple, and recovery/unsupported-inventory state.
Use the migration's installation-key-derived account namespace. Mobile clients never
parse these private files.

Flush candidate bytes before publishing their durable pending record, and persist that
record before dispatch. Atomically persist acknowledgement before deleting the candidate.
Flush replacement state and required directory metadata. Interrupted cleanup cannot
create a new upload; missing, truncated, or unreadable candidate bytes require repair.

Each data owner persists data, desired entry inventory, stable IDs, account/client
binding, store incarnation, export-format version, and two monotonic revisions:

- `current_revision` advances with every committed backup-relevant mutation, including
  deletion and export-format changes.
- `uploaded_revision` identifies the latest revision covered by a successful snapshot
  or confirmed matching recovery baseline.

Require `0 <= uploaded_revision <= current_revision`; reject overflow or inconsistent
state. A larger current revision means pending work. The queue represents the latest
desired contents, including removals, rather than every historical user action.

Commit data, inventory, and revision together before returning mutation success.
Schedule afterward. A crash before enqueue leaves discoverable pending work. WalletKit
needs transactional revisions; Oxide and referrals need equivalent guarantees. Where
transactions are insufficient, publish immutable data and its revision through one
durable active-generation record. A separate dirty flag or job payload is insufficient.

If owner data is shared between app clients, keep uploaded checkpoints separate per
client. One client's success cannot clear another's pending work.

Acknowledgement uses the owner's same serialization boundary, verifies account/client/
incarnation, and advances only the captured revision. It never rewrites data or resets
`current_revision`. Bookkeeping is local-only and excluded from exports and imports.

Protect and version all coordination state; exclude it from OS backups and cross-app
transfer. Unknown schema versions block writing until a compatible build is available. Locked, corrupt, unreadable,
or unexpectedly missing metadata must not become clean/empty state.

## Capture a complete, immutable snapshot

One coordinator owns the manager and serializes every state-changing call per client,
including create, reauthorization, factor removal, recovery, and teardown. Hold this
lane across awaits and acknowledgements. A Swift actor alone is insufficient; neither
a second process nor another adapter may independently write the same manager state.

Under a short producer barrier, drain active commits and capture vault, Oxide, and
referral revisions, IDs, and immutable bytes together. Release the barrier before
network work so later edits can proceed. Cover extension/other-process writers through
the store's interprocess boundary or one owning process, not an in-memory lock alone.

Lock order is lane, producer barrier, then owner snapshots in a documented order.
Producers notify scheduling after releasing owner locks and never await the lane.
Consumer and ceremony callbacks must not reenter the coordinator.

An owner returns its complete desired inventory, revision/incarnation, and immutable
sources from one committed state. Legitimately empty is explicit. Locked, uninitialized,
corrupt, incomplete, or unsupported data fails preparation; it never implies deletion.
Build changes against Bedrock's acknowledged entry IDs:

- `Put` every retained entry, including unchanged files.
- Remove only explicit desired deletions. Missing files are errors.
- Use `ReplaceFiles` only for a wholly owned designator. Update only this client's
  referral entry; Bedrock retains the other platform's bytes.
- Apply retirement and conditional cleanup explicitly. A skipped checksum-conditional
  removal cannot acknowledge a local deletion.

Deleting the last credential must export a valid empty vault or an explicit removal.
Unsupported inventory blocks rewrites with `UpdateRequired`, including retirement-only
writes. Stable IDs come from the owner catalog, never temporary paths.

Repeated exports of an unchanged revision must reproduce identical bytes and IDs across
restarts and source relocation. Version serialization changes and advance the revision
before upload admission; block partial migrations and incompatible binaries. WalletKit's
[SQLite export](https://github.com/worldcoin/walletkit/blob/aac0e59c286e85b3e4a9706f2a4e5653c769f9b6/crates/walletkit-sqlite/src/cipher.rs)
uses `CREATE TABLE ... AS SELECT *`, which alone proves neither stable ordering nor
identical bytes. Prove or implement deterministic exports within the supported format;
do not replace Bedrock checksums with logical hashes.

Prepare fresh vault exports and immutable copies or pinned generations for every retained
source. Keep them unchanged until the underlying Bedrock call finishes. Enforce limits
while materializing and validating: 15 MiB sealed, 32 MiB per entry, 128 MiB expanded,
128 entries. Exceeding limits fails the batch; never trim contents.

Use protected, backup-excluded, client-private export storage. Allow one owned snapshot
directory per client; clean its abandoned predecessor before creating another. Failed
cleanup defers new materialization and surfaces a storage error. Never remove unknown
or live-owned directories or recovery staging. Bedrock's encrypted candidate, not these
plaintext exports, is the durable retry input.

## Upload and acknowledge

```text
run_upload_pass(account, client):
    hold the coordinator lane through completion
    on exit: finish underlying call, attempt export cleanup, release lane
    require readable state, ready account, and no recovery/teardown
    sync(fresh_root_session, promoted_key, changes = [])
    // Reconcile a saved candidate and validate the remote head.
    // This alone acknowledges no new mobile-client revision.
    if no owner is pending: return

    snapshot = capture_complete_snapshot_under_producer_barrier()
    changes = build_changes_from_acknowledged_inventory(snapshot)
    sync(fresh_root_session, promoted_key, changes)

    for each represented owner:
        verify account/client and captured owner incarnation
        persist uploaded_revision = max(uploaded_revision, captured_revision)

    if pending work remains: schedule one coalesced successor
```

Each call consumes a fresh one-use root session and uses the initialized manager's
signer and promoted encryption key.

Reconcile before calculating deletions because an older candidate can change the
acknowledged inventory. The real sync rechecks remote state, so another client's update
between calls cannot authorize a stale snapshot.

Only success of the captured snapshot's call advances its revisions, including a checked
no-op. Empty reconciliation, skipped exports, disabled backup, and generic worker success
do not. A complete snapshot whose explicit desired inventory is already empty may
legitimately have no changes; that checked snapshot can acknowledge its empty state.

For example, an upload captures vault revision 12, then the user commits 13. Success
advances uploaded revision to 12; 13 remains pending. If one owner's acknowledgement
fails after another commits, retain the remaining debt. The next pass still supplies a
complete snapshot; unchanged content is a no-op.

Caller cancellation must not release the lane or exports while Rust still reads or
mutates them. The coordinator awaits actual underlying completion/termination even if
the UI stops waiting. Network calls have bounded deadlines; timeout does not prove a
server write stopped. Retain Bedrock's candidate and original precondition. Cleanup
failures are surfaced and retried without undoing confirmed success or clearing debt.

Crash rules:

- Before an owner commit: old data/revision remain. After commit but before enqueue:
  startup discovers pending work.
- During snapshotting or before candidate persistence: rebuild from durable owner
  data; empty reconciliation cannot acknowledge the abandoned snapshot.
- After candidate persistence or an uncertain response: resolve those saved encrypted
  bytes before any fresh batch. Never reseal the unresolved candidate.
- After remote/Bedrock success but before all owner acknowledgements: debt remains.
  Reconcile and recapture; unchanged bytes produce no new publication, newer edits
  produce the next snapshot.

## Finish recovery before uploading edits

Keep the account gate closed throughout imports and completion. Extend each consumer's
transactional recovery receipt with its imported incarnation/revision and baseline result:

1. Import data and receipt together with current revision 1, uploaded revision 0,
   and comparison `unknown`. Initialize these once: retries reuse the same recovery
   ID, receipt, and incarnation without resetting revisions or reimporting completed data.
2. While staging exists, compare the owner's complete export with its validated staged
   inventory, including IDs, sizes, and checksums. Save `match` or `changed` against
   that receipt/revision. Failure or interruption remains `unknown`; successful import
   or logical equality alone cannot prove a match.
3. `finalize_login` acknowledges the archive revision saved with the downloaded
   inventory. Never substitute a revision from a later metadata fetch.
4. After confirmed finalization, set uploaded revision to 1 only for `match`; leave
   `unknown`/`changed` at 0. Persist results, promote the verified key/signer, reload
   consumers, clear the recovery journal, then open the gate.

Invalid contents, failed imports, unreadable/incomplete stores, or failed reloads still
block recovery completion. `unknown` means byte equality is unproven; it does not waive
consumer validation or readiness.

A completion failure retains the journal for idempotent retry. If staging was already
deleted, retain `unknown`; do not reimport or download different input to compare it.
After recovery, normal sync makes matching bytes a no-op and uploads transformed bytes
once. Do not silently carry forward the legacy Android merge-on-import queue.

On `RemoteAhead`, retain debt/candidate, stop uploads, and request `DownloadUpdates`.
Otherwise-ready account use may continue until recovery closes the account gate.
Replacement requires explicit confirmation that unsynced edits will be discarded.
Drain producers and uploads first. Each replacement commits with its receipt and a fresh
incarnation; retire the superseded queue/candidate only after recovery completes.
Pre-import failure or cancellation preserves the existing queue. Never replay an old
incarnation onto the replacement. Confirmed replacement or account-data deletion is the
explicit exception to preserving pending edits.

`UpdateRequired` retains debt. Installing an update alone does not clear Bedrock's
persisted unsupported-inventory block; a completed `DownloadUpdates` must do so.

## Scheduling and account lifecycle

Reuse JobScheduling/WorkManager as wakeups, with one running pass and one coalesced
successor per client. Preserve edits arriving between the worker's final debt check and
job completion: `KEEP` alone can lose that wakeup. Use a successor-capable handoff and
recheck durable debt under the scheduling boundary. Surface enqueue failures; durable
scans repair them.

Scan after initialization, recovery, creation, reauthorization, and foreground,
connectivity, or unlock events. After creation confirms its initial complete archive,
run the normal sync pass before acknowledging revisions: a retried `create` may confirm
an older candidate rather than the latest snapshot.

End each pass after one new snapshot. Use bounded scheduler retries and exponential
backoff with jitter where supported; exhaustion retains debt. `Busy` waits for the
owning operation. Authentication, `RemoteAhead`, `UpdateRequired`, storage locks,
corruption, and full disk wait for their specific remedy rather than busy retry loops.

Serialize logout, delete/reset, signer promotion, and account switching with the same
lane. Close producer admission and drain work before teardown. Keep acknowledgements
inside the lane and bind callbacks to account/client/incarnation. Delegate remote
operations and candidate retirement to Bedrock. Timeout cannot clear debt, and a stale
worker cannot recreate a deleted backup. Disabling backup preserves local pending work;
future creation/re-enablement includes current complete contents. Account teardown
clears only that account's bookkeeping with its owned data under existing policy.

Show pending changes, uploading, up to date, or action required. Claim up to date only
after Bedrock reconciliation, captured acknowledgements, and a fresh pending-work check.
Recovery completion alone does not establish that later edits are backed up.

## Delivery and compatibility

Implementation order and ownership:

1. **Backup-service and Bedrock:** agree and implement archive-revision checks, compatible
   writer admission, safe object publication, durable candidate reconciliation, and
   empty/unchanged sync behavior through Swift and Kotlin bindings.
2. **WalletKit, Oxide, and referral owners:** implement atomic mutation/revision commits,
   acknowledgements, deterministic complete exports, and immutable snapshots. Verify
   file/directory flush support; extend the injected filesystem contract if necessary.
3. **Recovery integration:** add receipt comparisons, downloaded archive revisions,
   replacement incarnations, and replayable completion to the companion proposal.
4. **Mobile clients:** adapt iOS `BackupSyncCoordinator`; replace Android's in-memory
   follow-up source of truth and integrate referral generations. Wire the common lane,
   barrier, worker handoff, scans, and UI. iOS uses injected `WLDFileSystem` and its
   migration-aware accessors for all file I/O. Retain existing recovery markers until
   a valid migration establishes completion.
5. **Cutover:** audit every producer, SDK write, extension, deletion, and background
   path. Any bypass of revision commits or the barrier blocks activation. Switch all
   stateful backup callers together per client after dependencies pass; old and new
   writers cannot share manifest ownership. Platforms can cut over independently.

These are required capabilities, not claims about existing component APIs. At migration,
freeze legacy writers, validate the remote baseline, and initialize readable existing
owner data conservatively pending. Do not infer deletion from missing metadata or an
uninitialized owner. Run a complete checked snapshot before claiming clean.

Preserve V0 schema, archived IDs, and supported consumer payloads. Older readers use
archived paths as live destinations; stable but invented IDs can still break them.
Moving export/staging files must not change archived identifiers. Serialization changes
must remain readable by supported old clients; new formats/IDs need a separate decision.
Test actual old/new archives in both directions on iOS and Android. Revisions, receipts,
and journals stay out of exports.

Use the migration's disabled-by-default admission gate and existing configuration
adapters. iOS uses `WLDDynamicConfiguration`, Statsig naming rules, and live-key
validation. Disabling admission must preserve saved recovery, candidate reconciliation,
and revision debt. Ramp per client only after its checks pass. Rollback requires a
compatible reader/writer of saved state; an incompatible legacy writer is not a fallback.
If resume breaks, preserve state and ship a compatible fix.

Implementation needs GUARD-02/03 approval, plus GUARD-01/05/06 review where secrets,
exports, or service/dependency contracts change. Update TFH backup
`structure-and-sync`, `flows`, and `components` during adoption, preserving flow anchors
and labelling unreleased behavior.

## Verification and operation

Use existing Rust, Swift, and Kotlin test conventions. Required release coverage:

- **Durability:** inject failure before/after owner commit, candidate persistence,
  remote commit, Bedrock acknowledgement, and each owner acknowledgement. Recreate
  state after process death; verify surviving data, exact next action, and publication
  count. Include edit-before-enqueue and partial owner acknowledgement.
- **Concurrent edits:** pause N, commit N+1 or last-item deletion, then finish N.
  Preserve N+1 through restart and retry exhaustion. Test complete snapshots across
  owners, extension/process writes, immutable sources, explicit empties/removals,
  unsupported entries, missing sources, and size limits.
- **Remote races:** lose responses; interleave another client's update; exercise
  A-to-B delayed behind A-to-C-to-A and deletion/recreation. Reject stale revisions
  for every admitted writer. Verify factor-only updates preserve archive revision
  and cleanup preserves selected/in-use objects.
- **Replay and formats:** unchanged snapshots create no new publication across restarts
  and path changes. Test SQLite ordering, metadata, empty vaults, import/export, and
  serialization upgrades with durable revision advancement, interrupted migration,
  and incompatible binaries. Legacy uploads without a known prior revision must not
  be replayed blindly.
- **Recovery:** interrupt baseline comparison, finalization, and local completion.
  Unknown/transformed contents remain pending; matched baselines need no new publication.
  Repeated recovery must not reset revisions; invalid or unreadable stores still block.
  Change remote state during restore and retain the downloaded revision. Cancel before
  replacement or complete it; verify preservation or deliberate retirement of old debt.
- **Lifecycle and scheduling:** lose a creation response, edit, and retry. Cancel while
  Rust still reads sources. Race an edit with worker completion, and queue old callbacks
  across account/store changes. Preserve source lifetime, successor work, and bindings.
- **Storage:** exercise locks, full disk, corrupt/missing metadata, unknown schemas,
  enqueue failure, and repeated cleanup failure. Never report empty success or accumulate
  plaintext copies; leave recovery staging untouched.
- **Compatibility:** run creation, edits, deletions, retries, and restore in both mobile
  directions, including other-platform referrals and separate app signers. Use actual
  installed bindings and supported old/new readers; verify restored contents and paths,
  not only archive decoding. Disable admission and verify saved work can finish.

Mocks prove coordination; real-store fault injection proves atomicity and snapshot
consistency. Service tests prove conditional publication and replay. Manual termination
is smoke coverage. No runtime implementation or runtime test result is claimed here.

Use Datadog for pending owners/age, pass outcomes, reconciliations/no-ops, retries,
blocked reasons, and cleanup failures, with bounded platform/app/owner/failure dimensions.
Keep random correlation IDs in low-volume traces/events, not metric tags. Never log
account/entry IDs, paths, sensitive-content hashes, roots/handles, tokens, or plaintext.
Alert on sustained sync failure and growing pending age, excluding known user blocks;
choose thresholds during internal validation before rollout.
