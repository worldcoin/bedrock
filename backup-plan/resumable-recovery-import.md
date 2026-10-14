# Resumable recovery import on iOS and Android

**Status:** Proposed

**Updated:** 2026-10-14

## TLDR

The main idea is to treat restore as one operation we can resume, instead of
starting over after a crash. The mobile clients save the recovery ID, the device
signer, references to the staged backup files, and the current step.

Each component imports its data and saves a completion receipt together. If the
app crashes after WalletKit finishes but before Oxide does, we skip WalletKit
and continue Oxide using the same staged backup. We don't download a newer backup
halfway through or create another device key on retry.

Until every import finishes, account activity and uploads stay paused. The mobile
client then completes login, calls Bedrock's `finalize_login`, reloads the stores,
and opens the account. If finalization's response is lost, we retry it with the
same recovery ID.

That prevents a partial restore from becoming a usable account or overwriting
the cloud backup. It builds on the Bedrock plan, with the same recovery contract
for iOS and Android.

## Scope

This follows the [Bedrock backup migration architecture](https://github.com/worldcoin/bedrock/pull/443).
It covers factor-based recovery (`Login`) and replacement from a remote backup
(`DownloadUpdates`). Legacy local-file and cloud-file recovery remain separate.
Normal edits and upload retries after recovery are outside this proposal.

Both platforms use the same contract. Each app client has its own recovery ID,
staging, and device signer. Another device or app cannot continue its attempt.

## Current behavior

- iOS decrypts and unpacks before restoring the credential vault. Its
  [vault restoration helper](https://github.com/worldcoin/world-app-ios/blob/main/Sources/WorldAppLegacy/Sources/AccountRecovery/Core/AccountManagementService/AccountManagementService.swift)
  logs an import failure and continues login. Its
  [vault worker](https://github.com/worldcoin/world-app-ios/blob/main/Sources/WorldAppLegacy/Sources/JobScheduling/JobSchedulingService/Workers/CredentialVaultBackupWorker.swift)
  and [Oxide adapter](https://github.com/worldcoin/world-app-ios/blob/main/Sources/WorldAppLegacy/Sources/OxideWrapper/OxideBackupManager.swift)
  also have direct legacy backup paths.
- Android's durable
  [`restore_pending` marker](https://github.com/worldcoin/wld-android/blob/main/bedrockSdk/src/main/java/com/worldcoin/bedrockSdk/backupManifest/BackupRecoveryState.kt)
  blocks backup mutations after an interrupted restore. It lacks an attempt ID,
  input identity, receipts, and a complete resume protocol. Its
  [credential recovery path](https://github.com/worldcoin/wld-android/blob/main/walletKit/impl/src/main/java/com/world/walletkit/impl/recovery/DefaultRecoveredWorldIdCredentialStorageService.kt)
  can schedule backup work.

The new flow replaces these recovery paths. Every backup writer must respect
its gates before the flow is enabled.

## Ownership and account gate

Bedrock owns archive validation, staging, pending recovery, device registration,
the acknowledged inventory, and its `RecoveryPending` sync gate.

WalletKit, Oxide, and referral storage own their imports and receipts.
Each platform owns a RecoveryCoordinator, its journal, secure storage, UI,
account login, and startup integration.

Before retrieval, persist a bootstrap record and close the account gate.
Stop new producers and workers. Drain existing account, storage, and backup
operations before touching restored data.

While recovery is active:

- Block normal account UI, credential generation, referral writes, and exports.
- Keep queued jobs pending. Wake them after completion, without busy retry loops.
- Route logout, reset, deletion, account switching, and additional restores
  through the coordinator. Before import they can request cancellation.
  After import starts they wait for completion.
- Allow the coordinator to perform recovery operations.

Startup checks the journal before enabling account services. Locked, corrupt,
or unreadable state blocks safely. A stored root alone does not establish account
readiness. Accept a missing journal only when storage is readable and the owning
stores report no inconsistent pending recovery.

## Persist the attempt

Before calling `login`, save the purpose, expected account when known,
authentication method, and persisted candidate signer reference.
After an interrupted retrieval, reuse that signer and purpose.

The adopted binding must preserve pending-recovery context on failed
`login`: recovery ID, purpose, and candidate public key, alongside the original
error. Read it through Bedrock's own persistence. Mobile clients must not parse
its private files. Match it to the bootstrap record before acting. For initialized accounts,
the architecture's `init` flow returns the ID and purpose through `RecoveryPending`.

This handles a crash after Bedrock stages data but before the mobile client receives its
ID. If retry reports `RemoteAhead`, use the pending ID to cancel the old attempt.
No root or consumer data has changed yet. Only then start another retrieval.
Unreadable pending context retains the bootstrap record and blocks safely.

After `login` returns, atomically save:

- Recovery ID, authenticated account, purpose, and candidate signer reference.
- The returned encryption public key, for promotion after finalization.
- Each supported file's designator, entry ID, relative staging reference,
  checksum, and size. Compute checksums and sizes from the validated staged files;
  the returned descriptors do not expose those fields.
- A digest of that descriptor set. Bedrock owns the full archive inventory.
- Phase: `prepared`, `import_started`, `client_login_complete`, or `finalized`.
- Cancellation intent, when requested.

Save this before writing the root or importing data. Retain the original staged
references so restart does not require another download midway through import.
Resolve them inside the attempt's durable staging area. Reject invalid paths
and symlinks. Verify bytes against the saved size and checksum.

Journal writes must be atomic and durable. Keep journal and staging in protected
app-private storage, excluded from OS backups and cross-app transfer.
Never put roots, tokens, PRF outputs, or private keys in the journal or telemetry.
Consumer receipts stay local, are excluded from exports and incoming imports,
and are cleared with their owning account data.

## Root handoff

For `Login`, save the root and its account/recovery binding in one secure-store
value. A separate root marker would create another crash window.
Preserve existing access controls and compatible root handling.

On restart, a matching readable root proves handoff completed. If it is missing
while still `prepared`, repeat authenticated `login` with the same account and
candidate. If a fresh attempt is required, cancel and clean up the old one first.

For `DownloadUpdates`, keep the existing root. Discard the returned root handle.
Require the same account and explicit confirmation that remote replacement may
discard unsynced local data.

Locked storage waits for unlock. Missing, corrupt, or mismatched root storage
after import starts is a repair condition. Restore a missing/damaged root only
if authenticated recovery proves the same account and attempt. Never overwrite
another account's root. If safe repair is unavailable, retain state and offer
support.

Permanent loss of roots, staging, or consumer storage is distinct from ordinary
process interruption. Do not silently replace lost input or generate an identity.

## Import and finish

Preflight all supported input before changing any consumer. Validate keys,
identity, format, entry IDs, contents, and destinations. Storage-capacity checks
are advisory; commits must handle later storage failures.

Unknown designators follow Bedrock's `requires_app_update` policy.
They remain in its inventory and block sync. An unsupported format within a
known consumer blocks import before any changes. Do not finalize that attempt.

Persist `import_started` before the first live mutation. From then on, complete
the attempt rather than cancel it.

Each consumer uses a serial, durable import operation:

- Check its receipt first. A matching receipt means success, even if a
  `Login` vault is now nonempty. Different account/input under the same ID is an error.
- Without a receipt, require an empty onboarding store for `Login`.
  For `DownloadUpdates`, apply the confirmed replacement.
- Commit data and receipt together. Bind the receipt to the recovery ID,
  account, entry IDs, and input digest.
- Handle absent supported data explicitly. Replacement clears stale data in
  that owner's backup scope, with a receipt for an empty replacement.
  Preserve unrelated settings and other owners' data.

WalletKit uses a vault database transaction. Oxide uses its existing safe storage
mechanisms. If insufficient, prepare an immutable generation and publish its
data and receipt through one durable active-generation record. Write all files
durably before publication; retain the old generation until completion.
Referral storage commits its owned entry and receipt together and preserves
other namespace data, including the other platform's entry.

There is no transaction across consumers. A failed consumer retains staging and
completed receipts. Retry every required owner; receipts identify finished work.
The account gate hides the temporary inconsistency between stores.

After all imports succeed, the mobile client completes account login for `Login`.
Reconcile an existing session against the expected account on retry.
Persist `client_login_complete`, then call `finalize_login`.

A lost response retries finalization with the same ID and signer.
Staging may already be deleted; do not reopen or reimport it in this phase.
Bedrock's idempotent finalization determines the outcome.

After confirmed finalization, persist `finalized`. Promote the saved signer and
encryption public key idempotently. Reload all consumer caches.
Failures retain the journal and retry these local steps.
Clear the journal durably before reopening the account gate.
Normal `RemoteAhead` and `UpdateRequired` checks still govern sync.

## Cancellation

Before import, persist cancellation intent. Let a running `login` resolve.
Cancel any returned pending attempt. Clean up bootstrap state only after
establishing that no pending attempt exists.

Retry `cancel_login` after `Busy` or a temporary failure.
If it returns `RecoveryPending`, clear cancellation intent durably and resume
completion. Never loop indefinitely trying to cancel it.

Only confirmed cancellation permits cleanup:

- `Login`: remove this attempt's unpublished root, onboarding data,
  session, and candidate key.
- `DownloadUpdates`: preserve the existing account, root, signer, and stores.
  Remove only attempt bookkeeping and a distinct attempt-only candidate.

Retain cancellation state until idempotent cleanup completes.
A crash retries cancellation and unfinished cleanup before account use.

## Work ordering and dependencies

These are proposed work items. No new tickets have been filed.

1. <a id="bedrock-work"></a>**Bedrock adoption and bindings.** Adopt the planned pending recovery,
   finalization, sync gate, and required error context.
   Depends on the existing service migration being deployed compatibly.
2. <a id="walletkit-work"></a>**WalletKit import.** Add transactional receipts and replacement/retry behavior.
3. <a id="oxide-work"></a>**Oxide import.** Add safe commits and durable receipts using existing storage.
4. <a id="referral-work"></a>**Referral import.** Add owned-data receipts. This can be a mobile integration subtask.
5. <a id="mobile-work"></a>**Mobile integration.** Implement the coordinator, startup/lifecycle gates,
   secure storage, cancellation, completion, and Statsig wiring separately on
   iOS and Android. Depends on
   [Bedrock](#bedrock-work), [WalletKit](#walletkit-work),
   [Oxide](#oxide-work), and [referral work](#referral-work).
   Remove best-effort import success and gate every legacy writer.
6. **Validation and rollout.** Depends on each platform's completed [integration](#mobile-work)
   and tested component contracts. Enable each platform only after its own checks pass.

Shared work and mobile scaffolding can proceed in parallel.
On Android, retain old `restore_pending` blocking until the old flow reconciles it
or validated attempt data supports migration. A marker cannot invent a recovery ID.

## Rollout and rollback

Use a Statsig gate, disabled by default, to admit new attempts.
Use each platform's existing configuration adapter. On iOS, this is
`WLDDynamicConfiguration`; follow the
[configuration guidance](https://github.com/worldcoin/world-app-ios/blob/main/Documentation/StatsigConfigurationGuidelines.md).

A saved attempt takes precedence over the gate, including when Statsig is
unavailable. Resume and safe cancellation must remain available.

<!-- Rollout suggestion: test internally, then use a small production cohort.
Expand only after completion, failure, and unfinished-attempt metrics are acceptable. -->

Disable the gate to stop new attempts during a regression.
If resume itself is broken, ship a compatible fix for existing attempts.
Preserve their journal, receipts, and staging while users wait.

A rollback build must understand existing recovery state and retain its resume
path. Never erase state or route an unfinished attempt into legacy recovery.

## User flows

- Normal restore: authenticate, show “Restoring your account,” then open the account.
- Relaunch: show “Finishing your restore” and continue the same input.
  Authenticate only if a remaining step requires it.
- Offline after import: retain progress and show Retry. Account access waits
  for finalization.
- Cancel before import: clean up, then return to onboarding or the unchanged account.
- Leave after import starts: resume on reopening; leaving does not cancel.
- Cloud backup changes: finish the original import. Later sync prompts a separate
  DownloadUpdates flow if needed.
- Unsupported consumer format: offer Update before changing stores.
  Revalidate the pending input after upgrading.
- Unknown designator: restore supported data, but explain the backup-sync update
  requirement. Upgrading alone does not clear it.
- Locked storage or full disk: explain the action needed, then Retry.
- Permanent storage damage: offer support and retain the blocked attempt.
  Do not offer destructive reset as ordinary recovery.

## Verification

Add tests for both mobile clients with existing mocks and injectable storage.
The new coordinator and receipt APIs are implemented alongside these tests.

- Inject storage, import, and network errors. Check pending state survives,
  finalization does not run early, and uploads remain blocked. Remove the
  error and retry.
- Recreate the coordinator from retained test storage or seeded checkpoints.
  Check the next step, receipt handling, and unchanged ID, signer, and input.
- Return finalization success after a simulated uncertain result.
  Check there is no second import and promotion/reload completes.
- Supply invalid input, mismatched receipts, or missing staged files.
  Check completion blocks without empty success or a new identity.
- Test cancellation success, refusal, temporary failure, and partial cleanup.
  Check DownloadUpdates preserves the existing account.
- Exercise workers and account-lifecycle actions while pending.
  Check they respect the gate. Disable Statsig admission and verify resume still works.
- On staging accounts, disconnect, terminate the app during visible restore,
  reopen, and reconnect. Count the run only if pending recovery was retained.

Existing foundations:
[iOS file-system stubs](https://github.com/worldcoin/world-app-ios/blob/main/Sources/WorldAppCore/Sources/WLDFileSystem/MockWLDFileSystem.swift),
[iOS root-storage tests](https://github.com/worldcoin/world-app-ios/blob/main/Sources/WorldAppCrypto/Tests/LocalWalletBackupTests/LiveLocalWalletBackupStoreTests.swift),
[Android vault recovery tests](https://github.com/worldcoin/wld-android/blob/main/walletKit/impl/src/test/java/com/world/walletkit/impl/CredentialVaultBackupServiceImplTest.kt),
[Android restore tests](https://github.com/worldcoin/wld-android/blob/main/domain/src/test/kotlin/com/worldcoin/domain/backup/v2/usecase/RestoreBackupViaPasskeyTest.kt).

Before rollout, consumer dependencies must pass real-store commit-failure,
receipt-consistency, and repeated-import tests.
[WalletKit's rollback test](https://github.com/worldcoin/walletkit/blob/main/crates/walletkit-core/src/storage/credential_vault/merge.rs)
is an existing pattern to extend.

Follow-up coverage requires additional support:

- Exact pause/kill points around persistence, imports, cancellation, and finalization.
  Include Bedrock staging committed before the mobile client receives the ID.
- Process death inside actual WalletKit/Oxide transactions.
- Service commit followed by a dropped response; verify registration/eviction
  happens once. Also change the cloud backup during a paused import.
- Controlled device storage-lock and exhaustion tests.

Mocks of mobile-client dependencies prove coordination, not disk durability or service idempotency.
Manual interruption gives smoke coverage, not every crash boundary.
Storage and service implementations retain responsibility for their guarantees.

Use existing Datadog telemetry for phases, consumers, purpose, bounded failure
classes, retries, and a local random correlation ID. Measure completion and
unfinished attempts. Do not log secrets, account IDs, paths, or backup contents.
Avoid automatic retry loops for authentication and storage corruption.

Implementation requires explicit GUARD-02 and GUARD-03 review, plus GUARD-01
review of root handoff.

## Architecture references

- [Bedrock backup migration design](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/design.md)
- [Bedrock recovery flows](https://github.com/worldcoin/bedrock/blob/pdc/plan-backup-migration/backup-plan/flows.md)
