# BackupManager flows

[design.md](design.md) defines ownership and the public API. This file explains operation order,
what success means, and what happens when an operation stops halfway through.

## `new()` and `init(root, sync)`

`new()` attaches the native ceremony handler. `init()` consumes the root to derive the account ID,
loads this client's local state, and retains its signer. Neither registers a remote factor.
Creation requires init; login derives the account ID itself.

A signer always refers to one fixed key. Init cannot replace an initialized account or signer;
use `reauthorize` to change the device key. Each native client has its own key and local state.
A newly opened client authorizes itself, even if another app already has access to the account.

Migrate the old manifest only after authenticated remote metadata confirms the account, manifest
hash, and encryption public key. Missing remote keys require main-factor verification before
accepting migrated state; a native cached key alone is not evidence. On disagreement, preserve the old state
and return `RemoteAhead`. An absent manifest is safe to initialize only for an empty remote backup.
The remote validation is asynchronous; complete it on first remote state access, before writes.

If recovery is pending, return its ID and purpose so native can resume it before enabling mutations.
A restart before the root was stored resumes through `login`, without init. The signer must match
that pending attempt. Switching accounts requires a new manager.

## Reading backup state

| Method | Meaning |
| --- | --- |
| `has_backup()` | Uses the cached account ID to check remote existence. A network failure is an error, never `false`. |
| `metadata()` | Returns authenticated factor information even when file sync is blocked. |
| `check_for_remote_updates()` | Compares the acknowledged manifest hash and encryption public key with remote metadata; also reports persisted `UpdateRequired`. Native calls it after startup init. |
| `list_files_in_backup(designator)` | Returns logical keys in that namespace, not filesystem destinations. Uses the same remote-state check before returning the inventory. |

`RemoteAhead` means native must offer a confirmed `DownloadUpdates` restore. `UpdateRequired`
means this client cannot understand the whole archive; updating the app alone does not clear it.
Only a subsequent compatible restore does. Neither error discards local data. Metadata remains
available to manage factors while file updates are paused.

## `create(factor, root, files)`

1. Verify the root matches the initialized account and that no backup already exists.
2. Run the selected factor ceremony. For passkeys, require a usable PRF result before any commit.
3. Build the complete initial backup from the supplied vault, Oxide, and referral exports.
4. Prove root ownership and possession of this client's sync key; create the remote backup.
5. Save the acknowledged manifest and encryption public key, then return that public key to native.

**Passkey:** create a passkey-only backup without a Turnkey organization.

**OIDC:** create the organization through the app backend. Set up the main user, sole-root quorum,
sync user/policy, and organization-delete-only break-glass user/policy; remove bootstrap authority.
Install the initial OIDC identity, including all Apple audiences, and import its factor secret
before committing the backup. Share this setup with OIDC addition and migrations.

Success includes the initial archive upload. Native must not mark backup enabled after factor
registration alone. Keep exported source files alive until the awaited call finishes.

**Interrupted creation:** persist one creation UUID before calling the backend. Reusing it must
resolve the same provisioning attempt. Record the exact provisional organization ID and pending
manifest before further remote writes. If the response is lost, authenticate with the pending sync
key and compare the remote manifest/public key. A matching commit is success; current absence does
not prove that an outstanding request will never commit. Preserve the key and organization while
uncertain. Do not retry with another UUID or delete provisional authority on a timeout.

## `login(authentication, sync_factor, purpose, expected_backup_id)`

Login prepares a restore; it does not register the sync factor or replace live data.

1. Authenticate with the chosen main factor using the [shared authentication rules](#authentication).
2. Retrieve the backup and check the expected/bound account before decryption or staging. Unwrap the
   backup key and validate the recovered root against that account.
3. Validate the complete archive using the format rules in design. Stage data entries under
   Bedrock-chosen filenames; archive keys never become filesystem destinations. Root/version
   entries are format metadata, not staged files.
4. Retain one pending recovery ID, purpose, original inventory, manifest hash, encryption public key,
   and sync public key. Return staged descriptors, metadata, and the root through Siegel.

| Purpose | Native work between `login` and `finalize_login` |
| --- | --- |
| `Login` | Signed-out onboarding with an empty vault. Store the root, import consumer data, and complete the native app-account login. |
| `DownloadUpdates` | Confirm replacement of unsynced data for the initialized account. Keep the existing native root, discard the returned root handle, and import the complete remote data. This is not a merge. |

Native routes descriptors to WalletKit, Oxide, and referral consumers. Each validates its own keys,
formats, identity bindings, and destinations. Validate all inputs before the first live import.
Consumers report unsupported and explicitly retired entries to Bedrock; unknown namespaces are
unsupported and remain internal, rather than being forced into the closed public designator enum.
Their reporting interface still needs to be reflected in the public stubs, as noted
under [interface decisions](#interface-decisions-to-finish).

An existing iCloud factor may recover the account; it cannot grant Turnkey main authority. If
Turnkey is unavailable, passkey/iCloud recovery can still succeed through backup-service. OIDC
recovery needs Turnkey to export its factor secret, so it fails when that dependency is unavailable.
Missing Turnkey authorization must not be reported as full device authorization.

**Interrupted login:** native persists the pending signer and recovery ID. Resume with that same
signer and ID; never generate a new key to bypass an unresolved attempt. Before native has imported
anything, a changed remote head requires a new validated attempt. Once replacement has begun,
finish that staged attempt rather than applying a new archive over it. Never reuse an import receipt
for different contents.

## `finalize_login(recovery_id)`

Native calls this only after every required consumer import and native login step succeeds.

1. Verify the pending recovery ID and native completion/classification results.
2. Register this client's signer using the [device registration rules](#device-registration).
3. Acknowledge the full restored inventory, verified encryption public key, and compatibility state.
   Persist `UpdateRequired` if unsupported entries remain.
4. Release temporary recovery authority and disposable staging. Preserve the other platform's
   referral entry in isolated storage for future syncs, as required by design.

Finalization **does not copy archive entries into live app storage**. WalletKit, Oxide, and referral
consumers already performed their imports. It makes that imported state the acknowledged backup
baseline; it does not upload a new backup.

Afterward native reloads Oxide and referral caches before showing completion. Keep the native
recovery ID until this finishes. If reload fails, retry it without importing or enrolling again.
Finalization with the same completed ID is idempotent, including after restart.

**Interrupted imports:** WalletKit's transactional `import_backup_once(bytes, recovery_id, replace)`
records a local completion receipt in the same transaction as the import. It enforces empty-only
Login or confirmed replacement; a failed transaction preserves the old vault. Receipts are local-only:
exclude them from exports and source imports, and clear them with the vault. Oxide and referral imports
must likewise resume safely using the same recovery ID.
There is no transaction spanning all consumers: retain staging and resume unfinished work before
allowing the app to use a partially restored account.

Expired authentication is reacquired through the stored `FactorAuthentication` and ceremony
handler, checking the same account again. There is no separate `reauth` argument. A short-lived
session or registration token stays in memory only and is wiped on expiry, even if native stalls.
Persist progress, never authentication secrets or a retained root.

## `cancel_login(recovery_id)`

Use this to abandon prepared recovery when native cannot proceed, such as failing to store the
root. Bedrock removes staging, clears the pending recovery, and releases temporary authority;
it does not roll back remote enrollment.

Before replacing existing consumer data for `DownloadUpdates`, native persists a completion-only
marker and disables cancellation. Only a definitely rolled-back import may reopen cancellation.
After sync registration starts, Bedrock also refuses cancellation: return `Busy` during the call or
`RecoveryPending` after interruption. Resume finalization with the retained signer.

After an allowed Login cancellation, native runs its onboarding reset: clear the newly stored root,
all imported consumer data, and any native login session created by that attempt.
Native persists cancellation intent before the call and keeps its recovery ID until both Bedrock
cancellation and native reset finish. Restart retries that sequence; cancellation is idempotent for
an already-cancelled attempt, and native cleanup never proceeds after a refused cancellation.
Cancelling DownloadUpdates must not clear the existing account. Do not cancel by dropping an active
mutation future, or log out midway through consumer replacement.

## `reauthorize(authentication, sync)`

Use this when an existing native account needs a newly authorized client key. Native persists a
fresh pending signer and passes it directly; the current signer remains active until replacement
is confirmed.

Authenticate the main factor, check the initialized account and encryption-key identity, and
register the candidate key. Install it in the manager only after confirmed backup-service enrollment;
native then marks it active. Reauthorization never transfers a root, imports files, or changes the
acknowledged file inventory. A remote mismatch still blocks sync pending explicit DownloadUpdates.

Extend `/verify-factor` to return authenticated metadata and a one-use sync-registration token for
this flow. These remain private transport details, not native session objects. A missing legacy
remote encryption public key may be initialized from a verified main-factor unwrap; an existing key
cannot be silently replaced.

**Failure:** retain the old signer on definite failure and the candidate on uncertainty. Resolve any
pending upload with the newly authorized signer before permitting another upload. A revoked key
must not be resurrected as a repair; require a new key and main-factor authorization.

## `sync(root, encryption_public_key, changes)`

1. Check the root/account, compatibility state, remote head, and verified encryption public key.
2. Apply the change batch to a candidate inventory. Inputs distinguish logical keys from source paths.
   `Put` updates one key; `Remove` and `ReplaceFiles` change the backup inventory, not live storage.
3. Read and checksum the sources, preserving the other platform's referral entry. Missing or changed
   exports fail the whole batch. An empty or unchanged batch does not upload.
4. Persist the candidate manifest/public key, then upload conditionally against the acknowledged head.
5. On confirmed remote success, atomically acknowledge the candidate locally.

Native keeps exports alive for the whole call. When the backup includes a vault, include a fresh
vault export in each nonempty batch. Its temporary file disappearing after import does not remove
its remote entry. Consumers update their own referral key, never replace the entire namespace.
Explicitly retired entries can be dropped on the next real sync. Unsupported entries block every
archive rewrite, including retirement-only updates.

**An upload response is lost:** compare authenticated remote metadata with the pending candidate.
A matching candidate hash/key completes the local commit. The old hash/key permits rebuilding from
fresh sources; another head returns `RemoteAhead`. If the timed-out upload commits later, the next
conditional write fails rather than overwriting it. No upload queue or automatic merge.

**Required service change:** upload to a new immutable archive object, then atomically select its
reference, manifest hash, and expected encryption public key in the conditional metadata update.
A failed update leaves the previous backup readable. Factor-only writes preserve the archive
reference; cleanup must not remove selected objects or objects still being read. Initialize missing
legacy keys through main-authorized registration, and deploy client key support before requiring it.

## `add_factor(factor, existing)`

1. Authenticate the **existing** main factor and check the account. Unwrap the backup key and verify
   any required Turnkey authority before starting the new ceremony.
2. Obtain authorization for one addition, then authenticate/register the new factor. An existing
   passkey prevents creating another; iCloud-only authority cannot modify an existing Turnkey main user.
3. Wrap the same backup key for the new factor. Complete Turnkey enrollment when applicable, then
   conditionally add the factor to backup-service. Return updated metadata.

This prevents creating a new passkey when existing authentication fails. It cannot promise to
remove a credential from the OS if a later network operation fails.

**Required service change:** today's challenge contains the new OIDC token, which forces new-factor
first. Extend verify-factor authorization with an add-factor scope bound to the account, existing
main factor, requested new factor kind, and ephemeral public key. Issue a five-minute, single-use
token. After the new ceremony, that key signs a challenge binding the token, exact new identity or
credential, Turnkey references, and wrapped key. Verify the new proof independently and recheck
existing-factor membership during the conditional commit. A sync-registration token cannot add a
main factor. Consume the addition token before mutation; after ambiguity, reconcile and obtain fresh
authorization rather than restoring a possibly consumed token.

**Turnkey:** provision an organization only if OIDC is being added to a backup without one. Install
its existing saved passkey registration during that first provisioning. Otherwise reuse matching
credentials. A new organization must have a usable main credential before service enrollment.

For Apple, install every audience from the existing canonical environment table before committing
the factor. Share that table with migrations. Retries reuse already-installed audience entries;
unknown audiences survive, and retirement requires an explicit rule.

**Partial success:** reconcile service membership before retrying. The same identity and wrapped
key is an idempotent retry; different key material is not. Do not roll back reusable main credentials
because this attempt created them or a service listing currently lacks them. They may be in use by
another attempt. Report the incomplete addition; organization cleanup follows creation's stricter
rules. Never create another iCloud factor.

## `remove_factor(id, reauth, confirm_backup_deletion)`

Keep the existing removal preflight: validate the target/scope and obtain needed main-factor
Turnkey authority before committing. Remove service membership before cleaning up that main factor's
Turnkey credentials. Remove all Apple audiences belonging to the removed identity. For iCloud,
remove its encrypted key only when no surviving factor uses it.

**Last main factor:** the service must check confirmation within the conditional metadata mutation,
not just in client preflight. Bind `allowBackupDeletion` and the factor ID to the challenge; default
confirmation to false. A concurrent removal must not turn this operation into unconfirmed backup
deletion. Return `WouldDeleteBackup` before mutation if confirmation is required.

A confirmed last-factor removal follows the full deletion cleanup below. For a sync factor,
remove only that key's pair; deleting the acting key uses Turnkey-first ordering so it does not
revoke its own authority before cleanup. Other sync keys use service-first ordering.

## `delete_backup()` and `reset(root)`

Both delete the remote backup and its Turnkey organization, then clear this client's backup state.
Native confirms the action. They do not erase the native wallet.

| Method | Authority |
| --- | --- |
| `delete_backup()` | The bound sync signer; the canonical sync policy permits organization deletion. |
| `reset(root)` | Root-derived secp256k1 proof for `/v1/reset`, then break-glass authority for Turnkey. No prior init or signer required. |

1. Persist the exact target organization IDs before deleting backup-service state.
2. Delete backup-service first. A primary deletion failure preserves Turnkey and local state.
3. Delete those Turnkey organizations, then clear local manifests, staging, and the account binding.
4. Return success once service deletion and local clearing succeed. Log secondary Turnkey cleanup
   failures internally; missing break-glass must not block reset.

For reset, discover the organization through Auth Proxy `/v1/account` using the root-derived public
key. This still works after service metadata disappears. No app-backend recovery bypass.
Authenticated, correctly scoped NotFound is idempotent success; a failed existence check is not.

Reuse one private cleanup journal for deletion and provisional creation. It contains public target
IDs and eligibility state, never secrets. Unresolved creation is not eligible for deletion. Before
retrying cleanup, verify no live backup references the target. Retry only with valid authority;
logout cannot promise later deletion after the signer/root is gone. Keep this journal outside local
manifest clearing. Missing break-glass is deferred until authority changes, not retried every launch.

## `logout()`

Native first stops file producers and waits for the active operation. Pending recovery must be
completed or safely cancelled; `Busy`/`RecoveryPending` prevents teardown and native retains its key.

1. Attempt revocation of this client's Turnkey sync user, then its backup-service sync factor.
   Attempt both even if the first fails. Leave other clients' factors and the backup intact.
2. Clear this client's Bedrock manifests/staging and release its signer/account binding.
3. Native erases its own signer and wallet state after local clearing succeeds.

A remote cleanup failure is logged and does not block local logout. A local clearing failure is an
error and must be retryable even after the in-memory binding is released. An unavailable signer
still permits local clearing after logging failed revocation. Already-cleared state is a no-op.
Do not introduce `logout(false)` or reuse another client's key. Orphan Turnkey policies are left
for a later main-authorized migration; the sync policy cannot delete policies.

## `run_migrations(reauth)`

Use the existing plan/apply runner after device authorization and during settings maintenance.
Re-read actual state each time; no migration-version framework. Return the existing completed or
main-factor-required outcome. Native owns presentation and the existing migration-prompt throttle.

| Order | Repair |
| --- | --- |
| 1 | Resolve the metadata-linked main user; set sole-root quorum before removing bootstrap authority. |
| 2 | Ensure the root-derived break-glass user and organization-delete-only policy; never put it in root quorum. |
| 3 | Apply canonical sync policies; remove positively identified orphan policies and expired temporary keys. |
| 4 | Reconcile main credentials by passkey ID or OIDC issuer/subject; add missing Apple audiences before retiring explicitly obsolete ones. |
| 5 | Match sync users by normalized public key. Repair service-only legacy keys when main authority is available; never restore revoked service membership. |
| 6 | Remove known stale sync pairs from both stores, preserving current/authenticating keys and unpaired Turnkey users. |

Backup-service owns factor membership. Export OIDC subject in authenticated metadata; never match
by masked email. A main-authorized repair-factor challenge/route may replace a broken Turnkey
provider reference only after confirming the same organization, main user, and issuer/subject.
It cannot add membership or change encrypted keys, and needs no login to the broken factor.

Record `last_used_date` on successful main- and sync-factor authentication. Main-factor usage is for
display; automatic cleanup applies only to sync factors. Keep activity and membership in the same
conditional metadata update, preserving the archive reference. A required activity write must
succeed before authentication returns success. Missing history is unknown, never proof of inactivity.

Retain the 25-sync-factor limit and 365-day inactivity threshold. Automatic deletion requires a
challenge-bound `onlyIfStale` predicate checked against the metadata revision being mutated; an
intervening authentication invalidates the stale decision. For another key's pair, revoke service
membership before removing its Turnkey user and policy. Sync itself never runs Turnkey cleanup.

Only mutate positively identified app-owned policies/users, after a complete paginated listing.
Preserve unknown roles/audiences and unpaired users: an enrollment may still be in flight. A service
listing alone cannot prove a Turnkey user is safe to delete. Defer ambiguous repairs or missing
main authority rather than deleting working factors to make the two stores agree.

## Device registration

`finalize_login` and `reauthorize` share this private operation; creation uses the same policies.

- Native keeps one pending key per attempt and promotes it only after confirmed service enrollment.
  Register the Turnkey user/policy first, then backup-service, matching the normalized public key.
  Reuse one matching sync-role user; multiple matches require repair, not guessing.
- A healthy Turnkey-backed passkey/OIDC login ends with the key in both stores. Passkey/iCloud may
  complete service enrollment when Turnkey is unavailable; log secondary failure for later repair.
- At capacity, automatic replacement may select only a server-confirmed stale, noncurrent key.
  Remove/add membership in one conditional service write; a failed addition preserves the old key.
  Remove the displaced Turnkey user only after commit. Keep lookup indexes consistent with confirmed
  membership and reconcile ambiguous writes before removing either lookup.
- If no eligible slot exists, return `Capacity`. There is no `replace_device` parameter in the
  current public API; the remaining user recovery path needs a decision below.
- A lost response requires reconciliation using the retained pending signer. Current absence is
  not permission to rotate it, delete provisional authority, or declare registration failed.

## Authentication

These rules are shared by login, reauthorization, addition, and privileged management.

**OIDC:** create a temporary P-256 key; request the native token with nonce
`SHA256_HEX(UTF8(HEX(compressed_public_key)))`. Use Turnkey Auth Proxy `/v1/oauth_login` with the
configured `X-Auth-Proxy-Config-Id`, requesting a five-minute session without invalidating others.
Verify the session's organization/main user against authenticated service metadata with a signed
Turnkey query. The app backend is used only to create the Turnkey account. Sign service challenges
with that ephemeral key; verify issuer, audience, expiry, nonce, signature, and operation binding.
Consume both the OIDC nonce and service challenge once. A consumed token needs a fresh ceremony.

**Passkey:** one discoverable assertion authorizes both systems. Extend service retrieve/verify
challenges to accept the exact Turnkey `ACTIVITY_TYPE_STAMP_LOGIN` activity, targeting the configured
parent organization with a five-minute expiry and `invalidateExisting = false`. The WebAuthn
challenge is `UTF8(lowercase_hex(SHA256(exact_activity_bytes)))`; submit the byte-identical stamped
activity to Turnkey when the backup has an organization. A passkey-only backup needs no organization.

The service verifies credential signature, `webauthn.get`, RP/origin/cross-origin rules, user presence
and verification, and operation binding. Reject activities older than five minutes or more than
30 seconds in the future. Burn the challenge and activity fingerprint across newly issued tokens;
fingerprint retention includes clock skew and fails closed. Preserve the old challenge format until
released clients migrate. Share this verifier with factor addition.

**Existing iCloud:** load the selected main-factor key, never substitute a sync key. It can authorize
service recovery and upgrades, but cannot grant Turnkey main authority. Android has no iCloud login
ceremony; it can still display/remove these factors. No new iCloud enrollment.

## Errors and reporting

Use bounded network retries and Turnkey activity polling. OS ceremonies have their own cancellation
and timeout; do not spend the HTTP retry deadline while the user is authenticating. Never blindly
retry an ambiguous remote mutation.

One Bedrock operation owns its existing ClientEventsReporter event. Keep native screen/funnel
analytics and consent behavior; remove duplicate flow events. Surface actionable primary errors
(`RemoteAhead`, `UpdateRequired`, `CommitUncertain`, `Busy`, `RecoveryPending`) and log secondary
cleanup failures internally. Do not log secrets, response bodies, or unmasked identities. Telemetry
failure never changes a successful operation result.

## Interface decisions to finish

These gaps are in the current design/stubs; implementation must not invent competing solutions.

- **Consumer handoff:** `BackupFileChange` and `RetrievedFile` must distinguish logical keys from
  source paths. The stubs also need a way to deliver consumer validation/classification results
  before `finalize_login`; otherwise it cannot know when to persist `UpdateRequired` or retire keys.
  Define when `requires_app_update` is authoritative, since consumer validation follows `login`.
- **Local account directories:** `account_id mod 2^8` has only 256 values. It cannot isolate accounts
  by itself. Choose a collision-resistant, non-raw account identifier; do not silently load another
  account's manifest on a collision.
- **Full device capacity:** removal of `replace_device` leaves no selected-replacement input. Decide
  how a signed-out user with no stale slot regains access; do not silently evict an active client.
- **Previously shared sync keys:** define the transition to independent client keys before enabling
  unconditional revocation on logout. Revoking an old shared key would also revoke the other app.
