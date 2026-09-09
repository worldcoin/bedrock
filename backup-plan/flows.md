# Backup migration: flow contracts

Every remote write uses existing bounded HTTP/activity polling. Retry reads/transient transport
errors within the existing operation deadline; do not automatically resubmit an ambiguous create.
Native ceremonies have their own cancellation/OS timeout and do not consume a background HTTP
budget. Network responses, tokens, PRF outputs, root keys, and unmasked identities must not appear
in logs. Bedrock owns one existing ClientEventsReporter event per flow attempt: Sync, LogIn,
MethodVerification, AddMainFactor, or RemoveMainFactor. Remove only duplicate native
ClientEventsReporter emissions; keep native screen/funnel analytics and their consent behavior. Use
canonical failure codes for RemoteAhead, UpdateRequired, RecoveryPending, CommitUncertain, and
TurnkeyIncomplete; other flows use structured operation/outcome logs. Report state transitions, not
the same paused state on every read. Native surfaces these states and their retry/resume action;
telemetry failure never changes the committed operation result.

## Authentication shared by all flows

**OIDC.** Bedrock creates a temporary P-256 session key and asks native for an ID token whose nonce
is `SHA256_HEX(UTF8(HEX(compressed_public_key)))`, matching existing clients. Login calls
`https://authproxy.turnkey.com/v1/oauth_login` with `oidcToken`, `publicKey`, and the configured
`X-Auth-Proxy-Config-Id`; request a five-minute session without invalidating other sessions.
Validate the resulting session against the authenticated backup's organization and `auth_user_main`;
a decoded JWT alone is not authority. Confirm by a signed Turnkey query. The app backend is used
only for `POST /v1/backup-keys/create-account`, through the existing authenticated HTTP bridge,
including the per-attempt UUID and timestamped key proof. Delete iOS's
`public/v1/backup-keys/start-recovery` caller.

For backup-service OIDC authorization, sign its fresh, operation-bound challenge with that same
ephemeral key; send token, public key, and signature through the existing `Authorization` form.
Reuse the server's signature/issuer/audience/expiry/nonce checks and atomic provider-scoped nonce
burn plus challenge-token burn. One OIDC token is consumed once by backup-service; retries that need
new authorization obtain a fresh token/key, not another challenge for a consumed nonce.

**Passkey.** Use one discoverable ceremony that can authorize both systems. Bedrock creates the
temporary key and exact `ACTIVITY_TYPE_STAMP_LOGIN` JSON targeting the configured parent org, with
`expirationSeconds = "300"` and `invalidateExisting = false`. Extend the existing retrieve and
verify passkey challenge routes to accept `turnkeyActivity`, return WebAuthn options with challenge
`UTF8(lowercase_hex(SHA256(exact_activity_bytes)))`, and bind the exact digest into the existing
challenge token. Follow-up requests carry the same activity and assertion.

Backup-service authenticates the selected credential against its stored registration and consumes
the token. It must also atomically reject reuse of an activity fingerprint across newly issued
tokens until the activity expires; token single-use alone permits replay with another token. Verify
`webauthn.get`, RP ID hash, configured iOS/Android origins, cross-origin policy, UP/UV, credential
signature, challenge/context, and timestamps no older than five minutes or more than 30 seconds
ahead. Fingerprint expiry includes that skew; its store fails closed. Use the same verifier for
`add-factor`, with the installed WebAuthn library where it supports the required challenge bytes.
The optional STAMP_LOGIN path is additive. Shared hardening preserves the existing native add-factor
activity/challenge format until those callers are retired. Both formats enforce the same expiry,
context binding, and replay rejection.

Submit the byte-identical stamped activity to Turnkey when metadata has a Turnkey account. Validate
its resulting org/user against that metadata, then use the temporary signer for writes. No Turnkey
account means PRF recovery only; do not provision Turnkey just to recover a passkey-only backup. If
an existing account lacks this authenticator, recover the wallet and report that Turnkey
registration needs another working main factor; do not claim full device authorization.

**Existing iCloud Keychain.** Native selects/loads the existing factor. Bedrock owns its challenge,
decryption, and recovery. It may register a backup-service sync factor. It cannot manufacture
Turnkey main authority: defer Turnkey repair until a passkey/OIDC factor is available. Never
create/add another iCloud factor; existing ones can authorize an upgrade to passkey/OIDC. Android
can display/remove one but offers no iCloud login ceremony.

## Create, recover, authorize, sync

| Operation | Ordered work and completion boundary |
| --- | --- |
| `create(FactorRegistration::Passkey)` | Check no backup; obtain registration + PRF; build the complete initial archive from supplied files; prove root ownership and sync-key possession; `/create`; publish local manifest/public key only after commit. No Turnkey account. |
| `create(FactorRegistration::Oidc)` | Bind nonce/token; create suborg through app backend; establish main user, sole-root quorum, sync user/policy, break-glass user/policy; remove bootstrap authority; import factor secret; seal complete initial archive; `/create`; publish local state. |
| `recover` | Authenticate and retrieve; check selected/bound account; unwrap key; validate archive; stage files according to mode; return descriptors and (Login only) root via Siegel. No sync-factor registration or manifest publication yet. |
| `complete_recovery` | After required native import/login work, register the pending signer, publish files and acknowledged inventory/public key/compatibility; remove retired files and temporary vault data. Returns TurnkeyStatus for secondary registration. |
| `reauthorize` | Authenticate against the bound ID; verify encryption-key identity; repair/register the supplied sync key in both applicable systems; return TurnkeyStatus. Callers needing metadata use metadata(sync). Never unpack files, return a root, or import a vault. Extend `/verify-factor` to return metadata and a one-use sync-registration token internally. |
| `sync` | Validate root/account; check compatibility; compare remote head to acknowledged inventory; apply the batch to a candidate; read/checksum accepted files; seal; conditional `/sync`; atomically publish candidate manifest after confirmed remote commit. |

For each new authorization attempt, native creates and persists a fresh pending sync key before
remote registration; mark it active only after backup-service registration is confirmed. Retain that
key for the same unresolved attempt's retries. Never re-enroll a previously active, revoked key or
reattach its old Turnkey user. A still-enrolled key may repair its Turnkey half through migrations,
but that path cannot recreate missing service membership: return `NeedsReauth(SyncFactorInvalid)`
and require fresh authorization if membership disappears. Register Turnkey user/policy first, then
backup-service, matching public keys; reuse exactly one recognized sync-role user with the same
normalized key; multiple matches defer repair instead of guessing. At capacity, choose a
server-verified stale, noncurrent factor or return `Capacity` with authenticated device records for
user selection. `replace_device` is an explicitly confirmed factor ID; it is not a blanket eviction
permission. Extend `/add-sync-factor` with that optional replacement ID: prove possession of the new
key and use the existing main-authorized sync token, then atomically remove the selected factor and
add the new one in the same conditional metadata write. On failure the old factor stays enrolled.
Lock old/new factor IDs in deterministic order. Reread selected membership/activity for the
conditional metadata update; a conflict retries the read and predicate check. Insert the new Dynamo
lookup, conditionally replace membership in S3, then remove the old lookup only after confirmed
commit. On definite failure remove the new lookup and restore the registration token; on ambiguity
retain both lookups and resolve membership from authenticated metadata. Never evict the
new/authenticating key. Delete the displaced Turnkey user only after commit. No distributed
transaction framework. Passkey/OIDC login on a healthy Turnkey-backed backup finishes with the key
present in both stores. Both complete_recovery and reauthorize use this registration/replacement
contract.

If Turnkey is down, **passkey/iCloud** login may still recover and register with backup-service;
completion returns `TurnkeyStatus::Incomplete` rather than disabling wallet recovery. OIDC needs
Turnkey to export its factor secret and therefore cannot recover while that dependency is down.
Privileged Turnkey-dependent management remains unavailable until repaired. This same degraded
outcome applies to existing iCloud login and missing passkey authenticators, on both platforms.

If create/add-sync response is lost, query metadata with the pending sync key. A matching commit is
success; absence is only a snapshot and cannot prove the request will not commit later. Retain the
pending key and provisional authority on uncertainty. Cleanup is allowed before dispatch or after a
definitive precommit rejection, never from absence, timeout, or elapsed lock lifetime. A rejected
retry does not settle an earlier ambiguous request. For newly provisioned suborgs, retain the exact
ID for cleanup if backup creation never commits. Never delete a pre-existing organization as
rollback for adding one factor. Persist creation's UUID before calling the backend and its returned
provisional org ID in the pending-deletion file before further setup. Repeating that UUID must
resolve the same creation attempt, never create another org; unit E verifies/adds this backend
contract. An ambiguous response does not authorize a new UUID or speculative rollback. Lost
bootstrap authority is reported as incomplete cleanup, never hidden by a successful retry.

Creation includes current vault/PCP/referral files in its single `/create` upload. Native keeps
exported files alive for the whole awaited create/sync and deletes temporary exports afterward.
Missing or changed files fail the batch before upload; no silent omissions. Each platform has one
export adapter that adds the current vault export to every nonempty batch when the acknowledged
backup contains a vault. A temporary file's absence after import is not permission to drop its
remote entry. An empty or unchanged batch sends no upload. Retirement changes may accompany the next
real sync.

Before `/create` or `/sync`, atomically write the candidate to `manifest.pending`, including its
encryption public key; no root or file contents. Creation has no old head: a matching candidate hash
and encryption key authenticated by the pending sync key promotes local state; absence after an
ambiguous request remains `CommitUncertain`. Anything else is conflict. On timeout leave the
acknowledged manifest unchanged. Resolve pending state before processing another batch: remote
candidate hash and key mean promote it; the old hash with the same key means discard it and rebuild
from fresh inputs; any other head means `RemoteAhead`. This recognizes an already committed
candidate after process death or local-write failure, even when the vault export was
deleted/regenerated. If a timed-out sync commits after an old-head read, the next batch may require
`RemoteAhead` recovery; do not add an upload journal for this case. No persisted secrets, upload
retry queue, or automatic conflict overwrite.

The service must publish an archive and its metadata through one conditional commit. Write a new
immutable archive object first; the conditional metadata update selects that object together with
its manifest hash. A failed update leaves the previous object selected. Reads use the selected
object; factor-only updates preserve its reference. Cleanup removes only unreferenced objects, after
in-flight readers can finish. The same conditional sync commit checks the expected immutable
encryption public key as well as the old manifest hash. Creation records that public key; later
factor or file updates cannot change it. For existing metadata, the main-authorized add-sync flow
may initialize a missing key from Bedrock's verified unwrap. Once initialized, reject sync requests
that omit or mismatch it. Deploy client support before enabling this requirement. Keep archive
object references private to the service.

## Recovery consumers and interrupted work

| Mode | Preconditions | Restore behavior |
| --- | --- | --- |
| `Login` | Signed-out onboarding; empty vault. | Return the root to native; import the vault and publish accepted files. |
| `ReplaceLocal` | Bound, matching account; explicit confirmation to replace unsynced data. | Replace the vault and accepted files; retain the existing native root. |
| `ResumeSync` | App updated; remote head still matches the acknowledged head. | Restore only previously unsupported entries now recognized; preserve accepted local data. No root persistence or existing-vault import. |

In ResumeSync, an existing destination with different bytes is a conflict, not permission to
overwrite it. Completion clears UpdateRequired only if the full archive is now accepted/retired. A
changed remote head returns RemoteAhead.

For a selected login row, pass `expected_backup_id`; check it immediately after authenticated
retrieval, before decrypt/stage/bind. ReplaceLocal/ResumeSync always check the existing binding.
Only Login returns the root and persists it through the native secure adapter; ReplaceLocal and
ResumeSync validate then discard it inside Bedrock. Native imports required staged data and (Login
only) performs app-backend restore while keeping onboarding pending. It then calls
`complete_recovery` with the returned recovery ID; this call acknowledges all required native
imports/login. Only finalization enrolls the signer, publishes the manifest, and allows it to become
active. After publication reload PCP/invalidate referral caches before exposing completed recovery
to UI. Import failure blocks finalization and preserves staging. Reload failure blocks UI
completion; retry reload from the durably published files without enrolling another key or
reimporting the vault. Keep the native recovery ID until reload/invalidation succeed. After restart,
repeat idempotent complete_recovery with that ID, reload, then clear native pending state.

Add one WalletKit prerequisite: transactional `import_backup_once(bytes, recovery_id, replace)`.
Validate the source first; within one destination transaction enforce empty-only or replace known
vault tables, import, and record a completion receipt. The receipt is local-only, excluded from
exports and source imports, and cleared with its vault. Same recovery ID is an idempotent success;
failure rolls back both rows and receipt. `replace=true` is reachable only through confirmed
ReplaceLocal. Before import, native marks that pending ReplaceLocal as completion-only and disables
cancellation. Restart resumes the idempotent import and completion; only a definitely rolled-back
import can reopen cancellation. This is replacement, not merging, and preserves the old vault on any
import failure.

Keep one disk-backed pending recovery with account ID, mode, manifest hash, and publication
progress, not a second public session object. Generate a fresh opaque ID per attempt and retain it
on resume; a later deliberate restore of the same hash is a new attempt. This ID keys the receipt;
native root/onboarding persistence stores the same ID. No secret goes on disk in this record.
`recover` may reauthenticate and resume that attempt after restart (including before root transfer).
If the remote hash changed, stop with conflict; do not reuse an old import receipt for new contents.
Completion checks the ID/hash, reacquires expired authority through optional `reauth`, and is
idempotent after success. Keep staging until per-file atomic replacement, retired-file cleanup, and
final manifest publication succeed. Decode one tar member at a time; reject a header exceeding
per-entry/remaining aggregate bounds before allocation, bound the read, validate/stage the entry,
then release its buffers. Staging uses app-private storage excluded from OS backup, with the app's
data protection. Readers remain gated until publication.

Cancellation before finalization removes staging; no new remote key exists. Native must enforce the
ReplaceLocal import guard above before calling `cancel_recovery`. After registration starts,
cancellation is refused: Busy while the call runs, RecoveryPending after restart/failure. Native
retains the signer and resumes complete_recovery to resolve registration and publication; it must
not drop a running mutation future. After completion it can explicitly unregister/logout. This keeps
cancel local and synchronous; no second remote rollback flow. After an allowed cancel, abandoning
Login clears only that onboarding wallet/vault through the native reset; canceling ReplaceLocal does
not clear a pre-existing wallet. After vault replacement, finish publication before exposing the
restored wallet or permitting logout.

## Adding and removing main factors

`add_factor(factor, existing, sync)` dispatches by `FactorRegistration`; all enrollment paths share
the authorization and commit rules below.

Additions require proof of an existing main factor plus the new factor; a sync key alone cannot add
a recovery method. Extend backup-service's existing `/add-factor/challenge` and `/add-factor` for
existing OIDC/iCloud authorization and new passkey registration. Bind the new credential or OIDC
identity, operation, and backup ID into the existing-factor authorization; consume both challenge
tokens. Enforce one passkey, valid encrypted-key type, and matching account under the existing
conditional write. An authenticated retry of the same identity returns the existing factor rather
than creating another; a different encrypted key is not an idempotent retry.

If an existing Turnkey account has no usable passkey/OIDC main authority, return
`NeedsReauth(MainFactorRequired)` before starting an iCloud-authorized addition; do not provision
another organization or claim that iCloud can authorize Turnkey.

Before new-passkey registration, read bound metadata with the sync key and validate the existing
OIDC main session or possession of the enrolled iCloud key. Keep OIDC authorization unconsumed by
backup-service until the new credential is available for its identity-bound challenge. Then obtain
PRF, unwrap the existing backup key, rewrap it with PRF, and register the authenticator on
`auth_user_main` if Turnkey exists. For OIDC addition, obtain the new identity before the existing
passkey's final identity-bound assertion; provision Turnkey only if absent and reuse the backup key.
Always add the new issuer/subject credential to auth_user_main (all configured audiences for Apple).
Only when provisioning a passkey-only backup's first Turnkey account, also install its saved passkey
registration. Reuse matching credentials; do not register another passkey on every OIDC addition. On
OIDC creation, include the initial issuer/subject credential in main-user creation; add any
remaining Apple audiences before committing the service factor. Creating a Turnkey account with no
usable main credential is never a successful intermediate result.

For Apple, create all entries from `turnkey/policies.rs::turnkey_apple_audiences` for the same
issuer/subject before the backup-service factor commit. Production currently has App, World ID, and
web audiences; staging includes sandbox too. Share the table with the existing Apple migration and
assert equality with backup-service environment fixtures. Native never supplies the audience set.
Unknown audiences are retained; explicitly removing an Apple identity removes all its audiences for
that identity. Audience retirement is an explicit table, initially empty.

Commit Turnkey enrollment before backup-service addition. On rejection or uncertainty, preserve
reusable main credentials and report the incomplete addition: another attempt may already use them.
Reconcile authoritative membership before retrying. Never delete a main credential merely because
this attempt created it or a service listing currently lacks it; unreferenced main credentials
require explicit removal. Newly provisioned organization cleanup follows the stricter creation rule
above.

Removal retains #440's preflight and service-first ordering. Require any privileged Turnkey
reauthentication before committing. Add iCloud Keychain removal and drop its encrypted key only when
no surviving factor uses it. Last-main-factor confirmation must be enforced **inside the service
conditional mutation**: extend the challenge/request with `allowBackupDeletion`, default false. A
concurrent device removing another factor must not turn an ordinary removal into an unconfirmed
backup deletion. Under the conditional mutation, reject with `WouldDeleteBackup` before removing any
factor when no main factor would remain and the flag is false. The factor and flag are bound into
the challenge context.

## Delete, reset, logout

Native confirms explicit backup deletion/reset with the user. Sync keys deliberately retain
backup-deletion authority; root-based reset is the fallback when factor authority is unavailable.

Use one private cleanup file for provisional creation and deletion targets. Record each entry's
phase: unresolved creation is ineligible for cleanup; creation abandoned before dispatch, a
definitive precommit rejection, or confirmed service deletion makes it eligible. Before service
deletion, persist its exact Turnkey organization IDs there. Delete backup-service first, then
Turnkey, then clear local backup state. Return `Complete` only when both applicable remote deletions
are confirmed; service success plus Turnkey failure returns `TurnkeyStatus::Incomplete`. Bedrock
logs the underlying failure class and owns retry decisions; native reports incomplete cleanup
without inferring a retry policy from that binary status. Apply this to explicit deletion,
last-factor deletion, reset, and app-account deletion. Local wallet deletion is not a remote reset.

`reset(root)` signs `/v1/reset` with the root-derived secp256k1 key. Discover Turnkey through Auth
Proxy `POST /v1/account`, `{filterType:"PUBLIC_KEY", filterValue:<derived public key>}`; use
break-glass authority to delete that exact suborg. Discovery still works after backup-service
metadata is gone. Older accounts without break-glass can remain undeletable: reset succeeds with
`TurnkeyStatus::Incomplete`; do not require another factor or invent an app-backend recovery bypass.
The existing canonical sync policy permits organization deletion, so `delete_backup(sync)` needs no
root on a healthy account. Authenticated/appropriately scoped NotFound is idempotent deletion
success; auth failure or an unavailable existence check is not proof of absence.

Pending deletion contains public IDs and cleanup state, never a retained root/signer. Before retry,
verify the target is not referenced by a current live backup. Retry opportunistically in a later
root-bearing reset/create, or with still-valid authority; no promise of cleanup after logout when
authority is gone. Keep pending deletion separate from cleared manifest state. A failed primary
service delete does not authorize Turnkey deletion or local backup-state clearing. Record missing
break-glass authority as terminal until credentials/policy change; do not retry it or emit the same
alert on every create. Retry only transient failures within existing bounds.

`unregister_device` captures its public key and remote IDs before deleting anything; remove its
Turnkey user before revoking the backup-service sync factor, so the latter remains usable for retry.
The canonical sync policy cannot delete policies; its now-orphan policy is pruned by the next
main-authorized migration. `Complete` here means device credentials revoked in both stores. Logout
awaits a bounded attempt, reports failure, then native may clear its key. Android cross-app-imported
keys keep their current local-only logout behavior; do not revoke a peer's key.

## Repairs and migrations

Use the existing runner with one operation deadline and plan/apply per migration. Run after device
authorization and during settings maintenance, without file sync. Native owns when to show a prompt;
Bedrock keeps its existing outcome and pending descriptions; native retains the seven-day prompt
throttle. No persisted migration-version framework: re-read and converge on actual remote state.

| Order | Invariant and repair |
| --- | --- |
| 1 | Resolve one metadata-linked `auth_user_main`; verify the main session belongs to it. Set sole-root quorum, then remove obsolete bootstrap authority. Ambiguous identity blocks destructive repair. |
| 2 | Ensure exactly one `break_glass_user` with the root-derived public key and organization-delete-only policy. Repair duplicates only after the correct user/policy is verified. Never place break-glass in root quorum. |
| 3 | Apply current canonical sync policies; remove orphan policies and expired temporary keys. Protect main and break-glass roles. Unknown user roles are not cleanup targets. |
| 4 | Reconcile main credentials: passkey credential ID and OIDC issuer/subject identify logical factors; Apple audiences are members of that factor. Add missing accepted credentials before removing obsolete ones. Preserve unknown audiences. |
| 5 | Reconcile sync users by normalized P-256 public key, not name or cached native user ID. Service-only keys from old passkey logins remain valid; add missing Turnkey users when main authority is available. |
| 6 | Remove stale/excess sync pairs from both stores. Protect current/authenticating keys; preserve and report unpaired Turnkey users because an enrollment may still be in flight. |

Backup-service is authoritative for enrolled main/sync membership. Export OIDC `subject` on
authenticated metadata so repair still identifies Apple siblings when its stored provider ID is
gone; derive issuer from provider kind. Reuse `BackupFactor` fields rather than adding an account
graph. Existing passkey registration is already stored server-side; carry it in private wire data
for Turnkey repair. Never match masked email. Reattaching a recreated provider ID requires
main-authorized `/v1/repair-factor/challenge` + `/v1/repair-factor` with factor ID and new provider
ID bound into the challenge. Before repair, a signed Turnkey read must confirm that provider belongs
to the metadata-linked organization/main user and has the existing issuer/subject. This endpoint
only changes the reference of that existing OIDC identity; it cannot change subject, add membership,
or replace encrypted keys. It needs no fresh login to the broken factor. Keep `/add-factor`
idempotence for enrollment retries, not repair.

Creation/addition and repair use the same policy/audience/credential helpers. If a missing
credential cannot be recreated with available main authority, defer with the required factor; never
delete the service factor to make the inventories appear equal. Do not automatically remove unpaired
users or reusable main credentials; age and rereads cannot rule out a delayed enrollment. An
explicit factor removal still removes all that identity's Turnkey credentials; unknown unrelated
credentials are preserved and reported.

Use a 25-factor bound and a 365-day inactivity threshold, measured by backup-service authentication.
Normal backup sync never touches Turnkey. Add durable, server-recorded `lastUsedAt` to sync factors
in authoritative backup metadata, updated on successful sync-scope authentication at most once per
day. A required touch must commit before authentication succeeds; storage failure fails the request.
Activity and membership use the same conditional metadata write, preserving the archive reference.
On conflict, reread and reevaluate; locks reduce contention but are not correctness guards. Do not
duplicate activity in the lookup table. Missing/unparseable history is unknown, not eligible for
automatic eviction. Automatically remove only known >365-day inactive keys; at capacity a
healthy/unknown replacement needs explicit user selection and the atomic registration contract
above. Enforce the 25 cap in backup-service, always protecting current/authenticating keys. Cleanup
of passkey-only backups still runs without a Turnkey account. Automatic removal/replacement sets a
challenge-bound `onlyIfStale` predicate in the service request. The service checks its 365-day
cutoff and current membership against the metadata revision used by the conditional mutation; an
intervening activity touch invalidates that revision, even if a worker outlives its lock. Manual
confirmed replacement omits the predicate; client-side selection alone never authorizes automatic
eviction. Extend the existing delete-factor/add-sync routes, not a cleanup API.

Mutate/delete only positively owned policies: canonical name plus app notes or an enumerated legacy
policy form, valid role/key membership, and matching approver. An arbitrary single-user policy is
not app-owned. Preserve/report unknown policies; if creating a canonical policy would widen an
unrecognized restriction, defer rather than bypass it. Prune only app-owned orphan policies and
recognized expired app session keys. No name-only deletion of unrelated credentials. An orphan
policy must refer to a confirmed-absent user; a user with no service membership is not proof that
its policy is orphaned. Inventory reconciliation and same-identity retries also cover interrupted
factor additions; do not add a second local enrollment journal.

For paired deletion, the rule is acting key's own pair: Turnkey first; another key's pair: service
first. Migration never selects the acting pair. For another pair revoke service membership first,
then delete the Turnkey user. Delete its policy with main authority when available; otherwise leave
only the orphan policy for the existing policy migration. Never remove the acting user's own
authorization policy before using it to revoke that user. Require complete successful paginated
inventories before planning removals; a truncated/failed listing authorizes none. Re-read before
destructive repair and after ambiguous writes. Do not delete healthy service-only legacy keys solely
because their Turnkey half is missing.
