# BackupManager detailed flows

[design.md](design.md) defines the high-level overview, API and important decisions. This file contains detailed flows to make any design decisions obvious and implementation straightforward. Some of these decisions are better conveyed with pseudo-code.

The pseudocode describes decisions, not additional public APIs or required internal types. The API stubs omit receivers, `Arc`, and `Result`; `bedrock_export` is the existing UniFFI wrapper. Mutations use the existing operation lock; temporary secrets are released on every exit.

## `new()` and `init(root, sync)`

```text
new(main_factor_ceremony):
    return BackupManager(
        main_factor_ceremony = main_factor_ceremony,
        account_id = none,
        sync_signer = none,
        local_state = none,
        operation_lock = new_lock()
    )


init(root_session, sync_signer):
    acquire operation_lock or fail Busy

    root = consume(root_session)
    try:
        account_id = derive_backup_account_id(root)
    finally:
        zeroize(root)

    signer_public_key = sync_signer.public_key()

    if manager.account_id exists:
        if manager.account_id != account_id:
            fail "Create a new manager when switching accounts"

        if manager.sync_signer.public_key() != signer_public_key:
            fail "Use reauthorize() to change the sync signer"

        return  // Already initialized with this account and key.

    install_key = load_or_create_private_installation_namespace_key()
    account_segment = blake3.keyed_hash(install_key, utf8(account_id)).to_hex()
    account_directory = "backup_manager/" + account_segment

    local_state = read_account_state(account_directory)
    // Missing is allowed. Corrupt or unreadable state is an error.

    if local_state exists:
        require local_state.account_id == account_id

    else if legacy_manifest exists:
        manifest = read_legacy_manifest()
        // Parse failures are errors; never substitute an empty manifest.

        local_state = {
            account_id: account_id,
            manifest: manifest,
            verified_encryption_public_key: none,
            pending_recovery: none
        }

        atomically_write(account_directory, local_state)
        delete_legacy_manifest()
        // Write first: interruption must not lose the old manifest.
        // If both copies exist after restart, use the account-specific copy.

    else:
        local_state = {
            account_id: account_id,
            manifest: none,
            verified_encryption_public_key: none,
            pending_recovery: none
        }
        // Missing local inventory does not mean the remote backup is empty.

    if local_state.pending_recovery exists:
        require local_state.pending_recovery.sync_public_key == signer_public_key

    manager.account_id = account_id
    manager.sync_signer = sync_signer
    manager.local_state = local_state

    if local_state.pending_recovery exists:
        fail RecoveryPending(
            recovery_id = local_state.pending_recovery.id,
            purpose = local_state.pending_recovery.purpose
        )
        // Manager is initialized; native must resume or cancel recovery.

    // No network calls or remote registration in init().
    // Before any upload, the normal remote-state check must establish:
    //   - local and remote manifest hashes match;
    //   - the encryption public key is verified and matches;
    //   - a missing local manifest corresponds to an empty remote inventory.
    // Initialization alone never grants permission to upload.
```

## Reading backup state

| Method | Meaning |
| --- | --- |
| `status()` | Returns the service's factor kinds/providers using the cached account ID, without device authorization. Only backup-not-found returns `None`; network failures remain errors. |
| `metadata()` | Returns authenticated factor information even when file sync is blocked. |
| `check_for_remote_updates()` | Compares the acknowledged manifest hash and encryption public key with remote metadata; also reports persisted `UpdateRequired`. Native calls it after startup init. |
| `list_files_in_backup(designator)` | Returns entry IDs for the designator, not filesystem paths. Uses the same remote-state check before returning the inventory. |

`RemoteAhead` means native must trigger a backup download. `UpdateRequired` means this client cannot understand the whole archive.

## `create(factor, root_secret, files)`

1. Verify the root_secret matches the initialized account and that no backup already exists.
2. Run the selected factor ceremony. For passkeys, require a usable PRF result before any commit.
3. Build the complete initial backup from the supplied vault, Oxide, and referral exports.
4. Prove root ownership and possession of this client's sync key; create the remote backup.
5. Save the acknowledged manifest and encryption public key, then return that public key to native.

**Passkey:** create a passkey-only backup without a Turnkey organization.

**OIDC:** create the organization through the app backend. Set up the main user, sole-root quorum, sync user/policy, and organization-delete-only break-glass user/policy; remove bootstrap authority. Install the initial OIDC identity, including all Apple audiences, and import its factor secret before committing the backup. Share this setup with OIDC addition and migrations.

Success includes the initial archive upload. Native must not mark backup enabled after factor registration alone. Keep exported source files alive until the awaited call finishes.

**Creation and retry decisions:**

```text
before provisioning or uploading:
    persist one creation UUID and the pending sync key
    reuse them for every retry of this attempt

if an earlier creation outcome is unresolved:
    remote = inspect_backup_using_pending_sync_key()
    if remote matches the pending manifest and encryption public key:
        acknowledge_creation_locally()
        return encryption_public_key

    keep the pending key and any provisional organization
    fail CommitUncertain
    // Current absence cannot rule out a delayed commit.

if provisioning an OIDC organization:
    organization = provision_using_the_same_creation_UUID()
    persist its exact ID before further setup or writes

persist the candidate manifest before submitting creation

if creation is confirmed:
    acknowledge_creation_locally()
    return encryption_public_key

if creation is definitively rejected before commit:
    mark this attempt's provisional organization eligible for cleanup
    propagate the rejection

if the response is lost or ambiguous:
    retain the attempt and its authority
    fail CommitUncertain
```

An ambiguous provisioning response must be resolved using the same UUID. Do not create a replacement organization or treat a later rejected retry as proof that an earlier request never committed.

Before rollout, confirm that app-backend provisioning supports the creation idempotency contract and recreation after a deleted organization; implement missing backend support with OIDC creation.

## `login(authentication, sync_factor, purpose, expected_backup_id)`

Login prepares a restore; it does not register the sync factor or replace live data. Authentication follows the [shared rules](#authentication).

```text
login(authentication, sync_factor, purpose, expected_backup_id):
    require no concurrent mutation

    if purpose == DownloadUpdates:
        require an initialized account and native replacement confirmation

    if a recovery is already pending:
        require the same account, purpose, and pending sync key
        reuse its recovery ID
    else:
        choose a fresh recovery ID

    authenticated_backup = authenticate_and_retrieve(authentication)
    require its account matches expected_backup_id, if supplied
    require its account matches the initialized account, if any

    if resuming and the remote head differs from the staged attempt:
        if native imports have started:
            fail RecoveryPending  // Finish the existing staged attempt.
        fail RemoteAhead          // Cancel and start a newly validated attempt.

    unwrap the backup key
    decrypt and validate the complete archive
    require the recovered root derives the authenticated account ID

    if this attempt has no validated staging yet:
        stage data under Bedrock-chosen filenames
        // Root/version are metadata, never staged files.
        persist the original inventory, manifest hash, encryption public key,
                recovery ID, purpose, authentication method, and sync public key
        // Never persist root, tokens, or temporary private keys.

    bind the account and retain the attempt's signer
    return staged descriptors, metadata, and a one-use Siegel root handle
```

| Purpose | Native work between `login` and `finalize_login` |
| --- | --- |
| `Login` | Signed-out onboarding with an empty vault. Store the root, import consumer data, and complete the native app-account login. |
| `DownloadUpdates` | Confirm replacement of unsynced data for the initialized account. Keep the existing native root, discard the returned root handle, and import the complete remote data. This is not a merge. |

Native routes unpacked files to WalletKit, Oxide, and referral consumers. Each validates its own keys, formats, identity bindings, and destinations. Validate all inputs before the first live import. Consumers report unsupported and explicitly retired entries to Bedrock.

Native persists the pending signer and recovery ID across restart. A retry never rotates the key to escape an unresolved attempt or reuses an import receipt for different contents.

Parse one archive entry at a time with the existing tar/ciborium code; do not buffer the entire expanded archive. Preserve the original inventory and raw unsupported designators internally. Keep V0 `path` and manifest `file_path` values/matching rules unchanged, mapping them to public `entry_id` fields.

For the root handoff, fill the existing Siegel session in Rust and copy once through checked C/JNI into a native-owned buffer. Validate handles and lengths against Siegel's existing limits before copying; consume the session and wipe the native buffer after secure storage. Keep any conversion for wallet models inside the secure-store adapter; do not add a root field to JSON.

## `finalize_login(recovery_id)`

Native calls this only after every required consumer import and native login step succeeds. The conceptual completion/classification checks below depend on the still-open consumer reporting interface; they do not introduce another public API.

```text
finalize_login(recovery_id):
    require no concurrent mutation

    if this recovery ID is already completed:
        finish any remaining disposable-staging cleanup
        return success

    recovery = require_matching_pending_recovery(recovery_id)
    require all native imports/login steps succeeded
    require consumer classification results are available

    if service registration is not yet confirmed:
        if the required authentication has expired:
            reauthenticate through the saved method and ceremony handler
            require the same account

        persist that registration has started
        register_device_using_the_retained_signer()
        // On failure or uncertainty, keep recovery state for retry.

    acknowledge the full original inventory and verified encryption public key
    persist UpdateRequired if unsupported entries remain
    durably mark this recovery ID completed with the acknowledged state

    preserve the other platform's referral entry for future syncs
    remove disposable staging and release temporary recovery authority
    return success

native after finalize_login succeeds:
    reload Oxide and referral caches
    if reload fails:
        retain the recovery ID and retry reload
    else:
        clear native pending recovery and show completion
```

Finalization **does not copy archive entries into live app storage or upload a backup**. Consumer imports already happened; finalization commits the manifest.

**Interrupted imports:** WalletKit's transactional `import_backup_once(bytes, recovery_id, replace)` records a local completion receipt in the same transaction as the import. It enforces empty-only Login or confirmed replacement; a failed transaction preserves the old vault. Receipts are local-only: exclude them from exports and source imports, and clear them with the vault. Oxide and referral imports must likewise resume safely using the same recovery ID. There is no transaction spanning all consumers: retain staging and resume unfinished work before allowing the app to use a partially restored account.

Short-lived sessions and registration tokens remain memory-only and are wiped on expiry even if native stalls. Reauthentication uses the saved factor method; there is no separate `reauth` argument.

An app update alone cannot clear persisted `UpdateRequired`; a completed DownloadUpdates restore must confirm that every retained entry is supported. Native promotes the returned encryption public key only on finalization, then supplies it on subsequent syncs.

## `cancel_login(recovery_id)`

Cancellation abandons a prepared restore. It does not undo remote registration or replace the existing account during DownloadUpdates.

```text
native before cancelling:
    if DownloadUpdates replacement has started:
        resume imports and finalization instead
        // Cancellation reopens only if the import definitely rolled back.

    persist cancellation intent and retain the recovery ID
    call cancel_login(recovery_id)

    if Bedrock refuses cancellation:
        retain the key and recovery state; resume completion
    else:
        if purpose == Login:
            reset this onboarding attempt's root, imported consumer data,
                  and native login session
        clear the native cancellation/recovery record

    // After a crash, retry Bedrock cancellation and then native cleanup.

cancel_login(recovery_id):
    require no concurrent mutation, otherwise fail Busy

    if this attempt is already cancelled:
        return success

    recovery = require_matching_pending_recovery(recovery_id)
    if registration has started:
        fail RecoveryPending  // Resolve enrollment and finish finalization.

    remove staging, clear the pending recovery, and release temporary authority
    make successful cancellation safe to retry with the same ID
    return success
```

Native persists the completion-only guard before replacing existing consumer data. Never cancel by dropping a running mutation future, or log out midway through replacement. Native cleanup proceeds only after Bedrock cancellation succeeds; an interrupted onboarding reset resumes before the account becomes usable.

## `reauthorize(authentication, sync)`

Native persists a fresh candidate signer before calling. This authorizes the client without restoring files or transferring a root.

```text
reauthorize(authentication, candidate_signer):
    require an initialized account and no concurrent mutation
    if an authorization attempt is unresolved:
        require its same persisted candidate key

    authenticate the main factor and require the initialized account
    verify encryption-key identity
    // A missing legacy remote key may be established by verified unwrap.
    // An existing key cannot silently replace the acknowledged key.

    keep the current signer while registering the candidate
    result = register_device(candidate_signer)

    if result confirms service enrollment:
        install the candidate as the manager's active signer
        return success
    if result is uncertain:
        retain the candidate and unresolved attempt
        fail CommitUncertain
    otherwise:
        keep the current signer and propagate the error

native after success:
    promote the persisted candidate key
```

Reauthorization leaves the acknowledged file inventory unchanged. Resolve pending uploads with the newly authorized signer before another upload; remote divergence still requires DownloadUpdates. Never repair a revoked key by recreating its service membership: require fresh main-factor authorization and a new key.

Extend `/verify-factor` to return authenticated metadata and a one-use sync-registration token for this flow. These remain private transport details, not native session objects. A missing legacy remote encryption public key may be initialized from a verified main-factor unwrap; an existing key cannot be silently replaced.

## `sync(root, encryption_public_key, changes)`

```text
sync(root, encryption_public_key, changes):
    require no concurrent mutation or pending recovery
    require the supplied root derives the initialized account
    fail UpdateRequired if unsupported entries block rewrites

    remote = read_authenticated_remote_metadata()

    if an upload is pending:
        if remote matches the pending manifest hash and encryption key:
            acknowledge that completed upload locally
        else if remote matches the previous acknowledged hash and key:
            discard the pending candidate; rebuild from fresh sources
        else:
            fail RemoteAhead

    require local and remote inventory agree
    require supplied, acknowledged, and verified remote encryption keys agree
    // Missing local inventory is acceptable only when remote is empty.

    if the batch is empty:
        return success without uploading

    candidate = apply_changes_to_inventory(changes)
    require a source for every retained consumer-owned entry
    // Omissions never remove entries; Bedrock supplies the other platform's referral bytes.
    read and checksum all required sources
    fail the batch if an export is missing or changed
    if the inventory and checksums are unchanged:
        return success without uploading

    seal the candidate and persist its manifest/public key as pending
    upload conditionally against the acknowledged remote head

    if the remote commit is confirmed:
        atomically acknowledge the candidate locally
        return success
    if the outcome is uncertain:
        retain the pending candidate and old acknowledged state
        fail CommitUncertain
    otherwise:
        preserve the acknowledged state and propagate the rejection
```

`Put` and `ReplaceFiles` use `BackupFileSource`: `entry_id` identifies the archive entry, `source_path` is the file to read for this call. `Remove` and `RemoveIfChecksumMatches` also use `entry_id`. `ReplaceFiles` explicitly replaces its entire designator's inventory; an empty list removes all entries of that designator. Removals change the backup inventory, not live consumer storage. Root and other temporary secrets are wiped on every exit.

Native includes `Put` for unchanged retained entries too, including on removal-only syncs; do not re-add removed entries while assembling sources. Keep exports alive and unchanged for the whole call. When the resulting backup includes a vault, supply a fresh export. Its later deletion does not remove its remote entry. Source paths are not persisted or included in manifest hashes; retries may use different temporary paths. Consumers preserve or reconstruct entry IDs after import, rather than treating new destination paths as new IDs. No finalize-time path rebinding is needed.

Consumers update their own referral key, never replace the entire namespace. Explicitly retired entries can be dropped on the next real sync. Unsupported entries block every archive rewrite, including retirement-only updates.

A delayed upload may commit after an old-head read; the next conditional write must fail rather than overwrite it. Reconcile pending state before another batch. No upload queue or automatic merge.

**Required service change:** upload to a new immutable archive object, then atomically select its reference, manifest hash, and expected encryption public key in the conditional metadata update. A failed update leaves the previous backup readable. Factor-only writes preserve the archive reference; cleanup must not remove selected objects or objects still being read. Initialize missing legacy keys through main-authorized registration, and deploy client key support before requiring it.

## `add_factor(factor, existing)`

```text
add_factor(new_factor, existing_method):
    require an initialized account and no concurrent mutation

    existing = authenticate_existing_main_factor(existing_method)
    require the same account
    unwrap the existing backup key

    if adding a passkey and the backup already has one:
        reject before the new ceremony
    if the existing Turnkey account requires authority this factor cannot provide:
        request a working main factor before the new ceremony

    grant = authorize_one_addition(existing, new_factor.kind)
    new = perform_new_factor_ceremony(new_factor)
    verify the new proof and usable PRF when required
    wrap the same backup key for the new factor

    if adding OIDC and no Turnkey organization exists:
        provision it with a usable main credential
        install the backup's saved passkey registration, if present
    if Turnkey enrollment is required:
        reuse matching credentials; finish all required Apple audiences

    conditionally commit the new factor to backup-service
    if committed:
        return updated metadata

    reconcile membership before retrying
    if the exact identity and wrapped key already committed:
        return updated metadata
    retain reusable Turnkey credentials and report the incomplete addition
```

Existing authentication and key access must succeed before creating a new credential. Later failures can still leave an OS credential; native cannot promise to delete it. An existing iCloud factor can authorize supported upgrades, but no new iCloud factor can be enrolled.

**Required service change:** today's challenge contains the new OIDC token, which forces new-factor first. Extend verify-factor authorization with an add-factor scope bound to the account, existing main factor, requested new factor kind, and ephemeral public key. Issue a five-minute, single-use token. After the new ceremony, that key signs a challenge binding the token, exact new identity or credential, Turnkey references, and wrapped key. Verify the new proof independently and recheck existing-factor membership during the conditional commit. A sync-registration token cannot add a main factor. Consume the addition token before mutation; after ambiguity, reconcile and obtain fresh authorization rather than restoring a possibly consumed token.

For Apple, install every audience from the existing canonical environment table before committing the factor. Share that table with migrations. Retries reuse already-installed audience entries; unknown audiences survive, and retirement requires an explicit rule. **Importantly** when adding a new factor, the `sub` is taken from the user's OIDC token. The migration must be short-lived as Turnkey's backend response can't be trusted.

A retry with different wrapped-key material is not idempotent. Never remove a main credential merely because this attempt created it or the service currently lacks it: another attempt may use it. Newly provisioned organizations follow the stricter creation cleanup rules.

## `remove_factor(id, reauth, confirm_backup_deletion)`

Reuse the existing Bedrock removal flow. Only these changes remain:

- Use the manager's stored account and signer; obtain reauthentication through `MainFactorCeremonyHandler`.
- Enforce last-factor deletion confirmation inside backup-service's conditional write. Bind `allowBackupDeletion` and the target factor ID to the challenge; default confirmation to false and reject unconfirmed deletion with `WouldDeleteBackup` before mutation.
- Support removal of existing iCloud Keychain main factors. Remove their encrypted key only when no surviving factor uses it.

Sync-factor revocation belongs to `logout()` and device cleanup.

## `delete_backup()` and `reset(root)`

Both delete the remote backup and its Turnkey organization, then clear this client's backup state. Native confirms the action. They do not erase the native wallet.

| Method | Authority |
| --- | --- |
| `delete_backup()` | The bound sync signer; the canonical sync policy permits organization deletion. |
| `reset(root)` | Root-derived secp256k1 proof for `/v1/reset`, then break-glass authority for Turnkey. No prior init or signer required. |

```text
for delete_backup or reset:
    require no concurrent mutation or unresolved recovery
    choose the operation's authority from the table above
    capture and persist known exact organization IDs before service deletion

    delete/reset the backup in backup-service
    if primary deletion fails or is uncertain:
        preserve Turnkey and local state
        propagate the error; reconcile before attempting cleanup

    for each eligible organization target:
        confirm no current live backup references it
        attempt deletion with the available authority
        if deletion fails or break-glass authority is missing:
            log incomplete cleanup and retain the eligible target
            continue

    clear this client's local backup state
    if local clearing fails:
        return an error so cleanup can be retried

    release the signer and account binding
    return success
```

For reset, discover the organization through Auth Proxy `/v1/account` using the root-derived public key. This still works after service metadata disappears. No app-backend recovery bypass. Authenticated, correctly scoped NotFound is idempotent success; a failed existence check is not.

Reuse one private cleanup journal for deletion and provisional creation. It contains public target IDs and eligibility state, never secrets. Unresolved creation is not eligible for deletion. Before retrying cleanup, verify no live backup references the target. Retry only with valid authority; logout cannot promise later deletion after the signer/root is gone. Keep this journal outside local manifest clearing. Missing break-glass is deferred until authority changes, not retried every launch.

## `logout()`

Native stops file producers and waits for the active operation before calling. Pending recovery must first be completed or safely cancelled.

```text
logout():
    require no concurrent mutation, otherwise fail Busy
    if recovery is pending:
        fail RecoveryPending before teardown

    if the bound signer is usable:
        attempt to revoke its Turnkey sync user
        log failure, but still attempt backup-service revocation
        attempt to revoke its backup-service sync factor
        log failure, but still continue local logout
    else:
        log that remote revocation could not be performed

    try:
        clear this client's Bedrock manifests and staging
    finally:
        release temporary authority, signer, and account binding

    // Local deletion errors propagate; clearing must be retryable unbound.
    return success

native after success:
    erase this client's signer and wallet state
```

Preserve the backup and every other client's factors. Already-cleared state is a no-op. Native retains its key on Busy, RecoveryPending, or local clearing failure.


## Device registration

`finalize_login` and `reauthorize` share this private operation; creation uses the same policies. Native keeps one persisted candidate key per attempt and promotes it only after confirmed service enrollment.

Remove Android's cached Turnkey sync-user ID and its readers/writers. Bedrock resolves users by the signer's public key; native retains key storage and the verified backup encryption public key.

```text
register_device(candidate):
    require the same candidate key if this attempt is unresolved

    if this attempt has already been submitted:
        resolve its recorded outcome and current membership before Turnkey writes
        if it committed but the candidate was subsequently revoked:
            retain the result for displaced-key cleanup
            require fresh main authorization and a new candidate; do not promote this key
        if still uncertain:
            fail CommitUncertain

    if service enrollment is confirmed and the candidate remains a member:
        resume any recorded displaced-key cleanup
        return success

    if this backup has a Turnkey organization:
        find sync-role users matching the candidate public key
        if multiple users match:
            require repair rather than guessing
        otherwise:
            reuse the matching user or register its user/policy
            record any newly created authority for this attempt's cleanup

        if Turnkey authorization is unavailable:
            if this is a supported passkey/iCloud degraded flow:
                log the secondary failure and continue service enrollment
            else:
                propagate the failure

    prove candidate-key possession and use main-authorized registration
    bind replace_oldest_if_full = true to the account, attempt, and new key
    service conditionally enrolls it:
        if this attempt already committed:
            return its recorded result and current membership without another mutation
        if the candidate is already a member:
            return success without eviction
        if at the 25-factor limit:
            select minimum (last_used_date or created_at, factor_id)
        add candidate, remove selected member, and record result/displaced key
            in one metadata write conditional on the read revision
        // Bounded conflict retries reread current state and reselect.
        // Rejection preserves the old key's membership.

    if enrollment is definitively rejected:
        if this attempt is confirmed never committed, with no outstanding write:
            clean up only its newly created Turnkey authority; retain failed cleanup for retry
        // Never delete reused authority or roll back an unresolved attempt.
        propagate the rejection
    if the outcome is uncertain:
        reconcile with the same candidate key
        if service membership is not confirmed:
            retain candidate and provisional authority
            fail CommitUncertain

    after confirmed enrollment:
        require the returned result confirms current candidate membership
        reconcile lookup indexes with committed membership
        persist the displaced public key and matching Turnkey user/policy
        remove that Turnkey user/policy; retain unfinished cleanup for retry
        log secondary cleanup failures
        return success
```

A healthy Turnkey-backed passkey/OIDC login finishes with the key in both stores. Current absence is not proof that an outstanding registration will never commit. Do not rotate the candidate, remove either lookup, or delete provisional authority to escape uncertainty.

`replace_oldest_if_full` defaults false for existing service callers; Bedrock enables it for login and reauthorization, without a new public manager argument. Missing activity uses creation time only for capacity ranking, never for stale cleanup. An active device may be displaced and must reauthorize. Preserve the archive reference/hash/key during membership writes.

Resolve retries of consumed enrollment tokens to the recorded result after checking the bound attempt and key proof; never repeat eviction or resurrect a subsequently revoked key. Keep the result retrievable under main authorization if the new key was later revoked. Lookup entries confer no authority without current membership; repair indexes from confirmed state after ambiguous writes. Turnkey cleanup failure is logged/deferred without undoing enrollment. There is no cross-service transaction.

## Authentication

These rules are shared by login, reauthorization, addition, and privileged management.

**Factor activity:** update `last_used_date` on successful main/sync authentication, at most once per day using service time. Activity and membership share the conditional metadata write, preserving the archive reference. A required activity-write failure fails authentication; missing history remains unknown.

**OIDC:** create a temporary P-256 key; request the native token with nonce `SHA256_HEX(UTF8(HEX(compressed_public_key)))`. Use Turnkey Auth Proxy `/v1/oauth_login` with the configured `X-Auth-Proxy-Config-Id`, requesting a five-minute session without invalidating others. Verify the session's organization/main user against authenticated service metadata with a signed Turnkey query. The app backend is used only to create the Turnkey account. Sign service challenges with that ephemeral key; verify issuer, audience, expiry, nonce, signature, and operation binding. Consume both the OIDC nonce and service challenge once. A consumed token needs a fresh ceremony.

**Passkey:** one discoverable assertion authorizes both systems. Extend service retrieve/verify challenges to accept the exact Turnkey `ACTIVITY_TYPE_STAMP_LOGIN` activity, targeting the configured parent organization with a five-minute expiry and `invalidateExisting = false`. The WebAuthn challenge is `UTF8(lowercase_hex(SHA256(exact_activity_bytes)))`; submit the byte-identical stamped activity to Turnkey when the backup has an organization. A passkey-only backup needs no organization.

The service verifies credential signature, `webauthn.get`, RP/origin/cross-origin rules, user presence and verification, and operation binding. Reject activities older than five minutes or more than 30 seconds in the future. Burn the challenge and activity fingerprint across newly issued tokens; fingerprint retention includes clock skew and fails closed. Preserve the old challenge format until released clients migrate. Share this verifier with factor addition.

**Existing iCloud:** load the selected main-factor key, never substitute a sync key. It can authorize service recovery and upgrades, but cannot grant Turnkey main authority. Android has no iCloud login ceremony; it can still display/remove these factors. No new iCloud enrollment.

Passkey/iCloud recovery may finish service enrollment while Turnkey is unavailable, reporting incomplete device authorization. OIDC recovery cannot export its factor secret without Turnkey and must fail. A degraded result must never claim that both services authorized the device.

**Native ceremonies:** iOS retains main-thread presentation/dismissal and its OS capability guards. Android retains Activity access, cancellation/fallback handling, and the legacy PRF result. Android Apple authentication remains an explicit unsupported-capability error until its ceremony exists. Native forwards Bedrock's passkey labels unchanged; OS rename/orphan notifications remain native, without claiming unconfirmed credential deletion or rename.

## Shared service types and native bindings

Pin the public `backup-service-types` Git revision with `default-features = false` and update the lockfile. Keep UniFFI out of that crate. Reuse its endpoint declarations and request/response/auth/error types through the existing HTTP client; service changes update the shared types and Bedrock pin before native adoption.

Use UniFFI remote declarations for identical types: enums such as `OidcProvider` and `BackupEncryptionKey`, records such as `BackupStatusResponse` and `ExportedFactorSlim`. Retain full typed metadata privately, including passkey registration and OIDC subject; project once into the existing native metadata views. Ceremony inputs remain separate from service authorization and registered-factor metadata.

Remote declarations must fail compilation when closed variants or payloads change. Equal-set native mirrors use exhaustive conversions in both directions without default arms; narrower views explicitly handle every source variant/field without inventing reverse conversions. Keep the service's `ErrorCode::Unknown` fallback. Unknown metadata values are never valid authentication inputs.

Delete native wire enums with their network callers and update analytics/last-login mappings. Retain UI provider enums only where a module boundary needs them; map exhaustively in the live adapter. Reuse Bedrock `Os` for service `Platform`; no additional public platform enum.

## Adoption and documentation

Adopt each native button handler, flow call, and ceremony adapter together, deleting the replaced orchestration in that PR. Deploy service changes first while preserving released-client contracts. Existing creation/reauthorization callers must supply the verified encryption public key before server enforcement. App-backend wallet login/account deletion and legacy Drive/iCloud-file recovery remain native.

Update the existing docs alongside adoption: `world-app/backup/{index,components,factors,structure-and-sync,flows,advanced}.mdx`, `world-app/bedrock.mdx`, and `snippets/backup/terms.mdx`. Preserve BF-1–BF-10 anchors, label unreleased behavior, and link to Bedrock for signatures. Correct claims about service-side decryption, Turnkey private keys, quorum/permissions, and the migration anchor; verify platform capability claims against the adopted code.

## Verification across the boundaries

- Use sanitized V0 fixtures from both apps, including both referral formats and PRF salt variants. Rust tests own shared flow behavior; native tests cover bindings, ceremony cancellation, secret transfer, and temporary-file lifetime.
- Cover concurrent archive/factor writes, lost-response enrollment retries, simultaneous last-factor removals, and invalid/oversized/reused Siegel handles. These must preserve committed data, factor membership, and secret boundaries. Verify that a required activity-write failure fails authentication.
- Compile the pinned service types and Swift/Kotlin bindings. Temporarily add source variants/fields, and native variants for equal-set mirrors, to prove the declarations/mappings fail compilation. Serialization fixtures check wire tags and fields separately.
- Verify real provider ceremonies with working and missing PRF support, one prompt for login/reauthorization, existing-before-new prompts for addition, and recovery in both platform directions. iOS device/macOS checks remain required even when development happens on Linux.

## Errors and reporting

Use bounded network retries and Turnkey activity polling. OS ceremonies have their own cancellation and timeout; do not spend the HTTP retry deadline while the user is authenticating. Never blindly retry an ambiguous remote mutation.

One Bedrock operation owns its existing ClientEventsReporter event. Keep native screen/funnel analytics and consent behavior; remove duplicate flow events. Surface actionable primary errors (`RemoteAhead`, `UpdateRequired`, `CommitUncertain`, `Busy`, `RecoveryPending`) and log secondary cleanup failures internally. Do not log secrets, response bodies, or unmasked identities. Telemetry failure never changes a successful operation result.

## Interface decisions to finish

These gaps are in the current design/stubs; implementation must not invent competing solutions.

- **Consumer handoff:** the stubs still need a way to deliver consumer validation/classification results before `finalize_login`; otherwise it cannot know when to persist `UpdateRequired` or retire keys. Define when `requires_app_update` is authoritative, since consumer validation follows `login`. File identity/source handling is defined above.
- **Previously shared sync keys:** define the transition to independent client keys before enabling unconditional revocation on logout. Revoking an old shared key would also revoke the other app.
