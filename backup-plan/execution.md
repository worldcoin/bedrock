# Backup migration: implementation units

The contracts in [design.md](design.md) and [flows.md](flows.md) are shared. Implementers do not
introduce alternative public account/auth/session structures. A needed change to those contracts
comes back to the integration owner before parallel implementation proceeds.

Native still supplies/consumes data owned by WalletKit and Oxide: vault export/import, PCP reload,
referral-store access, and root-key persistence. Those are storage boundaries, not a reason to
retain native backup networking, challenge handling, or Turnkey DTOs. App-backend wallet
login/account deletion remain native account-lifecycle operations.

## Execution conventions

Start from [PR #440](https://github.com/worldcoin/bedrock/pull/440). The stubs omit receivers, Arc,
FFI attributes, and Result; add them where implementation requires them. Export a method and each
`FactorRegistration` variant only when their flows work. Reuse the existing clients, signer, factor
types, and migration outcomes.

Legacy iCloud-file/Google Drive migration, hardware-key rollout, and cross-app handoff redesign
remain separate. Existing iCloud Keychain factors support recovery, removal, and authorization of
passkey/OIDC upgrades; no new iCloud factors.

## Shared type wiring

Depend on the existing
[backup-service-types](https://github.com/worldcoin/backup-service/tree/main/types) crate with a
pinned public Git revision and `default-features = false`, following Bedrock's existing Git
dependency convention. Commit the lockfile update. Keep shared HTTP types independent of UniFFI;
Bedrock owns their native bindings. Every service API change updates
`types/src/{lib,endpoints,error}.rs` as applicable; update Bedrock's pin and adapters before native
adoption of that change.

| Boundary | Decision |
| --- | --- |
| Service HTTP | Use shared request/response types, `Authorization`, `OidcToken`, `FactorScope`, `Platform`, and `ErrorBody`. Reuse `Endpoint` paths, methods, body kind, response type, attestation requirement, and multipart/header constants through the existing client. Delete replaced private wire DTOs; no new transport framework. |
| Identical FFI types | Reuse shared `OidcProvider` and `BackupEncryptionKey` with `uniffi::remote(Enum)`. The declaration describes the existing Rust type; it does not create a second enum. |
| Metadata exposed to native | Keep existing `BackupMetadata`, `BackupFactor`, `BackupFactorKind`, and `BackupOidcAccount` only as the needed FFI views. Convert from typed service metadata once; keep passkey registration and OIDC subject in the private source data for Turnkey flows. Do not parse HTTP directly into a view that drops those fields. |
| Ceremony inputs | `FactorRegistration` and `FactorAuthentication` remain operation inputs. Neither service `Authorization` nor registered-factor metadata fits this role. Existing Bedrock `FactorType` describes encryption, not authentication; remove it with its replaced low-level callers. |
| Native adapters | Use generated Bedrock enums at the ceremony boundary. Preserve an existing UI enum only where its module boundary requires it; map once in that module's live adapter. Reuse configured Bedrock `Os` and map to service `Platform`; no new public platform enum. |

For example, the provider binding uses [UniFFI remote
enums](https://mozilla.github.io/uniffi-rs/0.32/types/remote_ext_types.html):

```rust
pub use backup_service_types::OidcProvider;

#[uniffi::remote(Enum)]
enum OidcProvider { Google, Apple }
```

The generated exhaustive match and constructors make missing/extra variants or changed payloads a
compile error. Keep the same mechanism for identical closed enums; no variant-count assertions or
new mapping macro. When a separate enum is required, use exhaustive conversions in both directions
for equal variant sets, without wildcard/default arms. For deliberately narrower views, exhaustively
match the source variants and destructure every source field without `..`; explicitly omit fields
excluded from FFI and retain the original typed response wherever private data is needed. Do not
fabricate reverse conversions for information-losing views.

These checks apply when the pinned dependency or generated bindings change, not automatically when
remote main changes. Service `ErrorCode` is intentionally non-exhaustive with `Unknown`: reuse it
and keep the generic error fallback. Unknown metadata/UI values are unsupported authentication
choices. Serialization fixtures still cover tags, field names, optional fields, and Apple token
audiences; exhaustive matches alone do not verify the wire format.

## Work split

Each row is an independently reviewable unit of value, usually one Bedrock/service PR plus small
native adoption PRs. Split transport plumbing from a flow only when the plumbing has a working
consumer and tests; no exported TODO methods or temporary public wrappers. Dependencies refer to
rows. Existing native flows remain until their replacements are adopted, then are deleted in that
adoption PR. This is release sequencing, not permanent compatibility shims.

| Unit | Concrete change / owned modules | Depends on | Acceptance |
| --- | --- | --- | --- |
| A | backup-service `turnkey_activity.rs`, passkey retrieve/verify/add-factor routes, challenge manager and endpoint types: STAMP_LOGIN challenge binding, full WebAuthn verification, fingerprint replay protection; verify returns metadata + sync token. | None | Same real staging assertion accepted by both systems; cold parent-org discovery, wrong origin/RP/UV, altered activity, future timestamp, replay with a fresh token; PRF results rejected. |
| B | One-use handoff of the recovered Login root to native: Siegel Rust → native transfer and Swift/JNI buffer adapters. | None | One consumption; invalid handle/length including >1MiB; second read rejected; native buffer wiped; no JSON root field in the new recovery binding. |
| C | Bedrock `backup/mod.rs`, `manifest.rs`, `backup_service/{mod,wire}.rs`, new `flows/sync.rs`: bound account ID, startup head check, old-state adoption, pending-manifest resolution, direct batched sync. | #440, Q, R | Old global manifest adopted only after ID/hash check; mismatch preserves files; one upload per batch; empty/unchanged no upload; root mismatch; Busy; startup divergence; same-inventory recreation with a different encryption key; timed-out commit recognized after vault re-export; temp-file lifetime. |
| D | Bedrock `backup_format/v0.rs`, `manifest.rs`, file-policy helper and atomic filesystem publication: bounded one-entry-at-a-time parse, allowlist, raw designators, retirement, staging/publication. | C | Malicious archive publishes nothing; all observed paths accepted; mixed referrals preserved; unsupported entries block rewrites; app update + ResumeSync clears the block; full original inventory retained; interrupted per-file publication resumes. |
| E | Bedrock `turnkey/api.rs`, policies and `flows/create.rs`; unified `create(FactorRegistration, ...)` and both native creation callsites. | C, D | Platform-correct passkey options and native labels; complete initial backup; required break-glass/quorum; root ownership; no backup-enabled result after a failed initial upload; uncertain create retains authority; late commit recognized from pending manifest; initial OIDC provider included in main-user creation. |
| F | Bedrock private authentication helpers and `flows/recover.rs`; iOS/Android login, cloud-list, authorize-device adapters. | A, B, D, P, O | Selected-account validation; healthy login registers both stores only at completion; iCloud login retained; degraded Turnkey result; all three restore modes; persisted UpdateRequired visible with unchanged head; restart before root transfer/after vault import/during publication/after return before reload; pending recovery surfaced; pre-registration cancel, completion-only after vault replacement, and post-registration resume; reauth never imports files. |
| G | backup-service enrollment: new passkey, existing OIDC/iCloud, same-identity retries; authenticated OIDC subject; narrow repair-factor challenge/route. | A | Proof of both factors, bound new identity, shared WebAuthn verifier/activity replay rejection, single PRF key, wrong-account denial, duplicate retry; main authority repairs only an existing factor reference without the broken factor's login. |
| H | Bedrock `flows/add_factor.rs`; unified `add_factor(FactorRegistration, ...)` and both factor settings adapters. | E, F, G | Passkey to OIDC and OIDC to passkey; additional OIDC; all Apple audiences; existing Turnkey blocks iCloud-only addition before ceremony; OIDC/iCloud validation before new-passkey registration; iCloud cannot be created; missing Turnkey provisioned once; concurrent retries never remove shared credentials. |
| I | backup-service `delete_factor`, storage conditional mutation and endpoint types: atomic last-factor confirmation. | None | Two concurrent removals cannot delete the backup without confirmation; MAIN/SYNC target/context checks; old missing flag defaults false. |
| J | Bedrock `flows/{remove_factor,delete_backup,reset,logout}.rs`; native reset/logout/account-delete callsites. | C, E, F, I | Reset deletes Turnkey through break-glass; missing break-glass returns incomplete cleanup; retry never deletes a live/new suborg; logout clears local state after remote timeout/auth failure, tries both stores, preserves backup/other factors; pending recovery blocks teardown; local deletion errors surface; imported-key/local-reset paths make no remote calls. |
| K | Bedrock migration files: root quorum, break-glass, main-factor consistency; extend existing Apple/policy repairs. | E, F, G | Already-correct state emits no writes; main required/deferred; missing provider anchor repaired; all Apple audiences; unknown audience/user preserved; no last working authority removed. |
| L | backup-service auth/metadata: daily last-used timestamp and membership share one conditional write; onlyIfStale deletion predicate. | None | Activity updated at most daily; no client timestamps; missing history remains unknown; touch failure fails auth; a touch during expired-lock eviction forces reread; archive reference preserved. |
| M | Bedrock migration files: public-key sync reconciliation and 25/365 paired cleanup; delete native stale-user workers. | F, K, L | Old service-only passkey device preserved/repaired; active sync-only device retained; stale and excess pairs removed from both stores; revoked keys never resurrected; incomplete listings and unpaired users preserved. |
| N | Both native projects + Bedrock export cleanup. | A–M, O, P, Q, R | No native backup-service/Turnkey network orchestration; one BackupManager; old codec/signing/manifest/Turnkey exports and duplicate DTOs removed; binding tests and platform flow smoke tests pass. |
| O | backup-service add-sync conditional replacement; reuse current challenge and registration-token authorization. | L | Failed/conflicting add preserves old membership; one selected replacement with new-key possession; known stale vs unknown history; concurrent activity/enrollment; no repeated eviction on retries. |
| P | WalletKit transactional, idempotent `import_backup_once`; native Swift/Kotlin adapters. | None | Empty-only import; confirmed replacement; invalid source and mid-copy error preserve old vault; crash after commit resumes via receipt; same content in a new attempt still imports; receipt not exported. |
| Q | backup-service archive storage and metadata: conditional immutable-archive publication and encryption-public-key binding; main-authorized initialization for existing backups. | None | Failed publication leaves the old archive readable; concurrent sync/factor updates keep archive and hash consistent; existing backups remain readable; missing-key upgrade requires verified unwrap; changed/missing expected key rejects sync; cleanup preserves selected objects and in-flight readers. |
| R | Bedrock dependency/lockfile and `backup_service/{mod,wire}.rs`: shared contract types, UniFFI declarations, and existing metadata/removal clients. | None | Current metadata/removal behavior preserved; shared endpoint routing/serialization; raw registration retained; changed shared variants/fields fail compilation; generated Swift/Kotlin bindings and live adapters compile. |

E is two PRs (passkey creation, then OIDC creation). F is three (OIDC recovery + shared completion,
passkey recovery, iCloud recovery); J is reset, removal extension, then device logout. K and M ship
one migration per PR. Each has its own native adoption PRs and the row's relevant acceptance tests.
Q is two PRs: immutable archive publication, then encryption-key binding with the native request
fields needed for rollout. Existing creation/reauthorization callers supply the verified public key
until their Bedrock replacements land. These subdivisions preserve the contracts; they are not
permission to bundle a whole row's flows.

Suggested parallel start: A, B, I, L, P, Q, R; C follows Q and R. After shared interfaces land, D
and native callback adapters can proceed independently; E starts after D, and authentication F
unlocks remaining flows. One integration owner coordinates shared `backup/mod.rs`, service
`types/src` contracts, endpoint mutations, exports, and dependency pins. Flow agents own distinct
files; they submit changes to shared types through that owner. Writers use separate worktrees.
During C, old native create/restore callers bind and adopt their existing state before invoking new
sync methods. Keep the old network callback only while a remaining old flow consumes it; delete each
replaced caller at adoption.

Unit B extends Siegel's existing session: fill from Rust, copy once through checked C/JNI into a
native-owned buffer, then consume/wipe. Preserve its existing length bounds; native stores then
wipes its buffer. Confine any conversion required by current wallet models to the secure-store
adapter.

Unit D reuses tar/ciborium and extracts atomic file promotion from the existing filesystem writer.
Do not buffer the whole expanded archive or add a separate streaming decoder.

## Native changes

Paths below are relative to each repository. Use the names to locate the concrete files; the final
adoption diff must delete replaced behavior, not wrap it in another service.

| iOS entry point | Replacement |
| --- | --- |
| `AccountRecovery/Core/AccountManagementService.swift` create/login/authorize/sync/reset | Call corresponding BackupManager methods; remove challenges, key wrapping, Turnkey import/export, Auth Proxy/backend recovery calls, and network retry decisions. |
| `FactorEnrollmentService.swift`, `TurnkeyService.swift` and its operation extensions | Ceremony implementations move to `MainFactorCeremony`; delete Turnkey DTO/operation orchestration after callers migrate. |
| `BedrockBackupManager.swift`, `BedrockBackupServiceApi.swift`, `WLDBedrock/BedrockWrapper.swift` | One manager instance, startup head check, and callback registration; remove the native backup-service callback once C/F cover its callers. |
| `RestoreWalletLogInReducer`, `RestoreWalletCloudListReducer` | Validate selected account, consume Login root securely, import with WalletKit receipt, perform native login, complete recovery/register signer, reload PCP, then expose completion. |
| `AuthorizeDeviceReducer` | Persist signer and call reauthorize; handle TurnkeyStatus. No root transfer, files, vault import, or wallet login. |
| `BackupFactorsClient+Live`, `BackupMethodInfoReducer`, `SignInBackupFeature` | Implement reauth retry consistently, last-factor confirmation, incomplete cleanup, and add-passkey-to-existing-backup UI. Preserve OS capability checks. |
| `CredentialVaultBackupManager`, `AnonymizedUserIDsBackupManager`, `OxideBackupManager` | File producer/consumer adapters only; one batch per user mutation, awaited export lifetime, own-path referral Put, supported-path query for Oxide. Vault errors are no longer swallowed. |
| `AppReducer`, `AccountDeletion`, `KeyManagementService` | Await logout before erasing native keys/data; preserve keys on Busy/RecoveryPending; report remote/local cleanup failures; use None for intentional local reset; retain existing keychain-login access. |

| Android entry point | Replacement |
| --- | --- |
| `domain/.../backup/v2/usecase/CreateBackupVia{Passkey,OIDC}Factor` | Thin BackupManager calls; remove bootstrap/quorum/import/enrollment and post-create best-effort sync. |
| `RestoreBackupViaPasskey`, `RestoreBackupViaGoogleOAuth`, `RunTurnkeyMigrations` | Shared recovery/reauth contract; secure root handoff; persist pending signer before registration; remove blank Turnkey-user-ID sentinel. |
| `AddPasskeyBackedOIDCFactor`, `DeleteBackup`, `DeleteSyncFactor` | Shared add/remove/delete/logout flows; add missing passkey enrollment UI; provider choice no longer hardcoded to Google in shared DTOs. |
| `BackupAccessService`, `ExternalAccountService`, `P256KeypairSigner` | Implement native ceremonies and existing signer only. Preserve the old Android PRF second result; no challenge token retained in UI state. |
| `BackupServiceImpl`, `TurnkeyServiceImpl`, networking `BackupServiceApi`, Turnkey DTOs | Remove migrated current-system network methods/DTOs; retain app-backend wallet/account operations and legacy Drive services. |
| `BedrockSdk`, `BedrockBackupServiceApi`, `OxideBedrockBridgeImpl` | Register one manager and `MainFactorCeremony` adapter; check the head at startup; batch file mutations; remove the native sync/metadata callback and old manifest methods. |
| `LocalSyncFactorStoreImpl`, `BackupSyncData`, `CleanupStaleTurnkeyUsers` | Keep storage compatibility for existing keys; remove duplicated runtime metadata, but retain cross-app wire fields/imported marker via `cross_app_metadata` and adoption; delete native stale-user algorithm/worker. |
| `ResetLocalAccountData`, `DeleteAccount`, `DeleteAllBackups`, cross-app import | Use logout(None) for local reset/imported keys and logout(Some(sync)) for device revocation; stop producers first, retain keys on Busy/RecoveryPending, and await teardown before native erasure; report cleanup failures. Current-system deletion stays explicit; legacy Drive deletion stays outside Bedrock. |

Both adapters pass actual capability failures to UI. Android does not yet implement Apple sign-in;
the shared API supports Apple without forcing a new native OAuth UI into this migration. iOS uses
its existing passkey OS guards (PRF requires iOS 18); OS rename/orphan notifications remain native.
Do not promise OS credential deletion/rename success when the OS supplies no confirmation.

Native wire enums disappear with their network callers: iOS `BackupMetadataAccountKind` and
`OIDCTokenKind`; Android networking `OidcAccountKind`. Update their analytics/last-login mappings.
Keep iOS `WLDAccount.BackupOAuthProvider` if its module boundary requires it, with exhaustive
conversions in `WLDAccountLive/BackupFactorsClient+Live.swift`. Android `OidcFactorKind.Unknown`
remains a metadata/UI state and is explicitly rejected for authentication. Use exhaustive Swift
`switch` and Kotlin `when` expressions in live adapters, with no default hiding new known providers;
Android's Apple branch returns the existing unsupported-capability error until its ceremony ships.

## Documentation updates

Update [toolsforhumanity/docs](https://github.com/toolsforhumanity/docs) alongside each native
adoption. Keep the existing pages and BF-1–BF-10 anchors; document deployed behavior and label any
unreleased change. Link to Bedrock for signatures/policies instead of copying another API contract.

| Existing page | Update | Units |
| --- | --- | --- |
| `world-app/backup/index.mdx`, `world-app/bedrock.mdx` | One manager, native boundaries, operation-scoped root. | B, C, E, F, N |
| `world-app/backup/components.mdx` | Shared authentication, actual main/sync/break-glass permissions, repair and device activity; archive publication guarantee. | A, E, G, I, K–M, O, Q |
| `world-app/backup/factors.mdx` | One passkey; PRF compatibility; all Apple audiences; existing-only iCloud factors; verified platform/storage capabilities. | A, E, F, H, J, K, N |
| `world-app/backup/structure-and-sync.mdx` | Replace ManifestManager API; batches, startup check, commit uncertainty, validated restore, accepted/retired/unsupported files. | C, D, F, P, Q |
| `world-app/backup/flows.mdx` | Update BF flows for complete creation, staged recovery, reauthorization, symmetric addition/removal, incomplete cleanup and device management. | A–Q |
| `world-app/backup/advanced.mdx` | Confirmed replacement versus update-resume; restart behavior; dependency failures; reset and stale-device cleanup. | C, D, F, I, J, L, M, O, P |
| `snippets/backup/terms.mdx` | Distinguish transient private keys from persisted public keys and encrypted key material. | C, N |

Separate factual corrections need no new feature: the service stores ciphertext but cannot decrypt
it; Turnkey registers native public keys; remove contradictory quorum history and factor-permission
claims; fix the migration anchor. Check platform capability claims against the adopted native code.
The cryptographic primitives remain unchanged, so `world-app/cryptography.mdx` needs no new section.

Keep passkey-only backups independent of Turnkey; create an organization when OIDC is first added.
Eager Turnkey creation and retiring stored passkey registration are a separate product decision.
Weekly sync-key rotation, absolute key expiry, and backup/factor-key or PRF-salt rotation need
separate credential/format transition contracts; inactivity cleanup is not rotation. Hardware-key
rollout and cross-app handoff changes remain separate. Additional providers/m-of-n, factor-storage
unification, and migration campaigns require separate requirements. Automatic removal of unpaired
Turnkey users needs enrollment coordination; preserve/report them until that contract exists.

Fetch origin/main before implementation and inspect the relevant modules. E verifies creation
idempotence and deleted-suborg recreation with the app-backend owner before rollout. Review the
current TODOs and unresolved audit findings in every touched service path; an old checklist is not
evidence they were fixed.

## Verification and completion

Use fixture-driven Rust flow tests at HTTP/filesystem/authentication boundaries. Include real V0
archives from both platforms with secrets replaced, both PRF salt variants, and both referral
formats. One shared suite owns flow decisions; Swift/Kotlin tests check `FactorRegistration`
variants, FFI shapes, async callback cancellation, signer encodings, secret transfer,
temporary-file lifetime, and caller sequencing. Do not duplicate the entire state-machine suite
in each native language. On each platform, verify a supported PRF provider, actionable
missing-PRF failure, and cross-device recovery that preserves the existing backup. Check native
analytics consent and single operational-event emission.

For R, compile the actual shared dependency and generated Swift/Kotlin adapters. During
verification, add a temporary source enum variant/field and confirm the remote declaration or
projection no longer compiles; then restore it. For equal-set native mirrors, verify additions on
either side break their exhaustive mappings. Use fixture checks for deliberately unsupported values
and wire serialization.

For implementation PRs, follow repository CI: `cargo build`, targeted backup tests with `--features
test_utils`, `cargo fmt -- --check`, workspace/all-target/all-feature Clippy, `taplo fmt --check`,
generated binding/version checks, `cargo xtask kotlin test`, and macOS `cargo xtask swift build` /
`cargo xtask swift run-tests` plus native adapter tests/linters. Use the actual workflows at
implementation time for remaining required checks. A Linux devbox cannot certify iOS device
ceremonies or macOS builds; record those as required external checks.

Security acceptance is specific: no path escape or partial-archive publication; no root/token leak
in FFI/logs; no PRF sent over HTTP; no cross-account session/key attachment; no challenge or
activity replay; no unconfirmed last-factor deletion; no silent lost files or erased working factor
after an ambiguous write. Prove ordinary sync-only activity cannot trigger stale-device eviction.
