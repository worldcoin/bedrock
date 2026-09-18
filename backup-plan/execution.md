# Backup migration: PR splits and checkpoints

Each row is a separate PR per listed repository. Checkpoints are tested integration commits within the planned single release. Prepare native adapters incrementally; switch each app's stateful flows together so old and new code never own different manifests. A completes only when released create/sync/login/add/remove requests still work.

| Checkpoint | PR | Repositories | Completion / dependency |
| --- | --- | --- | --- |
| **A. Service and library pre-work** | Atomic archive publication | backup-service | Immutable archives and conditional metadata publication; existing writers preserve the archive reference. **Gate:** resolve ambiguous publish attempts before accepting another batch. |
| A | Encryption-key binding | backup-service | Add verified public-key storage and checks. Keep released requests compatible; enforcement waits for the client rollout gate below. |
| A | Replayable creation | backup-service, app backend | Resolve lost creation/provisioning responses using the same attempt. **Gate:** agree the terminal retry contract before implementing. |
| A | Shared login proofs | backup-service | Turnkey-compatible passkey proofs, authenticated metadata, and sync-registration tokens. Preserve the released challenge format and specify the signed operation binding. |
| A | Factor activity | backup-service | Server-owned last-used timestamps for main and sync factors. |
| A | Device capacity | backup-service | Atomic add/replace and replayable enrollment results, after activity tracking; replacement defaults false for old callers. **Gate:** protect historical shared keys during the ownership transition. |
| A | Existing-first addition | backup-service | Authorize the existing main factor before creating the new credential; reuse the shared proof verifier. |
| A | Conditional factor removal | backup-service | Enforce last-factor confirmation at commit. **Gate:** agree how removal retires Turnkey authority so concurrent additions cannot reuse cleanup targets. |
| A | Root-secret handoff | Bedrock | One-use Rust-to-native Siegel transfer through Swift/JNI, including invalid/reused-handle checks. |
| A | Vault restore | WalletKit | Transactional, retry-safe import for new login and confirmed replacement. |
| A | Oxide restore | Oxide | Owned validation/import for orb, document, and face packages; resumable imports. |
| A | Shared service types | Bedrock | Pin the completed service contracts; retain full metadata privately, including passkey registration. Compile Swift/Kotlin bindings and exhaustive enum mappings. |
| **B. Bedrock flows ready** | Safe archive staging | Bedrock | Bounded V0 parsing, original inventory, unknown entries, and isolated staging; after shared types. |
| B | Manager state and reads | Bedrock | Account/signer binding, local state, status, metadata, inventory, and update checks. No native state migration is activated yet. |
| B | File sync | Bedrock | Complete-source batches, conditional publication, and interrupted-commit resolution; after staging and manager state. |
| B | Passkey creation | Bedrock | Initial upload and replayable creation; after file sync. |
| B | OIDC creation | Bedrock | Backend provisioning, canonical Turnkey setup, and initial upload; reuse passkey creation bookkeeping. |
| B | Login and finalization | Bedrock | Shared staged recovery, OIDC Auth Proxy login, device enrollment, finalize/cancel; after Siegel, consumer APIs, and service prerequisites. **Gate:** settle revoked-candidate recovery and degraded-enrollment outcomes. |
| B | Passkey login | Bedrock | Passkey-only and Turnkey-backed recovery through the shared completion flow. |
| B | Existing iCloud Keychain login | Bedrock | Existing-factor recovery through the same completion flow; no enrollment of new iCloud factors. |
| B | Device reauthorization | Bedrock | Candidate enrollment and promotion without restoring files; after the shared enrollment flow. |
| B | Existing migrations | Bedrock | Route the implemented runner through the manager and ceremony handler; no missing repairs or stale-factor cleanup. |
| B | Add OIDC factors | Bedrock | Existing-first addition, passkey-only upgrades, and all Apple audiences; after authorization and Turnkey prerequisites. |
| B | Add passkeys | Bedrock | Existing-first passkey addition using the same orchestration. |
| B | Backup deletion | Bedrock | Service deletion, Turnkey cleanup, and account-state clearing. |
| B | Adapt factor removal | Bedrock | Reuse removal logic with bound state, ceremonies, conditional confirmation, iCloud removal, and safe Turnkey cleanup; after deletion. |
| B | Backup reset | Bedrock | Root-authorized reset and break-glass cleanup, reusing deletion bookkeeping. |
| B | Device logout | Bedrock | Revoke only this client's signer and clear local state; retain best-effort remote failure behavior. |
| **C. Native wiring prepared** | Ceremony adapters | iOS, Android | OS presentation, cancellation, OIDC nonce handling, passkey results, and iOS existing-keychain access. Test callbacks without changing live callers. |
| C | Backup source adapters | iOS, Android | One batch across Oxide/vault/referrals; stable entry IDs and fresh temporary exports. Replace producer callers only at the app cutover. |
| C | Restore coordinator | iOS, Android | Persist the pending candidate signer separately; promote only after confirmed enrollment. Securely store the root, validate/import consumers, implement retry-safe referral imports, and resume/finalize/cancel after restart. Test without activating live callers. |
| C | Account and settings adapters | iOS, Android | Wire reads, creation, reauthorization, factor management, migrations, and teardown. Map each app target to its private signer/state; stop key transfer at cutover. Set startup blocking-screen priority and stop/wait for producers before replacement or logout. |
| **D. iOS cutover** | Replace live native orchestration | iOS | After A–C, for each app target: establish signer ownership and validate/migrate legacy state before enabling producers; switch all manifest readers/writers, recovery, signer promotion, remove-last-factor, reset/delete, and logout together. Delete old callers. Verify upgrade, restart, recovery, and released-client interoperability. **Gate:** resolve the legacy-validation ordering in `init`. |
| **E. Android cutover** | Replace live native orchestration | Android | Same per-app ownership switch after A–C; remove old callers and cached Turnkey sync-user IDs. Verify upgrade, restart, cross-app handoff, and recovery/sync in both platform directions. D and E may land independently. |
| **F. Remove unused exports** | Delete superseded APIs | Bedrock | After both native cutovers: remove low-level exports and legacy global-manifest access once caller checks are empty. Preserve legacy cloud-file recovery and existing migration behavior. |
| F | Encryption-key enforcement | backup-service | Enable only when supported released clients supply the key; a merged native PR alone is insufficient. Keep the compatible service contract until that condition holds. |
| **With each adoption** | Update existing documentation | toolsforhumanity/docs | Update the corresponding pages and BF flow anchors in the adoption checkpoint; do not defer documentation to the final cleanup. |
