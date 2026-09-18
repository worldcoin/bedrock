# Backup migration: PR splits

| Split | PRs (one per repository) | What ships | Depends on |
| --- | --- | --- | --- |
| 1. Shared service types | Bedrock | Shared HTTP types and UniFFI bindings, used by the existing metadata/removal clients. | — |
| 2. Atomic archive publication | backup-service | Upload immutable archives and conditionally publish their metadata reference. | — |
| 3. Encryption-key binding | backup-service, iOS, Android | Store/check the backup encryption public key; update existing native callers before enforcement. | 2 |
| 4. Safe archive staging | Bedrock | Bounded V0 parsing, unknown-entry handling, and isolated staging without writing to consumer storage. | 1 |
| 5. Root-secret handoff | Bedrock | One-use Rust-to-native Siegel transfer through the Swift/JNI bindings. | — |
| 6. Vault restore | WalletKit | Transactional, retry-safe import for new login and confirmed replacement. | — |
| 7. Oxide restore | Oxide | Validate and import orb/document/face packages into owned storage; resume interrupted imports. | — |
| 8. Manager state and reads | Bedrock, iOS, Android | Initialize account/signer and native ceremony callbacks, migrate local state, and adopt status, metadata, inventory, and startup update checks. | 1, 3 |
| 9. File sync | Bedrock, iOS, Android | Complete-source batches, conditional uploads, and resolution of interrupted commits. | 4, 8 |
| 10. Passkey creation | Bedrock, iOS, Android | Create a passkey-backed backup, including its initial upload. | 9 |
| 11. OIDC creation | Bedrock, iOS, Android; app backend if needed | Provision Turnkey through the backend and create the complete OIDC-backed backup. | 10 |
| 12. Shared login proofs | backup-service | Turnkey-compatible passkey authentication; verify-factor returns metadata and a sync-registration token. | — |
| 13. Factor activity | backup-service | Server-owned last-used timestamps for main and sync factors. | — |
| 14. Device capacity | backup-service | Atomic add/replace at capacity, with replayable enrollment results. | 13 |
| 15. OIDC login and completion | Bedrock, iOS, Android | OIDC login through Auth Proxy; shared staging, consumer adapters, finalize/cancel, and device enrollment. | 5, 6, 7, 11, 12, 14; [consumer handoff agreed](flows.md#interface-decisions-to-finish) |
| 16. Passkey login | Bedrock, iOS, Android | Recover passkey-only and Turnkey-backed backups through the shared login/completion flow. | 15 |
| 17. Existing iCloud Keychain login | Bedrock, iOS | Recover through existing keychain factors using the shared completion flow. | 15 |
| 18. Device reauthorization | Bedrock, iOS, Android | Authorize a new signer without restoring files; promote it only after confirmed enrollment. | 16, 17 |
| 19. Existing migrations | Bedrock, iOS, Android | Route the already-implemented migration runner through BackupManager; preserve its current repairs and prompts. | 18 |
| 20. Independent app keys | iOS, Android | Give each client its own signer and migrate existing shared-key installations. | 18; [shared-key transition agreed](flows.md#interface-decisions-to-finish) |
| 21. Existing-first factor authorization | backup-service | Authorize an addition before invoking the new factor's ceremony. | 12 |
| 22. Add OIDC factors | Bedrock, iOS, Android | Existing-first addition, Turnkey provisioning when needed, and all Apple audiences. | 18, 21 |
| 23. Add passkeys | Bedrock, iOS, Android | Existing-first passkey addition, including the missing native enrollment UI. | 22 |
| 24. Last-factor confirmation | backup-service | Enforce deletion confirmation in the conditional factor-removal write. | — |
| 25. Backup deletion | Bedrock, iOS, Android | Delete the backup and Turnkey organization, then clear local account state. | 18 |
| 26. Adapt existing factor removal | Bedrock, iOS, Android | Use bound state and ceremony callbacks, adopt service-side confirmation, and support existing iCloud Keychain factors. | 24, 25 |
| 27. Backup reset | Bedrock, iOS, Android | Root-authorized reset and break-glass cleanup, reusing deletion bookkeeping. | 25 |
| 28. Device logout | Bedrock, iOS, Android | Revoke this client's signer and clear local state before native key erasure. | 20, 25 |
| 29. Remove superseded APIs | Bedrock, iOS, Android | Remove remaining unused low-level backup exports and native service orchestration; retain legacy-file recovery and existing migrations. | 19, 23, 26, 27, 28 |
| 30. Documentation per adopted flow | toolsforhumanity/docs | Update the corresponding existing pages and BF flow anchors as each native flow is adopted. | Corresponding flow |
