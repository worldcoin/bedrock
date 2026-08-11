# General Review Guidelines for AI Agents

### Code Style Guidelines

- When interacting with times, use `chrono` crate and UTC. Avoid `SystemTime`.
- Never have a `message` or `error` attribute name for any variant of any error enums. When UniFFI generates Kotlin exception classes, they inherit from `kotlin.Exception` which has a `message` attribute, having a duplicate one creates conflicts in Kotlin; `error` gets translated into the native `Exception` class.
- Using `#[error(transparent)]` without `#[uniffi(flat_error)]` is not a good idea as UniFFI does not support re-using types across different error enums at least on Kotlin.

## Module-specific Guidelines

### Smart Account

- Ensure that the `TransactionTypeId` is never re-ordered. Only additive changes are allowed or this would break all past transactions handling.

### Logging & alerting

`#[bedrock_export]` wraps every exported `pub fn` in a log context, so every record logged in that call tree, nested private calls included, is prefixed with `[Bedrock][<tag>]`. Do not hand-write that prefix in a message.

- The tag defaults to the struct name. Pass `log_tag = "…"` (e.g. `#[bedrock_export(log_tag = "Backup")]`) to log under a stable subsystem name instead. Monitors match on the tag, so it must not move when a struct is renamed or split.
- The context is thread-local. Never hold a `LogContext` guard across an `.await`: the prefix is lost as soon as the future resumes on another worker. Use `primitives::logger::in_log_context` for futures, which `#[bedrock_export]` already does for exported `async` methods.
- Keep the event token at the start of the message stable (`request.failed`, `applied migration=…`) and pass context as `key=value` pairs. Renaming a token silently breaks the monitor built on it.
- Use `crate::critical!` instead of `crate::error!` for state that needs immediate attention (a corrupt manifest entry, an inconsistent Turnkey account) rather than an ordinary failure. It logs at error level and adds the `[Critical]` tag after the context, giving `[Bedrock][Backup] [Critical] …`. Never write `[Critical]` into a message by hand.

### Backup & Turnkey

Tags in use, which the alerts are built on. `backup/log_tag_test.rs` fails the build when an exported impl in this module does not declare one of them:

| Tag | Covers |
| --- | --- |
| `[Bedrock][Backup]` | Backup & Recovery: `BackupManager`, `ManifestManager`, and everything they call (manifest, backup service client, backup format, client events) |
| `[Bedrock][Turnkey]` | Turnkey stamping and enclave bundle helpers |
| `[Bedrock][TurnkeyMigration]` | `TurnkeyManager::run_migrations`, the individual migrations, and the Turnkey API calls they make (transport retries, cache recovery) |

A log statement that is not reachable from one of those exported methods (a spawned task, a `#[uniffi::export]` free function) gets no tag: set one explicitly there.
