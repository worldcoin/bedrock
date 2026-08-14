# General Review Guidelines for AI Agents

### Code Style Guidelines

- Use `crate::critical!` rather than `crate::error!` for state that needs immediate attention (a corrupt manifest, an inconsistent remote account). It logs at `LogLevel::Critical`, the severity alerts match on, so never write a `[Critical]` tag into a message by hand — not in a log, and not in an error's `Display` string either. If an error variant is alertable, `critical!` at the site that raises it.
- Pass the values a log is about as structured fields (`crate::error!(designator = entry.designator, "Checksum is unreadable")`), not interpolated into the message. Fields become log attributes the backend can filter and aggregate on; duplicating them in the message text only makes the line harder to group. Avoid keys log backends reserve: `message`, `status`, `service`, `host`, `timestamp`, `trace_id`, and anything under `error.*` (use `error_message`, not `error`).
- When interacting with times, use `chrono` crate and UTC. Avoid `SystemTime`.
- Never have a `message` or `error` attribute name for any variant of any error enums. When UniFFI generates Kotlin exception classes, they inherit from `kotlin.Exception` which has a `message` attribute, having a duplicate one creates conflicts in Kotlin; `error` gets translated into the native `Exception` class.
- Using `#[error(transparent)]` without `#[uniffi(flat_error)]` is not a good idea as UniFFI does not support re-using types across different error enums at least on Kotlin.

## Module-specific Guidelines

### Smart Account

- Ensure that the `TransactionTypeId` is never re-ordered. Only additive changes are allowed or this would break all past transactions handling.
