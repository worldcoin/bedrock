# General Review Guidelines for AI Agents

### Code Style Guidelines

- When interacting with times, use `chrono` crate and UTC. Avoid `SystemTime`.
- Never have a `message` attribute name for any variant of any error enums. When UniFFI generates Kotlin exception classes, they inherit from `kotlin.Exception` which has a `message` attribute, having a duplicate one creates conflicts in Kotlin.
- Using `#[error(transparent)]` without `#[uniffi(flat_error)]` is not a good idea as UniFFI does not support re-using types across different error enums at least on Kotlin.

## Module-specific Guidelines

### Smart Account

- Ensure that the `TransactionTypeId` is never re-ordered. Only additive changes are allowed or this would break all past transactions handling.
