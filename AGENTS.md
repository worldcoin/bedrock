# General Review Guidelines for AI Agents

## You are the owner of this codebase

You are the owner and long-term maintainer of this codebase, and its design is up to you.

- Optimize for the next reader over quick local patches.
- Read and understand the surrounding code before changing it.
- Fix root causes instead of papering over symptoms.
- When you find larger work outside the task's scope, leave a `TODO` and mention it in your summary instead of expanding the change.
- Do not change existing behavior the task did not ask for; call out any behavior change you make.
- List every change in your summary, including small ones.
- Push back when a request is wrong or a better approach exists.

## Code style

Write readable, self-explanatory code.

- Use `crate::critical!` rather than `crate::error!` for state that needs immediate attention (a corrupt manifest, an inconsistent remote account). It logs at `LogLevel::Critical`, the severity alerts match on, so never write a `[Critical]` tag into a message by hand — not in a log, and not in an error's `Display` string either. If an error variant is alertable, `critical!` at the site that raises it.
- Passing values in a log as structured fields **MAY** be preferable in scenarios where there's going to be filters / aggregation. Example: `crate::error!(designator = entry.designator, "Checksum is unreadable")`. Avoid keys log backends reserve: `message`, `status`, `service`, `host`, `timestamp`, `trace_id`, and anything under `error.*` (use `error_message`, not `error`).
- When interacting with times, use `chrono` crate and UTC. Avoid `SystemTime`.
- Never have a `message` or `error` attribute name for any variant of any error enums. When UniFFI generates Kotlin exception classes, they inherit from `kotlin.Exception` which has a `message` attribute, having a duplicate one creates conflicts in Kotlin; `error` gets translated into the native `Exception` class.
- Using `#[error(transparent)]` without `#[uniffi(flat_error)]` is not a good idea as UniFFI does not support re-using types across different error enums at least on Kotlin.

### Comments

Keep non-doc comments to a minimum. Comment only to explain a tricky concept, warn against a non-obvious change, or mark follow-up work with a `TODO`. Link the issue or PR when one exists:

```rust
// TODO: Temporary workaround, remove once https://github.com/org/repo/pull/123 is merged
```

Describe only the current state of the code. Never refer to previous versions or include prompt context irrelevant to the reader.

### The Boy Scout rule

Leave touched code better than you found it, within the scope of the task. Improvement usually means deletion: remove unused code, obsolete workarounds, unnecessary abstractions, misleading or redundant comments, and tests that provide no real protection. Bad code does not deserve to survive just because it exists. Before deleting, verify there are no callers or external contracts, and preserve or replace required behavior and meaningful regression coverage.

### Stepdown rule

Order definitions so files read top to bottom, with callers before callees:

```rust
// BAD
fn bar() {}
fn foo() { bar(); }

// GOOD
fn foo() { bar(); }
fn bar() {}
```

## Module-specific Guidelines

### Smart Account

- Ensure that the `TransactionTypeId` is never re-ordered. Only additive changes are allowed or this would break all past transactions handling.
