## Migration Controller
The Migration `controller.rs` is a simple state machine that runs a for loop over a series of processors and executes the processors. The processors contain logic around performing an individual migration and conform to a simple interface:

```rust
trait Process {
    /// Determines whether the migration should run.
    fn is_applicable(&self) -> bool;

    /// Business logic that performs the migration.
    fn execute(&self) -> Result<(), MigrationError>;
}
```

The migration system is a permanent artifact of the app and is run on app start to bring the app to a expected state. The processors are expected to be idempotent.

## States
The `controller.rs` stores a key value mapping between the id of the migration and a record of the migration. The record most importantly contains the status of the migration, but also useful monitoring and debug information such as `started_at`, `last_attempted_at`. 

The possible states are:
- `NotStarted` - migration has not been performed
- `InProgress` - migration started, but was interrupted
- `Succeeded` - migration successfully completed
- `FailedRetryable` - migration failed, but can be retried (e.g. there was a network error)
- `FailedTerminal` - migration failed and represents a terminal state. It can not be retried.

The migration state storage optimizes subsequent app starts by skipping `Succeeded` and `FailedTerminal` migrations without calling `process.is_applicable()`. For `NotStarted` and `FailedRetryable` migrations, `process.is_applicable()` is called each time to detect when they become applicable. This ensures migrations can respond to changing app state.

## State transitions
1. `NotStarted`
   - → `InProgress` when `is_applicable()` returns true and migration execution begins
   - Remains `NotStarted` if `is_applicable()` returns false (will be checked again on next app start)
   - → `FailedRetryable` if `is_applicable()` fails or times out

2. `InProgress`
   - → `Succeeded` when `execute()` completes successfully
   - → `FailedRetryable` if `execute()` times out or fails with retryable error
   - → `FailedTerminal` if `execute()` fails with terminal error
   - → `FailedRetryable` if detected as stale (app crashed mid-migration)

3. `Succeeded`
   - Terminal state. No further transitions. Migration is skipped on subsequent runs.

4. `FailedRetryable`
   - → `InProgress` when retry is attempted (after exponential backoff period)
   - → `Succeeded` if retry succeeds
   - → `FailedTerminal` if retry fails with terminal error
   - Remains `FailedRetryable` if retry fails again with retryable error (backoff period increases)

5. `FailedTerminal`
   - Terminal state. No further transitions. Migration is permanently skipped on subsequent runs.
