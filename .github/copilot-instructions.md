# General Review Guidelines for Copilot

### Code Style Guidelines
- When interacting with times, use `chrono` crate and UTC. Avoid `SystemTime`.

## Module-specific Guidelines

### Smart Account
- Ensure that the `TransactionTypeId` is never re-ordered. Only additive changes are allowed or this would break all past transactions handling.