# Contributing Guidelines

Thank you for your interest in contributing to our project! This document provides guidelines and steps for contributing.

## General Guidelines

1. Create a Pull Request for any contribution. Pull requests should include clear descriptions.
2. Pull requests titles should follow [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/#summary) specifications. Pull requests may contain any number of commits. Commit messages do not need to follow Conventional Commits.
3. Everything must be documented following Rust conventions.
4. All new functionality must include relevant unit and integration tests.

## Local Development

1. Install Rust (`rustup` is recommended). [Instructions](https://www.rust-lang.org/tools/install)/
2. Configure your environment
   ```bash
   cp .env.example .env
   ```
3. Install Foundry. Anvil (from the Foundry toolkit) is required for functional tests with Solidity. Remember to source your profile after installing Foundry for the tools to be available in your PATH.

   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

4. Run tests to ensure everything is working as expected. This will run **all tests** including integration tests and doctests.
   ```bash
   cargo test --features test_utils,tooling_tests
   ```

### Dependencies for Foreign Tests

More details on running foreign tests can be found in the respective READMEs for [Swift](swift/README.md) and [Kotlin](kotlin/README.md).

1. For Kotlin, the following dependencies are needed:

   ```bash
   brew install openjdk@17 # current LTS
   brew install gradle
   brew install ktlint # to lint tests
   ```

2. For Swift tests, installing **Xcode** which iOS support is required. **Only works on macOS.**

### About Integration Tests

Integration tests deploy and interact with Safe contracts on a local fork of World Chain. This tests are are enabled by default and they require [Anvil](https://book.getfoundry.sh/anvil/overview#anvil) to be running.

### Universal wind-down vault integration

`test_uasset_universal_fork` runs automatically with the normal integration suite.
Like the other fork tests, it starts and tears down its own Anvil instance using
`WORLDCHAIN_RPC_URL` (or the public fallback). No separately prepared fork,
Universal checkout, or opt-in flag is required. Run it alone with:

```bash
cargo test -p bedrock --test test_uasset_universal_fork -- --nocapture
```

The test pins World Chain block `37242824` and applies the two-asset subset of
[Universal PR #17's setup](https://github.com/Alongside-Finance/universal-winddown/blob/d03529bcc805d04044e8ccc3450db0f9f6aa14a2/evm/scripts/start-local-world-fork.sh):
configure mock rates and burn permissions, fund the deployed vault, deploy the
upstream `WrappedAssetV2`, upgrade the production beacon through its owner, verify
preserved names/supplies/holder balances, and unpause. All writes target Anvil.
The deployed vault and controller bytecode remain intact. The migration's
reproducible deployment artifact and regeneration instructions are in
[`bedrock/tests/fixtures/universal`](bedrock/tests/fixtures/universal/README.md).

It transfers existing uSOL/uXRP from pinned holders into a newly deployed Safe and
checks fractional quote rounding, exact USDC settlement, supply burns, consumed
approvals and real EntryPoint/vault events. Excessive minimum payout on the
second asset and insufficient shared USDC must each roll back the whole batch;
restoring liquidity must allow a successful retry. An unrelated transport error
cannot pass a rollback case. RPC requests have a 15-second deadline and the test
body has a 180-second deadline.

This complements `test_uasset_redemption`'s lightweight fixture. Mock rates and
synthetic vault USDC match Universal's script. `AnvilBackedHttpClient` mocks
screening and sponsorship, but executes signed operations through the real
EntryPoint, Safe module and MultiSend. This does not validate a production
bundler/paymaster, backend quotes, receipt API or mobile UI. Assertions use
on-chain events and state, not the helper's static receipt response.

## Code of Conduct

Please note that this project is released with a Code of Conduct. By participating in this project, you agree to abide by its terms.

## Questions?

Feel free to reach out to the maintainers if you have any questions.

Thank you for contributing!
