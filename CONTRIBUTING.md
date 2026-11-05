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

`test_uasset_universal_fork` runs Bedrock's `transaction_uasset_redeem` against
Universal's deployed vault, controller and beacon-backed tokens. It complements
the fast fixture test in `test_uasset_redemption`; it does not replace contract
bytecode with a test vault. The test is explicitly ignored in the default suite
because it requires a separately prepared fork and archive RPC access.

Prepare the environment using [Universal PR #17](https://github.com/Alongside-Finance/universal-winddown/pull/17).
Pin both its source revision and World Chain block so its mock rates, migration
implementation and existing token holders are reproducible. In a separate terminal:

```bash
git clone https://github.com/Alongside-Finance/universal-winddown.git
cd universal-winddown
git fetch origin d03529bcc805d04044e8ccc3450db0f9f6aa14a2
git checkout --detach d03529bcc805d04044e8ccc3450db0f9f6aa14a2
git submodule update --init --recursive
FORK_BLOCK_NUMBER=37242824 KEEP_RUNNING=true ./evm/scripts/start-local-world-fork.sh
```

The launcher needs `anvil`, `cast`, `forge`, `jq`, `python3` and `rg`. Set
`WORLD_RPC_URL` to an archive-capable World Chain RPC if the default public
endpoint is unavailable. Wait for the launcher's `ready` message before running
the test. Keep Anvil bound to loopback; it exposes impersonation and state-editing
RPC methods.

On Foundry 1.5.1, the public RPC can reject automatic `eth_feeHistory` estimation
with `invalid block range`. For that toolchain, append
`--gas-price 1000000000 --priority-gas-price 1000000` to the launcher's `cast send`
and `forge create` commands. Do not set global `ETH_GAS_PRICE` variables: they
also affect read-only `cast call` requests. A failed pre-upgrade read can also
surface later as `name changed`; check the earlier RPC errors before treating it
as a migration failure. These are limitations of the pinned upstream launcher.

From the Bedrock repository:

```bash
UNIVERSAL_FORK_RPC_URL=http://127.0.0.1:8545 \
  cargo test -p bedrock --test test_uasset_universal_fork -- --ignored --nocapture
```

The test starts its own child Anvil fork and destroys it when done, leaving the
prepared environment untouched. RPC requests have a 15-second deadline and the
test body has a 180-second deadline. It transfers existing uSOL/uXRP from pinned
holders into a newly deployed Safe, preserving token supply, and checks:

- Fractional quotes use integer rounding from 18-decimal assets to 6-decimal USDC.
- Signed Safe MultiSend redemption burns both assets and pays the Safe exactly;
  exact-amount approvals are consumed and the vault retains no redeemed tokens.
- An excessive minimum on the second asset rolls back the first redemption,
  both burns, USDC transfers and approvals.
- Shared USDC sufficient for the first asset but insufficient for the whole batch
  also rolls back atomically; restoring liquidity allows a successful retry.
- Real EntryPoint outcome events and vault redemption events agree with the
  balance/supply assertions, so an unrelated transport error cannot pass a
  rollback case.

Universal's launcher uses mock rates and synthetic vault USDC. Bedrock's existing
`AnvilBackedHttpClient` mocks screening and sponsorship, but executes signed
operations through the real EntryPoint, Safe module and MultiSend contracts.
This test does **not** validate a production bundler/paymaster, backend quotes,
receipt API or mobile UI; `wa_getUserOperationReceipt` is deliberately not used
as evidence because that helper returns a static success response.

## Code of Conduct

Please note that this project is released with a Code of Conduct. By participating in this project, you agree to abide by its terms.

## Questions?

Feel free to reach out to the maintainers if you have any questions.

Thank you for contributing!
