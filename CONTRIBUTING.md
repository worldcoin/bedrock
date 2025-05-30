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
3. Install Foundry. Anvil (from the Foundry toolkit) is required for functional tests with Solidity.
   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```
4. Run tests to ensure everything is working as expected. This will run **all tests** including integration tests and doctests.
   ```bash
   cargo test
   ```

### About Integration Tests

Integration tests deploy and interact with Safe contracts on a local fork of World Chain. This tests are are enabled by default and they require [Anvil](https://book.getfoundry.sh/anvil/overview#anvil) to be running.

## Code of Conduct

Please note that this project is released with a Code of Conduct. By participating in this project, you agree to abide by its terms.

## Questions?

Feel free to reach out to the maintainers if you have any questions.

Thank you for contributing!
