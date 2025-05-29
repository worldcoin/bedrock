# bedrock

Foundational library which powers World App's crypto wallet.

## Testing

### Integration Tests

The integration tests that deploy and interact with Safe contracts on a local fork are enabled by default. They require:

1. **Install Anvil**:

   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

2. **Configure API key**:

   ```bash
   cp .env.example .env
   # Edit .env and add your Alchemy API key for WorldChain
   ```

3. **Run tests**:
   ```bash
   cargo test
   ```

To run tests without the integration tests (faster, no Anvil required):

```bash
cargo test -- --show-output
```
