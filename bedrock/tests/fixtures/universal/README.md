# Universal migration artifact

`WrappedAssetV2.json` contains the creation bytecode and constructor ABI compiled
from Universal's actual token implementation. It is used only to migrate the
beacon on a disposable World Chain fork. It does not replace the vault or token
logic with a mock.

Source: [`evm/src/WrappedAssetV2.sol`](https://github.com/Alongside-Finance/universal-winddown/blob/d03529bcc805d04044e8ccc3450db0f9f6aa14a2/evm/src/WrappedAssetV2.sol)
at Universal commit `d03529bcc805d04044e8ccc3450db0f9f6aa14a2` (PR #17).
The source records its origin as universal-evm-contracts commit `e75bbdb`.

Build settings are those in upstream `evm/foundry.toml`: Solidity 0.8.26,
optimizer enabled with 100000 runs, Cancun EVM, IPFS bytecode metadata. Git
submodules pin the OpenZeppelin dependencies. Only the constructor ABI is kept
because the test uses its own small interfaces for contract calls. The entire
creation bytecode is retained, including metadata; Alloy appends the production
controller address as its constructor argument at deployment.

SHA-256 of the decoded creation bytecode:
`8ce977d2aa5c33ea7d0537e4f614ed8fe9d387b67d43f08092601a85f8b4aac9`.

To reproduce (Foundry 1.5.1 was used for the committed artifact):

```bash
git clone https://github.com/Alongside-Finance/universal-winddown.git
cd universal-winddown
git fetch origin d03529bcc805d04044e8ccc3450db0f9f6aa14a2
git checkout --detach d03529bcc805d04044e8ccc3450db0f9f6aa14a2
git submodule update --init --recursive
cd evm
forge build src/WrappedAssetV2.sol
jq '{abi: [.abi[] | select(.type == "constructor")], bytecode: .bytecode.object}' \
  out/WrappedAssetV2.sol/WrappedAssetV2.json > /tmp/WrappedAssetV2.json
```

Compare `/tmp/WrappedAssetV2.json` with this fixture. This regeneration is only
needed when changing the pinned implementation; normal Bedrock test runs do not
fetch Universal's repository or invoke its launcher.

The Rust setup follows the upstream launcher's admin calls for uSOL/uXRP, with
its exact mock rates. The pinned USDC balance mapping (slot 9) is used for
synthetic vault liquidity, with a balance assertion afterward. User uAssets are
funded by transferring existing holdings, without editing token balances or
supply. The real deployed vault, controller, beacon, token proxies and USDC
implementation are exercised on the fork.
