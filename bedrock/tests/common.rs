#![allow(dead_code)]
use std::str::FromStr;

use alloy::{
    network::Ethereum,
    node_bindings::AnvilInstance,
    primitives::{address, keccak256, Address, Log, U256},
    providers::{ext::AnvilApi, Provider},
    sol,
    sol_types::{SolCall, SolEvent},
};

use bedrock::primitives::config::{current_environment_or_default, BedrockEnvironment};

sol!(
    #[allow(missing_docs)]
    #[sol(rpc)]
    interface ISafeProxyFactory {
        event ProxyCreation(address indexed proxy, address singleton);

        function createProxyWithNonce(
            address _singleton,
            bytes memory initializer,
            uint256 saltNonce
        ) external returns (address proxy);
    }
);

// https://github.com/safe-global/safe-smart-account/blob/v1.5.0/contracts/interfaces/ISafe.sol
sol!(
    #[allow(clippy::too_many_arguments)]
    #[sol(rpc)]
    interface ISafe {
        function setup(
            address[] calldata _owners,
            uint256 _threshold,
            address to,
            bytes calldata data,
            address fallbackHandler,
            address paymentToken,
            uint256 payment,
            address payable paymentReceiver
        ) external;

        function enableModules(address[] memory modules) external;

        /// EIP-1271 validation
        function isValidSignature(bytes32 dataHash, bytes memory signature) external view returns (bytes4);

        /// Execute Safe transaction
        function execTransaction(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation,
            uint256 safeTxGas,
            uint256 baseGas,
            uint256 gasPrice,
            address gasToken,
            address payable refundReceiver,
            bytes memory signatures
        ) external payable returns (bool success);
    }
);

sol! {

    #[sol(rpc)]
    interface IERC20 {
        function transfer(address to, uint256 amount) external returns (bool);
        function balanceOf(address account) external view returns (uint256);
        function approve(address spender, uint256 amount) external returns (bool);
    }

    /// 4337 Module for Safe Smart Account
    #[sol(rpc)]
    interface ISafe4337Module {
        function executeUserOp(
            address to,
            uint256 value,
            bytes calldata data,
            uint8 operation
        ) external;
    }
}

// Safe contract addresses on Worldchain
pub const SAFE_PROXY_FACTORY_ADDRESS: Address =
    address!("4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67");
pub const SAFE_L2_SINGLETON_ADDRESS: Address =
    address!("29fcB43b46531BcA003ddC8FCB67FFE91900C762");
pub const SAFE_4337_MODULE_ADDRESS: Address =
    address!("75cf11467937ce3F2f357CE24ffc3DBF8fD5c226");
pub const SAFE_MODULE_SETUP_ADDRESS: Address =
    address!("2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47");

pub fn setup_anvil() -> AnvilInstance {
    dotenvy::dotenv().ok();
    let rpc_url = std::env::var("WORLDCHAIN_RPC_URL").unwrap_or_else(|_| {
        // Fallback to a public, no-key RPC if available.
        "https://worldchain-mainnet.g.alchemy.com/v2/demo".to_string()
    });

    alloy::node_bindings::Anvil::new().fork(rpc_url).spawn()
}

pub async fn deploy_safe<P>(
    provider: &P,
    owner: Address,
    deploy_nonce: U256,
) -> anyhow::Result<Address>
where
    P: Provider<Ethereum>,
{
    // Fund the owner to be able to execute transactions
    provider
        .anvil_set_balance(owner, U256::from(1e19 as u64))
        .await
        .unwrap();

    let proxy_factory = ISafeProxyFactory::new(SAFE_PROXY_FACTORY_ADDRESS, provider);

    // Encode the Safe setup call
    let setup_data = ISafe::setupCall {
        _owners: vec![owner],
        _threshold: U256::from(1),
        to: SAFE_MODULE_SETUP_ADDRESS,
        data: ISafe::enableModulesCall {
            modules: vec![SAFE_4337_MODULE_ADDRESS],
        }
        .abi_encode()
        .into(),
        fallbackHandler: SAFE_4337_MODULE_ADDRESS,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    }
    .abi_encode();

    // Deploy Safe via proxy factory
    let deploy_tx = proxy_factory
        .createProxyWithNonce(
            SAFE_L2_SINGLETON_ADDRESS,
            setup_data.into(),
            deploy_nonce,
        )
        .from(owner)
        .send()
        .await
        .expect("Failed to send createProxyWithNonce transaction");

    let receipt = deploy_tx
        .get_receipt()
        .await
        .expect("Failed to get transaction receipt");

    // Get the Safe address from the ProxyCreation event
    let proxy_creation_event = receipt
        .inner
        .logs()
        .iter()
        .find_map(|log| {
            let raw_log = Log {
                address: log.address(),
                data: log.data().clone(),
            };
            ISafeProxyFactory::ProxyCreation::decode_log(&raw_log).ok()
        })
        .expect("ProxyCreation event not found");

    Ok(proxy_creation_event.proxy)
}

/// Set an ERC-20 balance for a Safe by directly writing the storage slot
///
/// The underlying token must store balances as `mapping(address => uint256)` at slot `0`.
pub async fn set_erc20_balance_for_safe<P>(
    provider: &P,
    token: Address,
    safe: Address,
    balance: U256,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + AnvilApi<Ethereum>,
{
    // Simulate balance by writing storage slot for mapping(address => uint) at slot 0
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe.as_slice());
    let slot_hash = alloy::primitives::keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());

    provider
        .anvil_set_storage_at(token, slot, balance.into())
        .await?;

    Ok(())
}

/// Returns the World ID Address Book contract address for the current Bedrock environment.
/// Reference <https://github.com/worldcoin/worldcoin-vault/blob/main/src/WorldIDAddressBook.sol>
fn address_book_address() -> Address {
    match current_environment_or_default() {
        BedrockEnvironment::Staging => {
            Address::from_str("0xfd5b7aefdd478f34ae61d8399a206a4879f0af0a")
                .expect("failed to decode staging address book address")
        }
        BedrockEnvironment::Production => {
            Address::from_str("0x57b930D551e677CC36e2fA036Ae2fe8FdaE0330D")
                .expect("failed to decode production address book address")
        }
    }
}

/// Mark an address as verified in the WorldIDAddressBook by overriding the `addressVerifiedUntil`
/// mapping via storage writes.
///
/// Storage layout (from `WorldIDAddressBook` + OpenZeppelin `Ownable2Step`):
/// - slot 0: `_owner`          (from `Ownable`)
/// - slot 1: `_pendingOwner`   (from `Ownable2Step`)
/// - slot 2: `worldIdRouter`
/// - slot 3: `groupId`
/// - (immutable) `externalNullifierHash` — not stored in a slot
/// - slot 4: `verificationLength`
/// - slot 5: `maxProofTime`
/// - slot 6: `nullifierHashes` mapping
/// - slot 7: `addressVerifiedUntil` mapping
pub async fn set_address_verified_until_for_account<P>(
    provider: &P,
    account: Address,
    verified_until: U256,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + AnvilApi<Ethereum>,
{
    // Compute the storage slot for addressVerifiedUntil[account] where the mapping is at slot 7.
    let mut padded = [0u8; 64];
    // First 32 bytes: left-padded address
    padded[12..32].copy_from_slice(account.as_slice());
    // Second 32 bytes: mapping slot index (slot = 7 for `addressVerifiedUntil`).
    padded[63] = 7u8;
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());

    provider
        .anvil_set_storage_at(address_book_address(), slot, verified_until.into())
        .await?;

    Ok(())
}
