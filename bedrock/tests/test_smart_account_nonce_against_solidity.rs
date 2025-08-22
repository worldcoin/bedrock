// no std imports needed

use alloy::{
    node_bindings::Anvil,
    primitives::{Address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use bedrock::smart_account::{InstructionFlag, NonceKeyV1, TransactionTypeId};

mod common;
mod foundry;
use foundry::ForgeCreate;

sol!(
    #[sol(rpc)]
    contract NonceV1Checker {
        function decodeAll(uint256 nonce) external pure returns (uint8 typeId, bytes5 magic, uint8 instruction, bytes10 metadata, bytes7 randomTail, uint64 sequence);
    }
);

#[tokio::test]
async fn test_rust_nonce_matches_solidity_encoding() -> anyhow::Result<()> {
    let anvil = Anvil::new().spawn();

    let deployer = PrivateKeySigner::random();
    let provider = ProviderBuilder::new()
        .wallet(deployer.clone())
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(deployer.address(), U256::from(1e19 as u64))
        .await?;

    // Build and deploy the NonceV1Checker via forge
    let checker_addr_str =
        ForgeCreate::new("solidity/src/NonceV1Checker.sol:NonceV1Checker").run(
            format!("0x{}", hex::encode(deployer.to_bytes())),
            anvil.endpoint_url().to_string(),
        )?;
    let checker_addr: Address = checker_addr_str.parse()?;

    let checker = NonceV1Checker::new(checker_addr, &provider);

    // Build a deterministic nonce in Rust with explicit random tail
    let metadata: [u8; 10] = [0x11; 10];
    let random_tail: [u8; 7] = [0x22; 7];
    let rust_nonce = NonceKeyV1::with_random_tail(
        TransactionTypeId::Transfer,
        InstructionFlag::Default,
        metadata,
        random_tail,
    )
    .encode_with_sequence(0);

    // Solidity decode and compare fields
    let res = checker.decodeAll(rust_nonce).call().await?;

    // typeId
    assert_eq!(res.typeId, TransactionTypeId::Transfer as u8);
    // magic bytes "bdrck"
    let expected_magic: [u8; 5] = *b"bdrck";
    assert_eq!(res.magic.0, expected_magic);
    // instruction
    assert_eq!(res.instruction, InstructionFlag::Default as u8);
    // metadata
    assert_eq!(res.metadata.0, metadata);
    // random tail
    assert_eq!(res.randomTail.0, random_tail);
    // sequence must be zero
    assert_eq!(res.sequence, 0);

    Ok(())
}
