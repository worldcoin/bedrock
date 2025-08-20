use std::path::{Path, PathBuf};

use alloy::{
    network::Ethereum,
    primitives::{Address, FixedBytes, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
};

use bedrock::smart_account::{InstructionFlag, OperationNonce, TransactionTypeId};

mod common;
use common::setup_anvil;
mod foundry;

sol!(
    #[sol(rpc)]
    contract NonceV1Checker {
        function decodeAll(uint256 nonce) external pure returns (uint8 typeId, bytes5 magic, uint8 instruction, bytes10 metadata, bytes7 randomTail, uint64 sequence);
    }
);

#[tokio::test]
async fn test_rust_nonce_matches_solidity_encoding() -> anyhow::Result<()> {
    // 1) Spin up Anvil
    // Use a fresh local anvil without remote fork to make CI deterministic
    let anvil = alloy::node_bindings::Anvil::new().spawn();

    // 2) Local wallet/provider
    let deployer = PrivateKeySigner::random();
    let provider = ProviderBuilder::new()
        .wallet(deployer.clone())
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(deployer.address(), U256::from(1e19 as u64))
        .await?;

    // 3) Build and deploy the NonceV1Checker with Forge via helper
    let checker_addr_str = match crate::foundry::forge_create_checker(
        &format!("0x{}", hex::encode(deployer.to_bytes())),
        anvil.endpoint_url().as_str(),
    ) {
        Ok(addr) => addr,
        Err(e) => {
            eprintln!("skipping nonce v1 solidity cross-check: {e}");
            return Ok(());
        }
    };
    let checker_addr: Address = checker_addr_str.parse()?;

    let checker = NonceV1Checker::new(checker_addr, &provider);

    // 4) Build a deterministic nonce in Rust with explicit random tail
    let metadata: [u8; 10] = [0x11; 10];
    // let metadata2: [u8; 10] = [0x22; 10];
    let random_tail: [u8; 7] = [0x22; 7];
    // let random_tail2: [u8; 7] = [0x33; 7];
    let rust_nonce = OperationNonce::with_random_tail(
        TransactionTypeId::Transfer,
        InstructionFlag::Default,
        metadata,
        random_tail,
    )
    .to_encoded_nonce();

    // 5) Ask Solidity to decode and compare fields
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

    // 6) Only on-chain decode vs Rust encode

    Ok(())
}
