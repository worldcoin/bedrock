use alloy::{
    primitives::{address, keccak256, Address, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use bedrock::primitives::Network;
use bedrock::smart_account::{
    SafeOperation, SafeSmartAccount, SafeTransaction, UnparsedPermitTransferFrom,
    UnparsedTokenPermissions, PERMIT2_ADDRESS,
};
use chrono::Utc;

mod common;
use common::{deploy_safe, setup_anvil, ISafe, IERC20};

sol!(
    // NOTE: This is defined in the `permit2` module, but it cannot be easily re-used here.
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// The signed permit message for a single token transfer.
    struct PermitTransferFrom {
        TokenPermissions permitted;
        uint256 nonce;
        uint256 deadline;
    }

    /// Transfer details for permitTransferFrom
    struct SignatureTransferDetails {
        address to;
        uint256 requestedAmount;
    }

    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L9>
    #[sol(rpc)]
    interface ISignatureTransfer {
        function permitTransferFrom(
            PermitTransferFrom memory permit,
            SignatureTransferDetails calldata transferDetails,
            address owner,
            bytes calldata signature
        ) external;
    }
);

/// This integration test encompasses multiple key functionality of the `SafeSmartAccount`.
/// In particular it tests both `sign_transaction` & `sign_permit2_transfer`.
///
/// The high level flow is as follows:
/// 1. General set-up
/// 2. Deploy a Safe (World App User)
/// 3. Give the Safe some simulated WLD balance
/// 4. Approve the Permit2 contract to transfer WLD tokens from the Safe on the ERC-20 WLD contract (this tests `sign_transaction` works properly on-chain).
/// 5. Initialize a "Mini App" Wallet which will get approved to transfer WLD tokens on behalf of the user
/// 6. Execute a `permitTransferFrom` call on the Permit2 contract to transfer WLD tokens from the Safe to the Mini App
/// 7. Verify the tokens were transferred
#[tokio::test]
async fn test_integration_permit2_transfer() -> anyhow::Result<()> {
    // Step 1: Initial setup
    let anvil = setup_anvil();
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    provider.anvil_set_balance(owner, U256::from(1e18)).await?;

    // Step 2: Deploy a Safe (World App User)
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;
    let chain_id = Network::WorldChain as u32;
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;

    // Step 3: Give the Safe some simulated WLD balance
    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld_contract = IERC20::new(wld_token_address, &provider);

    // the simulated balance is provided by updating the storage slot of the contract
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe_address.as_slice());
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());
    let balance = U256::from(10e18); // 10 WLD

    provider
        .anvil_set_storage_at(wld_token_address, slot, balance.into())
        .await?;

    assert_eq!(wld_contract.balanceOf(safe_address).call().await?, balance,);

    // Step 4: Approve the Permit2 contract to transfer WLD tokens from the Safe
    // This uses the `sign_transaction` method to approve the Permit2 contract to transfer WLD tokens from the Safe on the ERC-20 WLD contract.
    let calldata = IERC20::approveCall {
        spender: PERMIT2_ADDRESS,
        amount: U256::MAX,
    }
    .abi_encode();

    let tx = SafeTransaction {
        to: wld_token_address.to_string(),
        value: "0".to_string(),
        data: format!("0x{}", hex::encode(&calldata)),
        operation: SafeOperation::Call,
        safe_tx_gas: "33000".to_string(),
        base_gas: "30000".to_string(),
        gas_price: "0".to_string(),
        gas_token: "0x0000000000000000000000000000000000000000".to_string(),
        refund_receiver: "0x0000000000000000000000000000000000000000".to_string(),
        nonce: "0".to_string(),
    };
    let signature = safe_account.sign_transaction(chain_id, tx)?;

    let safe_contract = ISafe::new(safe_address, &provider);
    let approve_result = safe_contract
        .execTransaction(
            wld_token_address,
            U256::ZERO, // value
            calldata.into(),
            0u8, // `Call`
            U256::from(33_000u64),
            U256::from(30_000u64), // base_gas
            U256::ZERO,            // gas_price (no refund)
            Address::ZERO,         // ETH token
            Address::ZERO,         // refund_receiver
            signature.to_vec()?.into(),
        )
        .from(owner)
        .send()
        .await?;

    approve_result.get_receipt().await?; // important to get the receipt to ensure the transaction was executed

    // Step 5: Initialize a "Mini App" Wallet which will get approved to transfer WLD tokens on behalf of the user
    let mini_app_signer = PrivateKeySigner::random();
    let mini_app_provider = ProviderBuilder::new()
        .wallet(mini_app_signer.clone())
        .connect_http(anvil.endpoint_url());

    mini_app_provider
        .anvil_set_balance(mini_app_signer.address(), U256::from(1e18))
        .await?;

    // Step 6: Execute a `permitTransferFrom` call on the Permit2 contract
    let permitted = UnparsedTokenPermissions {
        token: wld_token_address.to_string(),
        amount: "1000000000000000000".to_string(), // 1 WLD
    };

    let deadline = Utc::now().timestamp() + 180; // 3 minutes from now

    let transfer_from = UnparsedPermitTransferFrom {
        permitted,
        spender: mini_app_signer.address().to_string(),
        nonce: "0".to_string(),
        deadline: deadline.to_string(),
    };

    let signature = safe_account
        .sign_permit2_transfer(chain_id, transfer_from)
        .expect("Failed to sign permit2 transfer");

    let permit_struct = PermitTransferFrom {
        permitted: TokenPermissions {
            token: wld_token_address,
            amount: U256::from(1e18), // 1 WLD
        },
        nonce: U256::from(0),
        deadline: U256::from(deadline),
    };

    let signature_transfer = SignatureTransferDetails {
        to: mini_app_signer.address(),
        requestedAmount: U256::from(1e18), // 1 WLD
    };

    let signature = signature.to_vec()?;

    let permit2_contract = ISignatureTransfer::new(PERMIT2_ADDRESS, &mini_app_provider);
    let result = permit2_contract
        .permitTransferFrom(
            permit_struct,
            signature_transfer,
            safe_address,
            signature.into(),
        )
        .from(mini_app_signer.address())
        .gas(500_000)
        .send()
        .await?;

    result.get_receipt().await?;

    // Step 7: Verify the tokens were indeed transferred
    let wld_contract = IERC20::new(wld_token_address, &mini_app_provider);
    let mini_app_balance = wld_contract
        .balanceOf(mini_app_signer.address())
        .call()
        .await?;
    let safe_balance_after = wld_contract.balanceOf(safe_address).call().await?;

    assert_eq!(mini_app_balance, U256::from(1e18));
    assert_eq!(safe_balance_after, U256::from(9e18));

    Ok(())
}
