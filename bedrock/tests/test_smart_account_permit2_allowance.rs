use alloy::{
    primitives::{address, Address, U160, U256},
    providers::{ext::AnvilApi, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol,
    sol_types::SolCall,
};
use bedrock::primitives::Network;
use bedrock::smart_account::{
    SafeOperation, SafeSmartAccount, SafeTransaction, UnparsedPermitDetails,
    UnparsedPermitSingle, PERMIT2_ADDRESS,
};
use chrono::Utc;

mod common;
use common::{deploy_safe, set_erc20_balance_for_safe, setup_anvil, ISafe, IERC20};

sol!(
    // NOTE: This is defined in the `permit2` module, but it cannot be easily re-used here.
    struct PermitDetails {
        address token;
        uint160 amount;
        uint48 expiration;
        uint48 nonce;
    }

    /// The permit message for a single token allowance.
    struct PermitSingle {
        PermitDetails details;
        address spender;
        uint256 sigDeadline;
    }

    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/IAllowanceTransfer.sol>
    #[sol(rpc)]
    interface IAllowanceTransfer {
        function permit(
            address owner,
            PermitSingle memory permitSingle,
            bytes calldata signature
        ) external;

        function transferFrom(
            address from,
            address to,
            uint160 amount,
            address token
        ) external;

        function allowance(
            address user,
            address token,
            address spender
        ) external view returns (uint160 amount, uint48 expiration, uint48 nonce);
    }
);

/// This integration test encompasses multiple key functionality of the `SafeSmartAccount`.
/// In particular it tests both `sign_transaction` & `sign_permit2_allowance`.
///
/// The high level flow is as follows:
/// 1. General set-up
/// 2. Deploy a Safe (World App User)
/// 3. Give the Safe some simulated WLD balance
/// 4. Approve the Permit2 contract to transfer WLD tokens from the Safe on the ERC-20 WLD contract (this tests `sign_transaction` works properly on-chain).
/// 5. Initialize a "Mini App" Wallet which will get approved via allowance
/// 6. Sign a Permit2 allowance to grant the Mini App an allowance on behalf of the Safe
/// 7. Execute the `permit` call on the Permit2 contract to set the allowance
/// 8. Execute a `transferFrom` call on the Permit2 contract using the allowance
/// 9. Verify the tokens were transferred
#[tokio::test]
async fn test_integration_permit2_allowance() -> anyhow::Result<()> {
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
    let balance = U256::from(10e18); // 10 WLD

    set_erc20_balance_for_safe(&provider, wld_token_address, safe_address, balance)
        .await?;

    assert_eq!(wld_contract.balanceOf(safe_address).call().await?, balance);

    // Step 4: Approve the Permit2 contract to transfer WLD tokens from the Safe
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

    approve_result.get_receipt().await?;

    // Step 5: Initialize a "Mini App" Wallet which will get approved via allowance
    let mini_app_signer = PrivateKeySigner::random();
    let mini_app_provider = ProviderBuilder::new()
        .wallet(mini_app_signer.clone())
        .connect_http(anvil.endpoint_url());

    mini_app_provider
        .anvil_set_balance(mini_app_signer.address(), U256::from(1e18))
        .await?;

    // Step 6: Sign a Permit2 allowance to grant the Mini App an allowance
    let allowance_amount: u128 = 5_000_000_000_000_000_000; // 5 WLD
    let expiration = (Utc::now().timestamp() + 3600) as u64; // 1 hour from now
    let sig_deadline = Utc::now().timestamp() + 180; // 3 minutes from now

    let details = UnparsedPermitDetails {
        token: wld_token_address.to_string(),
        amount: allowance_amount.to_string(),
        expiration: expiration.to_string(),
        nonce: "0".to_string(),
    };

    let permit_single = UnparsedPermitSingle {
        details,
        spender: mini_app_signer.address().to_string(),
        sigDeadline: sig_deadline.to_string(),
    };

    let signature = safe_account
        .sign_permit2_allowance(chain_id, permit_single)
        .expect("Failed to sign permit2 allowance");

    // Step 7: Execute the `permit` call on the Permit2 contract to set the allowance
    let permit_struct = PermitSingle {
        details: PermitDetails {
            token: wld_token_address,
            amount: U160::from(allowance_amount),
            expiration: alloy::primitives::aliases::U48::from(expiration),
            nonce: alloy::primitives::aliases::U48::from(0u64),
        },
        spender: mini_app_signer.address(),
        sigDeadline: U256::from(sig_deadline),
    };

    let signature_bytes = signature.to_vec()?;

    let permit2_contract = IAllowanceTransfer::new(PERMIT2_ADDRESS, &mini_app_provider);

    let result = permit2_contract
        .permit(safe_address, permit_struct, signature_bytes.into())
        .from(mini_app_signer.address())
        .gas(500_000)
        .send()
        .await?;

    result.get_receipt().await?;

    // Verify the allowance was set
    let allowance = permit2_contract
        .allowance(safe_address, wld_token_address, mini_app_signer.address())
        .call()
        .await?;

    assert_eq!(allowance.amount, U160::from(allowance_amount));

    // Step 8: Execute a `transferFrom` call using the allowance
    let transfer_amount: u128 = 1_000_000_000_000_000_000; // 1 WLD

    let transfer_result = permit2_contract
        .transferFrom(
            safe_address,
            mini_app_signer.address(),
            U160::from(transfer_amount),
            wld_token_address,
        )
        .from(mini_app_signer.address())
        .gas(500_000)
        .send()
        .await?;

    transfer_result.get_receipt().await?;

    // Step 9: Verify the tokens were indeed transferred
    let wld_contract = IERC20::new(wld_token_address, &mini_app_provider);
    let mini_app_balance = wld_contract
        .balanceOf(mini_app_signer.address())
        .call()
        .await?;
    let safe_balance_after = wld_contract.balanceOf(safe_address).call().await?;

    assert_eq!(mini_app_balance, U256::from(1e18));
    assert_eq!(safe_balance_after, U256::from(9e18));

    // Verify the remaining allowance was decremented
    let remaining_allowance = permit2_contract
        .allowance(safe_address, wld_token_address, mini_app_signer.address())
        .call()
        .await?;

    assert_eq!(
        remaining_allowance.amount,
        U160::from(allowance_amount - transfer_amount)
    );

    Ok(())
}
