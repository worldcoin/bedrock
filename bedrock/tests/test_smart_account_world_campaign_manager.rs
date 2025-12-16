use std::sync::Arc;

mod common;
use common::{
    deploy_safe, set_address_verified_until_for_account, set_erc20_balance_for_safe,
    setup_anvil, IERC20,
};

use alloy::{
    network::Ethereum,
    primitives::{address, keccak256, Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};

use bedrock::{
    primitives::http_client::set_http_client,
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    test_utils::{AnvilBackedHttpClient, IEntryPoint},
    transactions::world_campaign_manager_address,
};

#[tokio::test]
async fn test_transaction_world_campaign_manager_sponsor_claim_user_operations(
) -> anyhow::Result<()> {
    let anvil = setup_anvil();

    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18 as u64))
        .await?;

    let safe_address_giftor = deploy_safe(&provider, owner, U256::ZERO).await?;
    let safe_address_giftee = deploy_safe(&provider, owner, U256::from(1)).await?;
    let safe_address_third = deploy_safe(&provider, owner, U256::from(2)).await?;

    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    for safe in [safe_address_giftor, safe_address_giftee] {
        let _ = entry_point
            .depositTo(safe)
            .value(U256::from(1e18 as u64))
            .send()
            .await?
            .get_receipt()
            .await?;
    }

    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld = IERC20::new(wld_token_address, &provider);

    // Prepare a fake campaign on WorldCampaignManager with id 1 funded in WLD.
    let amount = U256::from(1e18);
    let total_funds = amount * U256::from(10u8);

    setup_fake_world_campaign(&provider, wld_token_address, amount, total_funds)
        .await?;

    // Mark both Safe accounts as verified in the WorldIDAddressBook so that
    // WorldCampaignManager::sponsor passes the NotVerified checks.
    let far_future_timestamp = U256::from(2_000_000_000u64);
    for addr in [
        &safe_address_giftor,
        &safe_address_giftee,
        &safe_address_third,
    ] {
        set_address_verified_until_for_account(&provider, *addr, far_future_timestamp)
            .await?;
    }

    let before_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let before_giftee = wld.balanceOf(safe_address_giftee).call().await?;

    let client = AnvilBackedHttpClient::new(provider.clone());

    set_http_client(Arc::new(client));

    let safe_account_giftor =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftor.to_string())?;
    let safe_account_giftee =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftee.to_string())?;
    let campaign_id_str = "1";

    // First, giftor sponsors giftee. This makes giftee eligible to claim after he has sponsored someone.
    safe_account_giftor
        .transaction_world_campaign_manager_sponsor(
            campaign_id_str,
            &safe_address_giftee.to_string(),
        )
        .await
        .expect("transaction_world_campaign_manager_sponsor (giftor -> giftee) failed");

    // Then, giftee sponsors third safe so that giftee has sponsored someone and can claim.
    safe_account_giftee
        .transaction_world_campaign_manager_sponsor(
            &campaign_id_str.to_string(),
            &safe_address_third.to_string(),
        )
        .await
        .expect("transaction_world_campaign_manager_sponsor (giftee -> third) failed");

    let after_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let after_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    // `sponsor` does not move any WLD; it only records relationships.
    assert_eq!(after_giftor, before_giftor);
    assert_eq!(after_giftee, before_giftee);

    // Now giftee can claim the reward.
    safe_account_giftee
        .transaction_world_campaign_manager_claim(campaign_id_str)
        .await
        .expect("transaction_world_campaign_manager_claim failed");

    let after_redeem_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    assert_eq!(after_redeem_giftee, before_giftee + amount);

    Ok(())
}

/// Configure a fake campaign for the `WorldCampaignManager` contract directly via storage writes.
///
/// This avoids having to call the `onlyOwner` configuration functions on-chain.
/// The underlying storage layout assumptions are:
/// - `nextCampaignId` is at slot `0`
/// - `getCampaign` mapping is at slot `1`
/// - `Campaign` struct layout for a given `campaignId` is:
///   - slot `base + 0`: `address token`
///   - slot `base + 1`: `uint256 funds`
///   - slot `base + 2`: `uint256 endsAt`
///   - slot `base + 3`: `bool wasEndedEarly`
///   - slot `base + 4`: `uint256 lowerBound`
///   - slot `base + 5`: `uint256 upperBound`
///   - slot `base + 6`: `uint256 bonusRewardThreshold`
///   - slot `base + 7`: `uint256 bonusRewardAmount`
///   - slot `base + 8`: `uint256 randomnessSeed`
///
/// NOTE: This is tailored for tests only.
pub async fn setup_fake_world_campaign<P>(
    provider: &P,
    token: Address,
    reward_amount: U256,
    total_funds: U256,
) -> anyhow::Result<()>
where
    P: Provider<Ethereum> + AnvilApi<Ethereum>,
{
    // Address must match the one used by the transaction builder.
    let world_campaign_manager_address = world_campaign_manager_address();

    // Compute the base slot for getCampaign[campaign_id] where getCampaign is at slot 1.
    //
    // NOTE: This helper is currently tailored for `campaign_id == 1`
    let mut padded = [0u8; 64];
    // First 32 bytes: campaignId (we only support id = 1 in tests).
    padded[31] = 1u8;
    // Second 32 bytes: mapping slot index (slot = 1 for `getCampaign`).
    padded[63] = 1u8;
    let base_hash = keccak256(padded);
    let base_slot = U256::from_be_bytes(base_hash.into());

    // Slot 0: token (address left-padded to 32 bytes, stored as big-endian U256).
    let mut token_padded = [0u8; 32];
    token_padded[12..32].copy_from_slice(token.as_slice());
    let token_value = U256::from_be_bytes(token_padded);

    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot,
            token_value.into(),
        )
        .await?;

    // Slot 1: funds.
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(1u8),
            total_funds.into(),
        )
        .await?;

    // Slot 2: endsAt (set far in the future to avoid expiry issues).
    let far_future_timestamp = U256::from(2_000_000_000u64);
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(2u8),
            far_future_timestamp.into(),
        )
        .await?;

    // Slot 3: wasEndedEarly = false.
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(3u8),
            U256::ZERO.into(),
        )
        .await?;

    // Slot 4 & 5: lowerBound == upperBound == reward_amount for deterministic rewards.
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(4u8),
            reward_amount.into(),
        )
        .await?;
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(5u8),
            reward_amount.into(),
        )
        .await?;

    // Slot 6: bonusRewardThreshold = reward_amount (must be >= lowerBound and <= upperBound).
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(6u8),
            reward_amount.into(),
        )
        .await?;

    // Slot 7: bonusRewardAmount = reward_amount (must be >= upperBound, and this is what gets paid when bonus triggers).
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(7u8),
            reward_amount.into(),
        )
        .await?;

    // Slot 8: randomnessSeed (arbitrary non-zero value).
    provider
        .anvil_set_storage_at(
            world_campaign_manager_address,
            base_slot + U256::from(8u8),
            U256::from(1u8).into(),
        )
        .await?;

    // Finally, give the WorldCampaignManager enough token balance to pay rewards.
    set_erc20_balance_for_safe(
        provider,
        token,
        world_campaign_manager_address,
        total_funds,
    )
    .await?;

    Ok(())
}
