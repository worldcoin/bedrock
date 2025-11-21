use std::{str::FromStr, sync::Arc};

use alloy::{
    network::Ethereum,
    primitives::{address, keccak256, Address, Log, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::{SolEvent, SolValue},
};

use bedrock::{
    primitives::http_client::{
        set_http_client, AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    transactions::foreign::UnparsedUserOperation,
};

use serde::Serialize;
use serde_json::json;
use serial_test::serial;

mod common;
use common::{
    deploy_safe, set_erc20_balance_for_safe, setup_anvil, IEntryPoint,
    PackedUserOperation, IERC20,
};

// ------------------ Mock HTTP client that actually executes the op on Anvil ------------------
#[derive(Clone)]
struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    provider: P,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SponsorUserOperationResponseLite<'a> {
    paymaster: &'a str,
    paymaster_data: &'a str,
    pre_verification_gas: String,
    verification_gas_limit: String,
    call_gas_limit: String,
    paymaster_verification_gas_limit: String,
    paymaster_post_op_gas_limit: String,
    max_priority_fee_per_gas: String,
    max_fee_per_gas: String,
    provider_name: String,
}

#[async_trait::async_trait]
impl<P> AuthenticatedHttpClient for AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    async fn fetch_from_app_backend(
        &self,
        _url: String,
        method: HttpMethod,
        _headers: Vec<HttpHeader>,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError> {
        if method != HttpMethod::Post {
            return Err(HttpError::Generic {
                error_message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            error_message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                error_message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    error_message: "invalid json".into(),
                })?;
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method {
            // Respond with minimal, sane gas values and no paymaster
            "wa_sponsorUserOperation" => {
                let result = SponsorUserOperationResponseLite {
                    paymaster: "0x0000000000000000000000000000000000000000",
                    paymaster_data: "0x",
                    pre_verification_gas: "0x200000".into(), // 2M
                    verification_gas_limit: "0x200000".into(), // 2M
                    call_gas_limit: "0x200000".into(),       // 2M
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x12A05F200".into(), // 5 gwei
                    max_fee_per_gas: "0x12A05F200".into(),          // 5 gwei
                    provider_name: "pimlico".into(),
                };
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            // Execute the inner call directly through the Safe 4337 Module (no sponsorship path)
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    error_message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    error_message: "missing userOp param".into(),
                })?;
                let entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        error_message: "missing entryPoint param".into(),
                    },
                )?;
                // Build UnparsedUserOperation from JSON (which uses hex strings), then convert
                let obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    error_message: "userOp param must be an object".into(),
                })?;

                let get_opt = |k: &str| -> Option<String> {
                    obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
                };
                let get_or_zero = |k: &str| -> String {
                    get_opt(k).unwrap_or_else(|| "0x0".to_string())
                };
                let get_required = |k: &str| -> Result<String, HttpError> {
                    get_opt(k).ok_or(HttpError::Generic {
                        error_message: format!("missing or invalid {k}"),
                    })
                };

                let unparsed = UnparsedUserOperation {
                    sender: get_required("sender")?,
                    nonce: get_required("nonce")?,
                    call_data: get_required("callData")?,
                    call_gas_limit: get_or_zero("callGasLimit"),
                    verification_gas_limit: get_or_zero("verificationGasLimit"),
                    pre_verification_gas: get_or_zero("preVerificationGas"),
                    max_fee_per_gas: get_or_zero("maxFeePerGas"),
                    max_priority_fee_per_gas: get_or_zero("maxPriorityFeePerGas"),
                    paymaster: get_opt("paymaster"),
                    paymaster_verification_gas_limit: get_or_zero(
                        "paymasterVerificationGasLimit",
                    ),
                    paymaster_post_op_gas_limit: get_or_zero("paymasterPostOpGasLimit"),
                    paymaster_data: get_opt("paymasterData"),
                    signature: get_required("signature")?,
                    factory: get_opt("factory"),
                    factory_data: get_opt("factoryData"),
                };

                let user_op: bedrock::smart_account::UserOperation =
                    unparsed.try_into().map_err(|e| HttpError::Generic {
                        error_message: format!("invalid userOp: {e}"),
                    })?;

                // Convert to the packed format expected by EntryPoint
                let packed = PackedUserOperation::try_from(&user_op).map_err(|e| {
                    HttpError::Generic {
                        error_message: format!("pack userOp failed: {e}"),
                    }
                })?;

                // Compute the EntryPoint userOpHash per EIP-4337 spec
                let packed_for_hash =
                    PackedUserOperation::try_from(&user_op).map_err(|e| {
                        HttpError::Generic {
                            error_message: format!("pack userOp for hash failed: {e}"),
                        }
                    })?;
                let chain_id_u64 = self.provider.get_chain_id().await.map_err(|e| {
                    HttpError::Generic {
                        error_message: format!("getChainId failed: {e}"),
                    }
                })?;
                let inner_encoded = (
                    packed_for_hash.sender,
                    packed_for_hash.nonce,
                    keccak256(packed_for_hash.init_code.clone()),
                    keccak256(packed_for_hash.call_data.clone()),
                    packed_for_hash.account_gas_limits,
                    packed_for_hash.pre_verification_gas,
                    packed_for_hash.gas_fees,
                    keccak256(packed_for_hash.paymaster_and_data.clone()),
                )
                    .abi_encode();
                let inner_hash = keccak256(inner_encoded);

                // Execute via EntryPoint.handleOps on-chain
                let entry_point_addr =
                    Address::from_str(entry_point_str).map_err(|_| {
                        HttpError::Generic {
                            error_message: "invalid entryPoint".into(),
                        }
                    })?;
                let entry_point = IEntryPoint::new(entry_point_addr, &self.provider);
                let tx = entry_point
                    .handleOps(vec![packed], user_op.sender)
                    .send()
                    .await
                    .map_err(|e| HttpError::Generic {
                        error_message: format!("handleOps failed: {e}"),
                    })?;
                let receipt =
                    tx.get_receipt().await.map_err(|e| HttpError::Generic {
                        error_message: format!("handleOps receipt failed: {e}"),
                    })?;

                // Check for error events in the receipt
                for log in receipt.inner.logs() {
                    let raw_log = Log {
                        address: log.address(),
                        data: log.data().clone(),
                    };

                    // Check for UserOperationRevertReason event
                    if let Ok(revert_event) =
                        IEntryPoint::UserOperationRevertReason::decode_log(&raw_log)
                    {
                        let revert_reason = if revert_event.revertReason.is_empty() {
                            "Unknown revert reason".to_string()
                        } else {
                            String::from_utf8(revert_event.revertReason.to_vec())
                                .unwrap_or_else(|_| {
                                    format!(
                                        "0x{}",
                                        hex::encode(&revert_event.revertReason)
                                    )
                                })
                        };

                        return Err(HttpError::Generic {
                            error_message: format!(
                                "UserOperation reverted - sender: {}, nonce: {}, reason: {}",
                                revert_event.sender, revert_event.nonce, revert_reason
                            ),
                        });
                    }

                    // Log UserOperationEvent for debugging
                    if let Ok(event) =
                        IEntryPoint::UserOperationEvent::decode_log(&raw_log)
                    {
                        println!(
                            "UserOperationEvent - sender: {}, success: {}, actualGasCost: {}, actualGasUsed: {}",
                            event.sender, event.success, event.actualGasCost, event.actualGasUsed
                        );
                    }
                }

                // Return the chain userOpHash (EntryPoint-wrapped)
                let enc = (inner_hash, entry_point_addr, U256::from(chain_id_u64))
                    .abi_encode();
                let user_op_hash = keccak256(enc);

                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": format!("0x{}", hex::encode(user_op_hash)),
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            other => Err(HttpError::Generic {
                error_message: format!("unsupported method {other}"),
            }),
        }
    }
}

#[tokio::test]
#[serial]
async fn test_transaction_world_gift_manager_gift_redeem_user_operations(
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

    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    set_erc20_balance_for_safe(
        &provider,
        wld_token_address,
        safe_address_giftor,
        starting_balance,
    )
    .await?;
    set_erc20_balance_for_safe(
        &provider,
        wld_token_address,
        safe_address_giftee,
        starting_balance,
    )
    .await?;

    let before_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let before_giftee = wld.balanceOf(safe_address_giftee).call().await?;

    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };

    set_http_client(Arc::new(client));

    let safe_account_giftor =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftor.to_string())?;
    let safe_account_giftee =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftee.to_string())?;
    let amount = U256::from(1e18);

    let gift_result = safe_account_giftor
        .transaction_world_gift_manager_gift(
            &wld_token_address.to_string(),
            &safe_address_giftee.to_string(),
            &amount.to_string(),
        )
        .await
        .expect("transaction_world_gift_manager_gift failed");

    let after_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let after_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    assert_eq!(after_giftor, before_giftor - amount);
    assert_eq!(after_giftee, before_giftee);

    let _redeem_result = safe_account_giftee
        .transaction_world_gift_manager_redeem(gift_result.gift_id.as_str())
        .await
        .expect("transaction_world_gift_manager_redeem failed");

    let after_redeem_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    assert_eq!(after_redeem_giftee, before_giftee + amount);

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_transaction_world_gift_manager_gift_cancel_user_operations(
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

    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    set_erc20_balance_for_safe(
        &provider,
        wld_token_address,
        safe_address_giftor,
        starting_balance,
    )
    .await?;

    let before_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let before_giftee = wld.balanceOf(safe_address_giftee).call().await?;

    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };

    set_http_client(Arc::new(client));

    let safe_account_giftor =
        SafeSmartAccount::new(owner_key_hex.clone(), &safe_address_giftor.to_string())?;
    let amount = U256::from(1e18);

    let gift_result = safe_account_giftor
        .transaction_world_gift_manager_gift(
            &wld_token_address.to_string(),
            &safe_address_giftee.to_string(),
            &amount.to_string(),
        )
        .await
        .expect("transaction_world_gift_manager_gift failed");

    let after_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    let after_giftee = wld.balanceOf(safe_address_giftee).call().await?;
    assert_eq!(after_giftor, before_giftor - amount);
    assert_eq!(after_giftee, before_giftee);

    let _redeem_result = safe_account_giftor
        .transaction_world_gift_manager_cancel(gift_result.gift_id.as_str())
        .await
        .expect("transaction_world_gift_manager_cancel failed");

    let after_cancel_giftor = wld.balanceOf(safe_address_giftor).call().await?;
    assert_eq!(after_cancel_giftor, before_giftor);

    Ok(())
}
