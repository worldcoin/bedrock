use std::{str::FromStr, sync::Arc};

use alloy::{
    network::Ethereum,
    primitives::{address, keccak256, Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolValue,
};

use bedrock::{
    primitives::{
        http_client::{
            set_http_client, AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod,
        },
        Network,
    },
    smart_account::{SafeSmartAccount, ENTRYPOINT_4337},
    transaction::{foreign::UnparsedUserOperation, RpcProviderName},
};

use serde::Serialize;
use serde_json::json;

mod common;
use common::{deploy_safe, setup_anvil, IEntryPoint, PackedUserOperation, IERC20};

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
                message: "unsupported method".into(),
            });
        }

        let body = body.ok_or(HttpError::Generic {
            message: "missing body".into(),
        })?;

        let root: serde_json::Value =
            serde_json::from_slice(&body).map_err(|_| HttpError::Generic {
                message: "invalid json".into(),
            })?;

        let method =
            root.get("method")
                .and_then(|m| m.as_str())
                .ok_or(HttpError::Generic {
                    message: "invalid json".into(),
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
                    pre_verification_gas: "0x20000".into(),
                    verification_gas_limit: "0x20000".into(),
                    call_gas_limit: "0x20000".into(),
                    paymaster_verification_gas_limit: "0x0".into(),
                    paymaster_post_op_gas_limit: "0x0".into(),
                    max_priority_fee_per_gas: "0x3b9aca00".into(), // 1 gwei
                    max_fee_per_gas: "0x3b9aca00".into(),          // 1 gwei
                };
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": result,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
            // Send the userOperation to alchemy as Rundler will be able to determine this is a PBH userOperation
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    message: "missing userOp param".into(),
                })?;
                let entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing entryPoint param".into(),
                    },
                )?;
                // Build UnparsedUserOperation from JSON (which uses hex strings), then convert
                let obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    message: "userOp param must be an object".into(),
                })?;

                let get_opt = |k: &str| -> Option<String> {
                    obj.get(k).and_then(|v| v.as_str()).map(|s| s.to_string())
                };
                let get_or_zero = |k: &str| -> String {
                    get_opt(k).unwrap_or_else(|| "0x0".to_string())
                };
                let get_required = |k: &str| -> Result<String, HttpError> {
                    get_opt(k).ok_or(HttpError::Generic {
                        message: format!("missing or invalid {k}"),
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
                        message: format!("invalid userOp: {e}"),
                    })?;

                // Convert to the packed format expected by EntryPoint
                let packed = PackedUserOperation::try_from(&user_op).map_err(|e| {
                    HttpError::Generic {
                        message: format!("pack userOp failed: {e}"),
                    }
                })?;

                // Compute the EntryPoint userOpHash per EIP-4337 spec
                let packed_for_hash =
                    PackedUserOperation::try_from(&user_op).map_err(|e| {
                        HttpError::Generic {
                            message: format!("pack userOp for hash failed: {e}"),
                        }
                    })?;
                let chain_id_u64 = self.provider.get_chain_id().await.map_err(|e| {
                    HttpError::Generic {
                        message: format!("getChainId failed: {e}"),
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
                            message: "invalid entryPoint".into(),
                        }
                    })?;
                let entry_point = IEntryPoint::new(entry_point_addr, &self.provider);
                let _tx = entry_point
                    .handleOps(vec![packed], user_op.sender)
                    .send()
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("handleOps failed: {e}"),
                    })?;

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
                message: format!("unsupported method {other}"),
            }),
        }
    }
}

// ------------------ The test for the full transaction_transfer flow ------------------

#[tokio::test]
async fn test_transaction_transfer_full_flow_executes_user_operation_non_pbh(
) -> anyhow::Result<()> {
    // 1) Spin up anvil fork
    let anvil = setup_anvil();

    // 2) Owner signer and provider
    let owner_signer = PrivateKeySigner::random();
    let owner_key_hex = hex::encode(owner_signer.to_bytes());
    let owner = owner_signer.address();

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(anvil.endpoint_url());

    provider
        .anvil_set_balance(owner, U256::from(1e18 as u64))
        .await?;

    // 3) Deploy Safe with 4337 module enabled
    let safe_address = deploy_safe(&provider, owner, U256::ZERO).await?;

    // 4) Fund EntryPoint deposit for Safe
    let entry_point = IEntryPoint::new(*ENTRYPOINT_4337, &provider);
    let _ = entry_point
        .depositTo(safe_address)
        .value(U256::from(1e18 as u64))
        .send()
        .await?;

    // 5) Give Safe some ERC-20 balance (WLD on World Chain test contract used in other tests)
    let wld_token_address = address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003");
    let wld = IERC20::new(wld_token_address, &provider);

    // Simulate balance by writing storage slot for mapping(address => uint) at slot 0
    let mut padded = [0u8; 64];
    padded[12..32].copy_from_slice(safe_address.as_slice());
    let slot_hash = keccak256(padded);
    let slot = U256::from_be_bytes(slot_hash.into());
    let starting_balance = U256::from(10u128.pow(18) * 10); // 10 WLD
    provider
        .anvil_set_storage_at(wld_token_address, slot, starting_balance.into())
        .await?;

    // 6) Prepare recipient and assert initial balances
    let recipient = PrivateKeySigner::random().address();
    let before_recipient = wld.balanceOf(recipient).call().await?;
    let before_safe = wld.balanceOf(safe_address).call().await?;

    // 7) Install mocked HTTP client that routes calls to Anvil
    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    let _ = set_http_client(Arc::new(client));

    // 8) Execute high-level transfer via transaction_transfer
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let amount = "1000000000000000000"; // 1 WLD
    let _user_op_hash = safe_account
        .transaction_transfer(
            Network::WorldChain,
            &wld_token_address.to_string(),
            &recipient.to_string(),
            amount,
            false,
            RpcProviderName::Alchemy,
        )
        .await
        .expect("transaction_transfer failed");

    // 9) Verify balances updated
    let after_recipient = wld.balanceOf(recipient).call().await?;
    let after_safe = wld.balanceOf(safe_address).call().await?;

    assert_eq!(
        after_recipient,
        before_recipient + U256::from(10u128.pow(18))
    );
    assert_eq!(after_safe, before_safe - U256::from(10u128.pow(18)));

    Ok(())
}
