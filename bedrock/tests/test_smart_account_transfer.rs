use std::{str::FromStr, sync::Arc};

use alloy::{
    network::Ethereum,
    primitives::{address, keccak256, Address, U256},
    providers::{ext::AnvilApi, Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};

use bedrock::{
    primitives::{
        http_client::{
            set_http_client, AuthenticatedHttpClient, HttpError, HttpMethod,
        },
        Network,
    },
    smart_account::{ISafe4337Module, SafeSmartAccount, ENTRYPOINT_4337},
};

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

mod common;
use common::{deploy_safe, setup_anvil, IEntryPoint, IERC20};

// PackedUserOperation and interfaces are imported from common

// setup_anvil and deploy_safe are provided by common

// ------------------ Mock HTTP client that actually executes the op on Anvil ------------------

#[derive(Clone)]
struct AnvilBackedHttpClient<P>
where
    P: Provider<Ethereum> + Clone + Send + Sync + 'static,
{
    provider: P,
}

#[derive(Deserialize)]
struct JsonRpcRequestLite {
    _jsonrpc: String,
    id: Value,
    method: String,
    params: Value,
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
            // Execute the inner call directly through the Safe 4337 Module (no sponsorship path)
            "eth_sendUserOperation" => {
                let params = params.as_array().ok_or(HttpError::Generic {
                    message: "invalid params".into(),
                })?;
                let user_op_val = params.first().ok_or(HttpError::Generic {
                    message: "missing userOp param".into(),
                })?;
                let _entry_point_str = params.get(1).and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing entryPoint param".into(),
                    },
                )?;

                // Validate presence of required fields (no defaulting). Throw if invalid.
                let op_obj = user_op_val.as_object().ok_or(HttpError::Generic {
                    message: "userOp param must be an object".into(),
                })?;

                let sender_str = op_obj.get("sender").and_then(|v| v.as_str()).ok_or(
                    HttpError::Generic {
                        message: "missing or invalid sender".into(),
                    },
                )?;
                let call_data_str = op_obj
                    .get("callData")
                    .and_then(|v| v.as_str())
                    .ok_or(HttpError::Generic {
                        message: "missing or invalid callData".into(),
                    })?;

                let sender =
                    Address::from_str(sender_str).map_err(|_| HttpError::Generic {
                        message: "invalid sender".into(),
                    })?;

                let call_data_hex =
                    call_data_str.strip_prefix("0x").unwrap_or(call_data_str);
                let call_data_bytes =
                    hex::decode(call_data_hex).map_err(|_| HttpError::Generic {
                        message: "invalid callData".into(),
                    })?;

                // Decode the module callData and simulate a plain ERC20 transfer by updating storage
                let module_call =
                    ISafe4337Module::executeUserOpCall::abi_decode(&call_data_bytes)
                        .map_err(|e| HttpError::Generic {
                            message: format!(
                                "decode executeUserOp callData failed: {e}"
                            ),
                        })?;

                let token_address = module_call.to;
                let inner_data: Vec<u8> = module_call.data.to_vec();

                // Expect the ERC20 transfer selector (a9059cbb) and decode
                let transfer =
                    IERC20::transferCall::abi_decode(&inner_data).map_err(|e| {
                        HttpError::Generic {
                            message: format!("decode erc20 transfer failed: {e}"),
                        }
                    })?;

                let recipient = transfer.to;
                let amount = transfer.amount;

                // Read current balances
                let erc20 = IERC20::new(token_address, &self.provider);
                let sender_balance =
                    erc20.balanceOf(sender).call().await.map_err(|e| {
                        HttpError::Generic {
                            message: format!("read sender balance failed: {e}"),
                        }
                    })?;
                let recipient_balance =
                    erc20.balanceOf(recipient).call().await.map_err(|e| {
                        HttpError::Generic {
                            message: format!("read recipient balance failed: {e}"),
                        }
                    })?;

                // Compute mapping slots (balances mapping at slot 0)
                let calc_slot = |addr: Address| {
                    let mut padded = [0u8; 64];
                    padded[12..32].copy_from_slice(addr.as_slice());
                    let slot_hash = keccak256(padded);
                    U256::from_be_bytes(slot_hash.into())
                };

                let sender_slot = calc_slot(sender);
                let recipient_slot = calc_slot(recipient);

                // Update balances
                let new_sender = sender_balance.saturating_sub(amount);
                let new_recipient = recipient_balance.saturating_add(amount);

                self.provider
                    .anvil_set_storage_at(token_address, sender_slot, new_sender.into())
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("set sender storage failed: {e}"),
                    })?;
                self.provider
                    .anvil_set_storage_at(
                        token_address,
                        recipient_slot,
                        new_recipient.into(),
                    )
                    .await
                    .map_err(|e| HttpError::Generic {
                        message: format!("set recipient storage failed: {e}"),
                    })?;

                // Return a deterministic pseudo userOpHash from sender+callData
                let mut preimage =
                    Vec::with_capacity(sender.as_slice().len() + call_data_bytes.len());
                preimage.extend_from_slice(sender.as_slice());
                preimage.extend_from_slice(&call_data_bytes);
                let user_op_hash = keccak256(preimage);

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
async fn test_transaction_transfer_full_flow_executes_user_operation(
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
