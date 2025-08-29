use std::sync::Arc;

use alloy::{
    network::Ethereum,
    providers::{Provider, ProviderBuilder},
    signers::local::PrivateKeySigner,
};
use reqwest::Url;

use bedrock::{
    primitives::{
        http_client::{
            set_http_client, AuthenticatedHttpClient, HttpError, HttpHeader, HttpMethod,
        },
        Network,
    },
    smart_account::SafeSmartAccount,
    transaction::RpcProviderName,
};

use serde::Serialize;
use serde_json::json;

mod common;

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

        let method = root.get("method")
            .and_then(|m| m.as_str())
            .ok_or(HttpError::Generic {
                message: "invalid json".into(),
            })?
            .to_string();
        let id = root.get("id").cloned().unwrap_or(serde_json::Value::Null);
        let params = root
            .get("params")
            .cloned()
            .unwrap_or(serde_json::Value::Null);

        match method.as_str() {
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
            // Forward all other methods to the actual provider
            _ => {

                println!("method: {method}");
                println!("params: {params}");

                // Forward the JSON-RPC request to the provider
                let response = self.provider.raw_request::<serde_json::Value, serde_json::Value>(method.into(), params).await
                    .map_err(|e| HttpError::Generic {
                        message: format!("Provider request failed: {}", e),
                    })?;
                
                let resp = json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "result": response,
                });
                Ok(serde_json::to_vec(&resp).unwrap())
            }
        }
    }
}

// ------------------ The test for the full transaction_transfer flow ------------------

#[tokio::test]
async fn test_pbh_transaction_transfer_full_flow(
) -> anyhow::Result<()> {
    let secrets: String = std::fs::read_to_string("tests/sepolia_secrets.json")?;

    let secret: serde_json::Value = serde_json::from_str(&secrets)?;
    let private_key = secret["private_key"].as_str().unwrap();
    let safe_address = secret["safe_address"].as_str().unwrap();
    let rpc_url: Url = secret["rpc_url"].as_str().unwrap().parse()?;

    let owner_signer = PrivateKeySigner::from_slice(
        &hex::decode(private_key)?,
    )?;

    let owner_key_hex = hex::encode(owner_signer.to_bytes());

    let provider = ProviderBuilder::new()
        .wallet(owner_signer.clone())
        .connect_http(rpc_url);

    // 7) Install mocked HTTP client that routes calls to Anvil
    let client = AnvilBackedHttpClient {
        provider: provider.clone(),
    };
    let _ = set_http_client(Arc::new(client));

    // 8) Execute high-level transfer via transaction_transfer
    let safe_account = SafeSmartAccount::new(owner_key_hex, &safe_address.to_string())?;
    let amount = "1";
    let recipient = safe_address;
    
    let _user_op_hash = safe_account
        .transaction_transfer(
            Network::WorldChainSepolia,
            &"0xC82Ea35634BcE95C394B6BC00626f827bB0F4801".to_string(), // WORLD SEPOLIA LINK TOKEN
            &recipient.to_string(),
            amount,
            true,
            RpcProviderName::Alchemy,
        )
        .await
        .expect("transaction_transfer failed");

    Ok(())
}
