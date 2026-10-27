//! World Chain ERC-20 swaps through the 0x `AllowanceHolder`.
//!
//! Executable quotes come from the authenticated backend. [`ZeroExSwap::from_quote`]
//! authenticates their Settler against the World Chain registry. Route actions remain
//! opaque: this module validates outer spending and settlement constraints, not each
//! liquidity source or fee action.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};
use anyhow::{ensure, Context, Result};

use crate::{
    primitives::{Network, PrimitiveError},
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
    transactions::{rpc::IMulticall3, RpcClient},
};

use super::{
    erc20::Erc20,
    multisend::{MultiSend, MultiSendTx},
};

/// The Cancun `AllowanceHolder` used by 0x on World Chain.
/// Reference: <https://docs.0x.org/docs/core-concepts/contracts>
pub const ALLOWANCE_HOLDER_ADDRESS: Address =
    address!("0000000000001ff3684f28c67538d4d072c22734");

/// The 0x deployment registry on World Chain.
/// Reference: <https://github.com/0xProject/0x-settler/blob/9a5f9f9ee9f5f056cb9846048b36fa18562b1983/README.md#how-do-i-find-the-most-recent-deployment>
pub const SETTLER_REGISTRY_ADDRESS: Address =
    address!("00000000000004533fe15556b1e086bb1a72ceae");

const TAKER_SUBMITTED_FEATURE: u128 = 2;

const NATIVE_TOKEN_ADDRESS: Address =
    address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

sol! {
    /// Registry reads used by 0x's recommended deployment authentication procedure.
    /// Reference: <https://github.com/0xProject/0x-settler/blob/9a5f9f9ee9f5f056cb9846048b36fa18562b1983/README.md#0x-api-dwell-time>
    interface ISettlerRegistry {
        function ownerOf(uint256 tokenId) external view returns (address);
        function prev(uint128 featureId) external view returns (address);
    }

    /// Reference: <https://github.com/0xProject/0x-settler/blob/9a5f9f9ee9f5f056cb9846048b36fa18562b1983/src/allowanceholder/IAllowanceHolder.sol>
    interface IAllowanceHolder {
        function exec(address operator, address token, uint256 amount, address target, bytes data)
            external payable returns (bytes result);
        function transferFrom(address token, address owner, address recipient, uint256 amount)
            external returns (bool);
    }

    /// Reference: <https://github.com/0xProject/0x-settler/blob/9a5f9f9ee9f5f056cb9846048b36fa18562b1983/src/interfaces/ISettlerBase.sol>
    struct AllowedSlippage {
        address recipient;
        address buyToken;
        uint256 minAmountOut;
    }

    /// Reference: <https://github.com/0xProject/0x-settler/blob/9a5f9f9ee9f5f056cb9846048b36fa18562b1983/src/interfaces/ISettlerTakerSubmitted.sol>
    interface ISettlerTakerSubmitted {
        function execute(AllowedSlippage slippage, bytes[] actions, bytes32 affiliate)
            external payable returns (bool);
        function executeWithPermit(AllowedSlippage slippage, bytes[] actions, bytes32 affiliate, bytes permitData)
            external payable returns (bool);
    }
}

/// The swap constraints reviewed by the user, independent of the executable calldata.
#[derive(Debug, Clone)]
pub struct ZeroExSwapRequest {
    /// Safe that spends the input and receives the output.
    pub wallet_address: Address,
    /// ERC-20 token to spend.
    pub token_in: Address,
    /// ERC-20 token to receive.
    pub token_out: Address,
    /// Exact input amount in token base units.
    pub amount_in: U256,
    /// Minimum output amount in token base units.
    pub amount_out_min: U256,
}

/// Executable quote fields returned by the authenticated backend's 0x integration.
#[derive(Debug, Clone)]
pub struct ZeroExSwapQuote {
    /// Target of the quoted transaction; must be the World Chain `AllowanceHolder`.
    pub to: Address,
    /// Native value of the quoted transaction; must be zero for this ERC-20 flow.
    pub value: U256,
    /// `AllowanceHolder` `exec` calldata containing a Settler `execute` call.
    pub data: Bytes,
    /// Quoted output after provider and integrator fees, in token base units.
    pub amount_out: U256,
}

/// An exact-amount approval and swap batched through the Safe `MultiSend` contract.
#[derive(Debug)]
pub struct ZeroExSwap {
    wallet_address: Address,
    settler_address: Address,
    call_data: Bytes,
}

impl ZeroExSwap {
    /// Returns the Settler retained for validation before signing.
    pub(crate) const fn settler_address(&self) -> Address {
        self.settler_address
    }

    /// Builds a swap and authenticates its Settler against the World Chain registry.
    ///
    /// Accepts the current taker-submitted deployment or its predecessor during the
    /// 0x API rollout window. A paused registry or unavailable/invalid RPC response
    /// blocks construction. The quote and reviewed request must come from the same
    /// authenticated backend quote flow; route and company-fee policy belong there.
    ///
    /// This is a point-in-time check. Call [`validate_settler`] again before signing
    /// if the operation is retained for confirmation.
    ///
    /// # Errors
    /// Returns an error if the quote is invalid or its Settler cannot be authenticated.
    pub async fn from_quote(
        rpc_client: &RpcClient,
        request: &ZeroExSwapRequest,
        quote: &ZeroExSwapQuote,
    ) -> Result<Self> {
        let allowance = IAllowanceHolder::execCall::abi_decode_validate(&quote.data)
            .context("Invalid AllowanceHolder exec calldata")?;
        let transaction = Self::new(request, quote, allowance.target)?;
        validate_settler(rpc_client, allowance.target).await?;
        Ok(transaction)
    }

    /// Validates a quote against the reviewed request and builds approval + swap calls.
    ///
    /// `settler_address` must be authenticated independently of `quote.data`, for
    /// example against the 0x deployment registry. Copying the quote's operator or
    /// target into this argument does not authenticate the contract. Both must match
    /// this address; approvals are granted only to the canonical `AllowanceHolder`.
    /// [`Self::from_quote`] performs the registry check for callers without an
    /// independently authenticated address.
    ///
    /// The quote's stronger minimum output is preserved. Backend policy owns asset
    /// eligibility, quote freshness, route selection, and company-fee reconciliation.
    /// This builder performs no screening, sponsorship, signing, submission, or
    /// metadata registration.
    ///
    /// # Errors
    /// Returns an error for malformed calldata, native-token flows, mismatched swap
    /// constraints or contracts, or quoted output below the enforced minimum.
    pub fn new(
        request: &ZeroExSwapRequest,
        quote: &ZeroExSwapQuote,
        settler_address: Address,
    ) -> Result<Self> {
        ensure!(
            request.wallet_address != Address::ZERO,
            "Wallet must be nonzero"
        );
        ensure!(settler_address != Address::ZERO, "Settler must be nonzero");
        for token in [request.token_in, request.token_out] {
            ensure!(
                token != Address::ZERO && token != NATIVE_TOKEN_ADDRESS,
                "Only ERC-20 tokens are supported"
            );
        }
        ensure!(
            request.token_in != request.token_out,
            "Swap tokens must differ"
        );
        ensure!(
            request.amount_in > U256::ZERO,
            "Input amount must be positive"
        );
        ensure!(
            request.amount_out_min > U256::ZERO,
            "Minimum output must be positive"
        );
        ensure!(
            quote.to == ALLOWANCE_HOLDER_ADDRESS,
            "Unexpected AllowanceHolder"
        );
        ensure!(quote.value == U256::ZERO, "Native value is not supported");

        let mut allowance =
            IAllowanceHolder::execCall::abi_decode_validate(&quote.data)
                .context("Invalid AllowanceHolder exec calldata")?;
        ensure!(
            allowance.operator == settler_address,
            "Unexpected Settler operator"
        );
        ensure!(
            allowance.target == settler_address,
            "Unexpected Settler target"
        );
        ensure!(allowance.token == request.token_in, "Input token mismatch");
        ensure!(
            allowance.amount == request.amount_in,
            "Input amount mismatch"
        );

        let mut settlement =
            ISettlerTakerSubmitted::executeCall::abi_decode_validate(&allowance.data)
                .context("Invalid Settler execute calldata")?;
        ensure!(
            settlement.slippage.recipient == request.wallet_address,
            "Output recipient mismatch"
        );
        ensure!(
            settlement.slippage.buyToken == request.token_out,
            "Output token mismatch"
        );
        settlement.slippage.minAmountOut =
            settlement.slippage.minAmountOut.max(request.amount_out_min);
        ensure!(
            quote.amount_out >= settlement.slippage.minAmountOut,
            "Quoted output is below the minimum"
        );
        allowance.data = settlement.abi_encode().into();

        let approval =
            Erc20::encode_approve(ALLOWANCE_HOLDER_ADDRESS, request.amount_in);
        let swap = allowance.abi_encode();
        let bundle = MultiSend::build_bundle(&[
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: request.token_in,
                value: U256::ZERO,
                data_length: U256::from(approval.len()),
                data: approval.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: ALLOWANCE_HOLDER_ADDRESS,
                value: U256::ZERO,
                data_length: U256::from(swap.len()),
                data: swap.into(),
            },
        ]);

        Ok(Self {
            wallet_address: request.wallet_address,
            settler_address,
            call_data: ISafe4337Module::executeUserOpCall {
                to: bundle.to,
                value: bundle.value,
                data: bundle.data.into(),
                operation: bundle.operation as u8,
            }
            .abi_encode()
            .into(),
        })
    }
}

/// Authenticates a taker-submitted Settler on World Chain without caching the result.
///
/// The current and previous deployments are read in one EVM call so they describe
/// the same registry state. Failure of `ownerOf(2)` blocks the entire call, including
/// when 0x pauses the feature. A missing previous deployment is tolerated only when
/// the current deployment matches. No next or historical deployment is accepted.
///
/// # Errors
/// Returns an error for a paused registry, RPC failure, malformed response, or an
/// address outside the registry's current/previous taker-submitted deployments.
pub async fn validate_settler(rpc_client: &RpcClient, settler: Address) -> Result<()> {
    ensure!(settler != Address::ZERO, "Settler must be nonzero");
    let call = IMulticall3::aggregate3Call {
        calls: vec![
            IMulticall3::Call3 {
                target: SETTLER_REGISTRY_ADDRESS,
                allowFailure: false,
                callData: ISettlerRegistry::ownerOfCall {
                    tokenId: U256::from(TAKER_SUBMITTED_FEATURE),
                }
                .abi_encode()
                .into(),
            },
            IMulticall3::Call3 {
                target: SETTLER_REGISTRY_ADDRESS,
                allowFailure: true,
                callData: ISettlerRegistry::prevCall {
                    featureId: TAKER_SUBMITTED_FEATURE,
                }
                .abi_encode()
                .into(),
            },
        ],
    };
    let response = rpc_client
        .eth_call(
            Network::WorldChain,
            alloy::providers::MULTICALL3_ADDRESS,
            call.abi_encode().into(),
        )
        .await
        .context("Failed to query 0x Settler registry")?;
    let results = IMulticall3::aggregate3Call::abi_decode_returns_validate(&response)
        .context("Invalid 0x Settler registry batch response")?;
    ensure!(results.len() == 2, "Expected two Settler registry results");
    ensure!(results[0].success, "Current Settler registry lookup failed");
    ensure!(
        results[0].returnData.len() == 32,
        "Invalid current Settler response length"
    );
    let current = ISettlerRegistry::ownerOfCall::abi_decode_returns_validate(
        &results[0].returnData,
    )
    .context("Invalid current Settler response")?;
    ensure!(current != Address::ZERO, "Current Settler is unavailable");
    if current == settler {
        return Ok(());
    }
    ensure!(
        results[1].success,
        "Previous Settler registry lookup failed"
    );
    ensure!(
        results[1].returnData.len() == 32,
        "Invalid previous Settler response length"
    );
    let previous =
        ISettlerRegistry::prevCall::abi_decode_returns_validate(&results[1].returnData)
            .context("Invalid previous Settler response")?;
    ensure!(previous == settler, "Unrecognized 0x Settler deployment");
    Ok(())
}

impl Is4337Encodable for ZeroExSwap {
    type MetadataArg = ();

    fn build_execute_user_op_call_data(&self) -> Bytes {
        self.call_data.clone()
    }

    fn build_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        if wallet_address != self.wallet_address {
            return Err(PrimitiveError::InvalidInput {
                attribute: "wallet_address".to_string(),
                error_message: "Swap belongs to another wallet".to_string(),
            });
        }
        let key = NonceKeyV1::new(
            TransactionTypeId::ZeroExSwap,
            InstructionFlag::Default,
            [0u8; 10],
        );
        Ok(UserOperation::new_with_defaults(
            wallet_address,
            key.encode(),
            self.build_execute_user_op_call_data(),
        ))
    }
}
