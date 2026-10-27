//! World Chain ERC-20 swaps through the 0x `AllowanceHolder`.
//!
//! The caller supplies a backend-authenticated executable quote and an independently
//! trusted Settler address. Route actions remain opaque: this module validates the
//! outer spending and settlement constraints, not each liquidity source or fee action.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};
use anyhow::{ensure, Context, Result};

use crate::{
    primitives::PrimitiveError,
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
};

use super::{
    erc20::Erc20,
    multisend::{MultiSend, MultiSendTx},
};

/// The Cancun `AllowanceHolder` used by 0x on World Chain.
/// Reference: <https://docs.0x.org/docs/core-concepts/contracts>
pub const ALLOWANCE_HOLDER_ADDRESS: Address =
    address!("0000000000001ff3684f28c67538d4d072c22734");

const NATIVE_TOKEN_ADDRESS: Address =
    address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee");

sol! {
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
    call_data: Bytes,
}

impl ZeroExSwap {
    /// Validates a quote against the reviewed request and builds approval + swap calls.
    ///
    /// `settler_address` must be authenticated independently of `quote.data`, for
    /// example against the 0x deployment registry. Copying the quote's operator or
    /// target into this argument does not authenticate the contract. Both must match
    /// this address; approvals are granted only to the canonical `AllowanceHolder`.
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
