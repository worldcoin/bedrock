//! Prepared World Chain ERC-20 swaps for mobile confirmation and submission.

use alloy::primitives::{Address, U256};
use bedrock_macros::bedrock_export;

use crate::smart_account::{Is4337Encodable, SafeSmartAccount};

use super::{
    contracts::zero_ex::{ZeroExSwap, ZeroExSwapQuote, ZeroExSwapRequest},
    foreign::{UnparsedZeroExSwapQuote, UnparsedZeroExSwapRequest},
    prepare_operation,
    rpc::get_rpc_client,
    screening_error, PreparedTransaction, TransactionError,
};
use crate::primitives::{Network, ParseFromForeignBinding};

#[bedrock_export]
impl SafeSmartAccount {
    /// Prepares an unsigned 0x ERC-20 swap on World Chain for user confirmation.
    ///
    /// `request` contains the independently reviewed input and minimum output;
    /// `quote` contains executable data from the authenticated backend quote flow.
    /// The backend owns asset eligibility, quote freshness, route selection, and
    /// company-fee reconciliation. Bedrock validates spending and settlement,
    /// authenticates the Settler, screens the wallet, and estimates network fees.
    ///
    /// Omit `custom_bundler_url` to request backend sponsorship. A custom bundler
    /// estimates and submits the operation, covering its gas costs. Self-sponsorship
    /// requires existing fee-token allowance and balance; expected swap proceeds
    /// cannot fund the upfront network fee.
    ///
    /// Call `submit_prepared_transaction` after confirmation. Submission checks the
    /// Settler registry again. Preparation performs no signing, submission, or swap
    /// metadata registration.
    ///
    /// # Errors
    /// Returns an error for invalid inputs or quotes, unavailable/unrecognized
    /// Settlers, failed screening or estimation, or insufficient fee-token funds.
    pub async fn prepare_transaction_swap(
        &self,
        request: UnparsedZeroExSwapRequest,
        quote: UnparsedZeroExSwapQuote,
        custom_bundler_url: Option<String>,
    ) -> Result<PreparedTransaction, TransactionError> {
        let route = if custom_bundler_url.is_some() {
            "custom"
        } else {
            "default"
        };
        let log_failure = |stage: &str, error: &dyn std::fmt::Display| {
            crate::error!(
                transaction_type = "zero_ex_swap",
                network = Network::WorldChain.network_name(),
                sender = self.wallet_address,
                route = route,
                stage = stage,
                outcome = "error",
                error_message = error,
                "Failed to prepare ERC-20 swap"
            );
        };
        let request = ZeroExSwapRequest {
            wallet_address: self.wallet_address,
            token_in: Address::parse_from_ffi(&request.token_in, "token_in")
                .inspect_err(|e| log_failure("parse_token_in", e))?,
            token_out: Address::parse_from_ffi(&request.token_out, "token_out")
                .inspect_err(|e| log_failure("parse_token_out", e))?,
            amount_in: U256::parse_from_ffi(&request.amount_in, "amount_in")
                .inspect_err(|e| log_failure("parse_amount_in", e))?,
            amount_out_min: U256::parse_from_ffi(
                &request.amount_out_min,
                "amount_out_min",
            )
            .inspect_err(|e| log_failure("parse_amount_out_min", e))?,
        };
        let quote = ZeroExSwapQuote::try_from(quote)
            .inspect_err(|e| log_failure("parse_quote", e))?;
        let rpc_client = get_rpc_client().map_err(|e| {
            log_failure("get_rpc_client", &e);
            TransactionError::Generic {
                error_message: format!(
                    "Failed to get RPC client for swap preparation: {e}"
                ),
            }
        })?;
        let transaction = ZeroExSwap::from_quote(rpc_client, &request, &quote)
            .await
            .map_err(|e| {
                let error_message = format!("Failed to validate swap quote: {e:#}");
                log_failure("validate_quote", &error_message);
                TransactionError::Generic { error_message }
            })?;
        let operation = transaction
            .build_preflight_user_operation(self.wallet_address, None)
            .inspect_err(|e| log_failure("build_user_operation", e))?;
        let screening = async {
            rpc_client
                .screen_addresses(Network::WorldChain, &[self.wallet_address])
                .await
                .map_err(screening_error)
        };
        let preparation = prepare_operation(
            rpc_client,
            operation,
            request.token_in,
            request.amount_in,
            custom_bundler_url,
        );
        let (screening, prepared) = tokio::join!(screening, preparation);
        screening.inspect_err(|error| log_failure("screening", error))?;
        let mut prepared =
            prepared.inspect_err(|error| log_failure("prepare", error))?;
        prepared.swap_settler = Some(transaction.settler_address());
        crate::debug!(
            transaction_type = "zero_ex_swap",
            network = Network::WorldChain.network_name(),
            sender = self.wallet_address,
            outcome = "prepared",
            "Prepared ERC-20 swap"
        );
        Ok(prepared)
    }
}
