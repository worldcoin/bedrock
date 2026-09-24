use alloy::{
    primitives::{Address, U256},
    sol_types::SolValue,
};

use super::TransactionError;

/// Verifies that the TFH payload matches the fee token and confirmed charge ceiling.
pub(super) fn validate_fee(
    paymaster_data: &[u8],
    expected_token: Address,
    expected_cost: U256,
) -> Result<(), TransactionError> {
    // TFH accepts (token, ceiling) or (token, ceiling, premiumBps).
    let (token, ceiling) = match paymaster_data.len() {
        64 => <(Address, U256)>::abi_decode_validate(paymaster_data),
        96 => <(Address, U256, U256)>::abi_decode_validate(paymaster_data)
            .map(|(token, ceiling, _)| (token, ceiling)),
        length => {
            crate::error!(
                paymaster_data_length = length,
                "Invalid TFH paymaster data length"
            );
            return Err(TransactionError::Generic {
                error_message: "Invalid TFH paymaster data length".to_string(),
            });
        }
    }
    .map_err(|error| {
        crate::error!(error_message = error, "Invalid TFH paymaster data encoding");
        TransactionError::Generic {
            error_message: format!("Invalid TFH paymaster data encoding: {error}"),
        }
    })?;

    if token != expected_token {
        crate::error!(
            expected_fee_token = expected_token,
            actual_fee_token = token,
            "TFH paymaster fee token does not match the advisory"
        );
        return Err(TransactionError::Generic {
            error_message: "TFH paymaster fee token does not match the advisory"
                .to_string(),
        });
    }
    if ceiling != expected_cost {
        crate::error!(
            expected_fee = expected_cost,
            actual_ceiling = ceiling,
            "TFH paymaster charge ceiling does not match the final fee estimate"
        );
        return Err(TransactionError::Generic {
            error_message:
                "TFH paymaster charge ceiling does not match the final fee estimate"
                    .to_string(),
        });
    }
    Ok(())
}
