use alloy::{
    primitives::{Address, U256},
    sol_types::SolValue,
};

use super::TransactionError;

/// Verifies that the TFH payload charges the token shown in the fee advisory.
pub(super) fn validate_fee_token(
    paymaster_data: &[u8],
    expected_token: Address,
) -> Result<(), TransactionError> {
    // TFH accepts (token, ceiling) or (token, ceiling, premiumBps).
    let token = match paymaster_data.len() {
        64 => <(Address, U256)>::abi_decode_validate(paymaster_data)
            .map(|(token, _)| token),
        96 => <(Address, U256, U256)>::abi_decode_validate(paymaster_data)
            .map(|(token, _, _)| token),
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
    Ok(())
}
