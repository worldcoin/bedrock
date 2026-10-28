//! Atomic Universal uAsset redemptions through the Safe's `MultiSend`.

use std::collections::HashSet;

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::{
    primitives::{HexEncodedData, ParseFromForeignBinding, PrimitiveError},
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
};

use super::{
    erc20::Erc20,
    multisend::{MultiSend, MultiSendBundle, MultiSendTx},
};

sol! {
    /// Universal's shared-liquidity wind-down vault interface.
    interface IUniversalWindDownVault {
        function redeem(address asset, uint256 amount, uint256 minimumUSDCAmount)
            external returns (uint256 usdcAmount);
    }
}

/// One accepted uAsset redemption quote, using decimal integer base units.
#[derive(Clone, Debug, uniffi::Record)]
pub struct UAssetRedemption {
    /// The uAsset token contract address from the backend's redemption status.
    pub token_address: String,
    /// Amount to redeem in 18-decimal uAsset base units. Must be positive.
    pub amount: String,
    /// Minimum accepted payout in six-decimal USDC base units. Must be positive.
    /// Use the quoted payout accepted by the user to protect against rate reductions.
    pub minimum_usdc_amount: String,
}

/// An exact-amount approval and redemption for each uAsset in one atomic batch.
pub struct UniversalWindDownVault {
    bundle: MultiSendBundle,
}

impl UniversalWindDownVault {
    /// Builds a batch without RPC calls, signing, or submission.
    ///
    /// `vault_address` must come from trusted backend configuration. This encoder
    /// does not authenticate the vault or check balances, rates, pause state, or
    /// liquidity. The caller must supply only redeemable holdings and preserve
    /// the amounts and minimum payouts accepted by the user.
    ///
    /// # Errors
    /// Returns `PrimitiveError::InvalidInput` for invalid addresses or uint256
    /// values, zero addresses/amounts/minimums, an empty batch, or duplicate tokens.
    pub fn new(
        vault_address: &str,
        redemptions: &[UAssetRedemption],
    ) -> Result<Self, PrimitiveError> {
        let invalid =
            |attribute: &str, error_message: &str| PrimitiveError::InvalidInput {
                attribute: attribute.to_string(),
                error_message: error_message.to_string(),
            };
        // TODO: Pin the independently verified deployed World Chain vault before production rollout.
        let vault = Address::parse_from_ffi(vault_address, "vault_address")?;
        if vault.is_zero() {
            return Err(invalid("vault_address", "Vault address must not be zero"));
        }
        if redemptions.is_empty() {
            return Err(invalid(
                "redemptions",
                "At least one redemption is required",
            ));
        }

        let mut tokens = HashSet::new();
        let mut entries = Vec::new();
        for redemption in redemptions {
            let token =
                Address::parse_from_ffi(&redemption.token_address, "token_address")?;
            if token.is_zero() || token == vault {
                return Err(invalid(
                    "token_address",
                    "Token must be nonzero and different from the vault",
                ));
            }
            if !tokens.insert(token) {
                return Err(invalid("token_address", "Duplicate redemption token"));
            }
            let amount = U256::parse_from_ffi(&redemption.amount, "amount")?;
            let minimum = U256::parse_from_ffi(
                &redemption.minimum_usdc_amount,
                "minimum_usdc_amount",
            )?;
            if amount.is_zero() {
                return Err(invalid("amount", "Redemption amount must be positive"));
            }
            if minimum.is_zero() {
                return Err(invalid(
                    "minimum_usdc_amount",
                    "Minimum USDC payout must be positive",
                ));
            }

            let approve = Erc20::encode_approve(vault, amount);
            let redeem = IUniversalWindDownVault::redeemCall {
                asset: token,
                amount,
                minimumUSDCAmount: minimum,
            }
            .abi_encode();
            for (to, data) in [(token, approve), (vault, redeem)] {
                entries.push(MultiSendTx {
                    operation: SafeOperation::Call as u8,
                    to,
                    value: U256::ZERO,
                    data_length: U256::from(data.len()),
                    data: data.into(),
                });
            }
        }

        Ok(Self {
            bundle: MultiSend::build_bundle(&entries),
        })
    }
}

impl Is4337Encodable for UniversalWindDownVault {
    type MetadataArg = ();

    fn build_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.bundle.to,
            value: self.bundle.value,
            data: self.bundle.data.clone().into(),
            operation: self.bundle.operation as u8,
        }
        .abi_encode()
        .into()
    }

    fn build_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let nonce = NonceKeyV1::new(
            TransactionTypeId::UAssetRedemption,
            InstructionFlag::Default,
            [0u8; 10],
        )
        .encode();
        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            self.build_execute_user_op_call_data(),
        ))
    }
}

/// Encodes a World Chain Safe `executeUserOp` call for an atomic redemption batch.
///
/// The result includes exact-amount token approvals and calls to the vault, wrapped
/// in a delegatecall to the existing Safe `MultiSend`. USDC is paid to the Safe.
/// It is not bare vault calldata and must not be sent directly to the vault.
/// No RPC calls, signing, or submission occur. Use a trusted backend vault address
/// and only redeemable holdings with the amounts/minimum payouts accepted by the
/// user. One failed call reverts the entire batch, including all approvals.
///
/// # Errors
/// Returns `PrimitiveError::InvalidInput` for invalid redemption inputs.
#[uniffi::export]
#[allow(clippy::needless_pass_by_value)] // UniFFI requires an owned list at the FFI boundary.
pub fn build_uasset_redemption_call_data(
    vault_address: &str,
    redemptions: Vec<UAssetRedemption>,
) -> Result<HexEncodedData, PrimitiveError> {
    let transaction = UniversalWindDownVault::new(vault_address, &redemptions)?;
    HexEncodedData::new(&hex::encode(transaction.build_execute_user_op_call_data()))
}

#[cfg(test)]
mod tests {
    use alloy::primitives::address;

    use super::*;
    use crate::{
        primitives::BEDROCK_NONCE_PREFIX_CONST,
        transactions::contracts::{
            erc20::IErc20,
            multisend::{IMultiSend, MULTISEND_ADDRESS},
        },
    };

    const VAULT: &str = "0x1111111111111111111111111111111111111111";
    const TOKEN_A: &str = "0x2222222222222222222222222222222222222222";
    const TOKEN_B: &str = "0x3333333333333333333333333333333333333333";

    fn quote(token: &str) -> UAssetRedemption {
        UAssetRedemption {
            token_address: token.to_string(),
            amount: "1000000000000000000".to_string(),
            minimum_usdc_amount: "1250000".to_string(),
        }
    }

    #[test]
    fn encodes_single_and_multiple_redemptions() {
        for tokens in [vec![TOKEN_A], vec![TOKEN_A, TOKEN_B]] {
            let quotes = tokens.iter().map(|token| quote(token)).collect();
            let encoded = build_uasset_redemption_call_data(VAULT, quotes).unwrap();
            let call_data =
                hex::decode(encoded.as_str().trim_start_matches("0x")).unwrap();
            let outer =
                ISafe4337Module::executeUserOpCall::abi_decode(&call_data).unwrap();
            assert_eq!(outer.to, MULTISEND_ADDRESS);
            assert_eq!(outer.value, U256::ZERO);
            assert_eq!(outer.operation, SafeOperation::DelegateCall as u8);
            let batch = IMultiSend::multiSendCall::abi_decode(&outer.data).unwrap();
            let mut remaining = batch.transactions.as_ref();
            for token in tokens {
                let token: Address = token.parse().unwrap();
                let vault: Address = VAULT.parse().unwrap();
                for (target, length) in [(token, 68), (vault, 100)] {
                    assert_eq!(remaining[0], SafeOperation::Call as u8);
                    assert_eq!(Address::from_slice(&remaining[1..21]), target);
                    assert_eq!(U256::from_be_slice(&remaining[21..53]), U256::ZERO);
                    assert_eq!(
                        U256::from_be_slice(&remaining[53..85]),
                        U256::from(length)
                    );
                    let data = &remaining[85..85 + length];
                    if target == token {
                        assert_eq!(&data[..4], &hex::decode("095ea7b3").unwrap());
                        let approve = IErc20::approveCall::abi_decode(data).unwrap();
                        assert_eq!(approve.spender, vault);
                        assert_eq!(approve.value, U256::from(10u64.pow(18)));
                    } else {
                        let redeem =
                            IUniversalWindDownVault::redeemCall::abi_decode(data)
                                .unwrap();
                        assert_eq!(redeem.asset, token);
                        assert_eq!(redeem.amount, U256::from(10u64.pow(18)));
                        assert_eq!(redeem.minimumUSDCAmount, U256::from(1_250_000));
                    }
                    remaining = &remaining[85 + length..];
                }
            }
            assert!(remaining.is_empty());
        }
    }

    #[test]
    fn rejects_invalid_redemption_inputs() {
        let mut cases = vec![
            ("invalid", vec![quote(TOKEN_A)]),
            (
                "0x0000000000000000000000000000000000000000",
                vec![quote(TOKEN_A)],
            ),
            (VAULT, vec![]),
            (VAULT, vec![quote(TOKEN_A), quote(TOKEN_A)]),
            (VAULT, vec![quote(VAULT)]),
            (VAULT, vec![quote("invalid")]),
            (
                VAULT,
                vec![quote("0x0000000000000000000000000000000000000000")],
            ),
        ];
        for value in ["0", "-1", "", "1.5", "not-a-number", "115792089237316195423570985008687907853269984665640564039457584007913129639936"] {
            let mut invalid_amount = quote(TOKEN_A);
            invalid_amount.amount = value.to_string();
            cases.push((VAULT, vec![invalid_amount]));
            let mut invalid_minimum = quote(TOKEN_A);
            invalid_minimum.minimum_usdc_amount = value.to_string();
            cases.push((VAULT, vec![invalid_minimum]));
        }
        for (vault, quotes) in cases {
            assert!(matches!(
                build_uasset_redemption_call_data(vault, quotes),
                Err(PrimitiveError::InvalidInput { .. })
            ));
        }
    }

    #[test]
    fn preserves_uint256_values_and_rejects_case_insensitive_duplicates() {
        let token = "0xabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let mut maximum = quote(token);
        maximum.amount = U256::MAX.to_string();
        maximum.minimum_usdc_amount = U256::MAX.to_string();
        assert!(UniversalWindDownVault::new(VAULT, &[maximum]).is_ok());
        assert!(UniversalWindDownVault::new(
            VAULT,
            &[
                quote(token),
                quote("0xABCDEFABCDEFABCDEFABCDEFABCDEFABCDEFABCD")
            ],
        )
        .is_err());
    }

    #[test]
    fn uses_redemption_nonce_and_safe_sender() {
        let transaction =
            UniversalWindDownVault::new(VAULT, &[quote(TOKEN_A)]).unwrap();
        let wallet = address!("4444444444444444444444444444444444444444");
        let operation = transaction
            .build_preflight_user_operation(wallet, None)
            .unwrap();
        assert_eq!(operation.sender, wallet);
        assert_eq!(
            operation.call_data,
            transaction.build_execute_user_op_call_data()
        );
        let nonce = operation.nonce.to_be_bytes::<32>();
        assert_eq!(&nonce[..5], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(nonce[5], 143);
        assert_eq!(TransactionTypeId::ERC4626Migrate as u8, 142);
        assert_eq!(&nonce[6..17], &[0; 11]);
        assert_eq!(&nonce[24..], &[0; 8]);
    }
}
