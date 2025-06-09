use std::str::FromStr;

use alloy::{
    primitives::Address,
    signers::{k256::ecdsa::SigningKey, local::LocalSigner},
};
pub use signer::SafeSmartAccountSigner;

use crate::{bedrock_export, debug, error, info, primitives::HexEncodedData};

/// Enables signing of messages and EIP-712 typed data for Safe Smart Accounts.
mod signer;

/// Enables EIP-4337 transaction crafting and signing
mod transaction_4337;

pub use transaction_4337::{
    EncodedSafeOpStruct, PackedUserOperation, UserOperation, ENTRYPOINT_4337,
    GNOSIS_SAFE_4337_MODULE,
};
/// Errors that can occur when working with Safe Smart Accounts.
#[crate::bedrock_error]
pub enum SafeSmartAccountError {
    /// Failed to decode a hex-encoded secret key into a k256 signer.
    #[error("failed to decode hex-encoded secret into k256 signer: {0}")]
    KeyDecoding(String),
    /// Error occurred during the signing process.
    #[error(transparent)]
    Signing(#[from] alloy::signers::Error),
    /// Failed to parse an Ethereum address string.
    #[error("failed to parse address: {0}")]
    AddressParsing(String),
    /// Failed to encode data to a specific format.
    #[error("failed to encode: {0}")]
    Encoding(String),
    /// A provided raw input could not be parsed, is incorrectly formatted, incorrectly encoded or otherwise invalid.
    #[error("invalid input on {attribute}: {message}")]
    InvalidInput {
        /// The name of the attribute that was invalid.
        attribute: &'static str,
        /// Explicit failure message for the attribute validation.
        message: String,
    },
}

/// A Safe Smart Account (previously Gnosis Safe) is the representation of a Safe smart contract.
///
/// It is used to sign messages, transactions and typed data on behalf of the Safe smart contract.
///
/// Reference: <https://github.com/safe-global/safe-smart-account>
#[derive(Debug, uniffi::Object)]
pub struct SafeSmartAccount {
    /// The Ethereum signer from the EOA which is an owner for the Safe Smart Account.
    signer: LocalSigner<SigningKey>,
    /// The address of the Safe Smart Account (i.e. the deployed smart contract)
    wallet_address: Address,
}

#[bedrock_export]
impl SafeSmartAccount {
    /// Initializes a new `SafeSmartAccount` instance with the given EOA signing key.
    ///
    /// # Arguments
    /// - `private_key`: A hex-encoded string representing the **secret key** of the EOA who is an owner in the Safe.
    /// - `wallet_address`: The address of the Safe Smart Account (i.e. the deployed smart contract). This is required because
    ///   some legacy versions of the wallet were computed differently. Today, it cannot be deterministically computed for all
    ///   users. This is also necessary to support signing for Safes deployed by third-party Mini App devs, where the
    ///   wallet address is only known at runtime.
    ///
    /// # Errors
    /// - Will return an error if the key is not a validly encoded hex string.
    /// - Will return an error if the key is not a valid point in the k256 curve.
    #[uniffi::constructor]
    pub fn new(
        private_key: String,
        wallet_address: &str,
    ) -> Result<Self, SafeSmartAccountError> {
        debug!(
            "Initializing SafeSmartAccount with wallet address: {}",
            wallet_address
        );

        let signer = LocalSigner::from_slice(
            &hex::decode(private_key)
                .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?,
        )
        .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?;

        let wallet_address = Address::from_str(wallet_address).map_err(|_| {
            SafeSmartAccountError::AddressParsing(wallet_address.to_string())
        })?;

        info!(
            "Successfully initialized SafeSmartAccount for wallet: {}",
            wallet_address
        );

        Ok(Self {
            signer,
            wallet_address,
        })
    }

    /// Signs a string message using the `personal_sign` method on behalf of the Safe Smart Account.
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain where the message is being signed. While technically the chain ID is a `U256` in EVM, we limit
    ///   to sensible `u32` (which works well with foreign code).
    /// - `message`: The message to sign. Do not add the EIP-191 prefix, or typehash prefixes. Should be the raw message.
    ///
    /// # Errors
    /// - Will throw an error if the signature process unexpectedly fails.
    pub fn personal_sign(
        &self,
        chain_id: u32,
        message: String,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let signature = self.sign_message_eip_191_prefixed(message, chain_id)?;
        Ok(signature.into())
    }

    /// Crafts and signs a 4337 user operation.
    ///
    /// # Arguments
    /// - `user_operation`: The user operation to sign.
    /// - `chain_id`: The chain ID of the chain where the user operation is being signed.
    ///
    /// # Errors
    /// - Will throw an error if the user operation is invalid, particularly if any attribute is not valid.
    /// - Will throw an error if the signature process unexpectedly fails.
    ///
    /// # Examples
    /// ```rust
    /// use bedrock::smart_account::{UserOperation, SafeSmartAccount};
    ///
    /// let safe = SafeSmartAccount::new(
    ///     // this is Anvil's default private key, it is a test secret
    ///     "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
    ///     "0x4564420674EA68fcc61b463C0494807C759d47e6",
    /// )
    /// .unwrap();
    ///
    /// // This would normally be crafted by the user, or requested by Mini Apps.
    /// let user_op = UserOperation {
    ///      sender:"0xf1390a26bd60d83a4e38c7be7be1003c616296ad".to_string(),
    ///     nonce: "0xb14292cd79fae7d79284d4e6304fb58e21d579c13a75eed80000000000000000".to_string(),
    ///     call_data:  "0x7bb3742800000000000000000000000079a02482a880bce3f13e09da970dc34db4cd24d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000ce2111f9ab8909b71ebadc9b6458daefe069eda4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000".to_string(),
    ///     signature:  "0x000012cea6000000967a7600ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
    ///     call_gas_limit: "0xabb8".to_string(),
    ///     verification_gas_limit: "0xfa07".to_string(),
    ///     pre_verification_gas: "0x8e4d78".to_string(),
    ///     max_fee_per_gas: "0x1af6f".to_string(),
    ///     max_priority_fee_per_gas: "0x1adb0".to_string(),
    ///     paymaster: Some("0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B".to_string()),
    ///     paymaster_verification_gas_limit: "0x7415".to_string(),
    ///     paymaster_post_op_gas_limit: "0x".to_string(),
    ///     paymaster_data: Some("000000000000000067789a97c4af0f8ae7acc9237c8f9611a0eb4662009d366b8defdf5f68fed25d22ca77be64b8eef49d917c3f8642ca539571594a84be9d0ee717c099160b79a845bea2111b".to_string()),
    ///     factory: None,
    ///     factory_data: None,
    /// };
    ///
    /// let signature = safe.sign_4337_op(&user_op, 480).unwrap();
    ///
    /// println!("Signature: {}", signature.to_hex_string());
    /// ```
    pub fn sign_4337_op(
        &self,
        user_operation: &UserOperation,
        chain_id: u32,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let user_op: EncodedSafeOpStruct = user_operation.try_into()?;

        let signature = self.sign_digest(
            user_op.into_transaction_hash(),
            chain_id,
            Some(*GNOSIS_SAFE_4337_MODULE),
        )?;

        Ok(signature.into())
    }
}

#[cfg(test)]
impl SafeSmartAccount {
    /// Creates a new `SafeSmartAccount` instance with a random EOA signing key.
    ///
    /// Only for test usage.
    ///
    /// # Panics
    /// - Will panic if the wallet address cannot be computed correctly.
    #[must_use]
    pub fn random() -> Self {
        let signer = LocalSigner::random();
        let wallet_address =
            Address::from_str("0x0000000000000000000000000000000000000000").unwrap(); // TODO: compute address correctly
        Self {
            signer,
            wallet_address,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloy::signers::local::PrivateKeySigner;

    use super::*;

    #[test]
    fn test_cannot_initialize_with_invalid_hex_secret() {
        let invalid_hex = "invalid_hex";
        let result = SafeSmartAccount::new(
            invalid_hex.to_string(),
            "0x0000000000000000000000000000000000000042",
        );
        assert!(result.is_err());
        assert_eq!(
        result.unwrap_err().to_string(),
        format!("failed to decode hex-encoded secret into k256 signer: Odd number of digits")
    );
    }

    #[test]
    fn test_cannot_initialize_with_invalid_curve_point() {
        let invalid_hex = "2a"; // `42` is not a valid point on the curve
        let result = SafeSmartAccount::new(
            invalid_hex.to_string(),
            "0x0000000000000000000000000000000000000042",
        );
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            format!(
                "failed to decode hex-encoded secret into k256 signer: signature error"
            )
        );
    }

    #[test]
    fn test_cannot_initialize_with_invalid_wallet_address() {
        let invalid_addresses = [
            "0x000000000000000000000000000000000000001", // not 32 bytes
            "my_string",
            &"1".repeat(32),
        ];

        for invalid_address in invalid_addresses {
            let result = SafeSmartAccount::new(
                hex::encode(PrivateKeySigner::random().to_bytes()),
                invalid_address,
            );
            assert!(result.is_err());
            assert_eq!(
                result.unwrap_err().to_string(),
                format!("failed to parse address: {invalid_address}")
            );
        }
    }

    #[test]
    fn test_sign_4337_user_op() {
        let safe = SafeSmartAccount::new(
            "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
                .to_string(),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();
        let chain_id = 10;
        let safe_address = "0x4564420674EA68fcc61b463C0494807C759d47e6".to_string();
        let user_op = UserOperation {
          sender:safe_address,
          nonce: "0xb14292cd79fae7d79284d4e6304fb58e21d579c13a75eed80000000000000000".to_string(),
          call_data:  "0x7bb3742800000000000000000000000079a02482a880bce3f13e09da970dc34db4cd24d10000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb000000000000000000000000ce2111f9ab8909b71ebadc9b6458daefe069eda4000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000".to_string(),
          signature:  "0x000012cea6000000967a7600ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_string(),
          call_gas_limit: "0xabb8".to_string(),
          verification_gas_limit: "0xfa07".to_string(),
          pre_verification_gas: "0x8e4d78".to_string(),
          max_fee_per_gas: "0x1af6f".to_string(),
          max_priority_fee_per_gas: "0x1adb0".to_string(),
          paymaster: Some("0xEF725Aa22d43Ea69FB22bE2EBe6ECa205a6BCf5B".to_string()),
          paymaster_verification_gas_limit: "0x7415".to_string(),
          paymaster_post_op_gas_limit: "0x".to_string(),
          paymaster_data: Some( "000000000000000067789a97c4af0f8ae7acc9237c8f9611a0eb4662009d366b8defdf5f68fed25d22ca77be64b8eef49d917c3f8642ca539571594a84be9d0ee717c099160b79a845bea2111b".to_string()),
          factory: None,
          factory_data: None,
      };

        assert_eq!(safe.sign_4337_op(&user_op, chain_id).unwrap().to_hex_string(), "0x20c0b7ee783b39fa09b5fd967e250cc793556489ee351694cec43341efa0af9304c96e0167319d01b174d76d4420bf0345221740282d70e6f48eb7775a01de381c");
    }
}
