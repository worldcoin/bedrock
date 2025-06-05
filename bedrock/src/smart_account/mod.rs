use std::str::FromStr;

use alloy::{
    primitives::Address,
    signers::{k256::ecdsa::SigningKey, local::LocalSigner},
};
use signer::SafeSmartAccountSigner;

use crate::primitives::{HexEncodedData, PrimitiveError};
use crate::{bedrock_export, debug, error, info};

mod signer;

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

        let signature: HexEncodedData =
            signature
                .to_string()
                .try_into()
                .map_err(|e: PrimitiveError| {
                    SafeSmartAccountError::Encoding(format!(
                        "signature encoding error: {e}"
                    ))
                })?;

        Ok(signature)
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
}
