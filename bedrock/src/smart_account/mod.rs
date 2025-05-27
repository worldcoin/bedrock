use std::str::FromStr;

use alloy::{
    primitives::Address,
    signers::{k256::ecdsa::SigningKey, local::LocalSigner},
};
use signer::SafeSmartAccountSigner;

mod signer;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum SafeSmartAccountError {
    #[error("failed to decode hex-encoded secret into k256 signer: {0}")]
    KeyDecoding(String),
    #[error(transparent)]
    Signing(#[from] alloy::signers::Error),
    #[error("failed to parse address: {0}")]
    AddressParsing(String),
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

#[uniffi::export]
impl SafeSmartAccount {
    /// Initializes a new `GnosisSafe` instance with the given EOA signing key.
    ///
    /// # Arguments
    /// - `ethereum_key`: A hex-encoded string representing the **secret key** of the EOA who is an owner in the Safe.
    /// - `wallet_address`: The address of the Safe Smart Account (i.e. the deployed smart contract). This is required because
    ///   some legacy versions of the wallet were computed differently. Today, it cannot be deterministically computed for all users.
    ///
    /// # Errors
    /// - Will return an error if the key is not a validly encoded hex string.
    /// - Will return an error if the key is not a valid point in the k256 curve.
    #[uniffi::constructor]
    pub fn new(
        ethereum_key: String,
        wallet_address: &str,
    ) -> Result<Self, SafeSmartAccountError> {
        let signer = LocalSigner::from_slice(
            &hex::decode(ethereum_key)
                .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?,
        )
        .map_err(|e| SafeSmartAccountError::KeyDecoding(e.to_string()))?;

        let wallet_address = Address::from_str(wallet_address).map_err(|_| {
            SafeSmartAccountError::AddressParsing(wallet_address.to_string())
        })?;

        Ok(Self {
            signer,
            wallet_address,
        })
    }

    /// Signs a string message using the `personal_sign` method on behalf of the Safe Smart Account.
    ///
    /// # Errors
    /// - Will throw an error if the signature process unexpectedlyfails.
    pub fn personal_sign(
        &self,
        chain_id: u32,
        message: String,
    ) -> Result<String, SafeSmartAccountError> {
        let signature = self.sign_message_eip_191_prefixed(message, chain_id)?;
        Ok(signature.to_string())
    }
}

#[cfg(test)]
mod tests;
