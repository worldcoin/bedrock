use alloy::signers::{k256::ecdsa::SigningKey, local::LocalSigner};

#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum Error {
    #[error("failed to decode hex-encoded secret into k256 signer: {0}")]
    KeyDecodeError(String),
}

#[derive(Debug, uniffi::Object)]
pub struct GnosisSafe {
    #[allow(dead_code)] // FIXME: project still scaffolding
    signer: LocalSigner<SigningKey>,
}

#[uniffi::export]
impl GnosisSafe {
    /// Initializes a new `GnosisSafe` instance with the given EOA signing key.
    ///
    /// # Arguments
    /// - `ethereum_key`: A hex-encoded string representing the **secret key** of the EOA who is an owner in the Safe.
    ///
    /// # Errors
    /// - Will return an error if the key is not a validly encoded hex string.
    /// - Will return an error if the key is not a valid point in the k256 curve.
    #[uniffi::constructor]
    pub fn new(ethereum_key: String) -> Result<Self, Error> {
        let signer = LocalSigner::from_slice(
            &hex::decode(ethereum_key)
                .map_err(|e| Error::KeyDecodeError(e.to_string()))?,
        )
        .map_err(|e| Error::KeyDecodeError(e.to_string()))?;

        Ok(Self { signer })
    }
}

#[cfg(test)]
mod tests;
