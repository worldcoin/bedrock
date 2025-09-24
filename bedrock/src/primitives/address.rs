use std::str::FromStr;

use alloy::{primitives::Address, sol_types::SolValue};
use bedrock_macros::bedrock_export;

use crate::primitives::PrimitiveError;

/// A primitive for interacting with Ethereum addresses.
///
/// Wraps the `Address` type from the `alloy` crate for foreign exports.
#[derive(Debug, PartialEq, Eq, Clone, Copy, uniffi::Object)]
pub struct BedrockAddress(pub Address);

#[bedrock_export]
impl BedrockAddress {
    /// Initializes a new `BedrockAddress` from a String.
    ///
    /// # Errors
    /// - `PrimitiveError::InvalidInput` if the provided string is not a valid Ethereum address.
    #[uniffi::constructor]
    pub fn new(address: &str) -> Result<Self, PrimitiveError> {
        Ok(Self(Address::from_str(address).map_err(|_| {
            PrimitiveError::InvalidInput {
                attribute: "address",
                message: "invalid address".to_string(),
            }
        })?))
    }

    /// Returns the address as an ABI **packed** encoded byte array.
    #[must_use]
    pub fn as_abi_encode_packed(&self) -> Vec<u8> {
        self.0.abi_encode_packed()
    }

    /// Returns the address as an ABI encoded byte array.
    #[must_use]
    pub fn as_abi_encode(&self) -> Vec<u8> {
        self.0.abi_encode()
    }

    /// Returns the address as a checksummed string.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-55>
    #[must_use]
    pub fn as_checksummed_str(&self, chain_id: Option<u64>) -> String {
        self.0.to_checksum(chain_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy::primitives::address;

    #[test]
    fn test_parse_and_encode() {
        let address =
            BedrockAddress::new("0x163f8c2467924be0ae7B5347228cabf260318753").unwrap();
        assert_eq!(
            address.0,
            address!("0x163f8C2467924be0ae7B5347228CABF260318753")
        );

        assert_eq!(
            address.as_checksummed_str(None),
            "0x163f8C2467924be0ae7B5347228CABF260318753" // note how `CABF` is uppercased
        );

        assert_eq!(
            hex::encode(address.as_abi_encode_packed()),
            "163f8c2467924be0ae7b5347228cabf260318753"
        );

        assert_eq!(
            hex::encode(address.as_abi_encode()),
            "000000000000000000000000163f8c2467924be0ae7b5347228cabf260318753"
        );
    }

    #[test]
    fn test_parse_and_encode_invalid() {
        let address = BedrockAddress::new("0x163f8C2467924be0ae7B8753");
        assert!(address.is_err());
    }
}
