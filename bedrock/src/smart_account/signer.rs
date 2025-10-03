use alloy::{
    dyn_abi::DynSolValue,
    primitives::{eip191_hash_message, fixed_bytes, keccak256, Address, FixedBytes},
    signers::{Signature, SignerSync},
};
use ruint::aliases::U256;

use super::{SafeSmartAccount, SafeSmartAccountError};

// https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L52
static DOMAIN_SEPARATOR_TYPEHASH: FixedBytes<32> =
    fixed_bytes!("0x47e79534a245952e8b16893a336b85a3d9ea9fa8c573f3d803afb92a79469218");

/// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol#L15C50-L15C116>
static SAFE_MSG_TYPEHASH: FixedBytes<32> =
    fixed_bytes!("0x60b3cbf8b4a223d68d641b3b6ddf9a298e7f33710cf3d3a9d1146b5a6150fbca");

/// Implements a custom `Signer` explicitly for a Safe Smart Account (previously Gnosis Safe) (works on v1.4.1 and v1.3.0).
///
/// Enables signing of messages and EIP-712 typed data for Safe Smart Accounts.
///
/// All signed messages follow the EIP-712 prefix: `0x1901`, and use the Safe contract's global domain separator. Personally signed
/// messages may be encoded and prefixed further.
pub trait SafeSmartAccountSigner {
    /// Signs an EIP-191 message (`personal_sign` Message; version: `0x45`).
    /// Reference: <https://eips.ethereum.org/EIPS/eip-191#version-0x45-e>
    ///
    /// The message will be prefixed with the EIP-191 prefix `"\x19Ethereum Signed Message:\n"`.
    ///
    /// # Errors
    /// - Will throw an error if the signature process fails.
    fn sign_message_eip_191_prefixed<T: AsRef<[u8]>>(
        &self,
        message: T,
        chain_id: u32,
    ) -> Result<Signature, SafeSmartAccountError>;

    /// Signs a message on behalf of the Safe Smart Account (through the EOA). Generally for use with EIP-712 typed data.
    ///
    /// # Errors
    /// - Will throw an error if the signature process fails.
    fn sign_message<T: AsRef<[u8]>>(
        &self,
        message: T,
        chain_id: u32,
    ) -> Result<Signature, SafeSmartAccountError>;

    /// Signs an already pre-computed digest as EIP-712 message.
    ///
    /// This is used for example to sign transaction data.
    ///
    /// # Errors
    /// - Will throw an error if the signature process fails.
    #[allow(dead_code)] // FIXME: not yet in use
    fn sign_digest(
        &self,
        digest: FixedBytes<32>,
        chain_id: u32,
        domain_separator_address: Option<Address>,
    ) -> Result<Signature, SafeSmartAccountError>;
}

impl SafeSmartAccountSigner for SafeSmartAccount {
    fn sign_message_eip_191_prefixed<T: AsRef<[u8]>>(
        &self,
        message: T,
        chain_id: u32,
    ) -> Result<Signature, SafeSmartAccountError> {
        let eip_191_message_hash = eip191_hash_message(message);
        self.sign_message(eip_191_message_hash, chain_id)
    }

    fn sign_message<T: AsRef<[u8]>>(
        &self,
        message: T,
        chain_id: u32,
    ) -> Result<Signature, SafeSmartAccountError> {
        let message_hash = self.get_message_hash_for_safe(message, chain_id, None);
        self.signer
            .sign_hash_sync(&message_hash)
            .map_err(|e| SafeSmartAccountError::Signing(e.to_string()))
    }

    fn sign_digest(
        &self,
        digest: FixedBytes<32>,
        chain_id: u32,
        domain_separator_address: Option<Address>,
    ) -> Result<Signature, SafeSmartAccountError> {
        let message_hash =
            self.eip_712_hash(digest, chain_id, domain_separator_address);
        self.signer
            .sign_hash_sync(&message_hash)
            .map_err(|e| SafeSmartAccountError::Signing(e.to_string()))
    }
}

impl SafeSmartAccount {
    /// Computes the digest for a specific message to be signed by the Safe Smart Account.
    ///
    /// This is equivalent to the contract's `getMessageHashForSafe` method (including also the `encodeMessageDataForSafe` logic).
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/handler/CompatibilityFallbackHandler.sol#L68>
    fn get_message_hash_for_safe<T: AsRef<[u8]>>(
        &self,
        message: T,
        chain_id: u32,
        domain_separator_address: Option<Address>,
    ) -> FixedBytes<32> {
        let message_hash = DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(SAFE_MSG_TYPEHASH, 32),
            DynSolValue::FixedBytes(keccak256(message), 32),
        ]);
        let message_hash = keccak256(message_hash.abi_encode());
        // NOTE: the EIP-712 prefixing is part of `getMessageHashForSafe` but here it's abstracted into `eip_712_hash` to be re-used for transaction signing.
        self.eip_712_hash(message_hash, chain_id, domain_separator_address)
    }

    /// Computes the digest for a specific EIP-712 message to be signed by the Safe Smart Account.
    ///
    /// This is used to sign personal messages (EIP-191; `0x45`), sign typed data (EIP-191; `0x01`) and sign transaction data.
    ///
    /// This method replaces Alloy's built-in `eip712_signing_hash` to apply the domain separator specifically for the Safe Smart Account.
    /// Reference: <https://github.com/alloy-rs/core/blob/b20e2326796827cbc5ca9ff7bd037fab9ba37e93/crates/dyn-abi/src/eip712/typed_data.rs#L212>
    ///
    /// Spec Reference: <https://eips.ethereum.org/EIPS/eip-712>
    ///
    /// Should not be called directly. Use `sign_message_eip_191_prefixed`, `sign_message` or `sign_digest` instead.
    pub(crate) fn eip_712_hash(
        &self,
        structured_data_hash: FixedBytes<32>,
        chain_id: u32,
        domain_separator_address: Option<Address>,
    ) -> FixedBytes<32> {
        let mut buf = [0u8; 66];
        buf[0] = 0x19;
        buf[1] = 0x01;
        buf[2..34].copy_from_slice(
            self.get_domain_separator(chain_id, domain_separator_address)
                .as_slice(),
        );
        buf[34..66].copy_from_slice(structured_data_hash.as_slice());
        keccak256(buf)
    }

    /// Computes the domain separator ([EIP-712](https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata)) for the Safe Smart Account.
    ///
    /// This is equivalent to the contract's `domainSeparator` method.
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L365>
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain on which the Safe Smart Account is deployed.
    /// - `domain_separator_address`: The address of the domain separator. By default, this is the wallet address, **except**
    ///   for 4337 transactions, where the domain separator uses the 4337 module address.
    fn get_domain_separator(
        &self,
        chain_id: u32,
        domain_separator_address: Option<Address>,
    ) -> FixedBytes<32> {
        let domain_separator_address =
            domain_separator_address.unwrap_or(self.wallet_address);

        let domain_separator = DynSolValue::Tuple(vec![
            DynSolValue::FixedBytes(DOMAIN_SEPARATOR_TYPEHASH, 32),
            DynSolValue::Uint(U256::from(chain_id), 256),
            DynSolValue::Address(domain_separator_address),
        ]);
        let encoded = domain_separator.abi_encode();
        keccak256(encoded)
    }
}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::primitives::Network;
    use alloy::{hex::FromHex, signers::local::PrivateKeySigner};
    use ruint::uint;

    #[test]
    fn test_get_domain_separator() {
        // https://optimistic.etherscan.io/address/0x4564420674EA68fcc61b463C0494807C759d47e6

        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();

        assert_eq!(
            smart_account.get_domain_separator(Network::Optimism as u32, None),
            // From `domainSeparator()` in explorer
            FixedBytes::from(uint!(
                0xaf6246ae5d27e327c493da685e4990ad5dca90f74f3cf59da650812870c1bd37_U256
            )),
        );

        // https://etherscan.io/address/0xdab5dc22350f9a6aff03cf3d9341aad0ba42d2a6
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0xdab5dc22350f9a6aff03cf3d9341aad0ba42d2a6",
        )
        .unwrap();

        assert_eq!(
            smart_account.get_domain_separator(Network::Ethereum as u32, None),
            // From `domainSeparator()` in explorer
            FixedBytes::from(uint!(
                0xbd4304a4e2fd76ed2bd2bad9479581da3f5a173b19d45dc57b12dd7c27509d3a_U256
            )),
        );

        // 1.4.1 Safe - https://optimistic.etherscan.io/address/0x75c9553956dfe249c815700b1e7076a5738f3d6d#readProxyContract
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x75c9553956dfe249C815700b1E7076A5738F3d6d",
        )
        .unwrap();

        assert_eq!(
            smart_account.get_domain_separator(Network::Optimism as u32, None),
            // From `domainSeparator()` in explorer
            FixedBytes::from(uint!(
                0xcdee84b460ced58f4812951bcada15aaa862eab78e0dddf59f7839dc67b98c5d_U256
            )),
        );
    }

    #[test]
    fn test_compute_domain_separator_world_chain() {
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x29fcB43b46531BcA003ddC8FCB67FFE91900C762",
        )
        .unwrap();

        assert_eq!(
            smart_account.get_domain_separator(Network::WorldChain as u32, None),
            FixedBytes::from(uint!(
                0xf983f9bbe16178e12b086bfdacbe9b328aa09ad84c55527e6536ecaa2057ae01_U256
            ))
        );
    }

    #[test]
    fn test_compute_domain_separator_world_chain_alt() {
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x619525ED4E862B62cFEDACCc4dA5a9864D6f4A97",
        )
        .unwrap();

        assert_eq!(
            smart_account.get_domain_separator(Network::WorldChain as u32, None),
            FixedBytes::from(uint!(
                0xd32fd7ce04127de88eddf17bda79d56263972efc440b905379a83b99655b3c43_U256
            ))
        );
    }

    /// Test can be verified with the `FallbackHandler` contract in the explorer.
    /// Reference: <https://optimistic.etherscan.io/address/0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4>
    #[test]
    fn test_get_message_hash_for_safe() {
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();

        // remember to prefix with 0x if testing in the chain explorer
        let message_hash = smart_account.get_message_hash_for_safe(
            hex::decode("deadbeef").unwrap(),
            Network::Optimism as u32,
            None,
        );

        assert_eq!(
            message_hash,
            FixedBytes::from_hex(
                "0x9fa392e790461d261206f7eb4943aceb7402d8002116ce79ab3a27d26917199c"
            )
            .unwrap()
        );
    }

    /// Test can be verified with the `FallbackHandler` contract in the explorer.
    /// Reference: <https://optimistic.etherscan.io/address/0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4>
    #[test]
    fn test_get_message_hash_for_safe_alt() {
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();

        // remember to prefix with 0x if testing in the chain explorer
        let message_hash = smart_account.get_message_hash_for_safe(
            hex::decode(
                "9fa392e790461d261206f7eb4943aceb7402d8002116ce79ab3a27d26917199c",
            )
            .unwrap(),
            Network::Optimism as u32,
            None,
        );

        assert_eq!(
            message_hash,
            FixedBytes::from_hex(
                "0xcf36167bf66c2955ab5a5e41aa3ce93e290b25d7067788965f64c7379b6879e5"
            )
            .unwrap()
        );
    }

    /// Reference: <https://etherscan.io/address/0xf48f2B2d2a534e402487b3ee7C18c33Aec0Fe5e4>
    #[test]
    fn test_get_message_hash_for_safe_ethereum_chain() {
        let smart_account = SafeSmartAccount::new(
            hex::encode(PrivateKeySigner::random().to_bytes()),
            "0xdab5dc22350f9a6aff03cf3d9341aad0ba42d2a6",
        )
        .unwrap();

        // remember to prefix with 0x if testing in the chain explorer
        let message_hash = smart_account.get_message_hash_for_safe(
            hex::decode(
                "612b166f2a615243d8734e1b8a37fd9e662fc6de4d59cb0eb7799fad51182364",
            )
            .unwrap(),
            Network::Ethereum as u32,
            None,
        );

        assert_eq!(
            message_hash,
            FixedBytes::from_hex(
                "0x1e19c0424472f92d95ca5ab9d4f4c4a9e695bad76b0a03bc2d26a16292159d87"
            )
            .unwrap()
        );
    }
}
