use std::str::FromStr;

use alloy::{
    dyn_abi::TypedData,
    primitives::Address,
    signers::{k256::ecdsa::SigningKey, local::LocalSigner},
};
pub use signer::SafeSmartAccountSigner;
pub use transaction_4337::{ISafe4337Module, Is4337Operable};

use crate::{
    bedrock_export, debug, error, primitives::HexEncodedData,
    transaction::foreign::UnparsedUserOperation,
};

/// Enables signing of messages and EIP-712 typed data for Safe Smart Accounts.
mod signer;

/// Enables EIP-4337 transaction crafting and signing
mod transaction_4337;

/// Allows executing operations (i.e. regular transactions) on behalf of the Safe Smart Account
/// Reference: <https://docs.safe.global/reference-smart-account/transactions/execTransaction>
mod transaction;

/// Enables crafting and signing of Permit2 allowances.
/// Reference: <https://docs.uniswap.org/contracts/permit2/overview>
mod permit2;

pub use transaction_4337::{
    EncodedSafeOpStruct, UserOperation, ENTRYPOINT_4337, GNOSIS_SAFE_4337_MODULE,
};

// Import the generated types from permit2 module
pub use permit2::{
    UnparsedPermitTransferFrom, UnparsedTokenPermissions, PERMIT2_ADDRESS,
};

const RESTRICTED_TYPED_DATA_CONTRACTS: &[Address] = &[
    // Permit2 requires using the custom `sign_permit2_transfer` method which has additional validation and other permission verification.
    PERMIT2_ADDRESS,
];

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
    /// For security reasons, the contract is restricted from directly signing `TypedData`.
    #[error("the contract {0} is restricted from TypedData signing.")]
    RestrictedContract(String),
    /// A provided raw input could not be parsed, is incorrectly formatted, incorrectly encoded or otherwise invalid.
    #[error("invalid input on {attribute}: {message}")]
    InvalidInput {
        /// The name of the attribute that was invalid.
        attribute: &'static str,
        /// Explicit failure message for the attribute validation.
        message: String,
    },
    /// An error occurred with a primitive type. See `PrimitiveError` for more details.
    #[error(transparent)]
    PrimitiveError(#[from] crate::primitives::PrimitiveError),
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
    pub wallet_address: Address,
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

        debug!(
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

    /// Signs a transaction on behalf of the Safe Smart Account.
    ///
    /// This allows execution of normal transactions for the Safe.
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain where the transaction is being signed.
    /// - `transaction`: The transaction to sign.
    ///
    /// # Errors
    /// - Will throw an error if the transaction is invalid, particularly if any attribute is not valid.
    /// - Will throw an error if the signature process unexpectedly fails.
    pub fn sign_transaction(
        &self,
        chain_id: u32,
        transaction: SafeTransaction,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let signature =
            self.sign_digest(transaction.get_transaction_hash()?, chain_id, None)?;
        Ok(signature.into())
    }

    /// Crafts and signs a 4337 user operation on behalf of the Safe Smart Account.
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain where the user operation is being signed.
    /// - `user_operation`: The user operation to sign.
    ///
    /// # Errors
    /// - Will throw an error if the user operation is invalid, particularly if any attribute is not valid.
    /// - Will throw an error if the signature process unexpectedly fails.
    ///
    /// # Examples
    /// ```rust
    /// use bedrock::smart_account::{SafeSmartAccount};
    /// use bedrock::transaction::foreign::UnparsedUserOperation;
    ///
    /// let safe = SafeSmartAccount::new(
    ///     // this is Anvil's default private key, it is a test secret
    ///     "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80".to_string(),
    ///     "0x4564420674EA68fcc61b463C0494807C759d47e6",
    /// )
    /// .unwrap();
    ///
    /// // This would normally be crafted by the user, or requested by Mini Apps.
    /// let user_op = UnparsedUserOperation {
    ///     sender:"0xf1390a26bd60d83a4e38c7be7be1003c616296ad".to_string(),
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
    /// let signature = safe.sign_4337_op(480, user_op).unwrap();
    ///
    /// println!("Signature: {}", signature.to_hex_string());
    /// ```
    pub fn sign_4337_op(
        &self,
        chain_id: u32,
        user_operation: UnparsedUserOperation,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let user_op: UserOperation = user_operation.try_into()?;
        let encoded_safe_op_struct: EncodedSafeOpStruct = (&user_op).try_into()?;

        let signature = self.sign_digest(
            encoded_safe_op_struct.into_transaction_hash(),
            chain_id,
            Some(*GNOSIS_SAFE_4337_MODULE),
        )?;

        Ok(signature.into())
    }

    /// Signs an arbitrary EIP-712 typed data message on behalf of the Safe Smart Account.
    ///
    /// Please note that certain primary types are restricted and cannot be signed. For example Permit2's `PermitTransferFrom` is restricted.
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain where the message is being signed. While technically the chain ID is a `U256` in EVM, we limit
    ///   to sensible `u32` (which works well with foreign code).
    /// - `stringified_typed_data`: A JSON string representing the typed data as per EIP-712.
    ///
    /// # Errors
    /// - Will throw an error if the typed data is not a valid JSON string.
    /// - Will throw an error if the typed data is not a valid EIP-712 typed data message.
    /// - Will throw an error if the signature process unexpectedly fails.
    pub fn sign_typed_data(
        &self,
        chain_id: u32,
        stringified_typed_data: &str,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let typed_data: TypedData = serde_json::from_str(stringified_typed_data)
            .map_err(|_| SafeSmartAccountError::InvalidInput {
                attribute: "stringified_typed_data",
                message:
                    "invalid JSON string or not a valid EIP-712 typed data message"
                        .to_string(),
            })?;

        if let Some(verifying_contract) = typed_data.domain.verifying_contract {
            if RESTRICTED_TYPED_DATA_CONTRACTS.contains(&verifying_contract) {
                return Err(SafeSmartAccountError::RestrictedContract(
                    verifying_contract.to_string(),
                ));
            }
        }

        let typed_data_eip712_hash = typed_data.eip712_signing_hash().map_err(|e| {
            SafeSmartAccountError::Generic {
                message: format!("failed to calculate EIP-712 signing hash: {e}"),
            }
        })?;

        let signature = self.sign_message(typed_data_eip712_hash, chain_id)?;

        Ok(signature.into())
    }

    /// Signs a `Permit2` transfer on behalf of the Safe Smart Account.
    ///
    /// Used by Mini Apps where users approve transfers for specific tokens and amounts for a period of time on their behalf.
    ///
    /// # Arguments
    /// - `chain_id`: The chain ID of the chain where the message is being signed.
    /// - `transfer`: The `Permit2` transfer to sign.
    ///
    /// # Errors
    /// - Will throw an error if the transfer is invalid, particularly if any attribute is not valid.
    /// - Will throw an error if the signature process unexpectedly fails.
    pub fn sign_permit2_transfer(
        &self,
        chain_id: u32,
        transfer: UnparsedPermitTransferFrom,
    ) -> Result<HexEncodedData, SafeSmartAccountError> {
        let transfer_from: permit2::PermitTransferFrom = transfer.try_into()?;

        let signing_hash = transfer_from
            .as_typed_data(chain_id)
            .eip712_signing_hash()
            .map_err(|e| SafeSmartAccountError::Generic {
                message: format!("failed to calculate EIP-712 signing hash: {e}"),
            })?;

        let signature = self.sign_message(signing_hash, chain_id)?;
        Ok(signature.into())
    }
}

/// The type of operation to perform on behalf of the Safe Smart Account.
///
/// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/libraries/Enum.sol#L9>
#[derive(uniffi::Enum, Clone, Debug)]
#[repr(u8)]
pub enum SafeOperation {
    /// Performs a standard message call.
    Call,
    /// Performs a `delegatecall`. Executes the target contract’s code in the context of the Safe's storage.
    DelegateCall,
}

/// For Swift & Kotlin usage only.
///
/// Represents a Safe Smart Account transaction which can be initialized by foreign code to be then signed.
///
/// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L139>
#[derive(uniffi::Record, Clone, Debug)]
pub struct SafeTransaction {
    /// Destination address of the Safe transaction.
    /// Solidity type: `address`
    pub to: String,
    /// Ether value of the Safe transaction.
    /// Solidity type: `uint256`
    pub value: String,
    /// Data payload of the Safe transaction.
    /// Solidity type: `bytes`
    pub data: String,
    /// The type of operation to perform on behalf of the Safe Smart Account.
    /// Solidity type: `uint8`
    pub operation: SafeOperation,
    /// The maximum gas that can be used for the Safe transaction.
    /// Solidity type: `uint256`
    pub safe_tx_gas: String,
    /// Gas costs that are independent of the transaction execution (e.g. base transaction fee, signature check, payment of the refund)
    /// Solidity type: `uint256`
    pub base_gas: String,
    /// Gas price that should be used for the payment calculation.
    /// Solidity type: `uint256`
    pub gas_price: String,
    /// Token address (or 0 if ETH) that is used for the payment.
    /// Solidity type: `address`
    pub gas_token: String,
    /// Address of receiver of gas payment (or 0 if tx.origin).
    /// Solidity type: `address`
    pub refund_receiver: String,
    /// The sequential nonce of the transaction. Used to prevent replay attacks.
    /// Solidity type: `uint256`
    pub nonce: String,
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
    use alloy::{primitives::address, signers::local::PrivateKeySigner};
    use ruint::uint;
    use serde_json::json;

    use crate::smart_account::permit2::{PermitTransferFrom, TokenPermissions};

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
    fn test_sign_transaction() {
        let safe = SafeSmartAccount::new(
            "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
                .to_string(),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();
        let chain_id = 10;
        let tx = SafeTransaction {
            to: "0x00000000219ab540356cbb839cbe05303d7705fa".to_string(),
            value: "0x1".to_string(),
            data: "0x095ea7b3000000000000000000000000c36442b4a4522e871399cd717abdd847ab11fe8800000000000000000000000000000000000000000000000000015c3b87af4cf5".to_string(),
            operation: SafeOperation::DelegateCall,
            safe_tx_gas: "0x123".to_string(),
            base_gas: "0x321".to_string(),
            gas_price: "0x1234".to_string(),
            gas_token: "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2".to_string(),
            refund_receiver: "0x8315177ab297ba92a06054ce80a67ed4dbd7ed3a".to_string(),
            nonce: "0x2".to_string(),
        };
        assert_eq!(safe.sign_transaction(chain_id, tx).unwrap().to_hex_string(), "0x6245bb5f5685ad9089981baac54bb01eb9b2e5d5239ca8e9a7d6faa7b168bb03552bade1c61ef5d198ae11f11d12c6f59cbf3d092317140d28cad3163b5a88971b");
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
        let user_op = UnparsedUserOperation {
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

        assert_eq!(safe.sign_4337_op(chain_id, user_op).unwrap().to_hex_string(), "0x20c0b7ee783b39fa09b5fd967e250cc793556489ee351694cec43341efa0af9304c96e0167319d01b174d76d4420bf0345221740282d70e6f48eb7775a01de381c");
    }

    #[test]
    fn test_sign_typed_data() {
        let safe = SafeSmartAccount::new(
            "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583"
                .to_string(),
            "0x4564420674EA68fcc61b463C0494807C759d47e6",
        )
        .unwrap();
        let chain_id = 10;

        // Example from specs: https://eips.ethereum.org/EIPS/eip-712#specification-of-the-eth_signtypeddata-json-rpc
        let typed_data = json!({
             "types":{
                "EIP712Domain":[
                   {
                      "name":"name",
                      "type":"string"
                   },
                   {
                      "name":"version",
                      "type":"string"
                   },
                   {
                      "name":"chainId",
                      "type":"uint256"
                   },
                   {
                      "name":"verifyingContract",
                      "type":"address"
                   }
                ],
                "Person":[
                   {
                      "name":"name",
                      "type":"string"
                   },
                   {
                      "name":"wallet",
                      "type":"address"
                   }
                ],
                "Mail":[
                   {
                      "name":"from",
                      "type":"Person"
                   },
                   {
                      "name":"to",
                      "type":"Person"
                   },
                   {
                      "name":"contents",
                      "type":"string"
                   }
                ]
             },
             "primaryType":"Mail",
             "domain":{
                "name":"Ether Mail",
                "version":"1",
                "chainId":1,
                "verifyingContract":"0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
             },
             "message":{
                "from":{
                   "name":"Cow",
                   "wallet":"0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
                },
                "to":{
                   "name":"Bob",
                   "wallet":"0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
                },
                "contents":"Hello, Bob!"
             }
        });

        assert_eq!(
        safe.sign_typed_data(chain_id, &typed_data.to_string())
            .unwrap().to_hex_string(),
        "0x02ef654edf58fdc39597af35b8e16931cb5f16233d15a9f8d1a06f13612225f04c4927677f5f60a82a1b69d08dd61cd8658d1a7c29efc223f5912695adf7a0931c"
    );
    }

    #[test]
    fn test_cannot_sign_invalid_permit2_transfer() {
        let permitted = UnparsedTokenPermissions {
            token: "123".to_string(), // note this is invalid
            amount: "1000000000000000000".to_string(),
        };

        let transfer_from = UnparsedPermitTransferFrom {
            permitted,
            spender: "0x3f1480266afef1ba51834cfef0a5d61841d57572".to_string(),
            nonce: "123".to_string(),
            deadline: "1704067200".to_string(),
        };

        let smart_account = SafeSmartAccount::random();

        let result = smart_account.sign_permit2_transfer(480, transfer_from);

        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            format!("invalid input on token: odd number of digits")
        );
    }

    #[test]
    fn test_cannot_sign_restricted_permit2_typed_data() {
        let permitted = TokenPermissions {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U256),
        };

        let transfer_from = PermitTransferFrom {
            permitted,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            nonce: uint!(123_U256),
            deadline: uint!(1704067200_U256),
        };

        let typed_data =
            serde_json::to_string(&transfer_from.as_typed_data(480)).unwrap();

        let smart_account = SafeSmartAccount::random();

        let result = smart_account.sign_typed_data(480, &typed_data);

        assert!(result.is_err());

        assert_eq!(
            result.unwrap_err().to_string(),
            format!("the contract 0x000000000022D473030F116dDEE9F6B43aC78BA3 is restricted from TypedData signing.")
        );
    }

    #[test]
    fn test_cannot_sign_restricted_permit2_typed_data_with_alternate_contract_casing() {
        let permitted = TokenPermissions {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U256),
        };

        let transfer_from = PermitTransferFrom {
            permitted,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            nonce: uint!(123_U256),
            deadline: uint!(1704067200_U256),
        };

        let mut typed_data = transfer_from.as_typed_data(480);

        let alternative_cases = [
            "0x000000000022d473030f116ddee9f6b43ac78BA3", // mixed case
            "000000000022d473030f116ddee9f6b43ac78ba3",   // no 0x
            "0x000000000022D473030F116DDEE9F6B43AC78BA3", // upper case
            "000000000022D473030F116DDEE9F6B43AC78BA3",   // upper case, no 0x
        ];

        for alternative_case in alternative_cases {
            let mut domain = typed_data.domain.clone();
            let address = Address::from_str(alternative_case).unwrap();
            domain.verifying_contract = Some(address);

            typed_data.domain = domain;

            let typed_data_str = serde_json::to_string(&typed_data).unwrap();

            let smart_account = SafeSmartAccount::random();

            let result = smart_account.sign_typed_data(480, &typed_data_str);

            assert!(result.is_err());

            assert_eq!(
                result.unwrap_err().to_string(),
                format!("the contract {address} is restricted from TypedData signing.")
            );
        }
    }
}
