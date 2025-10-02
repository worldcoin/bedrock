use alloy::{
    primitives::{fixed_bytes, keccak256, Address, FixedBytes, U256},
    sol,
    sol_types::SolValue,
};

use crate::{
    primitives::ParseFromForeignBinding,
    smart_account::{SafeSmartAccountError, SafeTransaction},
};

/// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L62C49-L62C115>
static SAFE_TX_TYPEHASH: FixedBytes<32> =
    fixed_bytes!("0xbb8310d486368db6bd6f849402fdd73ad53d316b5a4b2644ad6efe0f941286d8");

sol! {
    /// Represents the hash of a Safe transaction.
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L427>
    #[derive(Debug)]
    #[sol(rename_all = "camelcase")]
    struct SafeTxHash {
        bytes32 safe_tx_typehash;
        address to;
        uint256 value;
        /// keccak256 of calldata (hashed when converted from `SafeTransaction`)
        bytes32 data;
        uint8 operation;
        uint256 safe_tx_gas;
        uint256 base_gas;
        uint256 gas_price;
        address gas_token;
        address refund_receiver;
        uint256 nonce;
    }
}

impl SafeTransaction {
    /// Encodes and hashes a Safe transaction (`getTransactionHash` equivalent), returning the hash to be signed by the EOA owner.
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L427>
    ///
    /// Attempts to convert the `SafeTransaction` (from foreign code) into a `SafeTxHash` which can be ABI encoded.
    ///
    /// # Errors
    /// - Returns an error if there's an error parsing any of the attributes.
    /// - Returns an error if there's an error ABI encoding the `SafeTxHash`.
    pub fn get_transaction_hash(self) -> Result<FixedBytes<32>, SafeSmartAccountError> {
        let safe_tx_hash: SafeTxHash = self.try_into()?;
        Ok(keccak256(safe_tx_hash.abi_encode()))
    }
}

impl TryFrom<SafeTransaction> for SafeTxHash {
    type Error = SafeSmartAccountError;

    fn try_from(unparsed_tx: SafeTransaction) -> Result<Self, Self::Error> {
        let to = Address::parse_from_ffi(&unparsed_tx.to, "to")?;

        let value = U256::parse_from_ffi(&unparsed_tx.value, "value")?;

        let data = if unparsed_tx.data.starts_with("0x") {
            &unparsed_tx.data[2..]
        } else {
            return Err(SafeSmartAccountError::InvalidInput {
                attribute: "data".to_string(),
                message: "must be hex encoded and start with 0x".to_string(),
            });
        };

        let data = keccak256(&hex::decode(data).map_err(|e| {
            SafeSmartAccountError::InvalidInput {
                attribute: "data".to_string(),
                message: e.to_string(),
            }
        })?);

        let operation: u8 = unparsed_tx.operation as u8;

        let safe_tx_gas =
            U256::parse_from_ffi(&unparsed_tx.safe_tx_gas, "safe_tx_gas")?;
        let base_gas = U256::parse_from_ffi(&unparsed_tx.base_gas, "base_gas")?;
        let gas_price = U256::parse_from_ffi(&unparsed_tx.gas_price, "gas_price")?;
        let gas_token = Address::parse_from_ffi(&unparsed_tx.gas_token, "gas_token")?;
        let refund_receiver =
            Address::parse_from_ffi(&unparsed_tx.refund_receiver, "refund_receiver")?;

        let nonce = U256::parse_from_ffi(&unparsed_tx.nonce, "nonce")?;

        Ok(Self {
            safe_tx_typehash: SAFE_TX_TYPEHASH,
            to,
            value,
            data,
            operation,
            safe_tx_gas,
            base_gas,
            gas_price,
            gas_token,
            refund_receiver,
            nonce,
        })
    }
}

#[cfg(test)]
mod test {
    use alloy::primitives::address;

    use crate::smart_account::{SafeOperation, SafeSmartAccount};

    use super::*;

    #[test]
    fn test_serialize_safe_transaction_to_hash() {
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

        let safe_tx_hash = tx.get_transaction_hash().unwrap();

        let smart_account = SafeSmartAccount::random();
        let safe_tx_hash = smart_account.eip_712_hash(
            safe_tx_hash,
            10,
            Some(address!("0x4564420674EA68fcc61b463C0494807C759d47e6")),
        );

        assert_eq!(
            safe_tx_hash,
            // From `getTransactionHash(tx)` in the explorer for 0x4564420674EA68fcc61b463C0494807C759d47e6 safe
            fixed_bytes!(
                "0x358c04136e795dddeb66023c9431955b6f6d63515c76f1f2113afcced52410e2"
            )
        );
    }
}
