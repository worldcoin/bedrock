//! This module introduces foreign bindings (Swift and Kotlin) for specific Solidity types where
//! the native app requires functionality to craft those transactions manually.

use alloy::primitives::{Address, Bytes, U128, U256};

use crate::{
    primitives::{ParseFromForeignBinding, PrimitiveError},
    smart_account::UserOperation,
};

/// A pseudo-transaction object for EIP-4337. Used to execute transactions through the Safe Smart Account.
///
/// This object is expected to be initialized from foreign languages.
///
/// Reference: <https://www.erc4337.io/docs/understanding-ERC-4337/user-operation>
///
/// Note the types of this struct are types that can be lifted from foreign languages to be then parsed and validated.
#[derive(uniffi::Record, Clone, Debug)]
pub struct UnparsedUserOperation {
    /// The address of the smart contract account (Solidity type: `address`)
    pub sender: String,
    /// Anti-replay protection; also used as the salt for first-time account creation (Solidity type: `uint256`)
    pub nonce: String,
    /// Data that's passed to the sender for execution (Solidity type: `bytes`)
    pub call_data: String,
    /// Gas limit for execution phase (Solidity type: `uint128`)
    pub call_gas_limit: String,
    /// Gas limit for verification phase (Solidity type: `uint128`)
    pub verification_gas_limit: String,
    /// Gas to compensate the bundler (Solidity type: `uint128`)
    pub pre_verification_gas: String,
    /// Maximum fee per gas (similar to [EIP-1559](https://eips.ethereum.org/EIPS/eip-1559)'s `max_fee_per_gas`) (Solidity type: `uint128`)
    pub max_fee_per_gas: String,
    /// Maximum priority fee per gas (Solidity type: `uint128`)
    pub max_priority_fee_per_gas: String,
    /// Paymaster contact address (Solidity type: `address`)
    pub paymaster: Option<String>,
    /// Paymaster verification gas limit (Solidity type: `uint128`)
    pub paymaster_verification_gas_limit: String,
    /// Paymaster post-operation gas limit (Solidity type: `uint128`)
    pub paymaster_post_op_gas_limit: String,
    /// Paymaster additional data for verification (Solidity type: `bytes`)
    pub paymaster_data: Option<String>,
    /// Used to validate a `UserOperation` along with the nonce during verification (Solidity type: `bytes`)
    pub signature: String,
    /// Factory address (Solidity type: `address`)
    pub factory: Option<String>,
    /// Factory data (Solidity type: `bytes`)
    pub factory_data: Option<String>,
}

impl TryFrom<UnparsedUserOperation> for UserOperation {
    type Error = PrimitiveError;

    fn try_from(user_op: UnparsedUserOperation) -> Result<Self, Self::Error> {
        let sender = Address::parse_from_ffi(&user_op.sender, "sender")?;

        let nonce = U256::parse_from_ffi(&user_op.nonce, "nonce")?;

        let call_data = Bytes::parse_from_ffi(&user_op.call_data, "call_data")?;

        let call_gas_limit =
            U128::parse_from_ffi(&user_op.call_gas_limit, "call_gas_limit")?;

        let verification_gas_limit = U128::parse_from_ffi(
            &user_op.verification_gas_limit,
            "verification_gas_limit",
        )?;

        let pre_verification_gas = U256::parse_from_ffi(
            &user_op.pre_verification_gas,
            "pre_verification_gas",
        )?;

        let max_fee_per_gas =
            U128::parse_from_ffi(&user_op.max_fee_per_gas, "max_fee_per_gas")?;

        let max_priority_fee_per_gas = U128::parse_from_ffi(
            &user_op.max_priority_fee_per_gas,
            "max_priority_fee_per_gas",
        )?;

        let paymaster = user_op
            .paymaster
            .map(|p| Address::parse_from_ffi(&p, "paymaster"))
            .transpose()?;

        let paymaster_verification_gas_limit = U128::parse_from_ffi(
            &user_op.paymaster_verification_gas_limit,
            "paymaster_verification_gas_limit",
        )
        .ok();

        let paymaster_post_op_gas_limit = U128::parse_from_ffi(
            &user_op.paymaster_post_op_gas_limit,
            "paymaster_post_op_gas_limit",
        )
        .ok();

        let paymaster_data = user_op
            .paymaster_data
            .map(|p| Bytes::parse_from_ffi(&p, "paymaster_data"))
            .transpose()?;

        let signature = Bytes::parse_from_ffi(&user_op.signature, "signature")?;

        let factory = user_op
            .factory
            .map(|f| Address::parse_from_ffi(&f, "factory"))
            .transpose()?;

        let factory_data = user_op
            .factory_data
            .map(|f| Bytes::parse_from_ffi(&f, "factory_data"))
            .transpose()?;

        Ok(Self {
            sender,
            nonce,
            factory,
            factory_data,
            call_data,
            call_gas_limit,
            verification_gas_limit,
            pre_verification_gas,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            paymaster,
            paymaster_verification_gas_limit,
            paymaster_post_op_gas_limit,
            paymaster_data,
            signature,
        })
    }
}
