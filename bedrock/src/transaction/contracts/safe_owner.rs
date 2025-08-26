//! This module introduces the contract interface for the Safe contract.
//!
//! Explicitly this only allows management of the Safe Smart Account. Executing transactions with the Safe Smart Account
//! is done via the `SafeSmartAccount` module.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::{
    primitives::PrimitiveError,
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
};

const SENTINEL_ADDRESS: Address =
    address!("0x0000000000000000000000000000000000000001");

sol! {
    ///Owner Manager Interface for the Safe
    ///
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/base/OwnerManager.sol>
    #[derive(serde::Serialize)]
    #[sol(rename_all = "camelcase")]
    interface IOwnerManager {
        function swapOwner(address prev_owner, address old_owner, address new_owner) public;
    }
}

pub struct SafeOwner {
    /// The inner call data for the ERC-20 `transferCall` function.
    call_data: Vec<u8>,
    /// The address of the Safe Smart Account.
    wallet_address: Address,
}

impl SafeOwner {
    pub fn new(
        wallet_address: Address,
        old_owner: Address,
        new_owner: Address,
    ) -> Self {
        Self {
            call_data: IOwnerManager::swapOwnerCall {
                prev_owner: SENTINEL_ADDRESS,
                old_owner,
                new_owner,
            }
            .abi_encode(),
            wallet_address,
        }
    }
}

impl Is4337Encodable for SafeOwner {
    type MetadataArg = ();

    // TODO: Make this the default in Is4337Encodable trait, it's a sensible default.
    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.wallet_address,
            value: U256::ZERO,
            data: self.call_data.clone().into(),
            operation: SafeOperation::Call as u8,
        }
        .abi_encode()
        .into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        _metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let key = NonceKeyV1::new(
            TransactionTypeId::SwapOwner,
            InstructionFlag::Default,
            [0u8; 10],
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}
