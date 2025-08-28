//! This module introduces the contract interface for the Safe contract.
//!
//! Explicitly this only allows management of the Safe Smart Account. Executing transactions with the Safe Smart Account
//! is done via the `SafeSmartAccount` module.

use alloy::{
    primitives::{address, Address, Bytes},
    sol,
    sol_types::SolCall,
};

use crate::{
    primitives::PrimitiveError,
    smart_account::{InstructionFlag, Is4337Encodable, NonceKeyV1, TransactionTypeId},
    transaction::UserOperation,
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

/// Represents a Safe owner swap transaction for key rotation.
pub struct SafeOwner {
    /// The inner call data for the ERC-20 `transferCall` function.
    call_data: Vec<u8>,
    /// The address of the Safe Smart Account.
    wallet_address: Address,
}

impl SafeOwner {
    /// Creates a new `SafeOwner` transaction for swapping Safe owners.
    ///
    /// # Arguments
    /// - `wallet_address`: The address of the Safe Smart Account
    /// - `old_owner`: The current owner to be replaced
    /// - `new_owner`: The new owner to replace the old owner
    #[must_use]
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

    fn target_address(&self) -> Address {
        self.wallet_address
    }

    fn call_data(&self) -> Bytes {
        self.call_data.clone().into()
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
