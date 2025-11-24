//! This module introduces the `WorldGiftManager` contract interface.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::config::{current_environment_or_default, BedrockEnvironment};
use crate::{
    primitives::PrimitiveError,
    transactions::contracts::{erc20::Erc20, multisend::MultiSend},
};
use crate::{
    smart_account::{
        ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
        TransactionTypeId, UserOperation,
    },
    transactions::contracts::multisend::MultiSendTx,
};

/// Returns the `WorldGiftManager` contract address for the current Bedrock environment.
#[must_use]
pub fn world_gift_manager_address() -> Address {
    match current_environment_or_default() {
        BedrockEnvironment::Staging => {
            address!("0x91479943841A4350f614Abb9745314F262F45b2e") // TODO replace with post-audit contract
        }
        BedrockEnvironment::Production => {
            address!("0x91479943841A4350f614Abb9745314F262F45b2e") // TODO replace with post-audit contract
        }
    }
}

sol! {
    /// The `WorldGiftManager` contract interface.
    /// Reference: <https://github.com/worldcoin/worldcoin-gift-contracts/blob/main/src/WorldGiftManager.sol>
    #[derive(serde::Serialize)]
    interface IWorldGiftManager {
        function gift(address token, uint256 giftId, address recipient, uint256 amount) external;
        function redeem(uint256 giftId) external;
        function cancel(uint256 giftId) external;
    }
}

// TODO merge WorldGiftManager and WorldGiftManagerGift
/// Enables operations with the `WorldGiftManager` contract.
pub struct WorldGiftManagerGift {
    /// The inner call data for the function.
    call_data: Vec<u8>,
    operation: SafeOperation,
    to: Address,
    value: U256,
    /// gift id, randomly generated
    gift_id: [u8; 17],
}

impl WorldGiftManagerGift {
    pub fn new(
        token: Address,
        recipient: Address,
        amount: U256,
        gift_id: [u8; 17],
    ) -> Self {
        let approve_data = Erc20::encode_approve(world_gift_manager_address(), amount);

        let mut padded_gift_id = [0u8; 32];
        padded_gift_id[32 - 17..].copy_from_slice(&gift_id);

        let gift_data = IWorldGiftManager::giftCall {
            token,
            giftId: U256::from_be_bytes(padded_gift_id),
            recipient,
            amount,
        }
        .abi_encode();

        let entries = vec![
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: token,
                value: U256::ZERO,
                data_length: U256::from(approve_data.len()),
                data: approve_data.into(),
            },
            MultiSendTx {
                operation: SafeOperation::Call as u8,
                to: world_gift_manager_address(),
                value: U256::ZERO,
                data_length: U256::from(gift_data.len()),
                data: gift_data.into(),
            },
        ];

        let bundle = MultiSend::build_bundle(&entries);
        Self {
            call_data: bundle.data,
            operation: bundle.operation,
            to: bundle.to,
            value: bundle.value,
            gift_id,
        }
    }
}

impl Is4337Encodable for WorldGiftManagerGift {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: self.to,
            value: self.value,
            data: self.call_data.clone().into(),
            operation: self.operation.clone() as u8,
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

        let mut metadata_bytes = [0u8; 10];
        metadata_bytes.copy_from_slice(&self.gift_id[0..10]);

        let mut random_tail = [0u8; 7];
        random_tail.copy_from_slice(&self.gift_id[10..17]);

        let key = NonceKeyV1::with_random_tail(
            TransactionTypeId::WorldGiftManagerGift,
            InstructionFlag::Default,
            metadata_bytes,
            random_tail,
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

pub enum GiftAction {
    Redeem,
    Cancel,
}

impl GiftAction {
    const fn tx_type_id(&self) -> TransactionTypeId {
        match self {
            Self::Redeem => TransactionTypeId::WorldGiftManagerRedeem,
            Self::Cancel => TransactionTypeId::WorldGiftManagerCancel,
        }
    }

    fn encode_call(&self, gift_id: U256) -> Bytes {
        match self {
            Self::Redeem => IWorldGiftManager::redeemCall { giftId: gift_id }
                .abi_encode()
                .into(),
            Self::Cancel => IWorldGiftManager::cancelCall { giftId: gift_id }
                .abi_encode()
                .into(),
        }
    }
}

pub struct WorldGiftManager {
    gift_id: U256,
    action: GiftAction,
    call_data: Bytes,
}

impl WorldGiftManager {
    pub fn new(gift_id: U256, action: GiftAction) -> Self {
        let call_data = action.encode_call(gift_id);
        Self {
            gift_id,
            action,
            call_data,
        }
    }
}
impl Is4337Encodable for WorldGiftManager {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: world_gift_manager_address(),
            value: U256::ZERO,
            data: self.call_data.clone(),
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

        // Extract 10 + 7 bytes from the tail of the 32-byte big-endian number.
        let (metadata_bytes, random_tail) = split_nonce_parts(self.gift_id);

        let key = NonceKeyV1::with_random_tail(
            self.action.tx_type_id(),
            InstructionFlag::Default,
            metadata_bytes,
            random_tail,
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

#[inline]
fn split_nonce_parts(gift_id: U256) -> ([u8; 10], [u8; 7]) {
    let bytes: [u8; 32] = gift_id.to_be_bytes();
    let mut meta = [0u8; 10];
    let mut tail = [0u8; 7];
    meta.copy_from_slice(&bytes[15..25]); // 10 bytes
    tail.copy_from_slice(&bytes[25..32]); // 7 bytes
    (meta, tail)
}

#[cfg(test)]
mod tests {
    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;
    use rand::RngCore;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_gift() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x44db85bca667056bdbf397f8e3f6db294587b288").unwrap();
        let mut gift_id = [0u8; 17];
        rand::thread_rng().fill_bytes(&mut gift_id);
        let gift = WorldGiftManagerGift::new(token, to, U256::from(1), gift_id);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = gift.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::WorldGiftManagerGift as u8);

        // Metadata = gift_id[0..10] (bytes 7..16)
        assert_eq!(&be[7..=16], &gift.gift_id[0..10]);

        // Random tail = gift_id[10..17] (bytes 17..23)
        assert_eq!(&be[17..=23], &gift.gift_id[10..17]);

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_redeem() {
        let gift_id = U256::from(123_456_789_123_456_789_123_456_852_u128);
        let gift_id_bytes: [u8; 32] = gift_id.to_be_bytes();
        let gift = WorldGiftManager::new(gift_id, GiftAction::Redeem);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = gift.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::WorldGiftManagerRedeem as u8);
        assert_eq!(&be[7..=16], &gift_id_bytes[15..25]);
        assert_eq!(&be[17..=23], &gift_id_bytes[25..32]);

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_cancel() {
        let gift_id = U256::from(123_456_789_123_456_789_123_456_852_u128);
        let gift_id_bytes: [u8; 32] = gift_id.to_be_bytes();
        let gift = WorldGiftManager::new(gift_id, GiftAction::Cancel);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = gift.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::WorldGiftManagerCancel as u8);
        assert_eq!(&be[7..=16], &gift_id_bytes[15..25]);
        assert_eq!(&be[17..=23], &gift_id_bytes[25..32]);

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
