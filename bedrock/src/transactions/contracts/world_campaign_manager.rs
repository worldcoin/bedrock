//! This module introduces the `WorldCampaignManager` contract interface.

use alloy::{
    primitives::{address, Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::config::{current_environment_or_default, BedrockEnvironment};
use crate::primitives::PrimitiveError;
use crate::smart_account::{
    ISafe4337Module, InstructionFlag, Is4337Encodable, NonceKeyV1, SafeOperation,
    TransactionTypeId, UserOperation,
};

/// Returns the `WorldCampaignManager` contract address for the current Bedrock environment.
///
/// # Panics
///
/// This function panics if the hard-coded address strings cannot be parsed into
/// a valid `Address`. This should never happen unless the constants are edited
/// to an invalid value.
#[must_use]
pub fn world_campaign_manager_address() -> Address {
    match current_environment_or_default() {
        BedrockEnvironment::Staging => {
            address!("0xD61F9411E768871ca9bc723afC5fF3A4f731D0C1") // TODO replace with post-audit contract
        }
        BedrockEnvironment::Production => {
            address!("0xD61F9411E768871ca9bc723afC5fF3A4f731D0C1") // TODO replace with post-audit contract
        }
    }
}

sol! {
    /// The `WorldCampaignManager` contract interface.
    /// Reference: <https://github.com/worldcoin/worldcoin-gift-contracts/blob/main/src/WorldCampaignManager.sol>
    #[derive(serde::Serialize)]
    interface IWorldCampaignManager {
         function sponsor(uint256 campaignId, address recipient) external;
         function claim(uint256 campaignId) external returns (uint256 rewardAmount) ;
    }
}

pub enum CampaignAction {
    Sponsor,
    Claim,
}

impl CampaignAction {
    const fn tx_type_id(&self) -> TransactionTypeId {
        match self {
            Self::Sponsor => TransactionTypeId::WorldCampaignManagerSponsor,
            Self::Claim => TransactionTypeId::WorldCampaignManagerClaim,
        }
    }
}

/// Enables operations with the `WorldCampaignManager` contract.
pub struct WorldCampaignManager {
    /// The inner call data for the function.
    call_data: Vec<u8>,
    /// campaingId
    campaign_id: U256,
    /// action
    action: CampaignAction,
}

impl WorldCampaignManager {
    const fn new(
        call_data: Vec<u8>,
        campaign_id: U256,
        action: CampaignAction,
    ) -> Self {
        Self {
            call_data,
            campaign_id,
            action,
        }
    }
    pub fn sponsor(campaign_id: U256, recipient: Address) -> Self {
        let call_data = IWorldCampaignManager::sponsorCall {
            campaignId: campaign_id,
            recipient,
        }
        .abi_encode();

        Self::new(call_data, campaign_id, CampaignAction::Sponsor)
    }
    pub fn claim(campaign_id: U256) -> Self {
        let call_data = IWorldCampaignManager::claimCall {
            campaignId: campaign_id,
        }
        .abi_encode();

        Self::new(call_data, campaign_id, CampaignAction::Claim)
    }
}

impl Is4337Encodable for WorldCampaignManager {
    type MetadataArg = ();

    fn as_execute_user_op_call_data(&self) -> Bytes {
        ISafe4337Module::executeUserOpCall {
            to: world_campaign_manager_address(),
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

        let bytes: [u8; 32] = self.campaign_id.to_be_bytes();
        let mut metadata_bytes = [0u8; 10];

        // copy last 10 bytes in the nonceKey.
        // campaign_id starts at 1 and is incremented by 1 for each new campaign, it will therefore never exceed 10 bytes <https://github.com/worldcoin/worldcoin-gift-contracts/blob/58e21822650958c11d089ef6e9a797668271848e/src/WorldCampaignManager.sol#L266>
        metadata_bytes.copy_from_slice(&bytes[32 - 10..]);

        let key = NonceKeyV1::new(
            self.action.tx_type_id(),
            InstructionFlag::Default,
            metadata_bytes,
        );
        let nonce = key.encode_with_sequence(0);

        Ok(UserOperation::new_with_defaults(
            wallet_address,
            nonce,
            call_data,
        ))
    }
}

#[cfg(test)]
mod tests {
    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_sponsor() {
        let campaign_id = U256::from(1234);
        let to =
            Address::from_str("0x44db85bca667056bdbf397f8e3f6db294587b288").unwrap();

        let gift = WorldCampaignManager::sponsor(campaign_id, to);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = gift.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::WorldCampaignManagerSponsor as u8);

        let expected_metadata: [u8; 32] = campaign_id.to_be_bytes();
        assert_eq!(&be[7..=16], &expected_metadata[32 - 10..]);

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_claim() {
        let campaign_id = U256::from(1234);
        let gift = WorldCampaignManager::claim(campaign_id);

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = gift.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::WorldCampaignManagerClaim as u8);
        let expected_metadata: [u8; 32] = campaign_id.to_be_bytes();
        assert_eq!(&be[7..=16], &expected_metadata[32 - 10..]);

        // Sequence number = 0 (bytes 24..31)
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
