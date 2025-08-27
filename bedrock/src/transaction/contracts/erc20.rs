//! This module introduces the ERC-20 token contract interface.

use alloy::{
    primitives::{Address, Bytes, U256},
    sol,
    sol_types::SolCall,
};

use crate::primitives::PrimitiveError;
use crate::smart_account::{
    InstructionFlag, Is4337Encodable, NonceKeyV1, TransactionTypeId, UserOperation,
};

sol! {
    /// The ERC20 contract interface.
    ///
    /// Reference: <https://eips.ethereum.org/EIPS/eip-20>
    /// Reference: <https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/token/ERC20/IERC20.sol>
    #[derive(serde::Serialize)]
    interface IErc20 {
        function transfer(address to, uint256 value) external returns (bool);
    }
}

/// Enables operations with the ERC-20 token contract.
pub struct Erc20 {
    /// The inner call data for the ERC-20 `transferCall` function.
    call_data: Vec<u8>,
    /// The address of the ERC-20 token contract.
    token_address: Address,
}

impl Erc20 {
    pub fn new(token_address: Address, to: Address, value: U256) -> Self {
        let call_data = IErc20::transferCall { to, value }.abi_encode();

        Self {
            call_data,
            token_address,
        }
    }
}

// First byte of the metadata field. Index starts at 1 as 0 is reserved for "not set"
// NOTE: Ordering should never change, only new values should be added
#[repr(u8)]
#[allow(dead_code)]
pub enum TransferSource {
    QrScanner = 1,
    WalletHome = 2,
    DollarPage = 3,
    WorldCoinPage = 4,
    CryptoPage = 5,
    ExternalPage = 6,
    Spending = 7,
    Savings = 8,
    TokenUnavailable = 9,
    SavingsIntro = 10,
    ContentCard = 11,
    InfoTabBanner = 12,
    MiniApp = 13,
    ClaimToVault = 14,
    ContactTab = 15,
    DeleteProfile = 16,
    NewPaymentFlow = 17,
    CashSection = 18,
    CryptoSection = 19,
    Deeplink = 20,
    WorldSection = 21,
}

// Second byte of the metadata field. Index starts at 1 as 0 is reserved for "not set"
// NOTE: Ordering should never change, only new values should be added
#[repr(u8)]
#[allow(dead_code)]
pub enum TransferAssociation {
    None = 1,
    XmtpMessage = 2,
}

pub struct MetadataArg {
    pub source: Option<TransferSource>,
    pub association: Option<TransferAssociation>,
}

impl Is4337Encodable for Erc20 {
    type MetadataArg = MetadataArg;

    fn target_address(&self) -> Address {
        self.token_address
    }

    fn call_data(&self) -> Bytes {
        self.call_data.clone().into()
    }

    fn as_preflight_user_operation(
        &self,
        wallet_address: Address,
        metadata: Option<Self::MetadataArg>,
    ) -> Result<UserOperation, PrimitiveError> {
        let call_data = self.as_execute_user_op_call_data();

        let mut metadata_bytes: [u8; 10] = [0u8; 10];
        if let Some(metadata) = metadata {
            // We use 0 if the individual field is not set
            // Hence why we use 1 as the first index in enum definition
            if let Some(source) = metadata.source {
                metadata_bytes[0] = source as u8;
            }
            if let Some(association) = metadata.association {
                metadata_bytes[1] = association as u8;
            }
        }

        let key = NonceKeyV1::new(
            TransactionTypeId::Transfer,
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
    use alloy::primitives::bytes;
    use std::str::FromStr;

    use crate::primitives::BEDROCK_NONCE_PREFIX_CONST;

    use super::*;

    #[test]
    fn test_erc20_transfer() {
        let erc20 = Erc20::new(
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap(),
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap(),
            U256::from(1),
        );

        let execute_user_op_call_data = erc20.as_execute_user_op_call_data();

        // generated with `chisel`
        let expected_call_data = bytes!("0x7bb374280000000000000000000000002cfc85d8e48f8eab294be644d9e25c30308630030000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000044a9059cbb0000000000000000000000001234567890123456789012345678901234567890000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000");

        assert_eq!(execute_user_op_call_data, expected_call_data);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_no_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();
        let user_op = erc20.as_preflight_user_operation(wallet, None).unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();

        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8); // instruction flags default

        // Empty metadata
        assert_eq!(&be[7..=16], &[0u8; 10]);

        assert_eq!(&be[24..32], &[0u8; 8]);
    }

    #[test]
    fn test_erc20_preflight_user_operation_nonce_v1_with_metadata() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let erc20 = Erc20::new(token, to, U256::from(1));

        let wallet =
            Address::from_str("0x4564420674EA68fcc61b463C0494807C759d47e6").unwrap();

        let metadata = MetadataArg {
            source: Some(TransferSource::QrScanner),
            association: Some(TransferAssociation::XmtpMessage),
        };

        let user_op = erc20
            .as_preflight_user_operation(wallet, Some(metadata))
            .unwrap();

        // Check nonce layout
        let be: [u8; 32] = user_op.nonce.to_be_bytes();
        assert_eq!(&be[0..=4], BEDROCK_NONCE_PREFIX_CONST);
        assert_eq!(be[5], TransactionTypeId::Transfer as u8);
        assert_eq!(be[6], 0u8);

        // Check metadata
        assert_eq!(be[7], TransferSource::QrScanner as u8);
        assert_eq!(be[8], TransferAssociation::XmtpMessage as u8);
        assert_eq!(&be[9..=16], &[0u8; 8]);

        // sequence must be zero
        assert_eq!(&be[24..32], &[0u8; 8]);
    }
}
