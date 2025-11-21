use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::{SolCall, SolValue},
};
use std::{str::FromStr, sync::LazyLock};

use crate::smart_account::SafeOperation;

pub static MULTISEND_ADDRESS: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x38869bf66a61cf6bdb996a6ae40d5853fd43b526")
        .expect("invalid MULTISEND address")
});

sol! {
    /// Reference: <https://github.com/safe-fndn/safe-smart-account/blob/main/contracts/libraries/MultiSend.sol>
    #[derive(serde::Serialize)]
    interface IMultiSend {
        function multiSend(bytes transactions) external payable;
    }

    /// The structure of an encoded transaction
    /// Reference: <https://eips.ethereum.org/EIPS/eip-4337#useroperation>
    #[sol(rename_all = "camelcase")]
    #[derive(Debug, Default, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MultiSendTx {
        /// call = 0, delegatecall = 1
        uint8 operation;
        /// contract to call
        address to;
        /// eth to send with the call
        uint256 value;
        /// length of the data
        uint256 data_length;
        /// call data
        bytes data;
    }
}

pub struct MultiSendBundle {
    pub operation: SafeOperation,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

/// Idiomatic struct wrapper
pub struct MultiSend {
    pub address: Address,
}

impl MultiSend {
    pub const fn new(address: Address) -> Self {
        Self { address }
    }

    pub fn encode_blob(txs: &[MultiSendTx]) -> Vec<u8> {
        let mut out = Vec::new();
        for tx in txs {
            out.extend_from_slice(&tx.abi_encode_packed());
        }
        out
    }

    pub fn build_operation(&self, txs: &[MultiSendTx]) -> MultiSendBundle {
        let blob = Self::encode_blob(txs);

        let multisend_data = IMultiSend::multiSendCall {
            transactions: blob.into(),
        }
        .abi_encode();

        MultiSendBundle {
            to: self.address,
            data: multisend_data,
            value: U256::ZERO,
            operation: SafeOperation::DelegateCall,
        }
    }
}
