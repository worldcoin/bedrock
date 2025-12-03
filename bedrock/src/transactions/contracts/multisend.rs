use alloy::{
    primitives::{address, Address, U256},
    sol,
    sol_types::{SolCall, SolValue},
};

use crate::smart_account::SafeOperation;

/// The MultiSend contract address on World Chain.
pub const MULTISEND_ADDRESS: Address =
    address!("0x38869bf66a61cf6bdb996a6ae40d5853fd43b526");

sol! {
    /// Reference: <https://github.com/safe-fndn/safe-smart-account/blob/main/contracts/libraries/MultiSend.sol>
    #[derive(serde::Serialize)]
    interface IMultiSend {
        function multiSend(bytes transactions) external payable;
    }

    /// The structure of an encoded transaction
    /// Reference: <https://github.com/safe-fndn/safe-smart-account/blob/cdb2eb578dbdba4c3f10a47f9a2dd9580773e63a/contracts/libraries/MultiSend.sol#L26>
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

/// A bundle of transactions to be executed via MultiSend.
pub struct MultiSendBundle {
    /// The operation type (Call or DelegateCall).
    pub operation: SafeOperation,
    /// The target address (MultiSend contract).
    pub to: Address,
    /// The ETH value to send.
    pub value: U256,
    /// The encoded MultiSend call data.
    pub data: Vec<u8>,
}

/// Helper for building MultiSend transaction bundles.
pub struct MultiSend;

impl MultiSend {
    pub fn build_bundle(txs: &[MultiSendTx]) -> MultiSendBundle {
        let mut blob = Vec::new();
        for tx in txs {
            blob.extend_from_slice(&tx.abi_encode_packed());
        }
        let multisend_data = IMultiSend::multiSendCall {
            transactions: blob.into(),
        }
        .abi_encode();

        MultiSendBundle {
            to: MULTISEND_ADDRESS,
            data: multisend_data,
            value: U256::ZERO,
            operation: SafeOperation::DelegateCall,
        }
    }
}
