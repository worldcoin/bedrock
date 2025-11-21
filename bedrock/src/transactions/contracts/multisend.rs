use alloy::{
    primitives::{Address, U256},
    sol,
    sol_types::SolCall,
};
use std::{str::FromStr, sync::LazyLock};

use crate::smart_account::SafeOperation;

/// Reference: <https://github.com/safe-fndn/safe-smart-account/blob/main/contracts/libraries/MultiSend.sol>
pub static MULTISEND_ADDRESS: LazyLock<Address> = LazyLock::new(|| {
    Address::from_str("0x38869bf66a61cf6bdb996a6ae40d5853fd43b526")
        .expect("invalid MULTISEND address")
});

sol! {
    #[derive(serde::Serialize)]
    interface IMultiSend {
        function multiSend(bytes transactions) external payable;
    }
}

pub struct MultiSendTx {
    pub operation: u8,
    pub to: Address,
    pub value: U256,
    pub data: Vec<u8>,
}

pub struct MultiSendBundle {
    pub operation: u8,
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

    pub fn encode_entry(tx: &MultiSendTx) -> Vec<u8> {
        let mut out = Vec::new();

        // uint8 operation
        out.push(tx.operation);

        // address 20 bytes
        out.extend_from_slice(tx.to.as_slice());

        // uint256 value (32 bytes)
        let value_bytes: [u8; 32] = tx.value.to_be_bytes();
        out.extend_from_slice(&value_bytes);

        // uint256 length of data (32 bytes)
        let len_u256 = U256::from(tx.data.len());
        let len_bytes: [u8; 32] = len_u256.to_be_bytes();
        out.extend_from_slice(&len_bytes);

        // bytes data
        out.extend_from_slice(&tx.data);

        out
    }

    pub fn encode_blob(txs: &[MultiSendTx]) -> Vec<u8> {
        let mut out = Vec::new();
        for tx in txs {
            out.extend_from_slice(&Self::encode_entry(tx));
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
            operation: SafeOperation::DelegateCall as u8,
        }
    }
}
