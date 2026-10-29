//! Pins every contract address the wallet migrations sign against without user consent,
//! imported through the same paths the migrations use.
//!
//! A change to any of these constants must also change this file.

use alloy::primitives::address;

use crate::primitives::contracts::ENTRYPOINT_4337;
use crate::smart_account::GNOSIS_SAFE_4337_MODULE;
use crate::transactions::contracts::multisend::MULTISEND_ADDRESS;
use crate::transactions::contracts::permit2::PERMIT2_ADDRESS;
use crate::transactions::contracts::worldchain::{
    TFH_PAYMASTER_ADDRESS, USDC_ADDRESS, WBTC_ADDRESS, WETH_ADDRESS, WLD_ADDRESS,
};

#[test]
fn test_auto_signed_contract_addresses_are_pinned() {
    let pinned = [
        (
            "PERMIT2_ADDRESS",
            PERMIT2_ADDRESS,
            address!("0x000000000022D473030F116dDEE9F6B43aC78BA3"),
        ),
        (
            "USDC_ADDRESS",
            USDC_ADDRESS,
            address!("0x79A02482A880bCE3F13e09Da970dC34db4CD24d1"),
        ),
        (
            "WETH_ADDRESS",
            WETH_ADDRESS,
            address!("0x4200000000000000000000000000000000000006"),
        ),
        (
            "WBTC_ADDRESS",
            WBTC_ADDRESS,
            address!("0x03C7054BCB39f7b2e5B2c7AcB37583e32D70Cfa3"),
        ),
        (
            "WLD_ADDRESS",
            WLD_ADDRESS,
            address!("0x2cFc85d8E48F8EAB294be644d9E25C3030863003"),
        ),
        (
            "TFH_PAYMASTER_ADDRESS",
            TFH_PAYMASTER_ADDRESS,
            address!("0x48BB71Ac56CAd233012a8Afb35Ab6684e9233756"),
        ),
        (
            "MULTISEND_ADDRESS",
            MULTISEND_ADDRESS,
            address!("0x38869bf66a61cF6bDB996A6aE40D5853Fd43B526"),
        ),
        (
            "GNOSIS_SAFE_4337_MODULE",
            *GNOSIS_SAFE_4337_MODULE,
            address!("0x75cf11467937ce3F2f357CE24ffc3DBF8fD5c226"),
        ),
        (
            "ENTRYPOINT_4337",
            *ENTRYPOINT_4337,
            address!("0x0000000071727De22E5E9d8BAf0edAc6f37da032"),
        ),
    ];

    for (name, actual, expected) in pinned {
        assert_eq!(
            actual, expected,
            "{name} no longer matches its pinned address"
        );
    }
}
