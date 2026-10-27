use alloy::{
    primitives::{address, Address, Bytes, B256, U256},
    sol_types::SolCall,
};
use bedrock::{
    smart_account::{ISafe4337Module, Is4337Encodable, SafeOperation},
    transactions::contracts::{
        erc20::IErc20,
        multisend::{IMultiSend, MULTISEND_ADDRESS},
        zero_ex::{
            AllowedSlippage, IAllowanceHolder, ISettlerTakerSubmitted, ZeroExSwap,
            ZeroExSwapQuote, ZeroExSwapRequest, ALLOWANCE_HOLDER_ADDRESS,
        },
    },
};

const WALLET: Address = address!("1111111111111111111111111111111111111111");
const TOKEN_IN: Address = address!("2222222222222222222222222222222222222222");
const TOKEN_OUT: Address = address!("3333333333333333333333333333333333333333");
const SETTLER: Address = address!("4444444444444444444444444444444444444444");
const OTHER: Address = address!("5555555555555555555555555555555555555555");

fn request() -> ZeroExSwapRequest {
    ZeroExSwapRequest {
        wallet_address: WALLET,
        token_in: TOKEN_IN,
        token_out: TOKEN_OUT,
        amount_in: U256::from(100),
        amount_out_min: U256::from(90),
    }
}

fn settlement() -> ISettlerTakerSubmitted::executeCall {
    ISettlerTakerSubmitted::executeCall {
        slippage: AllowedSlippage {
            recipient: WALLET,
            buyToken: TOKEN_OUT,
            minAmountOut: U256::from(80),
        },
        actions: vec![
            Bytes::from_static(&[1, 2, 3, 4]),
            Bytes::from_static(&[5, 6]),
        ],
        affiliate: B256::repeat_byte(0xab),
    }
}

fn allowance() -> IAllowanceHolder::execCall {
    IAllowanceHolder::execCall {
        operator: SETTLER,
        token: TOKEN_IN,
        amount: U256::from(100),
        target: SETTLER,
        data: settlement().abi_encode().into(),
    }
}

fn quote() -> ZeroExSwapQuote {
    ZeroExSwapQuote {
        to: ALLOWANCE_HOLDER_ADDRESS,
        value: U256::ZERO,
        data: allowance().abi_encode().into(),
        amount_out: U256::from(95),
    }
}

fn assert_rejected(request: &ZeroExSwapRequest, quote: &ZeroExSwapQuote, reason: &str) {
    let error = ZeroExSwap::new(request, quote, SETTLER).unwrap_err();
    assert!(error.to_string().contains(reason), "{error:#}");
}

#[derive(Debug)]
struct PackedCall {
    operation: u8,
    to: Address,
    value: U256,
    data: Bytes,
}

// Parse the Safe packed format independently of MultiSend's encoder.
fn calls(swap: &ZeroExSwap) -> Vec<PackedCall> {
    let execution = ISafe4337Module::executeUserOpCall::abi_decode_validate(
        &swap.build_execute_user_op_call_data(),
    )
    .unwrap();
    assert_eq!(execution.to, MULTISEND_ADDRESS);
    assert_eq!(execution.value, U256::ZERO);
    assert_eq!(execution.operation, SafeOperation::DelegateCall as u8);
    let bundle =
        IMultiSend::multiSendCall::abi_decode_validate(&execution.data).unwrap();
    let mut data = bundle.transactions.as_ref();
    let mut calls = Vec::new();
    while !data.is_empty() {
        let length = U256::from_be_slice(&data[53..85]).to::<usize>();
        calls.push(PackedCall {
            operation: data[0],
            to: Address::from_slice(&data[1..21]),
            value: U256::from_be_slice(&data[21..53]),
            data: Bytes::copy_from_slice(&data[85..85 + length]),
        });
        data = &data[85 + length..];
    }
    calls
}

fn swap_settlement(swap: &ZeroExSwap) -> ISettlerTakerSubmitted::executeCall {
    let calls = calls(swap);
    let allowance =
        IAllowanceHolder::execCall::abi_decode_validate(&calls[1].data).unwrap();
    ISettlerTakerSubmitted::executeCall::abi_decode_validate(&allowance.data).unwrap()
}

#[test]
fn builds_exact_approval_then_swap_with_reviewed_minimum_and_unchanged_route() {
    let swap = ZeroExSwap::new(&request(), &quote(), SETTLER).unwrap();
    let calls = calls(&swap);
    assert_eq!(calls.len(), 2);
    for call in &calls {
        assert_eq!(call.operation, SafeOperation::Call as u8);
        assert_eq!(call.value, U256::ZERO);
    }
    assert_eq!(calls[0].to, TOKEN_IN);
    let approval = IErc20::approveCall::abi_decode_validate(&calls[0].data).unwrap();
    assert_eq!(approval.spender, ALLOWANCE_HOLDER_ADDRESS);
    assert_eq!(approval.value, U256::from(100));

    assert_eq!(calls[1].to, ALLOWANCE_HOLDER_ADDRESS);
    let allowance =
        IAllowanceHolder::execCall::abi_decode_validate(&calls[1].data).unwrap();
    assert_eq!(&calls[1].data[..4], &[0x22, 0x13, 0xbc, 0x0b]);
    assert_eq!(allowance.operator, SETTLER);
    assert_eq!(allowance.target, SETTLER);
    assert_eq!(allowance.token, TOKEN_IN);
    assert_eq!(allowance.amount, U256::from(100));
    assert_eq!(&allowance.data[..4], &[0x1f, 0xff, 0x99, 0x1f]);
    let output = swap_settlement(&swap);
    assert_eq!(output.slippage.recipient, WALLET);
    assert_eq!(output.slippage.buyToken, TOKEN_OUT);
    assert_eq!(output.slippage.minAmountOut, U256::from(90));
    assert_eq!(output.actions, settlement().actions);
    assert_eq!(output.affiliate, settlement().affiliate);
}

#[test]
fn preserves_a_stronger_quote_minimum() {
    let mut settlement = settlement();
    settlement.slippage.minAmountOut = U256::from(93);
    let mut allowance = allowance();
    allowance.data = settlement.abi_encode().into();
    let quote = ZeroExSwapQuote {
        data: allowance.abi_encode().into(),
        ..quote()
    };
    let swap = ZeroExSwap::new(&request(), &quote, SETTLER).unwrap();
    assert_eq!(swap_settlement(&swap).slippage.minAmountOut, U256::from(93));
}

#[test]
fn rejects_output_below_either_reviewed_or_provider_minimum() {
    let quote_below_review = ZeroExSwapQuote {
        amount_out: U256::from(89),
        ..quote()
    };
    assert_rejected(&request(), &quote_below_review, "below the minimum");

    let mut settlement = settlement();
    settlement.slippage.minAmountOut = U256::from(96);
    let mut allowance = allowance();
    allowance.data = settlement.abi_encode().into();
    let quote_below_provider = ZeroExSwapQuote {
        data: allowance.abi_encode().into(),
        ..quote()
    };
    assert_rejected(&request(), &quote_below_provider, "below the minimum");
}

#[test]
fn rejects_allowance_holder_input_and_settler_mismatches() {
    let wrong_target = ZeroExSwapQuote {
        to: OTHER,
        ..quote()
    };
    assert_rejected(&request(), &wrong_target, "Unexpected AllowanceHolder");
    for (field, reason) in [
        (0, "Settler operator"),
        (1, "Settler target"),
        (2, "Input token"),
        (3, "Input amount"),
        (4, "Input amount"),
    ] {
        let mut allowance = allowance();
        match field {
            0 => {
                allowance.operator = OTHER;
            }
            1 => {
                allowance.target = OTHER;
            }
            2 => {
                allowance.token = OTHER;
            }
            3 => {
                allowance.amount = U256::from(99);
            }
            _ => {
                allowance.amount = U256::from(101);
            }
        }
        let quote = ZeroExSwapQuote {
            data: allowance.abi_encode().into(),
            ..quote()
        };
        assert_rejected(&request(), &quote, reason);
    }
}

#[test]
fn rejects_a_quote_that_redirects_output_or_changes_output_token() {
    for change_recipient in [true, false] {
        let mut settlement = settlement();
        let reason = if change_recipient {
            settlement.slippage.recipient = OTHER;
            "Output recipient"
        } else {
            settlement.slippage.buyToken = OTHER;
            "Output token"
        };
        let mut allowance = allowance();
        allowance.data = settlement.abi_encode().into();
        let quote = ZeroExSwapQuote {
            data: allowance.abi_encode().into(),
            ..quote()
        };
        assert_rejected(&request(), &quote, reason);
    }
}

#[test]
fn rejects_native_assets_and_value() {
    for native in [
        Address::ZERO,
        address!("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"),
    ] {
        for change_input in [true, false] {
            let mut request = request();
            if change_input {
                request.token_in = native;
            } else {
                request.token_out = native;
            }
            assert_rejected(&request, &quote(), "Only ERC-20");
        }
    }
    let with_value = ZeroExSwapQuote {
        value: U256::from(1),
        ..quote()
    };
    assert_rejected(&request(), &with_value, "Native value");
}

#[test]
fn rejects_zero_amounts_same_token_and_zero_wallet_or_settler() {
    let no_input = ZeroExSwapRequest {
        amount_in: U256::ZERO,
        ..request()
    };
    assert_rejected(&no_input, &quote(), "Input amount must be positive");
    let no_minimum = ZeroExSwapRequest {
        amount_out_min: U256::ZERO,
        ..request()
    };
    assert_rejected(&no_minimum, &quote(), "Minimum output must be positive");
    let same_token = ZeroExSwapRequest {
        token_out: TOKEN_IN,
        ..request()
    };
    assert_rejected(&same_token, &quote(), "Swap tokens must differ");
    let no_wallet = ZeroExSwapRequest {
        wallet_address: Address::ZERO,
        ..request()
    };
    assert_rejected(&no_wallet, &quote(), "Wallet must be nonzero");
    assert!(ZeroExSwap::new(&request(), &quote(), Address::ZERO)
        .unwrap_err()
        .to_string()
        .contains("Settler must be nonzero"));
}

#[test]
fn rejects_malformed_or_unsupported_outer_and_inner_calls() {
    for data in [
        Bytes::new(),
        Bytes::from_static(&[0x22, 0x13, 0xbc, 0x0b]),
        IAllowanceHolder::transferFromCall {
            token: TOKEN_IN,
            owner: WALLET,
            recipient: SETTLER,
            amount: U256::from(100),
        }
        .abi_encode()
        .into(),
    ] {
        assert_rejected(
            &request(),
            &ZeroExSwapQuote { data, ..quote() },
            "Invalid AllowanceHolder",
        );
    }
    for data in [
        Bytes::new(),
        Bytes::from_static(&[0x1f, 0xff, 0x99, 0x1f]),
        ISettlerTakerSubmitted::executeWithPermitCall {
            slippage: settlement().slippage,
            actions: settlement().actions,
            affiliate: settlement().affiliate,
            permitData: Bytes::new(),
        }
        .abi_encode()
        .into(),
    ] {
        let mut allowance = allowance();
        allowance.data = data;
        assert_rejected(
            &request(),
            &ZeroExSwapQuote {
                data: allowance.abi_encode().into(),
                ..quote()
            },
            "Invalid Settler",
        );
    }
}

#[test]
fn binds_preflight_sender_and_reserves_the_swap_nonce_type() {
    let swap = ZeroExSwap::new(&request(), &quote(), SETTLER).unwrap();
    let operation = swap.build_preflight_user_operation(WALLET, None).unwrap();
    assert_eq!(operation.sender, WALLET);
    assert_eq!(operation.call_data, swap.build_execute_user_op_call_data());
    let nonce = operation.nonce.to_be_bytes::<32>();
    assert_eq!(&nonce[..5], b"bdrck");
    assert_eq!(nonce[5], 143);
    assert_eq!(&nonce[6..17], &[0; 11]);
    assert_eq!(&nonce[24..], &[0; 8]);
    assert!(swap.build_preflight_user_operation(OTHER, None).is_err());
}
