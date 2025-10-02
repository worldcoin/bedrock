use crate::smart_account::{SafeSmartAccountError, GNOSIS_SAFE_4337_MODULE};
use alloy::primitives::{address, keccak256, Address, Bytes, U256};
use alloy::sol_types::{SolCall, SolValue};
use alloy::{hex, sol};
use std::str::FromStr;

static GNOSIS_SAFE_141_PROXY_FACTORY: Address =
    address!("0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67");

sol! {
    /// Setup method in Safe implementation
    ///
    /// Reference: <https://worldscan.org/address/0x29fcb43b46531bca003ddc8fcb67ffe91900c762#writeContract#F12>
    /// Reference: <https://github.com/safe-global/safe-smart-account/blob/v1.4.1/contracts/Safe.sol#L95>
    function setup(
        address[] calldata _owners,
        uint256 _threshold,
        address to,
        bytes calldata data,
        address fallbackHandler,
        address paymentToken,
        uint256 payment,
        address payable paymentReceiver
    );
}

/// Allows to compute the predicted wallet address from the EOA address **only for newly deployed Safe Smart Accounts**.
///
/// This function uses an algorithm that's specific for v1.4.1 Safe contracts. This function
/// should **NOT be used** for existing World App wallets as they may have been deployed with other
/// parameters. It's safer to rely on the on-chain/backend records for this.
///
/// Backend reference: <https://github.com/worldcoin/app-backend-main/blob/58c3debef35fb9b283a87c75fab023d6281a019f/src/users-wallets/users-wallets.service.ts#L423>
///
/// # Errors
/// * `SafeSmartAccountError::InvalidInput` - if the EOA address is invalid.
#[uniffi::export]
pub fn compute_wallet_address_for_fresh_account(
    eoa_address: &str,
) -> Result<String, SafeSmartAccountError> {
    let eoa_address = Address::from_str(eoa_address).map_err(|_| {
        SafeSmartAccountError::InvalidInput {
            attribute: "eoa_address".to_string(),
            message: "invalid EOA address".to_string(),
        }
    })?;

    let setup_calldata = setupCall {
        _owners: vec![eoa_address],
        _threshold: U256::from(1), // 1 of 1
        to: address!("0x2dd68b007B46fBe91B9A7c3EDa5A7a1063cB5b47"), // GNOSIS_SAFE_ADD_MODULES, utility contract to add multiple modules during initialization
        // Calldata to the GNOSIS_SAFE_ADD_MODULES, fetched from tenderly stack trace
        // https://dashboard.tenderly.co/tx/optimistic/0x933142ac7978d2c667613257591a11fc2b9980dd9915773cda536e430ca21c01?trace=0.5.0.2.1.2
        data: Bytes::from(hex!("0x8d0dc49f0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000100000000000000000000000075cf11467937ce3f2f357ce24ffc3dbf8fd5c226")),
        fallbackHandler: *GNOSIS_SAFE_4337_MODULE,
        paymentToken: Address::ZERO,
        payment: U256::ZERO,
        paymentReceiver: Address::ZERO,
    };
    let setup_calldata_hash = keccak256(setup_calldata.abi_encode());
    let encoded_nonce = U256::from(0).abi_encode();

    // The salt is the hash of the setup calldata and the nonce, which is always 0 for new users (this changed from a previous implementation)
    let mut salt_bytes = vec![];
    salt_bytes.extend_from_slice(setup_calldata_hash.as_slice());
    salt_bytes.extend_from_slice(&encoded_nonce);
    let salt = keccak256(&salt_bytes);

    // Hash of the init code for the wallet contract. Computed in Javascript:
    // const gnosisSafeProxyFactoryContractAddress = '0x4e1dcf7ad4e460cfd30791ccc4f9c8a4f820ec67';
    // const gnosisSafeProxyFactoryContract = new TypedContract(
    //     gnosisSafeProxyFactoryContractAddress,
    //     GNOSIS_SAFE_PROXY_FACTORY_ABI,
    //     provider,
    // );
    // const proxyCreationCode = await gnosisSafeProxyFactoryContract.read(
    //     'proxyCreationCode',
    //     [],
    // );
    // const constructorData = abi.rawEncode(
    //     ['address'],
    //     ['0x29fcb43b46531bca003ddc8fcb67ffe91900c762'], // GNOSIS_SAFE_141, Safe 1.4.1 implementation
    // );
    // const initCodeHash = ethUtil.keccak(
    //     Buffer.from([
    //         ...Buffer.from(proxyCreationCode.replace('0x', ''), 'hex'),
    //         ...constructorData,
    //     ]),
    // );
    let init_code_hash =
        hex!("e298282cefe913ab5d282047161268a8222e4bd4ed106300c547894bbefd31ee");

    let wallet_address = GNOSIS_SAFE_141_PROXY_FACTORY.create2(salt, init_code_hash);
    Ok(wallet_address.to_string().to_lowercase())
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn test_compute_wallet_address() {
        assert_eq!(
            compute_wallet_address_for_fresh_account(
                "0x521abb206fb9969aa9382b68aa578769420e95fc"
            )
            .unwrap(),
            "0xea51b7e5c07bb29237194aa14618057333435f3e"
        );
        assert_eq!(
            compute_wallet_address_for_fresh_account(
                "0xd36e6a37f6364b6e15b1f81df0211c041ade0f69"
            )
            .unwrap(),
            "0x4c47e3c637a2877afa3d051594ab06b156cc8115"
        );
        assert_eq!(
            compute_wallet_address_for_fresh_account(
                "0xa4eb68ce21c862f42e26ff31bb8351bf87f2c41a"
            )
            .unwrap(),
            "0xd462bac17966fd7a9ee76b55191a6083edf6f80b"
        );
    }
}
