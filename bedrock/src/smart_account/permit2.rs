use alloy::{
    dyn_abi::{Eip712Domain, TypedData},
    primitives::{address, Address},
    sol_types::eip712_domain,
};

use crate::bedrock_sol;

/// Reference: <https://docs.uniswap.org/contracts/v4/deployments#worldchain-480>
pub static PERMIT2_ADDRESS: Address =
    address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

bedrock_sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L22>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct TokenPermissions {
        // ERC20 token address
        address token;
        // Amount of tokens which can be transferred
        uint256 amount;
    }

    /// The signed permit message for a single token transfer.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L30>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct PermitTransferFrom {
        /// The token and amount details for a transfer signed in the permit transfer signature
        TokenPermissions permitted;
        /// The address that is allowed to spend the tokens. Note this is not part of the `PermitTransferFrom` struct in the contract.
        /// This is however added in the contract from `msg.sender` to compute the hash.
        /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/libraries/PermitHash.sol#L62>
        address spender;
        /// A unique value for every token owner's signature to prevent replays
        uint256 nonce;
        /// Deadline (timestamp) after which the signature is no longer valid
        uint256 deadline;
    }
}

impl PermitTransferFrom {
    /// Converts the `PermitTransferFrom` struct into an EIP-712 `TypedData` struct with its relevant domain.
    #[must_use]
    pub fn as_typed_data(&self, chain_id: u32) -> TypedData {
        let domain: Eip712Domain = eip712_domain!(
            name: "Permit2",
            chain_id: chain_id.into(),
            verifying_contract: PERMIT2_ADDRESS,
        );

        TypedData::from_struct(self, Some(domain))
    }
}

#[cfg(test)]
mod tests {
    use alloy::primitives::{address, fixed_bytes};

    use super::*;
    use ruint::uint;

    #[test]
    fn test_permit2_typed_data_and_signing_hash() {
        let permitted = TokenPermissions {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U256),
        };

        let transfer_from = PermitTransferFrom {
            permitted,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            nonce: uint!(123_U256),
            deadline: uint!(1704067200_U256),
        };

        let typed_data = transfer_from
            .as_typed_data(480)
            .eip712_signing_hash()
            .unwrap();

        assert_eq!(
            typed_data,
            fixed_bytes!(
                "0x22c2b928cf818940122abf8f5e7e04158c38653b9a985006e295e90f32abd351"
            )
        );
    }
}
