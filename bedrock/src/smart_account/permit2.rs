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

bedrock_sol! {
    /// The approval details for a single token allowance.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/IAllowanceTransfer.sol#L41>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct PermitDetails {
        // ERC20 token address
        address token;
        // Maximum amount allowed to transfer
        uint160 amount;
        // Timestamp at which the allowance expires
        uint48 expiration;
        // An incrementing value indexed per owner, token, and spender for each signature
        uint48 nonce;
    }

    /// The permit message for a single token allowance.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/IAllowanceTransfer.sol#L51>
    #[derive(serde::Serialize)]
    #[unparsed]
    struct PermitSingle {
        // The permit data for a single token allowance
        PermitDetails details;
        // Address permissioned on the allowed tokens
        address spender;
        // Deadline on the permit signature
        uint256 sigDeadline;
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

impl PermitSingle {
    /// Converts the `PermitSingle` struct into an EIP-712 `TypedData` struct with its relevant domain.
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
    use super::*;
    use crate::primitives::Network;
    use alloy::primitives::{fixed_bytes, uint};

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
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash()
            .unwrap();

        assert_eq!(
            typed_data,
            fixed_bytes!(
                "0x22c2b928cf818940122abf8f5e7e04158c38653b9a985006e295e90f32abd351"
            )
        );
    }

    #[test]
    fn test_permit2_allowance_typed_data_produces_valid_hash() {
        let details = PermitDetails {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U160),
            expiration: uint!(1704067200_U48),
            nonce: uint!(0_U48),
        };

        let permit_single = PermitSingle {
            details,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            sigDeadline: uint!(1704067200_U256),
        };

        let signing_hash = permit_single
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash();

        // Verify the hash can be computed without error
        assert!(signing_hash.is_ok());
        // The hash should be 32 bytes (B256)
        let hash = signing_hash.unwrap();
        assert_ne!(
            hash,
            fixed_bytes!(
                "0x0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
    }

    #[test]
    fn test_permit2_allowance_typed_data_is_deterministic() {
        let make_permit_single = || {
            let details = PermitDetails {
                token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
                amount: uint!(500000000000000000_U160),
                expiration: uint!(1704153600_U48),
                nonce: uint!(1_U48),
            };

            PermitSingle {
                details,
                spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
                sigDeadline: uint!(1704067200_U256),
            }
        };

        let hash1 = make_permit_single()
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash()
            .unwrap();

        let hash2 = make_permit_single()
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash()
            .unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_permit2_allowance_different_chain_id_produces_different_hash() {
        let details = PermitDetails {
            token: address!("0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1"),
            amount: uint!(1000000000000000000_U160),
            expiration: uint!(1704067200_U48),
            nonce: uint!(0_U48),
        };

        let permit_single = PermitSingle {
            details,
            spender: address!("0x3f1480266afef1ba51834cfef0a5d61841d57572"),
            sigDeadline: uint!(1704067200_U256),
        };

        let hash_worldchain = permit_single
            .as_typed_data(Network::WorldChain as u32)
            .eip712_signing_hash()
            .unwrap();

        let hash_ethereum = permit_single
            .as_typed_data(Network::Ethereum as u32)
            .eip712_signing_hash()
            .unwrap();

        assert_ne!(hash_worldchain, hash_ethereum);
    }
}
