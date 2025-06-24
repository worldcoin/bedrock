use alloy::{
    dyn_abi::{Eip712Domain, TypedData},
    primitives::{address, Address, U256},
    sol,
    sol_types::eip712_domain,
};

use crate::{
    primitives::ParseFromForeignBinding,
    smart_account::{Permit2TransferFrom, SafeSmartAccountError},
};

/// Reference: <https://docs.uniswap.org/contracts/v4/deployments#worldchain-480>
pub static PERMIT2_ADDRESS: Address =
    address!("0x000000000022d473030f116ddee9f6b43ac78ba3");

sol! {
    /// The token and amount details for a transfer signed in the permit transfer signature.
    ///
    /// This Solidity struct is constructed from a `Permit2TokenPermissions` coming from foreign code.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L22>
    #[derive(serde::Serialize)]
    struct TokenPermissions {
        address token;
        uint256 amount;
    }

    /// The signed permit message for a single token transfer.
    ///
    /// This Solidity struct is constructed from a `Permit2TransferFrom` coming from foreign code.
    ///
    /// Reference: <https://github.com/Uniswap/permit2/blob/cc56ad0f3439c502c246fc5cfcc3db92bb8b7219/src/interfaces/ISignatureTransfer.sol#L30>
    #[derive(serde::Serialize)]
    struct PermitTransferFrom {
        TokenPermissions permitted;
        address spender;
        uint256 nonce;
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

impl TryFrom<Permit2TransferFrom> for PermitTransferFrom {
    type Error = SafeSmartAccountError;

    fn try_from(value: Permit2TransferFrom) -> Result<Self, Self::Error> {
        let permitted = TokenPermissions {
            token: Address::parse_from_ffi(&value.permitted.token, "permitted.token")?,
            amount: U256::parse_from_ffi(&value.permitted.amount, "permitted.amount")?,
        };

        Ok(Self {
            permitted,
            spender: Address::parse_from_ffi(&value.spender, "spender")?,
            nonce: U256::parse_from_ffi(&value.nonce, "nonce")?,
            deadline: U256::parse_from_ffi(&value.deadline, "deadline")?,
        })
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
