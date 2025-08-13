//! NonceKey v1 helpers for 4337 UserOperation nonces (RIP-7712 style).
//!
//! Layout (24-byte nonceKey + 8-byte sequence):
//! [0]        : typeId (1 byte)
//! [1..=5]    : magic "bdrck" (5 bytes)
//! [6]        : instruction flags (1 byte) - LSB is privacy flag
//! [7..=16]   : subtype (10 bytes) - type-specific metadata
//! [17..=23]  : random tail (7 bytes)
//! [24..=31]  : sequence (8 bytes) - usually 0 for WA crafted txs

use alloy::primitives::{keccak256, Address};

/// Stable, never-reordered identifiers for transaction classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum TransactionTypeId {
    /// ERC-20 transfer
    Transfer = 1,
}

impl TransactionTypeId {
    /// Returns the numeric id for this transaction type.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Instruction flags carried in the nonceKey.
/// Bit 0 (LSB): privacy flag; Bits 1–7: reserved (must be 0).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InstructionFlags(u8);

impl InstructionFlags {
    /// Creates an `InstructionFlags` with the given privacy bit.
    #[inline]
    #[must_use]
    pub const fn new(privacy: bool) -> Self {
        let mut v = 0u8;
        if privacy {
            v |= 0x01;
        }
        Self(v)
    }

    /// Returns the underlying byte value for the flags.
    #[inline]
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self.0
    }
}

/// Concrete v1 nonceKey builder with explicit fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NonceKeyV1 {
    /// Stable transaction class id.
    pub type_id: TransactionTypeId,
    /// Instruction flags bitfield (LSB = privacy flag).
    pub instruction: InstructionFlags,
    /// Type-specific metadata for indexers (10 bytes).
    pub subtype: [u8; 10],
    /// Random tail to reduce accidental collisions (7 bytes, 56 bits).
    pub random_tail: [u8; 7],
}

impl NonceKeyV1 {
    /// Builds a new v1 nonceKey with a random 7-byte tail.
    #[must_use]
    pub fn new(
        type_id: TransactionTypeId,
        instruction: InstructionFlags,
        subtype: [u8; 10],
    ) -> Self {
        // Generate 7 bytes of entropy using a random u64 and dropping the MSB.
        let rand_u64: u64 = rand::random();
        let bytes = rand_u64.to_be_bytes();
        let mut tail = [0u8; 7];
        tail.copy_from_slice(&bytes[1..8]);
        Self {
            type_id,
            instruction,
            subtype,
            random_tail: tail,
        }
    }

    /// Test/advanced constructor allowing explicit random tail specification.
    #[must_use]
    pub const fn with_random_tail(
        type_id: TransactionTypeId,
        instruction: InstructionFlags,
        subtype: [u8; 10],
        random_tail: [u8; 7],
    ) -> Self {
        Self {
            type_id,
            instruction,
            subtype,
            random_tail,
        }
    }

    /// Serialize into the 24-byte nonceKey v1 layout.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; 24] {
        let mut out = [0u8; 24];
        // [0] typeId
        out[0] = self.type_id.as_u8();
        // [1..=5] magic = "bdrck"
        out[1..=5].copy_from_slice(b"bdrck");
        // [6] instruction flags
        out[6] = self.instruction.as_u8();
        // [7..=16] subtype (10 bytes)
        out[7..=16].copy_from_slice(&self.subtype);
        // [17..=23] random tail (7 bytes)
        out[17..=23].copy_from_slice(&self.random_tail);
        out
    }
}

/// Encode the 24-byte nonceKey and 8-byte sequence into a U256 big-endian integer.
#[must_use]
#[allow(clippy::missing_const_for_fn)]
pub fn encode_nonce_v1(nonce_key: [u8; 24], sequence: u64) -> ruint::aliases::U256 {
    let mut be = [0u8; 32];
    be[..24].copy_from_slice(&nonce_key);
    be[24..].copy_from_slice(&sequence.to_be_bytes());
    ruint::aliases::U256::from_be_bytes(be)
}

/// Subtype derivation for ERC-20 transfers: first 10 bytes of keccak256(token || to)
#[must_use]
pub fn derive_subtype_erc20_transfer(token: Address, to: Address) -> [u8; 10] {
    let mut preimage = [0u8; 40];
    preimage[0..20].copy_from_slice(token.as_slice());
    preimage[20..40].copy_from_slice(to.as_slice());
    let hash = keccak256(preimage);
    let mut out = [0u8; 10];
    out.copy_from_slice(&hash[0..10]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn test_nonce_key_v1_layout() {
        let subtype = [0x11u8; 10];
        let random_tail = [0x22u8; 7];
        let key = NonceKeyV1::with_random_tail(
            TransactionTypeId::Transfer,
            InstructionFlags::new(false),
            subtype,
            random_tail,
        );
        let bytes = key.to_bytes();

        // typeId
        assert_eq!(bytes[0], TransactionTypeId::Transfer.as_u8());
        // magic
        assert_eq!(&bytes[1..=5], &[0x62, 0x64, 0x72, 0x63, 0x6b]);
        // instruction
        assert_eq!(bytes[6], 0);
        // subtype
        assert_eq!(&bytes[7..=16], &subtype);
        // random tail
        assert_eq!(&bytes[17..=23], &random_tail);
    }

    #[test]
    fn test_encode_nonce_v1_sequence_zero() {
        let key = NonceKeyV1::with_random_tail(
            TransactionTypeId::Transfer,
            InstructionFlags::default(),
            [0u8; 10],
            [0u8; 7],
        )
        .to_bytes();
        let nonce = encode_nonce_v1(key, 0);
        let lower_64 = nonce & ruint::aliases::U256::from(u64::MAX);
        assert!(lower_64.is_zero(), "sequence must be zero");
    }

    #[test]
    fn test_derive_subtype_erc20_transfer() {
        let token =
            Address::from_str("0x2cFc85d8E48F8EAB294be644d9E25C3030863003").unwrap();
        let to =
            Address::from_str("0x1234567890123456789012345678901234567890").unwrap();
        let subtype = derive_subtype_erc20_transfer(token, to);
        // Sanity: deterministic and 10 bytes
        assert_eq!(subtype.len(), 10);
        // Check expected prefix against a locally recomputed value
        let mut preimage = [0u8; 40];
        preimage[0..20].copy_from_slice(token.as_slice());
        preimage[20..40].copy_from_slice(to.as_slice());
        let expected = keccak256(preimage);
        assert_eq!(&subtype, &expected[0..10]);
    }
}
