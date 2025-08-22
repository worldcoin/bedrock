// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title NonceV1Checker
/// @notice Decode helpers for Bedrock's v1 nonce layout (no on-chain encoding).
/// Layout (24-byte nonceKey + 8-byte sequence), big-endian within uint256:
/// [0..=4]    : magic "bdrck" or "pbhtx" (5 bytes)
/// [5]        : typeId (1 byte)
/// [6]        : instruction flags (1 byte)
/// [7..=16]   : metadata/subtype (10 bytes)
/// [17..=23]  : random tail (7 bytes)
/// [24..=31]  : sequence (8 bytes)
contract NonceV1Checker {
    bytes5 internal constant BEDROCK_NONCE_PREFIX_CONST = bytes5(0x626472636b);
    bytes5 internal constant PBH_NONCE_PREFIX_CONST = bytes5(0x7062687478);

    error InvalidNoncePrefix();

    function decodeTypeId(uint256 nonce) public pure returns (uint8) {
        return uint8((nonce >> 208) & 0xff);
    }

    function decodeMagic(uint256 nonce) public pure returns (bytes5) {
        return bytes5(uint40(nonce >> 216));
    }

    function decodeInstruction(uint256 nonce) public pure returns (uint8) {
        return uint8((nonce >> 200) & 0xff);
    }

    function decodeMetadata(uint256 nonce) public pure returns (bytes10) {
        return bytes10(uint80((nonce >> 120) & ((uint256(1) << 80) - 1)));
    }

    function decodeRandomTail(uint256 nonce) public pure returns (bytes7) {
        return bytes7(uint56((nonce >> 64) & ((uint256(1) << 56) - 1)));
    }

    function decodeSequence(uint256 nonce) public pure returns (uint64) {
        return uint64(nonce & ((uint256(1) << 64) - 1));
    }

    function decodeAll(
        uint256 nonce
    )
        external
        pure
        returns (
            bytes5 magic,
            uint8 typeId,
            uint8 instruction,
            bytes10 metadata,
            bytes7 randomTail,
            uint64 sequence
        )
    {
        magic = decodeMagic(nonce);

        if (magic != BEDROCK_NONCE_PREFIX_CONST && magic != PBH_NONCE_PREFIX_CONST)
            revert InvalidNoncePrefix();

        typeId = decodeTypeId(nonce);
        instruction = decodeInstruction(nonce);
        metadata = decodeMetadata(nonce);
        randomTail = decodeRandomTail(nonce);
        sequence = decodeSequence(nonce);
    }
}
