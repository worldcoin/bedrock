import Foundation
import XCTest
@testable import Bedrock

final class BedrockSolMacroTests: XCTestCase {
    
    func testUnparsedTokenPermissionsCreation() throws {
        // Test creating an UnparsedTokenPermissions struct
        let unparsed = UnparsedTokenPermissions(
            token: "0x1234567890123456789012345678901234567890",
            amount: "1000000000000000000"  // 1 token with 18 decimals
        )
        
        XCTAssertEqual(unparsed.token, "0x1234567890123456789012345678901234567890")
        XCTAssertEqual(unparsed.amount, "1000000000000000000")
    }
    
    func testUnparsedPermitTransferFromWithNesting() throws {
        // Test creating nested structures
        let tokenPermissions = UnparsedTokenPermissions(
            token: "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // USDC address
            amount: "1000000"  // 1 USDC (6 decimals)
        )
        
        let permitTransferFrom = UnparsedPermitTransferFrom(
            permitted: tokenPermissions,
            spender: "0x0000000000000000000000000000000000000001",
            nonce: "0",
            deadline: "1735689600"  // Jan 1, 2025
        )
        
        XCTAssertEqual(permitTransferFrom.permitted.token, "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
        XCTAssertEqual(permitTransferFrom.permitted.amount, "1000000")
        XCTAssertEqual(permitTransferFrom.spender, "0x0000000000000000000000000000000000000001")
        XCTAssertEqual(permitTransferFrom.nonce, "0")
        XCTAssertEqual(permitTransferFrom.deadline, "1735689600")
    }
    
    func testSignPermit2TransferIntegration() throws {
        // Test that the unparsed types work with the signing function
        let safeAccount = try SafeSmartAccount(
            privateKey: "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583",
            walletAddress: "0x4564420674EA68fcc61b463C0494807C759d47e6"
        )
        
        let tokenPermissions = UnparsedTokenPermissions(
            token: "0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1",
            amount: "1000000000000000000"
        )
        
        let permitTransferFrom = UnparsedPermitTransferFrom(
            permitted: tokenPermissions,
            spender: "0x3f1480266afef1ba51834cfef0a5d61841d57572",
            nonce: "123",
            deadline: "1704067200"
        )
        
        // This should successfully sign the permit
        let signature = try safeAccount.signPermit2Transfer(
            chainId: 480,
            transfer: permitTransferFrom
        )
        
        // Verify we got a valid signature back (should be 65 bytes hex = 130 chars + 0x)
        XCTAssertEqual(signature.toHexString().count, 132)
        XCTAssertTrue(signature.toHexString().hasPrefix("0x"))
    }
} 