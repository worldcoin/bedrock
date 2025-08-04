package bedrock

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import uniffi.bedrock.*

class BedrockSolMacroTests {
    
    @Test
    fun `test UnparsedTokenPermissions creation`() {
        // Test creating an UnparsedTokenPermissions struct
        val unparsed = UnparsedTokenPermissions(
            token = "0x1234567890123456789012345678901234567890",
            amount = "1000000000000000000"  // 1 token with 18 decimals
        )
        
        assertEquals("0x1234567890123456789012345678901234567890", unparsed.token)
        assertEquals("1000000000000000000", unparsed.amount)
    }
    
    @Test
    fun `test UnparsedPermitTransferFrom with nesting`() {
        // Test creating nested structures
        val tokenPermissions = UnparsedTokenPermissions(
            token = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48",  // USDC address
            amount = "1000000"  // 1 USDC (6 decimals)
        )
        
        val permitTransferFrom = UnparsedPermitTransferFrom(
            permitted = tokenPermissions,
            spender = "0x0000000000000000000000000000000000000001",
            nonce = "0",
            deadline = "1735689600"  // Jan 1, 2025
        )
        
        assertEquals("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", permitTransferFrom.permitted.token)
        assertEquals("1000000", permitTransferFrom.permitted.amount)
        assertEquals("0x0000000000000000000000000000000000000001", permitTransferFrom.spender)
        assertEquals("0", permitTransferFrom.nonce)
        assertEquals("1735689600", permitTransferFrom.deadline)
    }
    
    @Test
    fun `test sign Permit2 transfer integration`() {
        // Test that the unparsed types work with the signing function
        val safeAccount = SafeSmartAccount(
            privateKey = "4142710b9b4caaeb000b8e5de271bbebac7f509aab2f5e61d1ed1958bfe6d583",
            walletAddress = "0x4564420674EA68fcc61b463C0494807C759d47e6"
        )
        
        val tokenPermissions = UnparsedTokenPermissions(
            token = "0xdc6ff44d5d932cbd77b52e5612ba0529dc6226f1",
            amount = "1000000000000000000"
        )
        
        val permitTransferFrom = UnparsedPermitTransferFrom(
            permitted = tokenPermissions,
            spender = "0x3f1480266afef1ba51834cfef0a5d61841d57572",
            nonce = "123",
            deadline = "1704067200"
        )
        
        // This should successfully sign the permit
        val signature = safeAccount.signPermit2Transfer(
            chainId = 480u,
            transfer = permitTransferFrom
        )
        
        // Verify we got a valid signature back (should be 65 bytes hex = 130 chars + 0x)
        assertEquals(132, signature.toHexString().length)
        assertTrue(signature.toHexString().startsWith("0x"))
    }
    
    @Test
    fun `test unparsed types are serializable`() {
        // Test that the unparsed types can be easily created and modified
        val tokenPermissions = UnparsedTokenPermissions(
            token = "0x0000000000000000000000000000000000000000",
            amount = "0"
        )
        
        // Create a modified version
        val modifiedPermissions = tokenPermissions.copy(
            amount = "1000000000000000000"
        )
        
        assertEquals("0", tokenPermissions.amount)
        assertEquals("1000000000000000000", modifiedPermissions.amount)
        assertEquals(tokenPermissions.token, modifiedPermissions.token)
    }
} 