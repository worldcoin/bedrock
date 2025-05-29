package bedrock

import kotlin.test.*
import uniffi.bedrock.SafeSmartAccount
import uniffi.bedrock.SafeSmartAccountException

class BedrockTests {
    private val testPrivateKey = "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80"
    private val testWalletAddress = "0x4564420674EA68fcc61b463C0494807C759d47e6"
    private val chainId: UInt = 10u // Optimism

    // No explicit library preload is necessary: UniFFI-generated bindings
    // load the native `bedrock` library on first access.

    @Test
    fun testSafeSmartAccountCreation() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        assertNotNull(account)
    }

    @Test
    fun testPersonalSign() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        val message = "Hello from Bedrock!"
        val signature = account.personalSign(chainId, message)

        assertTrue(signature.isNotEmpty(), "Signature should not be empty")
        assertTrue(signature.startsWith("0x"), "Signature should start with 0x")
        assertEquals(132, signature.length, "Signature should be 132 characters long")
    }

    @Test
    fun testMultipleMessages() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        val messages = listOf(
            "Message 1",
            "Another test message",
            "Special characters: !@#\$%^&*()",
            "Numbers: 1234567890",
            "Empty string test: "
        )

        for (msg in messages) {
            val sig = account.personalSign(chainId, msg)
            assertTrue(sig.isNotEmpty(), "Signature for '$msg' should not be empty")
            assertEquals(132, sig.length, "Signature for '$msg' should be 132 characters")
        }
    }

    @Test
    fun testInvalidPrivateKey() {
        assertFailsWith<SafeSmartAccountException> {
            SafeSmartAccount("invalid_key", testWalletAddress)
        }
    }

    @Test
    fun testEmptyPrivateKey() {
        assertFailsWith<SafeSmartAccountException> {
            SafeSmartAccount("", testWalletAddress)
        }
    }

    @Test
    fun testInvalidWalletAddress() {
        assertFailsWith<SafeSmartAccountException> {
            SafeSmartAccount(testPrivateKey, "invalid_address")
        }
    }

    @Test
    fun testDifferentChainIds() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        val chainIds = listOf(1u, 10u, 137u, 42161u)
        val message = "Testing different chains"
        val signatures = mutableSetOf<String>()

        for (cid in chainIds) {
            val sig = account.personalSign(cid, message)
            assertTrue(sig.isNotEmpty(), "Signature for chain $cid should not be empty")
            assertEquals(132, sig.length, "Signature for chain $cid should be 132 characters")
            assertTrue(signatures.add(sig), "Signature for chain $cid should be unique")
        }
    }

    @Test
    fun testLongMessage() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        val longMsg = "Lorem ipsum dolor sit amet. ".repeat(100)
        val sig = account.personalSign(chainId, longMsg)
        assertTrue(sig.isNotEmpty(), "Signature for long message should not be empty")
        assertEquals(132, sig.length, "Signature for long message should be 132 characters")
    }

    @Test
    fun testUnicodeMessage() {
        val account = SafeSmartAccount(testPrivateKey, testWalletAddress)
        val unicodeMsg = "Hello 世界 🌍 Здравствуй мир"
        val sig = account.personalSign(chainId, unicodeMsg)
        assertTrue(sig.isNotEmpty(), "Signature for unicode message should not be empty")
        assertEquals(132, sig.length, "Signature for unicode message should be 132 characters")
    }
} 