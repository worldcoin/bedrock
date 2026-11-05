package bedrock

import java.nio.ByteBuffer
import java.time.Instant
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import uniffi.bedrock.DeviceProofException
import uniffi.bedrock.RootKey

class BedrockDeviceProofTests {
    @Test
    fun restoredRootSignsOnlyTrustedDeviceChallenges() {
        val root = RootKey.fromJson("""{"version":"V1","key":"${"11".repeat(32)}"}""")
        val challenge = """{"version":1,"issuer":"https://auth.world.org","ceremony_id":"019af784-3d00-7000-8000-000000000001","nonce":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","expires_at":${Instant.now().epochSecond + 300}}""".toByteArray()
        val buffer = ByteBuffer.allocateDirect(challenge.size).apply { put(challenge); flip() }
        val proof = root.createWorldIdDeviceProof(buffer, "https://auth.world.org")
        assertEquals("A78Nb3lXB_knP6aCAH-jz__oN54VcvsG8pPSq4Nb1JNI", proof.publicKey)
        assertTrue(proof.signature.isNotEmpty())
        assertFailsWith<DeviceProofException.InvalidChallenge> {
            root.createWorldIdDeviceProof(buffer, "https://foreign.example")
        }
    }
}
