package bedrock

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.Pointer
import uniffi.bedrock.SmartAccountKeyManager
import uniffi.siegel_uniffi.SiegelSession

/**
 * JNA binding for `siegel_fill`, the only siegel API exposed as a raw
 * `extern "C"` symbol. The function lives in `libbedrock` because the
 * bedrock cdylib statically links `siegel-uniffi`.
 */
internal object SiegelNative {
    init {
        Native.register(SiegelNative::class.java, "bedrock")
    }

    @JvmStatic
    external fun siegel_fill(handle: Long, src: Pointer, len: Long): Int
}

/**
 * Test [SmartAccountKeyManager] that delivers a fixed hex-encoded private
 * key in a fresh [SiegelSession] on every call. Production foreign code
 * would fetch the secret from the platform key store (e.g. Keychain).
 *
 * For the empty-key test case we pad with a single zero byte so the
 * `SiegelSession::new` length check passes and the failure surfaces from
 * Rust as a `SafeSmartAccountException.KeyDecoding`.
 */
internal class TestKeyManager(private val hexKey: String) : SmartAccountKeyManager {
    override fun getEoaPrivateKey(): SiegelSession {
        val raw = hexKey.toByteArray(Charsets.US_ASCII)
        val bytes = if (raw.isEmpty()) byteArrayOf(0) else raw
        val session = SiegelSession(bytes.size.toUInt())
        val mem = Memory(bytes.size.toLong())
        mem.write(0, bytes, 0, bytes.size)
        val rc = SiegelNative.siegel_fill(session.handle().toLong(), mem, bytes.size.toLong())
        check(rc == 0) { "siegel_fill failed with code $rc" }
        return session
    }
}
