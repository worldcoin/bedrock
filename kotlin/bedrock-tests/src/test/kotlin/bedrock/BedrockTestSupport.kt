package bedrock

import java.nio.file.Files

/**
 * Shared Bedrock initialization for the test suites.
 *
 * `setConfig` is a one-shot global that refuses every call after the first, so this
 * helper is what makes it safe to call from each suite's `setUp`.
 */
object BedrockTestSupport {
    /** Root directory Bedrock writes to during the test run. Recreated per process. */
    val dataDirectory: String by lazy {
        val root = Files.createTempDirectory("bedrock-tests").toFile()
        Runtime.getRuntime().addShutdownHook(Thread { root.deleteRecursively() })
        root.absolutePath
    }

    /**
     * Initializes the global Bedrock config, if it isn't already.
     *
     * A second `setConfig` throws, and this runs before every test, so the guard is what
     * keeps every test after the first from failing in `setUp`.
     */
    fun setUp() {
        if (uniffi.bedrock.isInitialized()) return

        uniffi.bedrock.setConfig(
            uniffi.bedrock.BedrockEnvironment.STAGING,
            uniffi.bedrock.Os.ANDROID,
            dataDirectory,
        )
    }
}
