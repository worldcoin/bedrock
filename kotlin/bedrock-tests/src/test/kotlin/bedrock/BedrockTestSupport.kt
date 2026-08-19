package bedrock

import java.nio.file.Files

/**
 * Shared Bedrock initialization for the test suites.
 *
 * `setConfig` is a one-shot global, so every suite must go through this helper: the
 * first caller wins and all of them need a usable root path for file operations.
 */
object BedrockTestSupport {
    /** Root directory Bedrock writes to during the test run. Recreated per process. */
    val rootPath: String by lazy {
        val root = Files.createTempDirectory("bedrock-tests").toFile()
        Runtime.getRuntime().addShutdownHook(Thread { root.deleteRecursively() })
        root.absolutePath
    }

    /** Initializes the global Bedrock config, if it isn't already. */
    fun setUp() {
        uniffi.bedrock.setConfig(
            uniffi.bedrock.BedrockEnvironment.STAGING,
            uniffi.bedrock.Os.ANDROID,
            rootPath,
        )
    }
}
