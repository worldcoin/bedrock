package bedrock

import uniffi.bedrock.FileSystemException
import uniffi.bedrock.FileSystemTestException
import uniffi.bedrock.FileSystemTester
import org.junit.Before
import java.io.File
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class BedrockFilesystemTests {

    @Before
    fun setUp() {
        // Bedrock resolves every path against the root supplied through the config.
        BedrockTestSupport.setUp()
    }

    @Test
    fun testFileSystemTesterWriteAndRead() {
        val tester = FileSystemTester()

        // Test writing a file
        tester.testWriteFile("test.txt", "Hello, World!")

        // Test reading the file back
        val readContent = tester.testReadFile("test.txt")
        assertEquals("Hello, World!", readContent, "Read content should match written content")
    }

    @Test
    fun testFileSystemTesterFileExists() {
        val tester = FileSystemTester()

        // Write a file
        tester.testWriteFile("exists.txt", "content")

        // Test file exists
        val exists = tester.testFileExists("exists.txt")
        assertTrue(exists, "File should exist after writing")

        // Test non-existent file
        val notExists = tester.testFileExists("nonexistent.txt")
        assertFalse(notExists, "Non-existent file should not exist")
    }

    @Test
    fun testFileSystemTesterListFilesAtDirectory() {
        val tester = FileSystemTester()

        // Write multiple files
        tester.testWriteFile("file1.txt", "content1")
        tester.testWriteFile("file2.txt", "content2")
        tester.testWriteFile("subdir/file3.txt", "content3")

        // List files in current directory
        val files = tester.testListFilesAtDirectory()
        assertTrue(files.contains("file1.txt"), "Should list file1.txt")
        assertTrue(files.contains("file2.txt"), "Should list file2.txt")
        assertFalse(files.contains("file3.txt"), "Should not list subdir/file3.txt")
        assertFalse(files.contains("subdir"), "Should not list sub-directories")
    }

    @Test
    fun testFileSystemTesterDeleteFile() {
        val tester = FileSystemTester()

        // Write a file
        tester.testWriteFile("delete_me.txt", "temporary content")

        // Verify it exists
        val existsBefore = tester.testFileExists("delete_me.txt")
        assertTrue(existsBefore, "File should exist before deletion")

        // Delete the file
        tester.testDeleteFile("delete_me.txt")

        // Verify it's deleted
        val existsAfter = tester.testFileExists("delete_me.txt")
        assertFalse(existsAfter, "File should not exist after deletion")
    }

    @Test
    fun testFileSystemTesterReadMissingFile() {
        val tester = FileSystemTester()

        val error = assertFailsWith<FileSystemTestException.FileSystem> {
            tester.testReadFile("never_written.txt")
        }
        assertIs<FileSystemException.FileDoesNotExist>(error.v1)
    }

    @Test
    fun testFileSystemTesterRejectsPathTraversal() {
        val tester = FileSystemTester()

        val error = assertFailsWith<FileSystemTestException.FileSystem> {
            tester.testWriteFile("../escaped.txt", "nope")
        }
        assertIs<FileSystemException.InvalidPath>(error.v1)
    }

    @Test
    fun testFileSystemTesterBinaryData() {
        val tester = FileSystemTester()

        // Test with binary data (using UTF-8 encoded emoji)
        val binaryContent = "Hello 🌍 World! 🚀"

        // Write binary content
        tester.testWriteFile("binary.txt", binaryContent)

        // Read it back
        val readContent = tester.testReadFile("binary.txt")
        assertEquals(binaryContent, readContent, "Binary content should match")
    }

    @Test
    fun testFileSystemTesterSubdirectories() {
        val tester = FileSystemTester()

        // Test writing to subdirectories, parent directories are created on demand
        tester.testWriteFile("configs/app.json", "{\"theme\": \"dark\"}")

        // Read from subdirectory
        val readContent = tester.testReadFile("configs/app.json")
        assertEquals("{\"theme\": \"dark\"}", readContent, "Content in subdirectory should match")
    }

    /**
     * Every `setConfig` after the first is refused, so a stray initializer naming a
     * different root cannot leave Bedrock reading one directory while the caller
     * believes it writes to another.
     *
     * Rejection of a *relative* root can only be observed in a process where nothing has
     * configured Bedrock yet, which the Rust suite covers.
     */
    @Test
    fun testSetConfigRefusesDuplicateInitialization() {
        val other = File(System.getProperty("java.io.tmpdir"), "bedrock-some-other-root")
        other.deleteRecursively()

        assertFailsWith<uniffi.bedrock.PrimitiveException.Generic> {
            uniffi.bedrock.setConfig(
                uniffi.bedrock.BedrockEnvironment.STAGING,
                uniffi.bedrock.Os.ANDROID,
                other.absolutePath,
            )
        }

        // The committed root still works, and the refused one was never created.
        assertFalse(other.exists())
        val tester = FileSystemTester()
        tester.testWriteFile("after_rejection.txt", "ok")
        assertEquals("ok", tester.testReadFile("after_rejection.txt"))
    }

    @Test
    fun testFilesAreScopedUnderTheConfiguredRoot() {
        val tester = FileSystemTester()
        tester.testWriteFile("scoped.txt", "on disk")

        // `FileSystemTester` is exported through `bedrock_export`, so its files land under
        // the snake_case struct name inside the root the app handed to `setConfig`.
        val expected = File(BedrockTestSupport.rootPath, "file_system_tester/scoped.txt")

        assertEquals(
            "on disk",
            expected.readText(),
            "Bedrock should write through to the real filesystem",
        )
    }
}
