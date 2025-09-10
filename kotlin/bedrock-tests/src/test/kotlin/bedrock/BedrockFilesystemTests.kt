package bedrock

import uniffi.bedrock.FileSystem
import uniffi.bedrock.FileSystemException
import uniffi.bedrock.FileSystemTester
import uniffi.bedrock.setFilesystem
import org.junit.Before
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class BedrockFilesystemTests {
    
    @Before
    fun setUp() {
        // Set up filesystem before each test
        setFilesystem(MockFileSystemBridge)
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
        
        // Test writing to subdirectories
        tester.testWriteFile("configs/app.json", "{\"theme\": \"dark\"}")
        
        // Read from subdirectory
        val readContent = tester.testReadFile("configs/app.json")
        assertEquals("{\"theme\": \"dark\"}", readContent, "Content in subdirectory should match")
    }
}

/// Mock filesystem implementation for testing
object MockFileSystemBridge : FileSystem {
    private val files = mutableMapOf<String, ByteArray>()
    
    override fun fileExists(filePath: String): Boolean {
        return files.containsKey(filePath)
    }
    
    override fun readFile(filePath: String): ByteArray {
        return files[filePath] ?: throw FileSystemException.FileDoesNotExist()
    }
    
    override fun writeFile(filePath: String, fileBuffer: ByteArray) {
        // Create any necessary parent directories in our mock
        files[filePath] = fileBuffer
    }
    
    override fun deleteFile(filePath: String) {
        files.remove(filePath)
    }
    
    override fun listFilesAtDirectory(folderPath: String): List<String> {
        var base = folderPath
        if (base.endsWith("/.")) base = base.dropLast(2)
        if (base.endsWith("/")) base = base.dropLast(1)
        
        // Root listing when base == "" or "." → only files without "/" (immediate children of root)
        if (base.isEmpty() || base == ".") {
            return files.keys
                .filter { !it.contains("/") }
                .sorted()
        }
        
        val prefix = "$base/"
        
        return files.keys
            .filter { it.startsWith(prefix) }
            .mapNotNull { path ->
                val rest = path.removePrefix(prefix)
                if (rest.isNotEmpty() && !rest.contains("/")) rest else null
            }
            .sorted()
    }

    override fun readFileRange(filePath: String, offset: ULong, maxLength: ULong): ByteArray {
        val data = files[filePath] ?: throw FileSystemException.FileDoesNotExist()
        val dataSize = data.size.toULong()

        val startULong = if (offset > dataSize) dataSize else offset
        val remaining = dataSize - startULong
        val lengthULong = if (maxLength > remaining) remaining else maxLength

        val start = startULong.toInt()
        val end = (startULong + lengthULong).toInt()
        return data.copyOfRange(start, end)
    }
} 