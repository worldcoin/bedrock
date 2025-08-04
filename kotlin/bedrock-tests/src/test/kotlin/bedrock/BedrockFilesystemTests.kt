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
    fun testFileSystemTesterListFiles() {
        val tester = FileSystemTester()
        
        // Write multiple files
        tester.testWriteFile("file1.txt", "content1")
        tester.testWriteFile("file2.txt", "content2")
        tester.testWriteFile("subdir/file3.txt", "content3")
        
        // List files in current directory
        val files = tester.testListFiles()
        assertTrue(files.contains("file1.txt"), "Should list file1.txt")
        assertTrue(files.contains("file2.txt"), "Should list file2.txt")
        // Note: subdir/file3.txt might not appear depending on how listFiles is implemented
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
    
    override fun listFiles(folderPath: String): List<String> {
        // Normalize the folder path by removing trailing "/." 
        val normalizedFolderPath = if (folderPath.endsWith("/.")) {
            folderPath.dropLast(2)
        } else {
            folderPath
        }
        
        // Return files that are in the specified folder
        return files.keys.filter { filePath ->
            // Files must start with the normalized folder path
            if (!filePath.startsWith("$normalizedFolderPath/")) {
                return@filter false
            }
            
            // Get the relative path within the folder
            val relativePath = filePath.removePrefix("$normalizedFolderPath/")
            
            // For the immediate directory, don't include files from subdirectories
            !relativePath.contains("/")
        }.map { filePath ->
            // Return just the filename 
            val relativePath = filePath.removePrefix("$normalizedFolderPath/")
            relativePath
        }
    }
} 