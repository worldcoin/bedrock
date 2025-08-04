import XCTest
import Foundation
@testable import Bedrock

final class BedrockFilesystemTests: XCTestCase {
    
    override func setUpWithError() throws {
        // Set up filesystem before each test
        Bedrock.setFilesystem(filesystem: MockFileSystemBridge.shared)
    }
    
    func testFileSystemTesterWriteAndRead() throws {
        let tester = FileSystemTester()
        
        // Test writing a file
        let writeResult = try tester.testWriteFile(filename: "test.txt", content: "Hello, World!")
        XCTAssertTrue(writeResult, "Write operation should succeed")
        
        // Test reading the file back
        let readContent = try tester.testReadFile(filename: "test.txt")
        XCTAssertEqual(readContent, "Hello, World!", "Read content should match written content")
    }
    
    func testFileSystemTesterFileExists() throws {
        let tester = FileSystemTester()
        
        // Write a file
        let writeResult = try tester.testWriteFile(filename: "exists.txt", content: "content")
        XCTAssertTrue(writeResult, "Write operation should succeed")
        
        // Test file exists
        let exists = try tester.testFileExists(filename: "exists.txt")
        XCTAssertTrue(exists, "File should exist after writing")
        
        // Test non-existent file
        let notExists = try tester.testFileExists(filename: "nonexistent.txt")
        XCTAssertFalse(notExists, "Non-existent file should not exist")
    }
    

    
    func testFileSystemTesterListFiles() throws {
        let tester = FileSystemTester()
        
        // Write multiple files
        _ = try tester.testWriteFile(filename: "file1.txt", content: "content1")
        _ = try tester.testWriteFile(filename: "file2.txt", content: "content2")
        _ = try tester.testWriteFile(filename: "subdir/file3.txt", content: "content3")
        
        // List files in current directory
        let files = try tester.testListFiles()
        XCTAssertTrue(files.contains("file1.txt"), "Should list file1.txt")
        XCTAssertTrue(files.contains("file2.txt"), "Should list file2.txt")
        // Note: subdir/file3.txt might not appear depending on how listFiles is implemented
    }
    
    func testFileSystemTesterDeleteFile() throws {
        let tester = FileSystemTester()
        
        // Write a file
        _ = try tester.testWriteFile(filename: "delete_me.txt", content: "temporary content")
        
        // Verify it exists
        let existsBefore = try tester.testFileExists(filename: "delete_me.txt")
        XCTAssertTrue(existsBefore, "File should exist before deletion")
        
        // Delete the file
        let deleteResult = try tester.testDeleteFile(filename: "delete_me.txt")
        XCTAssertTrue(deleteResult, "Delete operation should succeed")
        
        // Verify it's deleted
        let existsAfter = try tester.testFileExists(filename: "delete_me.txt")
        XCTAssertFalse(existsAfter, "File should not exist after deletion")
    }
    
    func testFileSystemTesterBinaryData() throws {
        let tester = FileSystemTester()
        
        // Test with binary data (using UTF-8 encoded emoji)
        let binaryContent = "Hello 🌍 World! 🚀"
        
        // Write binary content
        let writeResult = try tester.testWriteFile(filename: "binary.txt", content: binaryContent)
        XCTAssertTrue(writeResult, "Write operation should succeed")
        
        // Read it back
        let readContent = try tester.testReadFile(filename: "binary.txt")
        XCTAssertEqual(readContent, binaryContent, "Binary content should match")
    }
    
    func testFileSystemTesterSubdirectories() throws {
        let tester = FileSystemTester()
        
        // Test writing to subdirectories
        let writeResult = try tester.testWriteFile(filename: "configs/app.json", content: "{\"theme\": \"dark\"}")
        XCTAssertTrue(writeResult, "Write to subdirectory should succeed")
        
        // Read from subdirectory
        let readContent = try tester.testReadFile(filename: "configs/app.json")
        XCTAssertEqual(readContent, "{\"theme\": \"dark\"}", "Content in subdirectory should match")
    }
}

/// Mock filesystem implementation for testing
class MockFileSystemBridge: Bedrock.FileSystem {
    static let shared = MockFileSystemBridge()
    private var files: [String: Data] = [:]
    
    private init() {}
    
    func fileExists(filePath: String) throws -> Bool {
        return files[filePath] != nil
    }
    
    func readFile(filePath: String) throws -> Data {
        guard let data = files[filePath] else {
            throw Bedrock.FileSystemError.FileDoesNotExist
        }
        return data
    }
    
    func writeFile(filePath: String, fileBuffer: Data) throws -> Bool {
        // Create any necessary parent directories in our mock
        files[filePath] = fileBuffer
        return true
    }
    
    func deleteFile(filePath: String) throws -> Bool {
        return files.removeValue(forKey: filePath) != nil
    }
    
    func listFiles(folderPath: String) throws -> [String] {
        // Normalize the folder path by removing trailing "/."
        let normalizedFolderPath = folderPath.hasSuffix("/.") ? String(folderPath.dropLast(2)) : folderPath
        
        return files.keys.compactMap { filePath in
            // Check if the file is in the specified directory
            if filePath.hasPrefix(normalizedFolderPath + "/") {
                let relativePath = String(filePath.dropFirst(normalizedFolderPath.count + 1))
                
                // Return only files in the immediate directory (no subdirectories)
                if !relativePath.contains("/") {
                    return relativePath
                }
            }
            return nil
        }
    }
} 