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
        try tester.testWriteFile(filename: "test.txt", content: "Hello, World!")
        
        // Test reading the file back
        let readContent = try tester.testReadFile(filename: "test.txt")
        XCTAssertEqual(readContent, "Hello, World!", "Read content should match written content")
    }
    
    func testFileSystemTesterFileExists() throws {
        let tester = FileSystemTester()
        
        // Write a file
        try tester.testWriteFile(filename: "exists.txt", content: "content")
        
        // Test file exists
        let exists = try tester.testFileExists(filename: "exists.txt")
        XCTAssertTrue(exists, "File should exist after writing")
        
        // Test non-existent file
        let notExists = try tester.testFileExists(filename: "nonexistent.txt")
        XCTAssertFalse(notExists, "Non-existent file should not exist")
    }
    

    
    func testFileSystemTesterListFilesAtDirectory() throws {
        let tester = FileSystemTester()
        
        // Write multiple files
        try tester.testWriteFile(filename: "file1.txt", content: "content1")
        try tester.testWriteFile(filename: "file2.txt", content: "content2")
        try tester.testWriteFile(filename: "subdir/file3.txt", content: "content3")
        
        // List files in current directory
        let files = try tester.testListFilesAtDirectory()
        print("files: \(files)")
        XCTAssertTrue(files.contains("file1.txt"), "Should list file1.txt")
        XCTAssertTrue(files.contains("file2.txt"), "Should list file2.txt")
        XCTAssertFalse(files.contains("file3.txt"), "Should not list subdir/file3.txt")
    }
    
    func testFileSystemTesterDeleteFile() throws {
        let tester = FileSystemTester()
        
        // Write a file
        try tester.testWriteFile(filename: "delete_me.txt", content: "temporary content")
        
        // Verify it exists
        let existsBefore = try tester.testFileExists(filename: "delete_me.txt")
        XCTAssertTrue(existsBefore, "File should exist before deletion")
        
        // Delete the file
        try tester.testDeleteFile(filename: "delete_me.txt")
        
        // Verify it's deleted
        let existsAfter = try tester.testFileExists(filename: "delete_me.txt")
        XCTAssertFalse(existsAfter, "File should not exist after deletion")
    }
    
    func testFileSystemTesterBinaryData() throws {
        let tester = FileSystemTester()
        
        // Test with binary data (using UTF-8 encoded emoji)
        let binaryContent = "Hello 🌍 World! 🚀"
        
        // Write binary content
        try tester.testWriteFile(filename: "binary.txt", content: binaryContent)
        
        // Read it back
        let readContent = try tester.testReadFile(filename: "binary.txt")
        XCTAssertEqual(readContent, binaryContent, "Binary content should match")
    }
    
    func testFileSystemTesterSubdirectories() throws {
        let tester = FileSystemTester()
        
        // Test writing to subdirectories
        try tester.testWriteFile(filename: "configs/app.json", content: "{\"theme\": \"dark\"}")
        
        // Read from subdirectory
        let readContent = try tester.testReadFile(filename: "configs/app.json")
        XCTAssertEqual(readContent, "{\"theme\": \"dark\"}", "Content in subdirectory should match")
    }
}

/// Mock filesystem implementation for testing
final class MockFileSystemBridge: Bedrock.FileSystem {
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
    
    func readFileRange(filePath: String, offset: UInt64, maxLength: UInt64) throws -> Data {
        guard let data = files[filePath] else {
            throw Bedrock.FileSystemError.FileDoesNotExist
        }

        if offset >= UInt64(data.count) {
            return Data()
        }

        let startIndex = Int(offset)
        let safeMaxLength = maxLength > UInt64(Int.max) ? UInt64(Int.max) : maxLength
        let endIndex = min(data.count, startIndex + Int(safeMaxLength))
        return data.subdata(in: startIndex..<endIndex)
    }

    func writeFile(filePath: String, fileBuffer: Data) throws {
        // Create any necessary parent directories in our mock
        files[filePath] = fileBuffer
    }
    
    func deleteFile(filePath: String) throws {
        files.removeValue(forKey: filePath)
    }
    
    func listFilesAtDirectory(folderPath: String) throws -> [String] {
        var base = folderPath
        if base.hasSuffix("/.") { base.removeLast(2) }
        if base.hasSuffix("/")  { base.removeLast() }

        // Root: only file names without "/"
        if base.isEmpty {
            return files.keys
                .filter { !$0.contains("/") }
                .sorted()
        }

        let prefix = base + "/"

        // Immediate children only: remainder contains no "/"
        // Return just the remainder (the file name)
        return files.keys
            .filter { $0.hasPrefix(prefix) }
            .compactMap { path -> String? in
                let rest = String(path.dropFirst(prefix.count))
                guard !rest.isEmpty, !rest.contains("/") else { return nil }
                return rest // <-- name only
            }
            .sorted()
    }
} 