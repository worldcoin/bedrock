import XCTest
import Foundation
@testable import Bedrock

final class BedrockFilesystemTests: XCTestCase {

    override func setUpWithError() throws {
        try BedrockTestSupport.setUp()
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
        XCTAssertTrue(files.contains("file1.txt"), "Should list file1.txt")
        XCTAssertTrue(files.contains("file2.txt"), "Should list file2.txt")
        XCTAssertFalse(files.contains("file3.txt"), "Should not list subdir/file3.txt")
        XCTAssertFalse(files.contains("subdir"), "Should not list sub-directories")
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

    func testFileSystemTesterReadMissingFile() throws {
        let tester = FileSystemTester()

        XCTAssertThrowsError(try tester.testReadFile(filename: "never_written.txt")) { error in
            guard case FileSystemTestError.FileSystem(let inner) = error else {
                return XCTFail("Expected a FileSystem error, got \(error)")
            }
            guard case FileSystemError.FileDoesNotExist = inner else {
                return XCTFail("Expected FileDoesNotExist, got \(inner)")
            }
        }
    }

    func testFileSystemTesterRejectsPathTraversal() throws {
        let tester = FileSystemTester()

        XCTAssertThrowsError(
            try tester.testWriteFile(filename: "../escaped.txt", content: "nope")
        ) { error in
            guard case FileSystemTestError.FileSystem(let inner) = error else {
                return XCTFail("Expected a FileSystem error, got \(error)")
            }
            guard case FileSystemError.InvalidPath = inner else {
                return XCTFail("Expected InvalidPath, got \(inner)")
            }
        }
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

        // Test writing to subdirectories, parent directories are created on demand
        try tester.testWriteFile(filename: "configs/app.json", content: "{\"theme\": \"dark\"}")

        // Read from subdirectory
        let readContent = try tester.testReadFile(filename: "configs/app.json")
        XCTAssertEqual(readContent, "{\"theme\": \"dark\"}", "Content in subdirectory should match")
    }

    /// A second `setConfig` naming a different root is refused, so a stray initializer
    /// cannot leave Bedrock reading one directory while the caller writes another.
    ///
    /// Rejection of a *relative* root can only be observed in a process where nothing has
    /// configured Bedrock yet, which the Rust suite covers.
    func testSetConfigRejectsADifferentRootPath() throws {
        let other = NSTemporaryDirectory() + "bedrock-some-other-root"

        XCTAssertThrowsError(
            try setConfig(environment: .staging, os: .ios, rootPath: other)
        ) { error in
            guard case FileSystemError.InvalidPath = error else {
                return XCTFail("Expected InvalidPath, got \(error)")
            }
        }

        // The committed root still works.
        let tester = FileSystemTester()
        try tester.testWriteFile(filename: "after_rejection.txt", content: "ok")
        XCTAssertEqual(try tester.testReadFile(filename: "after_rejection.txt"), "ok")
    }

    func testFilesAreScopedUnderTheConfiguredRoot() throws {
        let tester = FileSystemTester()
        try tester.testWriteFile(filename: "scoped.txt", content: "on disk")

        // `FileSystemTester` is exported through `bedrock_export`, so its files land under
        // the snake_case struct name inside the root the app handed to `setConfig`.
        let expected = URL(fileURLWithPath: BedrockTestSupport.rootPath)
            .appendingPathComponent("file_system_tester")
            .appendingPathComponent("scoped.txt")

        XCTAssertEqual(
            try String(contentsOf: expected, encoding: .utf8),
            "on disk",
            "Bedrock should write through to the real filesystem"
        )
    }
}
