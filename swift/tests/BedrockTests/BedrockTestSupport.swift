import Foundation
@testable import Bedrock

/// Shared Bedrock initialization for the test suites.
///
/// `setConfig` is a one-shot global, so every suite must go through this helper: the
/// first caller wins and all of them need a usable root path for file operations.
enum BedrockTestSupport {
    static let rootPath: String = {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("bedrock-tests-\(ProcessInfo.processInfo.processIdentifier)")
        // clear anything left from a prior run.
        try? FileManager.default.removeItem(at: root)
        return root.path
    }()

    /// Initializes the global Bedrock config, if it isn't already.
    static func setUp() throws {
        try Bedrock.setConfig(environment: .staging, os: .ios, rootPath: rootPath)
    }
}
