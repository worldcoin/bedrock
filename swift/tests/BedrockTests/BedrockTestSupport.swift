import Foundation
@testable import Bedrock

/// Shared Bedrock initialization for the test suites.
///
/// `setConfig` is a one-shot global that refuses every call after the first, so this
/// helper is what makes it safe to call from each suite's `setUp`.
enum BedrockTestSupport {
    static let rootPath: String = {
        let root = FileManager.default.temporaryDirectory
            .appendingPathComponent("bedrock-tests-\(ProcessInfo.processInfo.processIdentifier)")
        // clear anything left from a prior run.
        try? FileManager.default.removeItem(at: root)
        return root.path
    }()

    /// Initializes the global Bedrock config, if it isn't already.
    ///
    /// A second `setConfig` throws, and this runs before every test, so the guard is what
    /// keeps every test after the first from failing in `setUp`.
    static func setUp() throws {
        guard !isInitialized() else { return }
        try Bedrock.setConfig(environment: .staging, os: .ios, rootPath: rootPath)
    }
}
