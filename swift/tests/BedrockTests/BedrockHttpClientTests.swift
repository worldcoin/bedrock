import XCTest
import Foundation

@testable import Bedrock

final class BedrockHttpClientTests: XCTestCase {

    static let sharedHttpClient = TestAuthenticatedHttpClient()

    override class func setUp() {
        super.setUp()
        if !isHttpClientInitialized() {
            _ = setHttpClient(httpClient: sharedHttpClient)
        }
    }

    // Test implementation of AuthenticatedHttpClient
    class TestAuthenticatedHttpClient: AuthenticatedHttpClient {
        var responses: [String: Result<Data, HttpError>] = [:]
        var requestHistory: [String] = []
        var methodHistory: [HttpMethod] = []
        var headersHistory: [[HttpHeader]] = []
        var bodyHistory: [Data?] = []

        func reset() {
            responses.removeAll()
            requestHistory.removeAll()
            methodHistory.removeAll()
            headersHistory.removeAll()
            bodyHistory.removeAll()
        }

        func setResponse(for url: String, result: Result<Data, HttpError>) {
            responses[url] = result
        }

        func fetchFromAppBackend(url: String, method: HttpMethod, headers: [HttpHeader], body: Data?) async throws -> Data {
            requestHistory.append(url)
            methodHistory.append(method)
            headersHistory.append(headers)
            bodyHistory.append(body)

            guard let response = responses[url] else {
                throw HttpError.Generic(message: "No response configured for URL: \(url)")
            }

            switch response {
            case .success(let data):
                return data
            case .failure(let error):
                throw error
            }
        }
    }

    func testSuccessfulGetRequest() async throws {
        let client = TestAuthenticatedHttpClient()
        let testData = "Hello from backend!".data(using: .utf8)!
        let testUrl = "https://api.example.com/test"

        client.setResponse(for: testUrl, result: .success(testData))

        let result = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)

        XCTAssertEqual(result, testData)
        XCTAssertEqual(client.requestHistory.count, 1)
        XCTAssertEqual(client.requestHistory[0], testUrl)
        XCTAssertEqual(client.methodHistory[0], .get)
        XCTAssertEqual(client.headersHistory[0].count, 0)
        XCTAssertNil(client.bodyHistory[0])
    }

    func testSuccessfulPostRequest() async throws {
        let client = TestAuthenticatedHttpClient()
        let testData = "Response from POST".data(using: .utf8)!
        let requestBody = "Request body data".data(using: .utf8)!
        let testUrl = "https://api.example.com/submit"

        client.setResponse(for: testUrl, result: .success(testData))

        let customHeaders = [HttpHeader(name: "X-Test", value: "1")]
        let result = try await client.fetchFromAppBackend(url: testUrl, method: .post, headers: customHeaders, body: requestBody)

        XCTAssertEqual(result, testData)
        XCTAssertEqual(client.requestHistory.count, 1)
        XCTAssertEqual(client.requestHistory[0], testUrl)
        XCTAssertEqual(client.methodHistory[0], .post)
        XCTAssertEqual(client.headersHistory[0].count, 1)
        XCTAssertEqual(client.headersHistory[0][0].name, "X-Test")
        XCTAssertEqual(client.headersHistory[0][0].value, "1")
        XCTAssertEqual(client.bodyHistory[0], requestBody)
    }

    func testBadStatusCodeError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/error"
        let responseBody = "Bad state".data(using: .utf8)!

        let error = HttpError.BadStatusCode(code: 400, responseBody: responseBody)
        client.setResponse(for: testUrl, result: .failure(error))

        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case let .BadStatusCode(code: statusCode, responseBody: body) = httpError {
                XCTAssertEqual(statusCode, 400)
                XCTAssertEqual(body, responseBody)
            } else {
                XCTFail("Expected BadStatusCode error, got \(httpError)")
            }
        }
    }

    func testNoConnectivityError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/offline"

        client.setResponse(for: testUrl, result: .failure(.NoConnectivity))

        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .NoConnectivity = httpError {
                // expected
            } else {
                XCTFail("Expected NoConnectivity error, got \(httpError)")
            }
        }
    }

    func testTimeoutError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/slow"

        client.setResponse(for: testUrl, result: .failure(.Timeout(seconds: 30)))

        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case let .Timeout(seconds: seconds) = httpError {
                XCTAssertEqual(seconds, 30)
            } else {
                XCTFail("Expected Timeout error, got \(httpError)")
            }
        }
    }

    func testDnsResolutionFailedError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://nonexistent.example.com/test"

        client.setResponse(for: testUrl, result: .failure(.DnsResolutionFailed(hostname: "nonexistent.example.com")))

        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case let .DnsResolutionFailed(hostname: hostname) = httpError {
                XCTAssertEqual(hostname, "nonexistent.example.com")
            } else {
                XCTFail("Expected DnsResolutionFailed error, got \(httpError)")
            }
        }
    }

    func testSslError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/ssl-error"

        client.setResponse(for: testUrl, result: .failure(.SslError(reason: "Certificate validation failed")))

        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, headers: [], body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case let .SslError(reason: reason) = httpError {
                XCTAssertEqual(reason, "Certificate validation failed")
            } else {
                XCTFail("Expected SslError, got \(httpError)")
            }
        }
    }

    func testMultipleRequests() async throws {
        let client = TestAuthenticatedHttpClient()
        let urls = [
            "https://api.example.com/endpoint1",
            "https://api.example.com/endpoint2",
            "https://api.example.com/endpoint3"
        ]

        for (index, url) in urls.enumerated() {
            let data = "Response \(index + 1)".data(using: .utf8)!
            client.setResponse(for: url, result: .success(data))
        }

        for (index, url) in urls.enumerated() {
            let result = try await client.fetchFromAppBackend(url: url, method: .get, headers: [], body: nil)
            let expectedData = "Response \(index + 1)".data(using: .utf8)!
            XCTAssertEqual(result, expectedData)
        }

        XCTAssertEqual(client.requestHistory.count, 3)
        XCTAssertEqual(client.requestHistory, urls)
        // Verify all requests were GET with no body
        XCTAssertEqual(client.methodHistory, [.get, .get, .get])
        XCTAssertEqual(client.headersHistory.map { $0.count }, [0, 0, 0])
        XCTAssertEqual(client.bodyHistory, [nil, nil, nil])
    }

    func testRustReceivesBadStatusCode() async throws {
        let url = "https://api.example.com/not-found"
        let responseBody = "Missing".data(using: .utf8)!
        let client = BedrockHttpClientTests.sharedHttpClient
        client.reset()
        client.setResponse(for: url, result: .failure(.BadStatusCode(code: 404, responseBody: responseBody)))

        let tester = HttpClientTester()
        let status = try await tester.fetchBadStatusCode(url: url, method: .get, headers: [], body: nil)

        XCTAssertEqual(status, 404)
        XCTAssertEqual(client.requestHistory.last, url)
        XCTAssertEqual(client.methodHistory.last, .get)
    }
}
