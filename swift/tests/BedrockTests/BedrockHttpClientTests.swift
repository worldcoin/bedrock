import XCTest
import Foundation

@testable import Bedrock

final class BedrockHttpClientTests: XCTestCase {
    
    // Test implementation of AuthenticatedHttpClient
    class TestAuthenticatedHttpClient: AuthenticatedHttpClient {
        var responses: [String: Result<Data, HttpError>] = [:]
        var requestHistory: [String] = []
        var methodHistory: [HttpMethod] = []
        var bodyHistory: [Data?] = []
        
        func setResponse(for url: String, result: Result<Data, HttpError>) {
            responses[url] = result
        }
        
        func fetchFromAppBackend(url: String, method: HttpMethod, body: Data?) async throws -> Data {
            requestHistory.append(url)
            methodHistory.append(method)
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
        
        let result = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
        
        XCTAssertEqual(result, testData)
        XCTAssertEqual(client.requestHistory.count, 1)
        XCTAssertEqual(client.requestHistory[0], testUrl)
        XCTAssertEqual(client.methodHistory[0], .get)
        XCTAssertNil(client.bodyHistory[0])
    }

    func testSuccessfulPostRequest() async throws {
        let client = TestAuthenticatedHttpClient()
        let testData = "Response from POST".data(using: .utf8)!
        let requestBody = "Request body data".data(using: .utf8)!
        let testUrl = "https://api.example.com/submit"
        
        client.setResponse(for: testUrl, result: .success(testData))
        
        let result = try await client.fetchFromAppBackend(url: testUrl, method: .post, body: requestBody)
        
        XCTAssertEqual(result, testData)
        XCTAssertEqual(client.requestHistory.count, 1)
        XCTAssertEqual(client.requestHistory[0], testUrl)
        XCTAssertEqual(client.methodHistory[0], .post)
        XCTAssertEqual(client.bodyHistory[0], requestBody)
    }
    
    func testBadStatusCodeError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/error"
        
        let error = HttpError.BadStatusCode(message: "Bad status code 400")
        client.setResponse(for: testUrl, result: .failure(error))
        
        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .BadStatusCode(let message) = httpError {
                XCTAssertEqual(message, "Bad status code 400")
                XCTAssertTrue(message.contains("400"))
            } else {
                XCTFail("Expected BadStatusCode error, got \(httpError)")
            }
        }
    }
    
    func testNoConnectivityError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/offline"
        
        client.setResponse(for: testUrl, result: .failure(.NoConnectivity(message: "No internet connectivity")))
        
        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .NoConnectivity(let message) = httpError {
                XCTAssertEqual(message, "No internet connectivity")
            } else {
                XCTFail("Expected NoConnectivity error, got \(httpError)")
            }
        }
    }
    
    func testTimeoutError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/slow"
        
        client.setResponse(for: testUrl, result: .failure(.Timeout(message: "Request timed out after 30 seconds")))
        
        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .Timeout(let message) = httpError {
                XCTAssertEqual(message, "Request timed out after 30 seconds")
                XCTAssertTrue(message.contains("30"))
            } else {
                XCTFail("Expected Timeout error, got \(httpError)")
            }
        }
    }
    
    func testDnsResolutionFailedError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://nonexistent.example.com/test"
        
        client.setResponse(for: testUrl, result: .failure(.DnsResolutionFailed(message: "DNS resolution failed for nonexistent.example.com")))
        
        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .DnsResolutionFailed(let message) = httpError {
                XCTAssertEqual(message, "DNS resolution failed for nonexistent.example.com")
                XCTAssertTrue(message.contains("nonexistent.example.com"))
            } else {
                XCTFail("Expected DnsResolutionFailed error, got \(httpError)")
            }
        }
    }
    
    func testSslError() async throws {
        let client = TestAuthenticatedHttpClient()
        let testUrl = "https://api.example.com/ssl-error"
        
        client.setResponse(for: testUrl, result: .failure(.SslError(message: "SSL certificate validation failed: Certificate validation failed")))
        
        do {
            _ = try await client.fetchFromAppBackend(url: testUrl, method: .get, body: nil)
            XCTFail("Should have thrown an error")
        } catch let httpError as HttpError {
            if case .SslError(let message) = httpError {
                XCTAssertEqual(message, "SSL certificate validation failed: Certificate validation failed")
                XCTAssertTrue(message.contains("Certificate validation failed"))
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
            let result = try await client.fetchFromAppBackend(url: url, method: .get, body: nil)
            let expectedData = "Response \(index + 1)".data(using: .utf8)!
            XCTAssertEqual(result, expectedData)
        }
        
        XCTAssertEqual(client.requestHistory.count, 3)
        XCTAssertEqual(client.requestHistory, urls)
        // Verify all requests were GET with no body
        XCTAssertEqual(client.methodHistory, [.get, .get, .get])
        XCTAssertEqual(client.bodyHistory, [nil, nil, nil])
    }
} 