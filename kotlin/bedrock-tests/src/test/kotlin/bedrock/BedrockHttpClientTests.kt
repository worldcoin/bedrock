package bedrock

import uniffi.bedrock.AuthenticatedHttpClient
import uniffi.bedrock.HttpException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.coroutines.test.runTest

class BedrockHttpClientTests {
    
    // Test implementation of AuthenticatedHttpClient
    class TestAuthenticatedHttpClient : AuthenticatedHttpClient {
        private val responses = mutableMapOf<String, Result<ByteArray>>()
        val requestHistory = mutableListOf<String>()
        
        fun setResponse(url: String, result: Result<ByteArray>) {
            responses[url] = result
        }
        
        override suspend fun fetchFromAppBackend(url: String): ByteArray {
            requestHistory.add(url)
            
            val response = responses[url] 
                ?: throw HttpException.Generic("No response configured for URL: $url")
                
            return response.getOrThrow()
        }
    }
    
    @Test
    fun testSuccessfulRequest() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testData = "Hello from backend!".toByteArray()
        val testUrl = "https://api.example.com/test"
        
        client.setResponse(testUrl, Result.success(testData))
        
        val result = client.fetchFromAppBackend(testUrl)
        
        assertEquals(testData.contentToString(), result.contentToString())
        assertEquals(1, client.requestHistory.size)
        assertEquals(testUrl, client.requestHistory[0])
    }
    
    @Test
    fun testBadStatusCodeError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/error"
        
        val error = HttpException.BadStatusCode("Bad status code 400")
        client.setResponse(testUrl, Result.failure(error))
        
        val exception = assertFailsWith<HttpException.BadStatusCode> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("Bad status code 400", exception.message)
        assertTrue(exception.message!!.contains("400"))
    }
    
    @Test
    fun testNoConnectivityError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/offline"
        
        client.setResponse(testUrl, Result.failure(HttpException.NoConnectivity("No internet connectivity")))
        
        val exception = assertFailsWith<HttpException.NoConnectivity> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("No internet connectivity", exception.message)
    }
    
    @Test
    fun testTimeoutError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/slow"
        
        client.setResponse(testUrl, Result.failure(HttpException.Timeout("Request timed out after 30 seconds")))
        
        val exception = assertFailsWith<HttpException.Timeout> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("Request timed out after 30 seconds", exception.message)
        assertTrue(exception.message!!.contains("30"))
    }
    
    @Test
    fun testDnsResolutionFailedError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://nonexistent.example.com/test"
        
        client.setResponse(testUrl, Result.failure(HttpException.DnsResolutionFailed("DNS resolution failed for nonexistent.example.com")))
        
        val exception = assertFailsWith<HttpException.DnsResolutionFailed> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("DNS resolution failed for nonexistent.example.com", exception.message)
        assertTrue(exception.message!!.contains("nonexistent.example.com"))
    }
    
    @Test
    fun testSslError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/ssl-error"
        
        client.setResponse(testUrl, Result.failure(HttpException.SslException("SSL certificate validation failed: Certificate validation failed")))
        
        val exception = assertFailsWith<HttpException.SslException> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("SSL certificate validation failed: Certificate validation failed", exception.message)
        assertTrue(exception.message!!.contains("Certificate validation failed"))
    }
    
    @Test
    fun testCancelledError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/cancelled"
        
        client.setResponse(testUrl, Result.failure(HttpException.Cancelled("Request was cancelled")))
        
        val exception = assertFailsWith<HttpException.Cancelled> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("Request was cancelled", exception.message)
    }
    
    @Test
    fun testConnectionRefusedError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/refused"
        
        client.setResponse(testUrl, Result.failure(HttpException.ConnectionRefused("Connection refused by api.example.com")))
        
        val exception = assertFailsWith<HttpException.ConnectionRefused> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("Connection refused by api.example.com", exception.message)
        assertTrue(exception.message!!.contains("api.example.com"))
    }
    
    @Test
    fun testGenericError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/generic-error"
        
        client.setResponse(testUrl, Result.failure(HttpException.Generic("Generic error: Unexpected error occurred")))
        
        val exception = assertFailsWith<HttpException.Generic> {
            client.fetchFromAppBackend(testUrl)
        }
        
        assertEquals("Generic error: Unexpected error occurred", exception.message)
        assertTrue(exception.message!!.contains("Unexpected error occurred"))
    }
    
    @Test
    fun testMultipleRequests() = runTest {
        val client = TestAuthenticatedHttpClient()
        val urls = listOf(
            "https://api.example.com/endpoint1",
            "https://api.example.com/endpoint2",
            "https://api.example.com/endpoint3"
        )
        
        urls.forEachIndexed { index, url ->
            val data = "Response ${index + 1}".toByteArray()
            client.setResponse(url, Result.success(data))
        }
        
        urls.forEachIndexed { index, url ->
            val result = client.fetchFromAppBackend(url)
            val expectedData = "Response ${index + 1}".toByteArray()
            assertEquals(expectedData.contentToString(), result.contentToString())
        }
        
        assertEquals(3, client.requestHistory.size)
        assertEquals(urls, client.requestHistory)
    }
} 