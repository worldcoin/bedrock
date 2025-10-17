package bedrock

import uniffi.bedrock.AuthenticatedHttpClient
import uniffi.bedrock.HttpException
import uniffi.bedrock.HttpHeader
import uniffi.bedrock.HttpMethod
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
        val methodHistory = mutableListOf<HttpMethod>()
        val headersHistory = mutableListOf<List<HttpHeader>>()
        val bodyHistory = mutableListOf<ByteArray?>()
        
        fun setResponse(url: String, result: Result<ByteArray>) {
            responses[url] = result
        }
        
        override suspend fun fetchFromAppBackend(url: String, method: HttpMethod, headers: List<HttpHeader>, body: ByteArray?): ByteArray {
            requestHistory.add(url)
            methodHistory.add(method)
            headersHistory.add(headers)
            bodyHistory.add(body)
            
            val response = responses[url] 
                ?: throw HttpException.Generic("No response configured for URL: $url")
                
            return response.getOrThrow()
        }
    }
    
    @Test
    fun testSuccessfulGetRequest() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testData = "Hello from backend!".toByteArray()
        val testUrl = "https://api.example.com/test"
        
        client.setResponse(testUrl, Result.success(testData))
        
        val result = client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        
        assertEquals(testData.contentToString(), result.contentToString())
        assertEquals(1, client.requestHistory.size)
        assertEquals(testUrl, client.requestHistory[0])
        assertEquals(HttpMethod.GET, client.methodHistory[0])
        assertEquals(0, client.headersHistory[0].size)
        assertEquals(null, client.bodyHistory[0])
    }

    @Test
    fun testSuccessfulPostRequest() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testData = "Response from POST".toByteArray()
        val requestBody = "Request body data".toByteArray()
        val testUrl = "https://api.example.com/submit"
        
        client.setResponse(testUrl, Result.success(testData))
        
        val customHeaders = listOf(HttpHeader("X-Test", "1"))
        val result = client.fetchFromAppBackend(testUrl, HttpMethod.POST, customHeaders, requestBody)
        
        assertEquals(testData.contentToString(), result.contentToString())
        assertEquals(1, client.requestHistory.size)
        assertEquals(testUrl, client.requestHistory[0])
        assertEquals(HttpMethod.POST, client.methodHistory[0])
        assertEquals(1, client.headersHistory[0].size)
        assertEquals("X-Test", client.headersHistory[0][0].name)
        assertEquals("1", client.headersHistory[0][0].value)
        assertEquals(requestBody.contentToString(), client.bodyHistory[0]?.contentToString())
    }
    
    @Test
    fun testBadStatusCodeError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/error"
        val responseBody = "Bad status".toByteArray()

        val error = HttpException.BadStatusCode(400u, responseBody)
        client.setResponse(testUrl, Result.failure(error))

        val exception = assertFailsWith<HttpException.BadStatusCode> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }

        assertEquals(400u, exception.`code`)
        assertEquals("Bad status", String(exception.`responseBody`))
    }
    
    @Test
    fun testNoConnectivityError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/offline"

        client.setResponse(testUrl, Result.failure(HttpException.NoConnectivity()))

        assertFailsWith<HttpException.NoConnectivity> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }
    }
    
    @Test
    fun testTimeoutError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/slow"

        client.setResponse(testUrl, Result.failure(HttpException.Timeout()))

        val exception = assertFailsWith<HttpException.Timeout> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }
    }
    
    @Test
    fun testDnsResolutionFailedError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://nonexistent.example.com/test"

        client.setResponse(testUrl, Result.failure(HttpException.DnsResolutionFailed("failed to reach nonexistent.example.com")))

        val exception = assertFailsWith<HttpException.DnsResolutionFailed> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }

        assertEquals("nonexistent.example.com", exception.`errorMessage`)
    }
    
    @Test
    fun testSslError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/ssl-error"

        client.setResponse(testUrl, Result.failure(HttpException.SslException("Certificate validation failed")))

        val exception = assertFailsWith<HttpException.SslException> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }

        assertEquals("Certificate validation failed", exception.`reason`)
    }
    
    @Test
    fun testCancelledError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/cancelled"

        client.setResponse(testUrl, Result.failure(HttpException.Cancelled()))

        assertFailsWith<HttpException.Cancelled> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }
    }
    
    @Test
    fun testConnectionRefusedError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/refused"

        client.setResponse(testUrl, Result.failure(HttpException.ConnectionRefused("api.example.com")))

        val exception = assertFailsWith<HttpException.ConnectionRefused> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }

        assertEquals("api.example.com", exception.`errorMessage`)
    }
    
    @Test
    fun testGenericError() = runTest {
        val client = TestAuthenticatedHttpClient()
        val testUrl = "https://api.example.com/generic-error"

        client.setResponse(testUrl, Result.failure(HttpException.Generic("Unexpected error occurred")))

        val exception = assertFailsWith<HttpException.Generic> {
            client.fetchFromAppBackend(testUrl, HttpMethod.GET, emptyList(), null)
        }

        assertEquals("Unexpected error occurred", exception.`errorMessage`)
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
            val result = client.fetchFromAppBackend(url, HttpMethod.GET, emptyList(), null)
            val expectedData = "Response ${index + 1}".toByteArray()
            assertEquals(expectedData.contentToString(), result.contentToString())
        }
        
        assertEquals(3, client.requestHistory.size)
        assertEquals(urls, client.requestHistory)
        // Verify all requests were GET with no body
        assertEquals(listOf(HttpMethod.GET, HttpMethod.GET, HttpMethod.GET), client.methodHistory)
        assertEquals(listOf(0, 0, 0), client.headersHistory.map { it.size })
        assertEquals(arrayOf<ByteArray?>(null, null, null).toList(), client.bodyHistory)
    }
} 