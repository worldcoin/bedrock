/// Authenticated HTTP client interface that native applications must implement for bedrock to make backend requests.
///
/// This trait allows bedrock to make HTTP requests through the native app's networking stack,
/// ensuring proper handling of platform-specific networking requirements like SSL pinning,
/// proxy support, and authentication.
///
/// # Examples
///
/// ## Swift Implementation
///
/// ```swift
/// class BedrockAuthenticatedHttpClientBridge: Bedrock.AuthenticatedHttpClient {
///     func fetchFromAppBackend(url: String) async throws -> Data {
///         guard let url = URL(string: url) else {
///             throw HttpError.Generic(message: "Invalid URL")
///         }
///         
///         let (data, response) = try await URLSession.shared.data(from: url)
///         
///         guard let httpResponse = response as? HTTPURLResponse else {
///             throw HttpError.Generic(message: "Invalid response type")
///         }
///         
///         guard 200...299 ~= httpResponse.statusCode else {
///             throw HttpError.BadStatusCode(
///                 code: UInt64(httpResponse.statusCode),
///                 responseBody: data // Include error response body
///             )
///         }
///         
///         return data
///     }
/// }
/// ```
///
/// ## Kotlin Implementation
///
/// ```kotlin
/// class BedrockAuthenticatedHttpClientBridge : AuthenticatedHttpClient {
///     override suspend fun fetchFromAppBackend(url: String): ByteArray {
///         return withContext(Dispatchers.IO) {
///             val request = Request.Builder().url(url).build()
///             val response = httpClient.newCall(request).execute()
///             
///             if (!response.isSuccessful) {
///                 val errorBody = response.body?.bytes() ?: ByteArray(0)
///                 throw HttpError.BadStatusCode(
///                     code = response.code.toULong(),
///                     responseBody = errorBody // Include error response body
///                 )
///             }
///             
///             response.body?.bytes() ?: throw HttpError.Generic("Empty response body")
///         }
///     }
/// }
/// ```
#[uniffi::export(with_foreign)]
#[async_trait::async_trait]
pub trait AuthenticatedHttpClient: Send + Sync {
    /// Fetches data from the specified URL using the app's backend networking infrastructure.
    ///
    /// This method should handle all networking concerns including:
    /// - SSL certificate validation and pinning
    /// - Proxy configuration
    /// - Request authentication headers
    /// - Timeout handling
    /// - Network error handling
    ///
    /// # Arguments
    /// * `url` - The URL to fetch data from
    ///
    /// # Returns
    /// * `Result<Vec<u8>, HttpError>` - The response body as bytes on success, or an error
    ///
    /// # Errors
    /// * `HttpError::BadStatusCode` - For HTTP error status codes (4xx, 5xx) with response body
    /// * `HttpError::NoConnectivity` - When no internet connection is available
    /// * `HttpError::Timeout` - When the request times out
    /// * `HttpError::DnsResolutionFailed` - When DNS lookup fails
    /// * `HttpError::ConnectionRefused` - When the server refuses the connection
    /// * `HttpError::SslError` - When SSL/TLS validation fails
    /// * `HttpError::Cancelled` - When the request is cancelled
    /// * `HttpError::Generic` - For other unexpected errors
    async fn fetch_from_app_backend(&self, url: String) -> Result<Vec<u8>, HttpError>;
}

/// Represents HTTP-related errors that can occur during network requests.
#[crate::bedrock_error]
pub enum HttpError {
    /// HTTP error with specific status code (4xx, 5xx responses)
    #[error("Bad status code {code}")]
    BadStatusCode {
        /// The HTTP status code that was returned
        code: u64,
        /// The response body, which may contain error details
        response_body: Vec<u8>,
    },
    /// No internet connectivity available
    #[error("No internet connectivity")]
    NoConnectivity,
    /// Request timed out
    #[error("Request timed out after {seconds} seconds")]
    Timeout {
        /// Number of seconds before timeout occurred
        seconds: u64,
    },
    /// DNS resolution failed for the hostname
    #[error("DNS resolution failed for {hostname}")]
    DnsResolutionFailed {
        /// The hostname that failed to resolve
        hostname: String,
    },
    /// Connection was refused by the server
    #[error("Connection refused by {host}")]
    ConnectionRefused {
        /// The host that refused the connection
        host: String,
    },
    /// SSL/TLS certificate validation failed
    #[error("SSL certificate validation failed: {reason}")]
    SslError {
        /// Reason for the SSL failure
        reason: String,
    },
    /// The request was cancelled before completion
    #[error("Request was cancelled")]
    Cancelled,
    /// Generic error for unexpected errors
    #[error("Generic error: {message}")]
    Generic {
        /// The error message
        message: String,
    },
}

/// Converts unexpected UniFFI callback errors to `HttpError`.
///
/// This implementation is required for foreign trait support. When native apps
/// (Swift/Kotlin) implement `AuthenticatedHttpClient` and encounter unexpected
/// errors (panics, unhandled exceptions), UniFFI converts them to this error type
/// instead of causing Rust to panic.
///
/// Without this implementation, unexpected foreign errors would panic the Rust code.
impl From<uniffi::UnexpectedUniFFICallbackError> for HttpError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        error.to_string().parse::<u64>().map_or_else(
            |_| Self::Generic {
                message: error.to_string(),
            },
            |code| Self::BadStatusCode {
                code,
                response_body: Vec::new(), // No response body for unexpected UniFFI errors
            },
        )
    }
}
