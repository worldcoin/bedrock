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
///             throw HttpError.BadStatusCode(code: UInt64(httpResponse.statusCode))
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
///                 throw HttpError.BadStatusCode(response.code.toULong())
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
    /// * `HttpError::Generic` - For general networking errors (network unavailable, timeout, etc.)
    /// * `HttpError::BadStatusCode` - For HTTP error status codes (4xx, 5xx)
    async fn fetch_from_app_backend(&self, url: String) -> Result<Vec<u8>, HttpError>;
}

/// Represents HTTP-related errors that can occur during network requests.
#[crate::bedrock_error]
pub enum HttpError {
    /// HTTP error with specific status code
    #[error("Bad status code {code}")]
    BadStatusCode {
        /// The HTTP status code that was returned
        code: u64,
    },
}

impl Clone for HttpError {
    fn clone(&self) -> Self {
        match self {
            Self::BadStatusCode { code } => Self::BadStatusCode { code: *code },
            Self::Generic { message } => Self::Generic {
                message: message.clone(),
            },
        }
    }
}

impl From<uniffi::UnexpectedUniFFICallbackError> for HttpError {
    fn from(error: uniffi::UnexpectedUniFFICallbackError) -> Self {
        error.to_string().parse::<u64>().map_or_else(
            |_| Self::Generic {
                message: error.to_string(),
            },
            |code| Self::BadStatusCode { code },
        )
    }
}
