use std::sync::{Arc, OnceLock};

/// Global HTTP client instance for Bedrock operations
static HTTP_CLIENT_INSTANCE: OnceLock<Arc<dyn AuthenticatedHttpClient>> =
    OnceLock::new();

/// Authenticated HTTP client interface that native applications must implement for bedrock to make backend requests.
///
/// This trait allows bedrock to make HTTP requests through the native app's networking stack,
/// ensuring proper handling of platform-specific networking requirements like SSL pinning,
/// proxy support, and authentication.
///
/// Native implementations should map platform-specific errors to the appropriate `HttpError` variants
/// for consistent error handling across platforms.
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
    /// * `method` - The HTTP method to use for the request
    /// * `body` - Optional request body data for POST requests
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
    async fn fetch_from_app_backend(
        &self,
        url: String,
        method: HttpMethod,
        body: Option<Vec<u8>>,
    ) -> Result<Vec<u8>, HttpError>;
}

/// HTTP methods supported by the authenticated HTTP client.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum HttpMethod {
    /// HTTP GET method for retrieving data
    Get,
    /// HTTP POST method for sending data
    Post,
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

/// Sets the global HTTP client instance.
///
/// This function allows you to provide your own implementation of the `AuthenticatedHttpClient` trait.
/// It should be called once at application startup before any HTTP operations.
///
/// # Arguments
///
/// * `http_client` - An `Arc` containing your HTTP client implementation.
///
/// # Note
///
/// If the HTTP client has already been set, this function will do nothing and return false.
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// let httpClient = MyHttpClient()
/// let success = setHttpClient(httpClient: httpClient)
/// ```
#[uniffi::export]
pub fn set_http_client(http_client: Arc<dyn AuthenticatedHttpClient>) -> bool {
    if HTTP_CLIENT_INSTANCE.set(http_client).is_err() {
        crate::warn!("HTTP client already initialized, ignoring");
        false
    } else {
        crate::info!("HTTP client initialized successfully");
        true
    }
}

/// Gets a reference to the global HTTP client instance.
///
/// # Returns
/// An Option containing a reference to the HTTP client if initialized, None otherwise.
///
/// # Examples
///
/// ## Swift
///
/// ```swift
/// if let httpClient = getHttpClient() {
///     // Use the HTTP client
/// }
/// ```
#[uniffi::export]
#[must_use]
pub fn get_http_client() -> Option<Arc<dyn AuthenticatedHttpClient>> {
    HTTP_CLIENT_INSTANCE.get().cloned()
}

/// Checks if the HTTP client has been initialized.
///
/// # Returns
/// true if the HTTP client has been initialized, false otherwise.
#[uniffi::export]
#[must_use]
pub fn is_http_client_initialized() -> bool {
    HTTP_CLIENT_INSTANCE.get().is_some()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    // Mock HTTP client for testing
    struct MockHttpClient;

    #[async_trait::async_trait]
    impl AuthenticatedHttpClient for MockHttpClient {
        async fn fetch_from_app_backend(
            &self,
            _url: String,
            _method: HttpMethod,
            _body: Option<Vec<u8>>,
        ) -> Result<Vec<u8>, HttpError> {
            Ok(b"mock response".to_vec())
        }
    }

    #[test]
    fn test_global_http_client_lifecycle() {
        // Initially, no HTTP client should be set
        assert!(!is_http_client_initialized());
        assert!(get_http_client().is_none());

        // Set the HTTP client
        let mock_client = Arc::new(MockHttpClient);
        let success = set_http_client(mock_client);
        assert!(success);

        // Verify the HTTP client is now initialized
        assert!(is_http_client_initialized());
        assert!(get_http_client().is_some());

        // Verify that trying to set it again fails
        let another_mock_client = Arc::new(MockHttpClient);
        let success = set_http_client(another_mock_client);
        assert!(!success); // Should return false since already set

        // The original client should still be there
        assert!(is_http_client_initialized());
        assert!(get_http_client().is_some());
    }
}
