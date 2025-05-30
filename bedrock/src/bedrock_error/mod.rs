//! Bedrock error handling utilities
//!
//! This module provides a unified approach to error handling that combines:
//! - Strongly typed error variants for specific, known error cases
//! - Generic error handling for complex anyhow-based error chains
//!
//! Use the `#[bedrock_error]` macro to automatically add generic error handling
//! capabilities to your error enums.

pub use bedrock_error_macros::bedrock_error;

/// Re-export anyhow for convenience
pub use anyhow;

/// Helper trait for converting anyhow errors to generic error messages
pub trait AnyhowErrorExt {
    /// Convert an anyhow error to a string, preserving the error chain
    fn to_generic_message(self) -> String;

    /// Convert an anyhow error to a string with a custom prefix
    fn to_generic_message_with_prefix(self, prefix: &str) -> String;
}

impl AnyhowErrorExt for anyhow::Error {
    fn to_generic_message(self) -> String {
        // Include the full error chain in the message
        let mut message = self.to_string();

        // Add context from the error chain
        let chain: Vec<String> = self.chain().skip(1).map(|e| e.to_string()).collect();
        if !chain.is_empty() {
            message.push_str(" (caused by: ");
            message.push_str(&chain.join(" -> "));
            message.push(')');
        }

        message
    }

    fn to_generic_message_with_prefix(self, prefix: &str) -> String {
        format!("{}: {}", prefix, self.to_generic_message())
    }
}

/// Helper macros for common error handling patterns
#[macro_export]
macro_rules! anyhow_to_generic {
    ($result:expr) => {
        $result.map_err(|e| {
            use $crate::bedrock_error::AnyhowErrorExt;
            e.to_generic_message()
        })
    };

    ($result:expr, $prefix:expr) => {
        $result.map_err(|e| {
            use $crate::bedrock_error::AnyhowErrorExt;
            e.to_generic_message_with_prefix($prefix)
        })
    };
}

/// Convenience macro for creating generic errors from anyhow results
#[macro_export]
macro_rules! generic_error {
    ($result:expr) => {{
        use $crate::bedrock_error::AnyhowErrorExt;
        match $result {
            Ok(val) => Ok(val),
            Err(e) => Err(Self::Generic {
                message: e.to_generic_message(),
            }),
        }
    }};

    ($result:expr, $prefix:expr) => {{
        use $crate::bedrock_error::AnyhowErrorExt;
        match $result {
            Ok(val) => Ok(val),
            Err(e) => Err(Self::Generic {
                message: e.to_generic_message_with_prefix($prefix),
            }),
        }
    }};
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_anyhow_error_ext() {
        use anyhow::Context;

        let error = anyhow::anyhow!("base error")
            .context("middle context")
            .context("outer context");

        let message = error.to_generic_message();
        assert!(message.contains("outer context"));
        assert!(message.contains("caused by"));
        assert!(message.contains("middle context"));
        assert!(message.contains("base error"));
    }

    #[test]
    fn test_anyhow_error_ext_with_prefix() {
        let error = anyhow::anyhow!("something went wrong");
        let message = error.to_generic_message_with_prefix("Operation failed");
        assert!(message.starts_with("Operation failed:"));
        assert!(message.contains("something went wrong"));
    }
}
