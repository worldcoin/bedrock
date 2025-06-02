use crate::{module_debug, module_error, module_info, module_trace, module_warn};

/// Demonstrates the logging functionality with different log levels.
///
/// This function showcases how to use the module-specific logging macros
/// with the "LoggerDemo" prefix.
pub fn demonstrate_logging() {
    module_trace!("LoggerDemo", "This is a trace message from LoggerDemo");
    module_debug!("LoggerDemo", "This is a debug message with value: {}", 42);
    module_info!(
        "LoggerDemo",
        "LoggerDemo module has been initialized successfully"
    );
    module_warn!("LoggerDemo", "This is a warning message about something");
    module_error!(
        "LoggerDemo",
        "This is an error message with details: {}",
        "sample error"
    );
}

/// Demonstrates logging with formatted messages and multiple arguments.
pub fn demonstrate_formatted_logging() {
    let user_id = 12345;
    let operation = "transaction";
    let amount = 100.50;

    module_info!(
        "LoggerDemo",
        "User {} initiated {} for amount ${:.2}",
        user_id,
        operation,
        amount
    );
    module_debug!(
        "LoggerDemo",
        "Processing operation with parameters: user_id={}, operation={}, amount={}",
        user_id,
        operation,
        amount
    );

    // Simulate some error condition
    if amount > 100.0 {
        module_warn!("LoggerDemo", "Large transaction detected: ${:.2}", amount);
    }
}

/// Demonstrates conditional logging based on different scenarios.
pub fn demonstrate_conditional_logging(success: bool, retry_count: u32) {
    if success {
        module_info!(
            "LoggerDemo",
            "Operation completed successfully after {} attempts",
            retry_count
        );
    } else {
        if retry_count < 3 {
            module_warn!(
                "LoggerDemo",
                "Operation failed, attempt {} of 3",
                retry_count
            );
        } else {
            module_error!(
                "LoggerDemo",
                "Operation failed after {} attempts, giving up",
                retry_count
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_logging_functions() {
        // These tests mainly ensure the logging functions compile and run
        // without panicking. The actual log output would need to be tested
        // with a custom logger implementation.

        demonstrate_logging();
        demonstrate_formatted_logging();
        demonstrate_conditional_logging(true, 1);
        demonstrate_conditional_logging(false, 1);
        demonstrate_conditional_logging(false, 5);
    }
}
