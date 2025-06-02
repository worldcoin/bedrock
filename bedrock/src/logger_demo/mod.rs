use crate::{module_debug, module_error, module_info, module_trace, module_warn};
use crate::{set_log_context, with_log_context};

/// Demonstrates the original module-specific logging macros.
pub fn demonstrate_module_logging() {
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

/// Demonstrates context-aware logging with thread-local storage and RAII.
pub fn demonstrate_context_logging() {
    // Approach 1: Using the with_log_context! macro
    with_log_context!("ContextDemo" => {
        crate::info!("This message will be prefixed with [ContextDemo]");
        crate::debug!("Debug message with value: {}", 123);
        crate::warn!("Warning from context");
    });

    // Approach 2: Using set_log_context! for manual scope management
    {
        let _ctx = set_log_context!("ManualScope");
        crate::info!("This message will be prefixed with [ManualScope]");
        crate::error!("Error from manual scope");
    } // Context automatically cleared here

    // Outside of context - no prefix
    crate::info!("This message will NOT have a prefix");
}

/// Demonstrates alternative logging approach (placeholder for future implementation).
pub fn demonstrate_scoped_logging() {
    // This approach would redefine macros in a scope but has compilation complexities
    // For now, we recommend using the context-aware approach instead
    println!("Scoped logging approach - use context-aware logging instead");
}

/// Demonstrates function-level logging context (simplified version).
pub fn demonstrate_function_logging() {
    // Note: This approach requires careful macro scoping
    // For now, we'll use the context-based approach instead
    with_log_context!("FunctionDemo" => {
        crate::info!("Function-scoped message with context");
        crate::debug!("Function debug with value: {}", 789);
        helper_function();
    });
}

fn helper_function() {
    // Helper function now uses context-aware logging
    with_log_context!("Helper" => {
        crate::warn!("Helper function warning");
    });
}

/// Demonstrates nested contexts and context stacking.
pub fn demonstrate_nested_contexts() {
    with_log_context!("Outer" => {
        crate::info!("Message from outer context");

        with_log_context!("Inner" => {
            crate::info!("Message from inner context");  // Will show [Inner]
            crate::debug!("Nested debug message");
        });

        crate::info!("Back to outer context");  // Will show [Outer] again
    });
}

/// Demonstrates logging with formatted messages and multiple arguments.
pub fn demonstrate_formatted_logging() {
    let user_id = 12345;
    let operation = "transaction";
    let amount = 100.50;

    // Using context-aware logging
    with_log_context!("Transaction" => {
        crate::info!("User {} initiated {} for amount ${:.2}", user_id, operation, amount);
        crate::debug!(
            "Processing operation with parameters: user_id={}, operation={}, amount={}",
            user_id, operation, amount
        );

        if amount > 100.0 {
            crate::warn!("Large transaction detected: ${:.2}", amount);
        }
    });
}

/// Demonstrates conditional logging based on different scenarios.
pub fn demonstrate_conditional_logging(success: bool, retry_count: u32) {
    with_log_context!("Operation" => {
        if success {
            crate::info!("Operation completed successfully after {} attempts", retry_count);
        } else {
            if retry_count < 3 {
                crate::warn!("Operation failed, attempt {} of 3", retry_count);
            } else {
                crate::error!("Operation failed after {} attempts, giving up", retry_count);
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_logging_approaches() {
        // Test all different logging approaches
        demonstrate_module_logging();
        demonstrate_context_logging();
        demonstrate_scoped_logging();
        demonstrate_function_logging();
        demonstrate_nested_contexts();
        demonstrate_formatted_logging();
        demonstrate_conditional_logging(true, 1);
        demonstrate_conditional_logging(false, 1);
        demonstrate_conditional_logging(false, 5);
    }

    #[test]
    fn test_context_isolation() {
        // Test that contexts don't leak between different scopes
        {
            let _ctx = set_log_context!("TestContext1");
            // Context should be TestContext1 here
        }

        {
            let _ctx = set_log_context!("TestContext2");
            // Context should be TestContext2 here, completely separate
        }

        // No context here
    }
}
