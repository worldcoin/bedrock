//! Verifies the logging macros are free at rest, from outside the crate.
//!
//! This binary deliberately never calls `set_logger`, which the unit tests inside
//! `bedrock` cannot guarantee: `LOGGER_INSTANCE` is a process-global `OnceLock`, so
//! any single test there may find a logger another test already installed. Being a
//! separate integration binary also exercises `info!`/`critical!` as an external
//! crate consumes them, macro export path included.

use std::cell::Cell;
use std::fmt;

use bedrock::{critical, error, info};

/// Counts how many times it is formatted, standing in for a `Display` impl that is
/// expensive or has side effects.
struct CountsFormatting<'a>(&'a Cell<usize>);

impl fmt::Display for CountsFormatting<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.set(self.0.get() + 1);
        f.write_str("formatted")
    }
}

/// With no host logger, a structured call site must not format its field values.
///
/// The message arguments are a separate matter: `format_args!` captures them lazily
/// and the macro drops them unformatted too, so neither counter moves.
#[test]
fn no_logger_installed_means_no_attribute_formatting() {
    let fields = Cell::new(0);
    let message_args = Cell::new(0);

    info!(
        expensive = CountsFormatting(&fields),
        "dropped on the floor: {}",
        CountsFormatting(&message_args)
    );
    error!(a = CountsFormatting(&fields), b = 1, "also dropped");
    critical!(c = CountsFormatting(&fields), "and this one");

    assert_eq!(
        fields.get(),
        0,
        "attribute values must not be formatted without a logger"
    );
    assert_eq!(
        message_args.get(),
        0,
        "message arguments must not be formatted without a logger"
    );
}

/// A fieldless call site must stay free at rest too.
#[test]
fn no_logger_installed_means_no_message_formatting() {
    let formatted = Cell::new(0);

    info!("{}", CountsFormatting(&formatted));

    assert_eq!(formatted.get(), 0, "nothing should have been formatted");
}
