/// Example migration processors
///
/// This module contains skeleton implementations of migration processors
/// that can be used as templates for actual migrations.
mod example_processor;

/// NFC credential refresh processor
pub mod nfc_refresh_processor;

pub use nfc_refresh_processor::{
    ForeignNfcProcessor, NfcProcessorResult, NfcRefreshProcessor,
};
