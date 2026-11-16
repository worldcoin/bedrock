use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError};

use async_trait::async_trait;
use bedrock::migration::{
    MigrationController, MigrationError, MigrationProcessor, MigrationStatus,
    ProcessorResult,
};
use bedrock::primitives::key_value_store::{
    DeviceKeyValueStore, InMemoryDeviceKeyValueStore, KeyValueStoreError,
};
use bedrock::primitives::logger::{set_logger, LogLevel, Logger};

type Record = (LogLevel, String, HashMap<String, String>);

#[derive(Default)]
struct CapturingLogger(Mutex<Vec<Record>>);

impl Logger for CapturingLogger {
    fn log(
        &self,
        level: LogLevel,
        message: String,
        attributes: HashMap<String, String>,
    ) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push((level, message, attributes));
    }
}

impl CapturingLogger {
    fn take(&self) -> Vec<Record> {
        std::mem::take(&mut *self.0.lock().unwrap_or_else(PoisonError::into_inner))
    }
}

#[derive(Clone, Copy)]
enum Outcome {
    Success,
    Retryable,
    Terminal,
    Unexpected,
    Inapplicable,
    ApplicabilityError,
}

struct Processor(Outcome);

#[async_trait]
impl MigrationProcessor for Processor {
    fn migration_id(&self) -> String {
        "telemetry.test.v1".to_owned()
    }

    async fn is_applicable(&self) -> Result<bool, MigrationError> {
        match self.0 {
            Outcome::Inapplicable => Ok(false),
            Outcome::ApplicabilityError => {
                Err(MigrationError::InvalidOperation("applicability".to_owned()))
            }
            _ => Ok(true),
        }
    }

    async fn execute(&self) -> Result<ProcessorResult, MigrationError> {
        match self.0 {
            Outcome::Success => Ok(ProcessorResult::Success),
            Outcome::Retryable => Ok(ProcessorResult::Retryable {
                error_code: "RETRY".to_owned(),
                error_message: "retry".to_owned(),
            }),
            Outcome::Terminal => Ok(ProcessorResult::Terminal {
                error_code: "TERMINAL".to_owned(),
                error_message: "terminal".to_owned(),
            }),
            Outcome::Unexpected => {
                Err(MigrationError::InvalidOperation("unexpected".to_owned()))
            }
            Outcome::Inapplicable | Outcome::ApplicabilityError => {
                panic!("inapplicable processors must not execute")
            }
        }
    }
}

fn assert_events(logger: &CapturingLogger, namespace: &str, expected: &[&str]) {
    let records = logger.take();
    let events: Vec<_> = records
        .iter()
        .map(|(_, message, attributes)| {
            assert_eq!(
                attributes.len(),
                1,
                "legacy attribute schema must not change"
            );
            assert_eq!(attributes["bedrock_version"], env!("CARGO_PKG_VERSION"));
            if namespace != "migration" {
                assert!(!message.contains("migration."), "{message}");
                assert!(!message.contains("migration_run."), "{message}");
            }
            let message = message
                .strip_prefix("[Bedrock][MigrationController] ")
                .expect("existing logging context must be preserved");
            let (event, _) = message.split_once(' ').unwrap();
            let expected_fields = if event.ends_with("_run.started") {
                "total_processors timestamp"
            } else if event.ends_with("_run.completed") {
                "total succeeded failed_retryable failed_terminal skipped duration_ms timestamp pending"
            } else if event.ends_with(".started") {
                "id attempt timestamp"
            } else if event.ends_with(".succeeded") {
                "id attempt duration_ms timestamp"
            } else if event.ends_with(".failed_retryable") || event.ends_with(".failed_terminal") {
                "id attempt duration_ms error_code error_message timestamp"
            } else if event.ends_with(".failed_unexpected") {
                "id attempt duration_ms error timestamp"
            } else if event.ends_with(".is_applicable_error") {
                "id error timestamp"
            } else if event.ends_with(".skipped") {
                "id reason timestamp"
            } else if event.ends_with(".storage_error") {
                "error timestamp"
            } else {
                panic!("unrecognized event: {event}");
            };
            let fields: Vec<_> = message.split_whitespace().skip(1)
                .map(|field| field.split_once('=').unwrap().0).collect();
            assert_eq!(fields, expected_fields.split_whitespace().collect::<Vec<_>>());
            for field in message.split_whitespace().skip(1) {
                if let Some(duration) = field.strip_prefix("duration_ms=") {
                    assert!(duration.parse::<i64>().unwrap() >= 0);
                }
                if let Some(timestamp) = field.strip_prefix("timestamp=") {
                    chrono::DateTime::parse_from_rfc3339(timestamp).unwrap();
                }
            }
            message.split_whitespace().next().unwrap().to_owned()
        })
        .collect();
    let expected: Vec<_> = expected
        .iter()
        .map(|event| event.replace("migration", namespace))
        .collect();
    assert_eq!(events, expected);
    for (level, message, _) in records {
        let event = message.split_whitespace().nth(1).unwrap();
        let expected_level = if event.ends_with(".failed_retryable") {
            LogLevel::Warn
        } else if event.contains(".failed_")
            || event.ends_with(".storage_error")
            || event.ends_with(".is_applicable_error")
        {
            LogLevel::Error
        } else {
            LogLevel::Info
        };
        assert_eq!(format!("{level:?}"), format!("{expected_level:?}"));
    }
}

#[tokio::test]
async fn namespaces_isolate_events_without_changing_records_or_outcomes() {
    let logger = Arc::new(CapturingLogger::default());
    set_logger(logger.clone());
    logger.take();
    for namespace in [None, Some("nonblocking")] {
        let label = namespace.unwrap_or("migration");
        for (outcome, event, status) in [
            (Outcome::Success, "succeeded", MigrationStatus::Succeeded),
            (
                Outcome::Retryable,
                "failed_retryable",
                MigrationStatus::FailedRetryable,
            ),
            (
                Outcome::Terminal,
                "failed_terminal",
                MigrationStatus::FailedTerminal,
            ),
            (
                Outcome::Unexpected,
                "failed_unexpected",
                MigrationStatus::FailedRetryable,
            ),
        ] {
            let store = Arc::new(InMemoryDeviceKeyValueStore::new());
            let controller = MigrationController::new(
                store.clone(),
                None,
                vec![Arc::new(Processor(outcome))],
            );
            let summary = controller
                .run_migrations(namespace.map(str::to_owned))
                .await
                .unwrap();
            assert_eq!(summary.total, 1);
            match status {
                MigrationStatus::Succeeded => assert_eq!(summary.succeeded, 1),
                MigrationStatus::FailedRetryable => {
                    assert_eq!(summary.failed_retryable, 1)
                }
                MigrationStatus::FailedTerminal => {
                    assert_eq!(summary.failed_terminal, 1)
                }
                _ => unreachable!(),
            }
            assert_events(
                &logger,
                label,
                &[
                    "migration_run.started",
                    "migration.started",
                    &format!("migration.{event}"),
                    "migration_run.completed",
                ],
            );
            let record = controller.list_all_records().unwrap().remove(0);
            assert_eq!(record.migration_id, "telemetry.test.v1");
            assert_eq!(record.status, status);
            assert_eq!(record.attempts, 1);
            store.get("migration:telemetry.test.v1".to_owned()).unwrap();
            if matches!(
                status,
                MigrationStatus::Succeeded | MigrationStatus::FailedTerminal
            ) {
                let summary = controller.run_migrations(None).await.unwrap();
                assert_eq!(summary.skipped, 1);
                let expected = if matches!(status, MigrationStatus::FailedTerminal) {
                    vec![
                        "migration_run.started",
                        "migration.skipped",
                        "migration_run.completed",
                    ]
                } else {
                    vec!["migration_run.started", "migration_run.completed"]
                };
                assert_events(&logger, "migration", &expected);
            }
        }
        for outcome in [Outcome::Inapplicable, Outcome::ApplicabilityError] {
            let controller = MigrationController::new(
                Arc::new(InMemoryDeviceKeyValueStore::new()),
                None,
                vec![Arc::new(Processor(outcome))],
            );
            assert_eq!(
                controller
                    .run_migrations(namespace.map(str::to_owned))
                    .await
                    .unwrap()
                    .skipped,
                1
            );
            let expected = if matches!(outcome, Outcome::ApplicabilityError) {
                vec![
                    "migration_run.started",
                    "migration.is_applicable_error",
                    "migration_run.completed",
                ]
            } else {
                vec!["migration_run.started", "migration_run.completed"]
            };
            assert_events(&logger, label, &expected);
        }
        let controller = MigrationController::new(
            Arc::new(FailingStore),
            None,
            vec![Arc::new(Processor(Outcome::Success))],
        );
        assert_eq!(
            controller
                .run_migrations(namespace.map(str::to_owned))
                .await
                .unwrap()
                .failed_retryable,
            1
        );
        assert_events(
            &logger,
            label,
            &[
                "migration_run.started",
                "migration.started",
                "migration.storage_error",
                "migration_run.completed",
            ],
        );
    }
}

struct FailingStore;

impl DeviceKeyValueStore for FailingStore {
    fn get(&self, _key: String) -> Result<String, KeyValueStoreError> {
        Err(KeyValueStoreError::KeyNotFound)
    }

    fn set(&self, _key: String, _value: String) -> Result<(), KeyValueStoreError> {
        Err(KeyValueStoreError::UpdateFailure)
    }

    fn delete(&self, _key: String) -> Result<(), KeyValueStoreError> {
        Err(KeyValueStoreError::UpdateFailure)
    }
}

#[tokio::test]
async fn invalid_namespaces_are_rejected_before_execution() {
    let store = Arc::new(InMemoryDeviceKeyValueStore::new());
    let controller = MigrationController::new(
        store.clone(),
        None,
        vec![Arc::new(Processor(Outcome::Success))],
    );
    for namespace in [
        "",
        "Bad",
        "0bad",
        "bad.name",
        "bad\nname",
        "bad name",
        "é",
        &"x".repeat(65),
    ] {
        assert!(matches!(
            controller.run_migrations(Some(namespace.to_owned())).await,
            Err(MigrationError::InvalidOperation(_))
        ));
    }
    assert!(matches!(
        store.get("migration:telemetry.test.v1".to_owned()),
        Err(KeyValueStoreError::KeyNotFound)
    ));
}
