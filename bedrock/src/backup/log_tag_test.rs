//! Guardrail for the log tags of the backup subsystem.
//!
//! Monitors match on the `[Bedrock][<tag>]` prefix that
//! [`bedrock_export`](crate::bedrock_export) puts on every record logged from an
//! exported method. The prefix defaults to the struct name, which is not
//! something to hang an alert on, so every exported impl here has to name its
//! subsystem explicitly. This test fails when one does not.
//!
//! The tags themselves are documented in `AGENTS.md`.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

/// The subsystem tags this module is allowed to log under. Adding one means adding
/// (or widening) a monitor, so the list is deliberately short.
const APPROVED_TAGS: [&str; 3] = ["Backup", "Turnkey", "TurnkeyMigration"];

/// The attribute that injects the log context, with or without a `crate::` qualifier.
const EXPORT_ATTRIBUTE: &str = "bedrock_export";

#[test]
fn every_exported_impl_declares_an_approved_log_tag() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/backup");
    let sources = rust_sources(&root);
    assert!(
        !sources.is_empty(),
        "no sources found under {}",
        root.display()
    );

    let mut untagged: Vec<String> = Vec::new();
    let mut exports = 0_usize;
    for path in sources {
        let content = std::fs::read_to_string(&path).expect("read source file");
        let file = path.strip_prefix(&root).unwrap_or(path.as_path());
        for attribute in export_attributes(&content) {
            exports += 1;
            if !declares_approved_tag(attribute.text) {
                untagged.push(format!(
                    "backup/{}:{}: {}",
                    file.display(),
                    attribute.line,
                    attribute.text
                ));
            }
        }
    }

    assert!(exports > 0, "no #[{EXPORT_ATTRIBUTE}] impls found to check");
    assert!(
        untagged.is_empty(),
        "these exported impls do not declare a log_tag from {APPROVED_TAGS:?}, so the \
         records they log are not alertable:\n  {}",
        untagged.join("\n  ")
    );
}

/// An `#[bedrock_export(…)]` attribute found in a source file.
struct ExportAttribute<'a> {
    /// The attribute arguments, from the macro name up to the closing `]`.
    text: &'a str,
    /// 1-indexed line the attribute starts on.
    line: usize,
}

/// Every `.rs` file under `dir`, recursively, excluding test modules: nothing they
/// export reaches production.
fn rust_sources(dir: &Path) -> Vec<PathBuf> {
    let mut sources = Vec::new();
    for entry in std::fs::read_dir(dir).expect("read source directory") {
        let path = entry.expect("read directory entry").path();
        if path.is_dir() {
            sources.extend(rust_sources(&path));
        } else if is_checked_source(&path) {
            sources.push(path);
        }
    }
    sources.sort();
    sources
}

/// Whether `path` is a Rust source whose exported impls must declare a tag.
fn is_checked_source(path: &Path) -> bool {
    if path.extension().and_then(OsStr::to_str) != Some("rs") {
        return false;
    }
    path.file_stem()
        .and_then(OsStr::to_str)
        .is_some_and(|stem| !stem.ends_with("test") && !stem.ends_with("tests"))
}

/// Finds the export attributes in `content`, skipping other attributes, imports and
/// mentions in comments.
fn export_attributes(content: &str) -> Vec<ExportAttribute<'_>> {
    let mut attributes = Vec::new();
    for (position, _) in content.match_indices("#[") {
        let before = &content[..position];
        let line_start = before.rfind('\n').map_or(0, |index| index + 1);
        if before[line_start..].contains("//") {
            continue;
        }
        let rest = &content[position + "#[".len()..];
        let end = rest.find(']').unwrap_or(rest.len());
        let attribute = &rest[..end];
        let macro_name = attribute
            .split(['(', ',', ' ', '\n'])
            .next()
            .and_then(|path| path.rsplit("::").next());
        if macro_name != Some(EXPORT_ATTRIBUTE) {
            continue;
        }
        attributes.push(ExportAttribute {
            text: attribute,
            line: before.matches('\n').count() + 1,
        });
    }
    attributes
}

/// Whether the attribute declares `log_tag = "<approved>"`.
fn declares_approved_tag(attribute: &str) -> bool {
    APPROVED_TAGS
        .iter()
        .any(|tag| attribute.contains(&format!("log_tag = \"{tag}\"")))
}

/// Tests for the scanner above, so a change to it cannot quietly stop catching
/// untagged impls.
mod scanner {
    use super::{declares_approved_tag, export_attributes};

    #[test]
    fn tagged_attributes_are_accepted() {
        let source = "#[bedrock_export(log_tag = \"Backup\")]\nimpl BackupManager {}";
        let attributes = export_attributes(source);
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].line, 1);
        assert!(declares_approved_tag(attributes[0].text));
    }

    #[test]
    fn a_bare_export_is_reported() {
        let source = "struct S;\n\n#[bedrock_export]\nimpl S {}";
        let attributes = export_attributes(source);
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].line, 3);
        assert!(!declares_approved_tag(attributes[0].text));
    }

    /// A tag nobody has built a monitor for is as good as no tag.
    #[test]
    fn an_unapproved_tag_is_reported() {
        assert!(!declares_approved_tag(
            "bedrock_export(log_tag = \"Whatever\")"
        ));
    }

    #[test]
    fn qualified_and_multiline_attributes_are_found() {
        let source =
            "#[crate::bedrock_export(\n    log_tag = \"Turnkey\"\n)]\nimpl T {}";
        let attributes = export_attributes(source);
        assert_eq!(attributes.len(), 1);
        assert!(declares_approved_tag(attributes[0].text));
    }

    #[test]
    fn other_attributes_and_imports_are_ignored() {
        for source in [
            "use bedrock_macros::{bedrock_error, bedrock_export};",
            "#[derive(uniffi::Object, Clone, Debug, Default)]\nstruct S;",
            "#[uniffi::export]\nimpl S {}",
        ] {
            assert!(
                export_attributes(source).is_empty(),
                "unexpectedly matched: {source}"
            );
        }
    }

    #[test]
    fn mentions_in_comments_are_ignored() {
        assert!(export_attributes("// #[bedrock_export] is applied above").is_empty());
        assert!(export_attributes("/// See `bedrock_export` for details.").is_empty());
    }
}
