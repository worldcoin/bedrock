//! Filesystem access for Bedrock modules.
//!
//! Bedrock owns its file IO directly. Passing files through the FFI boundary consumes at
//! least 2x more memory with `UniFFI`.

use std::fs::{self, File};
use std::io::{self, BufReader, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use thiserror::Error;

use crate::primitives::config::get_config;
use crate::primitives::PrimitiveError;

/// Size of the buffer used to stream files when checksumming.
const CHECKSUM_CHUNK_SIZE: usize = 65_536; // 64 KiB

/// Directory under the root where in-flight writes are staged for atomic writes.
pub(crate) const ATOMIC_STAGED_DIRECTORY: &str = ".bedrock-staged";

/// Errors that can occur during filesystem operations
#[derive(Debug, Error, uniffi::Error)]
pub enum FileSystemError {
    /// Tried to read a file that doesn't exist
    #[error("requested file does not exist")]
    FileDoesNotExist,
    /// Something went wrong with the filesystem operation
    #[error("IO failure: {0}")]
    IoFailure(String),
    /// No root path is available because `set_config` has not been called yet
    #[error("filesystem not initialized")]
    NotInitialized,
    /// The requested path traverses outside the Bedrock root or names no file
    #[error("invalid path: {0}")]
    InvalidPath(String),
}

/// Maps an IO error where a missing file is an expected, separately reported outcome.
///
/// `std::fs` errors never embed the path they failed on, so the message is safe to log
fn io_error_or_missing(operation: &str, error: &io::Error) -> FileSystemError {
    if error.kind() == io::ErrorKind::NotFound {
        FileSystemError::FileDoesNotExist
    } else {
        FileSystemError::IoFailure(format!("failed to {operation}: {error}"))
    }
}

/// Maps an IO error where a missing file is not an expected outcome.
fn io_failure(operation: &str, error: &io::Error) -> FileSystemError {
    FileSystemError::IoFailure(format!("failed to {operation}: {error}"))
}

/// Validates the root directory and creates it if missing.
///
/// # Errors
/// - If the provided path is not absolute
/// - If unexpectedly the root directory cannot be created
pub(crate) fn prepare_root(root_path: &Path) -> Result<(), PrimitiveError> {
    if !root_path.is_absolute() {
        return Err(PrimitiveError::InvalidInput {
            attribute: "path".to_string(),
            error_message: "the Bedrock root path must be absolute".to_string(),
        });
    }

    fs::create_dir_all(root_path).map_err(|error| PrimitiveError::Generic {
        error_message: format!("create the Bedrock root directory: {error}"),
    })?;

    // ensures the staged directory is writable
    fs::create_dir_all(root_path.join(ATOMIC_STAGED_DIRECTORY)).map_err(|error| {
        PrimitiveError::Generic {
            error_message: format!(
                "the Bedrock root directory is not writable: {error}"
            ),
        }
    })
}

/// Discards writes staged but not committed (e.g. process died). Called only
/// at Bedrock initialization, so no Bedrock system has written files yet.
pub(crate) fn clear_stale_staged_writes(root_path: &Path) {
    match fs::remove_dir_all(root_path.join(ATOMIC_STAGED_DIRECTORY)) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => {
            crate::warn!(error_message = error, "Could not clear stale staged writes");
        }
    }
}

/// Appends a caller-supplied relative path to `target`, rejecting traversal.
fn append_relative(target: &mut PathBuf, path: &str) -> Result<(), FileSystemError> {
    for component in Path::new(path.trim_start_matches('/')).components() {
        match component {
            Component::Normal(segment) => {
                if segment.as_encoded_bytes().contains(&0) {
                    return Err(FileSystemError::InvalidPath(
                        "path must not contain a NUL byte".to_string(),
                    ));
                }
                target.push(segment);
            }
            Component::CurDir => (),
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(FileSystemError::InvalidPath(
                    "path must not traverse outside the Bedrock root".to_string(),
                ));
            }
        }
    }
    Ok(())
}

/// Rejects any path in an atomic staged directory. Only this module can touch it.
fn reject_staging_directory(
    root: &Path,
    resolved: &Path,
) -> Result<(), FileSystemError> {
    let reserved = resolved
        .strip_prefix(root)
        .ok()
        .and_then(|relative| relative.components().next())
        .is_some_and(|first| {
            first
                .as_os_str()
                .eq_ignore_ascii_case(std::ffi::OsStr::new(ATOMIC_STAGED_DIRECTORY))
        });

    if reserved {
        return Err(FileSystemError::InvalidPath(
            "path is inside a directory reserved by Bedrock".to_string(),
        ));
    }
    Ok(())
}

/// Names a staged file uniquely across the processes and threads sharing a root.
fn staged_file_name() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);

    let sequence = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{}-{sequence}.tmp", std::process::id())
}

/// Writes `contents` to `destination` through a staged file and an atomic rename.
fn write_atomically(
    root: &Path,
    destination: &Path,
    contents: &[u8],
) -> Result<(), FileSystemError> {
    let parent = destination.parent().unwrap_or(root);
    fs::create_dir_all(parent)
        .map_err(|error| io_failure("create parent directory", &error))?;

    let staging = root.join(ATOMIC_STAGED_DIRECTORY);
    fs::create_dir_all(&staging)
        .map_err(|error| io_failure("create atomic staged directory", &error))?;
    let staged = staging.join(staged_file_name());

    let result = (|| {
        let mut file = File::create(&staged)
            .map_err(|error| io_failure("create staged file", &error))?;
        file.write_all(contents)
            .map_err(|error| io_failure("write staged file", &error))?;

        if let Ok(existing) = fs::metadata(destination) {
            fs::set_permissions(&staged, existing.permissions())
                .map_err(|error| io_failure("carry over file permissions", &error))?;
        }

        file.sync_all()
            .map_err(|error| io_failure("flush staged file", &error))?;
        fs::rename(&staged, destination)
            .map_err(|error| io_failure("commit written file", &error))
    })();

    if result.is_err() {
        drop(fs::remove_file(&staged)); // Best effort
    }

    result
}

/// Filesystem handle scoped to a sub-directory of the configured root.
///
/// Every path passed to its methods is relative to `root / prefix`. Construct one per
/// module so files owned by different modules cannot collide; `bedrock_export` does this
/// automatically for exported structs.
pub struct ScopedFileSystem {
    /// Sub-directory of the root that scopes this handle. Empty means the root itself.
    prefix: String,
}

/// Returns a handle at the configured root, without any module scoping.
///
/// Only for paths that are already qualified relative to the root, such as backup
/// manifest entries owned by other modules. Prefer the `_bedrock_fs` handle injected by
/// `bedrock_export` for module-owned files.
#[must_use]
pub fn root_filesystem() -> ScopedFileSystem {
    ScopedFileSystem::new("")
}

impl ScopedFileSystem {
    /// Creates a handle scoped to `prefix` under the configured root.
    #[must_use]
    pub fn new(prefix: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
        }
    }

    /// Returns the configured Bedrock root.
    ///
    /// # Errors
    /// - [`FileSystemError::NotInitialized`] if `set_config` has not been called
    pub(crate) fn root() -> Result<PathBuf, FileSystemError> {
        get_config()
            .map(|config| config.root_path().to_path_buf())
            .ok_or(FileSystemError::NotInitialized)
    }

    /// Resolves a path that may name a directory, including the scope root itself.
    ///
    /// # Errors
    /// - [`FileSystemError::NotInitialized`] if no root path has been configured
    /// - [`FileSystemError::InvalidPath`] if the path escapes the scope or is reserved
    fn resolve_directory(&self, folder_path: &str) -> Result<PathBuf, FileSystemError> {
        let root = Self::root()?;

        let mut resolved = root.clone();
        append_relative(&mut resolved, &self.prefix)?;
        append_relative(&mut resolved, folder_path)?;

        reject_staging_directory(&root, &resolved)?;
        Ok(resolved)
    }

    /// Resolves a path that must name a file inside the scope.
    ///
    /// # Errors
    /// - [`FileSystemError::NotInitialized`] if no root path has been configured
    /// - [`FileSystemError::InvalidPath`] if the path escapes the scope, is reserved, or
    ///   names no file
    fn resolve_file(&self, file_path: &str) -> Result<PathBuf, FileSystemError> {
        let root = Self::root()?;

        let mut scope = root.clone();
        append_relative(&mut scope, &self.prefix)?;

        let mut resolved = scope.clone();
        append_relative(&mut resolved, file_path)?;

        if resolved == scope {
            return Err(FileSystemError::InvalidPath(
                "path must name a file, not the directory it is scoped to".to_string(),
            ));
        }

        reject_staging_directory(&root, &resolved)?;
        Ok(resolved)
    }

    /// Resolves a path without touching the filesystem, so a batch of untrusted paths can
    /// be rejected before any of them is used.
    ///
    /// # Errors
    /// - [`FileSystemError::NotInitialized`] if no root path has been configured
    /// - [`FileSystemError::InvalidPath`] if the path escapes the scope, is reserved, or
    ///   names no file
    pub fn resolved_file_path(
        &self,
        file_path: &str,
    ) -> Result<PathBuf, FileSystemError> {
        self.resolve_file(file_path)
    }

    /// Checks whether a file exists at the given path.
    ///
    /// Directories are not files: a path pointing at one reports `false`.
    ///
    /// # Errors
    /// - `FileSystemError` if the path is invalid or the metadata lookup fails
    pub fn file_exists(&self, file_path: &str) -> Result<bool, FileSystemError> {
        let path = self.resolve_file(file_path)?;
        match fs::metadata(&path) {
            Ok(metadata) => Ok(metadata.is_file()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(error) => Err(io_failure("check whether file exists", &error)),
        }
    }

    /// Reads the full contents of a file.
    ///
    /// # Errors
    /// - [`FileSystemError::FileDoesNotExist`] if the file doesn't exist
    /// - [`FileSystemError::IoFailure`] if the file cannot be read
    pub fn read_file(&self, file_path: &str) -> Result<Vec<u8>, FileSystemError> {
        let path = self.resolve_file(file_path)?;
        fs::read(&path).map_err(|error| io_error_or_missing("read file", &error))
    }

    /// Writes a file, creating any missing parent directories.
    ///
    /// The write is atomic: readers observe either the previous contents or the new ones.
    ///
    /// # Errors
    /// - [`FileSystemError::IoFailure`] if the file cannot be written
    pub fn write_file(
        &self,
        file_path: &str,
        file_buffer: &[u8],
    ) -> Result<(), FileSystemError> {
        let root = Self::root()?;
        let destination = self.resolve_file(file_path)?;
        write_atomically(&root, &destination, file_buffer)
    }

    /// Deletes a file.
    ///
    /// # Errors
    /// - [`FileSystemError::FileDoesNotExist`] if the file does not exist
    /// - [`FileSystemError::IoFailure`] if the file cannot be deleted
    pub fn delete_file(&self, file_path: &str) -> Result<(), FileSystemError> {
        let path = self.resolve_file(file_path)?;
        fs::remove_file(&path)
            .map_err(|error| io_error_or_missing("delete file", &error))
    }

    /// Lists the names of the files directly inside a directory, sorted.
    ///
    /// # Notes
    /// Names are returned without the directory path. Sub-directories are neither
    /// recursed into nor listed, and a directory that doesn't exist lists as empty.
    ///
    /// # Errors
    /// - [`FileSystemError::IoFailure`] if the directory cannot be listed
    pub fn list_files_at_directory(
        &self,
        folder_path: &str,
    ) -> Result<Vec<String>, FileSystemError> {
        let path = self.resolve_directory(folder_path)?;

        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Ok(Vec::new())
            }
            Err(error) => return Err(io_failure("list directory", &error)),
        };

        let mut file_names = Vec::new();
        for entry in entries {
            let entry =
                entry.map_err(|error| io_failure("read directory entry", &error))?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_failure("inspect directory entry", &error))?;
            if file_type.is_dir() {
                continue;
            }
            file_names.push(entry.file_name().to_string_lossy().into_owned());
        }

        file_names.sort_unstable();
        Ok(file_names)
    }

    /// Calculates the `blake3` checksum and the size in bytes of a file.
    ///
    /// The file is streamed rather than loaded into memory, so it is safe on large files.
    ///
    /// # Errors
    /// - [`FileSystemError::FileDoesNotExist`] if the path does not exist
    /// - [`FileSystemError::IoFailure`] for any other read failure
    pub fn calculate_checksum_and_size(
        &self,
        file_path: &str,
    ) -> Result<([u8; 32], u64), FileSystemError> {
        let path = self.resolve_file(file_path)?;
        let file = File::open(&path)
            .map_err(|error| io_error_or_missing("open file", &error))?;

        let mut reader = BufReader::with_capacity(CHECKSUM_CHUNK_SIZE, file);
        let mut hasher = blake3::Hasher::new();
        let size = io::copy(&mut reader, &mut hasher)
            .map_err(|error| io_failure("read file", &error))?;

        Ok((hasher.finalize().into(), size))
    }
}

#[cfg(test)]
pub(crate) fn init_test_filesystem() {
    use crate::primitives::config::{set_config, BedrockEnvironment, Os};

    static INITIALIZED: std::sync::OnceLock<()> = std::sync::OnceLock::new();

    // `get_or_init` blocks the other threads until this finishes, so no test observes a
    // half-prepared root.
    INITIALIZED.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("bedrock-tests-{}", std::process::id()));
        // A recycled PID could leave state from a previous run behind.
        drop(fs::remove_dir_all(&root));

        set_config(
            BedrockEnvironment::Staging,
            Os::Ios,
            root.to_string_lossy().into_owned(),
        )
        .expect("configure the test filesystem root");
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Returns a handle scoped to a directory only this test uses.
    ///
    /// Tests share one root, so an empty prefix here would wipe every other test's files.
    fn scoped(prefix: &str) -> ScopedFileSystem {
        assert!(!prefix.is_empty(), "tests must use a prefix of their own");

        init_test_filesystem();
        let fs = ScopedFileSystem::new(prefix);
        drop(fs::remove_dir_all(
            fs.resolve_directory("").expect("resolve scope root"),
        ));
        fs
    }

    /// Creates a root directory used by a single test.
    ///
    /// Tests that assert on staging cannot share the global root: they would observe, and
    /// `prepare_root` would delete, writes other tests have in flight.
    fn isolated_root(name: &str) -> PathBuf {
        let root =
            std::env::temp_dir().join(format!("bedrock-{name}-{}", std::process::id()));
        drop(fs::remove_dir_all(&root));
        fs::create_dir_all(&root).expect("create isolated root");
        root
    }

    /// Returns the names of the writes currently staged under `root`.
    fn staged_writes_in(root: &Path) -> Vec<String> {
        let staging = root.join(ATOMIC_STAGED_DIRECTORY);
        let Ok(entries) = fs::read_dir(&staging) else {
            return Vec::new();
        };
        entries
            .map(|entry| entry.expect("read staged entry").file_name())
            .map(|name| name.to_string_lossy().into_owned())
            .collect()
    }

    #[test]
    fn test_prepare_root_rejects_relative_paths() {
        for path in ["", "relative/dir", "./here"] {
            let error = prepare_root(Path::new(path)).unwrap_err();
            assert!(matches!(
                &error,
                PrimitiveError::InvalidInput { attribute, error_message }
                    if attribute == "path"
                        && error_message == "the Bedrock root path must be absolute"
            ));
        }
    }

    #[test]
    fn test_paths_containing_a_nul_byte_are_rejected() {
        let fs = scoped("fs_nul");

        // Lexically valid, but `std::fs` refuses it at the syscall
        for path in ["bad\0name.bin", "dir/bad\0name.bin", "ba\0d/name.bin"] {
            assert!(
                matches!(
                    fs.resolved_file_path(path),
                    Err(FileSystemError::InvalidPath(_))
                ),
                "expected `{}` to be rejected",
                path.escape_debug()
            );
            assert!(matches!(
                fs.write_file(path, b"payload"),
                Err(FileSystemError::InvalidPath(_))
            ));
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_prepare_root_rejects_a_read_only_root() {
        use std::os::unix::fs::PermissionsExt;

        let root = isolated_root("read-only-root");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o555)).unwrap();

        // A privileged user ignores the mode bits, which would make this vacuous.
        let privileged = fs::create_dir(root.join("control")).is_ok();
        if privileged {
            eprintln!("skipping: running with privileges that bypass directory modes");
        } else {
            assert!(
                matches!(prepare_root(&root), Err(PrimitiveError::Generic { .. })),
                "a root that cannot be written to must be refused"
            );
        }

        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        drop(fs::remove_dir_all(&root));
    }

    #[test]
    #[cfg(unix)]
    fn test_overwriting_keeps_the_destination_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let fs_handle = scoped("fs_perms");
        fs_handle.write_file("secret.bin", b"first").unwrap();

        let path = fs_handle.resolve_file("secret.bin").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();

        // The rename swaps in a new inode, so without carrying the mode across the file
        // would come back with the staging default.
        fs_handle.write_file("secret.bin", b"second").unwrap();

        assert_eq!(fs_handle.read_file("secret.bin").unwrap(), b"second");
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn test_prepare_root_creates_the_directory() {
        let root = std::env::temp_dir()
            .join(format!("bedrock-prepare-{}", std::process::id()))
            .join("nested");
        drop(fs::remove_dir_all(&root));

        prepare_root(&root).expect("root should be created");
        assert!(root.is_dir());

        // Idempotent: an existing root is accepted as-is.
        prepare_root(&root).expect("existing root should be accepted");

        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn test_prepare_root_reports_an_uncreatable_directory() {
        let blocker = std::env::temp_dir()
            .join(format!("bedrock-prepare-blocked-{}", std::process::id()));
        drop(fs::remove_file(&blocker));
        fs::write(&blocker, b"not a directory").expect("create blocking file");

        assert!(matches!(
            prepare_root(&blocker.join("root")),
            Err(PrimitiveError::Generic { .. })
        ));

        drop(fs::remove_file(&blocker));
    }

    /// Re-runs a single test in a child process, so it starts with no global config.
    ///
    /// The test must branch on `marker` and only assert in the child.
    fn run_in_fresh_process(test_name: &str, marker: &str) {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "--nocapture", test_name])
            .env(marker, "1")
            .output()
            .expect("re-run this test in a child process");

        let report = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "child run failed:\n{report}{}",
            String::from_utf8_lossy(&output.stderr)
        );
        // A filter that matches nothing also exits 0, which would silently pass.
        assert!(
            report.contains("1 passed"),
            "child did not run the test, only: {report}"
        );
    }

    /// Marks the child run of [`test_operations_report_not_initialized_without_a_root`].
    const UNINITIALIZED_CHILD_ENV: &str = "BEDROCK_UNINITIALIZED_FS_CHILD";

    /// Full libtest path of that test, needed to re-run exactly it in the child.
    const UNINITIALIZED_TEST_NAME: &str =
        "primitives::filesystem::tests::test_operations_report_not_initialized_without_a_root";

    #[test]
    fn test_operations_report_not_initialized_without_a_root() {
        // Every other test installs the global config, so the unconfigured path can only
        // be exercised in a fresh process.
        if std::env::var_os(UNINITIALIZED_CHILD_ENV).is_none() {
            run_in_fresh_process(UNINITIALIZED_TEST_NAME, UNINITIALIZED_CHILD_ENV);
            return;
        }

        assert!(matches!(
            root_filesystem().read_file("anything.txt"),
            Err(FileSystemError::NotInitialized)
        ));
    }

    /// Marks the child run of [`test_a_rejected_root_leaves_the_config_uncommitted`].
    const REJECTED_ROOT_CHILD_ENV: &str = "BEDROCK_REJECTED_ROOT_CHILD";

    /// Full libtest path of that test, needed to re-run exactly it in the child.
    const REJECTED_ROOT_TEST_NAME: &str =
        "primitives::filesystem::tests::test_a_rejected_root_leaves_the_config_uncommitted";

    #[test]
    fn test_a_rejected_root_leaves_the_config_uncommitted() {
        use crate::primitives::config::{
            get_config, is_initialized, set_config, BedrockEnvironment, Os,
        };

        // Needs a process where the config has not been committed yet: committing before
        // validating is exactly the regression this guards against.
        if std::env::var_os(REJECTED_ROOT_CHILD_ENV).is_none() {
            run_in_fresh_process(REJECTED_ROOT_TEST_NAME, REJECTED_ROOT_CHILD_ENV);
            return;
        }

        assert!(matches!(
            set_config(
                BedrockEnvironment::Staging,
                Os::Ios,
                "relative/bedrock".to_string()
            ),
            Err(PrimitiveError::InvalidInput { .. })
        ));
        assert!(!is_initialized(), "a rejected root must not be committed");

        // The caller can correct the path and try again.
        init_test_filesystem();
        assert!(is_initialized());

        let committed = get_config()
            .unwrap()
            .root_path()
            .to_string_lossy()
            .into_owned();
        assert!(matches!(
            set_config(BedrockEnvironment::Production, Os::Android, committed),
            Err(PrimitiveError::Generic { .. })
        ));
        assert_eq!(
            get_config().unwrap().environment(),
            BedrockEnvironment::Staging
        );

        // A refused call must not create the root it named.
        let other = std::env::temp_dir().join("bedrock-rejected-second-root");
        drop(fs::remove_dir_all(&other));
        assert!(matches!(
            set_config(
                BedrockEnvironment::Staging,
                Os::Ios,
                other.to_string_lossy().into_owned()
            ),
            Err(PrimitiveError::Generic { .. })
        ));
        assert!(!other.exists(), "a refused call must not create a root");

        // The committed root still works.
        root_filesystem()
            .write_file("still_works.txt", b"x")
            .unwrap();
    }

    #[test]
    fn test_write_read_roundtrip() {
        let fs = scoped("fs_roundtrip");
        fs.write_file("greeting.txt", b"Hello, World!").unwrap();
        assert_eq!(fs.read_file("greeting.txt").unwrap(), b"Hello, World!");
    }

    #[test]
    fn test_write_creates_missing_parent_directories() {
        let fs = scoped("fs_nested");
        fs.write_file("a/b/c/config.json", b"{}").unwrap();
        assert_eq!(fs.read_file("a/b/c/config.json").unwrap(), b"{}");
    }

    #[test]
    fn test_write_overwrites_existing_file() {
        let fs = scoped("fs_overwrite");
        fs.write_file("data.bin", b"first").unwrap();
        fs.write_file("data.bin", b"second").unwrap();
        assert_eq!(fs.read_file("data.bin").unwrap(), b"second");
    }

    #[test]
    fn test_successful_write_leaves_nothing_staged() {
        let root = isolated_root("staged-ok");
        let destination = root.join("nested").join("data.bin");

        write_atomically(&root, &destination, b"payload").unwrap();

        assert_eq!(fs::read(&destination).unwrap(), b"payload");
        assert!(
            staged_writes_in(&root).is_empty(),
            "{:?}",
            staged_writes_in(&root)
        );

        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn test_failed_write_leaves_nothing_staged() {
        let root = isolated_root("staged-fail");
        // A rename cannot replace a non-empty directory with a regular file.
        let destination = root.join("occupied");
        fs::create_dir_all(destination.join("child")).unwrap();

        assert!(matches!(
            write_atomically(&root, &destination, b"payload"),
            Err(FileSystemError::IoFailure(_))
        ));
        assert!(
            staged_writes_in(&root).is_empty(),
            "{:?}",
            staged_writes_in(&root)
        );

        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn test_paths_naming_no_file_are_rejected() {
        let fs = scoped("fs_empty_path");

        // `unpack_backup_to_filesystem` trims a leading `/`, so a payload path of `"/"`
        // arrives here as `""`. Staging these anywhere but under the root would put
        // attacker-supplied bytes outside it.
        for path in ["", "/", ".", "./"] {
            assert!(
                matches!(
                    fs.write_file(path, b"payload"),
                    Err(FileSystemError::InvalidPath(_))
                ),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(fs.read_file(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(fs.delete_file(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(fs.file_exists(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
        }
    }

    #[test]
    fn test_stale_staged_writes_are_cleared() {
        let root = isolated_root("staging-sweep");
        let orphan = root.join(ATOMIC_STAGED_DIRECTORY).join("99999-0.tmp");
        fs::create_dir_all(orphan.parent().unwrap()).unwrap();
        fs::write(&orphan, b"debris from a process killed mid-write").unwrap();

        clear_stale_staged_writes(&root);
        assert!(!orphan.exists());

        // A root that never staged anything is not an error.
        clear_stale_staged_writes(&root);

        drop(fs::remove_dir_all(&root));
    }

    #[test]
    fn test_read_missing_file_reports_does_not_exist() {
        let fs = scoped("fs_missing");
        assert!(matches!(
            fs.read_file("nope.txt"),
            Err(FileSystemError::FileDoesNotExist)
        ));
    }

    #[test]
    fn test_delete_file() {
        let fs = scoped("fs_delete");
        fs.write_file("temp.txt", b"bye").unwrap();
        assert!(fs.file_exists("temp.txt").unwrap());

        fs.delete_file("temp.txt").unwrap();
        assert!(!fs.file_exists("temp.txt").unwrap());
    }

    #[test]
    fn test_delete_missing_file_reports_does_not_exist() {
        let fs = scoped("fs_delete_missing");
        assert!(matches!(
            fs.delete_file("nope.txt"),
            Err(FileSystemError::FileDoesNotExist)
        ));
    }

    #[test]
    fn test_file_exists_is_false_for_directories() {
        let fs = scoped("fs_dir_not_file");
        fs.write_file("nested/file.txt", b"x").unwrap();
        assert!(!fs.file_exists("nested").unwrap());
    }

    #[test]
    fn test_list_files_is_not_recursive_and_excludes_directories() {
        let fs = scoped("fs_list");
        fs.write_file("data/users.txt", b"alice").unwrap();
        fs.write_file("data/metadata.txt", b"meta").unwrap();
        fs.write_file("data/subdir/nested.txt", b"nested").unwrap();

        assert_eq!(
            fs.list_files_at_directory("data").unwrap(),
            vec!["metadata.txt", "users.txt"]
        );
    }

    #[test]
    fn test_list_files_at_missing_directory_is_empty() {
        let fs = scoped("fs_list_missing");
        assert!(fs
            .list_files_at_directory("never/created")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn test_list_files_accepts_current_directory_notation() {
        let fs = scoped("fs_list_dot");
        fs.write_file("root.txt", b"x").unwrap();
        assert_eq!(fs.list_files_at_directory(".").unwrap(), vec!["root.txt"]);
    }

    #[test]
    fn test_paths_are_scoped_to_the_prefix() {
        init_test_filesystem();
        let scoped_fs = ScopedFileSystem::new("fs_scope");
        let root_fs = root_filesystem();

        scoped_fs.write_file("file.txt", b"scoped").unwrap();

        assert_eq!(
            root_fs.read_file("fs_scope/file.txt").unwrap(),
            b"scoped".to_vec()
        );
        assert!(!root_fs.file_exists("file.txt").unwrap());
    }

    #[test]
    fn test_leading_slash_is_treated_as_root_relative() {
        let fs = scoped("fs_leading_slash");
        fs.write_file("/file.txt", b"x").unwrap();
        assert!(fs.file_exists("file.txt").unwrap());
    }

    #[test]
    fn test_prefix_is_applied_even_when_the_path_repeats_it() {
        init_test_filesystem();
        let fs = ScopedFileSystem::new("fs_repeat");
        let resolved = fs.resolve_file("fs_repeat/file.txt").unwrap();
        assert!(resolved.ends_with("fs_repeat/fs_repeat/file.txt"));
    }

    #[test]
    fn test_parent_traversal_is_rejected() {
        let fs = scoped("fs_traversal");

        for path in ["../escaped.txt", "a/../../escaped.txt", "..", "a/.."] {
            assert!(
                matches!(fs.read_file(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(
                    fs.write_file(path, b"x"),
                    Err(FileSystemError::InvalidPath(_))
                ),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(fs.delete_file(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
            assert!(
                matches!(fs.file_exists(path), Err(FileSystemError::InvalidPath(_))),
                "expected `{path}` to be rejected"
            );
        }
    }

    #[test]
    fn test_scoped_writes_stage_under_the_root_not_the_scope() {
        let fs = scoped("fs_staging_location");
        fs.write_file("nested/data.bin", b"payload").unwrap();

        // Staging under the scope would put a staging directory inside every
        // module's tree, out of reach of the startup sweep.
        let scope = fs.resolve_directory("").unwrap();
        assert!(!scope.join(ATOMIC_STAGED_DIRECTORY).exists());
        assert!(!scope.join("nested").join(ATOMIC_STAGED_DIRECTORY).exists());
    }

    #[test]
    fn test_the_staging_directory_is_not_addressable() {
        init_test_filesystem();
        let fs = root_filesystem();

        // A restored backup payload must not be able to name Bedrock's own scratch
        // space; the startup sweep would delete whatever landed there.
        // Built from the constant: spelling these out let a rename silently turn this
        // test into a no-op, which is exactly what it exists to catch.
        let reserved = ATOMIC_STAGED_DIRECTORY;
        for path in [
            format!("{reserved}/planted.bin"),
            format!("/{reserved}/planted.bin"),
            format!("./{reserved}/planted.bin"),
            reserved.to_string(),
            // Same directory on a case-insensitive volume.
            format!("{}/planted.bin", reserved.to_uppercase()),
        ] {
            let path = path.as_str();
            assert!(
                matches!(
                    fs.write_file(path, b"payload"),
                    Err(FileSystemError::InvalidPath(_))
                ),
                "expected `{path}` to be rejected"
            );
        }

        assert!(matches!(
            fs.list_files_at_directory(reserved),
            Err(FileSystemError::InvalidPath(_))
        ));
    }

    #[test]
    fn test_checksum_matches_blake3_of_contents() {
        let fs = scoped("fs_checksum");
        fs.write_file("greeting.txt", b"Hello, World!").unwrap();

        let (checksum, size) = fs.calculate_checksum_and_size("greeting.txt").unwrap();
        assert_eq!(checksum, <[u8; 32]>::from(blake3::hash(b"Hello, World!")));
        assert_eq!(size, 13);
    }

    #[test]
    fn test_checksum_streams_files_larger_than_one_chunk() {
        let fs = scoped("fs_checksum_large");
        let data = vec![7_u8; CHECKSUM_CHUNK_SIZE * 3 + 11];
        fs.write_file("large.bin", &data).unwrap();

        let (checksum, size) = fs.calculate_checksum_and_size("large.bin").unwrap();
        assert_eq!(checksum, <[u8; 32]>::from(blake3::hash(&data)));
        assert_eq!(size, data.len() as u64);
    }

    #[test]
    fn test_checksum_of_missing_file_reports_does_not_exist() {
        let fs = scoped("fs_checksum_missing");
        assert!(matches!(
            fs.calculate_checksum_and_size("nope.bin"),
            Err(FileSystemError::FileDoesNotExist)
        ));
    }
}
