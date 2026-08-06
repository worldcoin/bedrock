//! Shared process and filesystem helpers for the build-automation tasks.
//!
//! All paths are resolved relative to the workspace root so the commands
//! behave the same whether invoked from the root or a sub-directory.

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};

use anyhow::{bail, Context, Result};

/// Absolute path to the workspace root.
pub fn project_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask Cargo.toml lives one directory below the workspace root")
        .to_path_buf()
}

/// Run `cmd` to completion; return an error if it exits non-zero.
pub fn run(cmd: &mut Command) -> Result<()> {
    let pretty = format!("{cmd:?}");
    let status = cmd
        .status()
        .with_context(|| format!("failed to spawn: {pretty}"))?;
    if !status.success() {
        bail!("command failed ({status}): {pretty}");
    }
    Ok(())
}

/// Run `cmd`, capturing the merged stdout+stderr stream into a `String` while
/// live-printing only the lines for which `show` returns `true`. The full
/// buffer is returned so callers can post-process noise that was filtered from
/// the console (e.g. parse test counts). Equivalent of bash's `2>&1` redirect.
pub fn run_streamed(
    cmd: &mut Command,
    show: impl Fn(&str) -> bool,
) -> Result<(String, ExitStatus)> {
    let pretty = format!("{cmd:?}");
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to spawn: {pretty}"))?;
    let stdout = child.stdout.take().expect("stdout was piped");
    let stderr = child.stderr.take().expect("stderr was piped");

    let (sender, receiver) = std::sync::mpsc::channel::<String>();
    let stderr_sender = sender.clone();
    let stdout_thread = std::thread::spawn(move || forward_lines(stdout, &sender));
    let stderr_thread =
        std::thread::spawn(move || forward_lines(stderr, &stderr_sender));

    let mut buffer = String::new();
    for line in receiver {
        if show(&line) {
            println!("{line}");
        }
        buffer.push_str(&line);
        buffer.push('\n');
    }
    let _ = stdout_thread.join();
    let _ = stderr_thread.join();
    let status = child.wait()?;
    Ok((buffer, status))
}

fn forward_lines<R: std::io::Read>(stream: R, sink: &std::sync::mpsc::Sender<String>) {
    for line in std::io::BufReader::new(stream)
        .lines()
        .map_while(Result::ok)
    {
        if sink.send(line).is_err() {
            break;
        }
    }
}

/// Run `cmd` to completion and return its captured stdout as a UTF-8 string.
pub fn capture(cmd: &mut Command) -> Result<String> {
    let pretty = format!("{cmd:?}");
    let out = cmd
        .output()
        .with_context(|| format!("failed to spawn: {pretty}"))?;
    if !out.status.success() {
        bail!("command failed ({}): {pretty}", out.status);
    }
    String::from_utf8(out.stdout).context("non-utf8 command output")
}

/// Remove `path` (recursively) if it exists, then recreate it as an empty directory.
pub fn reset_dir(path: &Path) -> Result<()> {
    if path.exists() {
        std::fs::remove_dir_all(path)
            .with_context(|| format!("removing {}", path.display()))?;
    }
    std::fs::create_dir_all(path)
        .with_context(|| format!("creating {}", path.display()))?;
    Ok(())
}

/// Return `true` when running inside GitHub Actions or a generic CI environment.
pub fn in_ci() -> bool {
    std::env::var("CI").as_deref() == Ok("true")
        || std::env::var("GITHUB_ACTIONS").as_deref() == Ok("true")
}
