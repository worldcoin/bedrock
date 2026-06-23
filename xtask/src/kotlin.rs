//! Kotlin/Android bindings and packaging tasks.
//!
//! `build` cross-compiles the distributable Android `jniLibs`, while `test`
//! builds a host-platform cdylib purely so the JVM (JUnit) suite can load it
//! via JNA — Android is the only shippable Kotlin target.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::common::{capture, project_root, reset_dir, run, run_streamed};

/// Android Rust targets paired with their Android ABI (`jniLibs`) directory.
const ANDROID_ABIS: &[(&str, &str)] = &[
    ("aarch64-linux-android", "arm64-v8a"),
    ("armv7-linux-androideabi", "armeabi-v7a"),
    ("x86_64-linux-android", "x86_64"),
    ("i686-linux-android", "x86"),
];

/// Gradle version bootstrapped when a project lacks a wrapper.
const GRADLE_VERSION: &str = "8.14.3";

/// Absolute path to the `kotlin/` directory inside the workspace.
fn kotlin_dir() -> PathBuf {
    project_root().join("kotlin")
}

/// Cross-compile the `bedrock` cdylib for every Android ABI and generate Kotlin bindings.
pub fn build() -> Result<()> {
    let root = project_root();
    let android = kotlin_dir().join("bedrock-android");
    let java_src = android.join("src/main/java");
    let jni = android.join("src/main/jniLibs");

    if jni.exists() {
        std::fs::remove_dir_all(&jni)?;
    }
    let generated = java_src.join("uniffi");
    if generated.exists() {
        std::fs::remove_dir_all(&generated)?;
    }
    std::fs::create_dir_all(&java_src)?;

    for (target, abi) in ANDROID_ABIS {
        println!("Building for {target}...");
        run(Command::new("cross").current_dir(&root).args([
            "build",
            "-p",
            "bedrock",
            "--release",
            "--target",
            target,
        ]))?;
        let abi_dir = jni.join(abi);
        std::fs::create_dir_all(&abi_dir)?;
        let lib = root.join(format!("target/{target}/release/libbedrock.so"));
        std::fs::copy(&lib, abi_dir.join("libbedrock.so"))
            .with_context(|| format!("copying {}", lib.display()))?;
    }

    generate_bindings(&root, &jni.join("arm64-v8a/libbedrock.so"), &java_src)?;
    println!("✅ Android build complete!");
    Ok(())
}

/// Build a host-platform cdylib and generate Kotlin/JNA bindings for the tests.
///
/// The native library only ever feeds the JVM test suite, so it targets the
/// host platform rather than Android.
fn host_build() -> Result<()> {
    let root = project_root();
    let kotlin = kotlin_dir();
    let java_src = kotlin.join("bedrock-android/src/main/java");
    let libs = kotlin.join("libs");

    reset_dir(&java_src)?;
    reset_dir(&libs)?;

    println!("🟢 Building Rust cdylib for host platform");
    run(Command::new("cargo").current_dir(&root).args([
        "build",
        "--package",
        "bedrock",
        "--release",
    ]))?;

    let lib = host_library(&root)?;
    let name = lib.file_name().expect("host library has a filename");
    std::fs::copy(&lib, libs.join(name))
        .with_context(|| format!("copying {}", lib.display()))?;
    println!("📦 Copied {} for host", name.to_string_lossy());

    generate_bindings(&root, &lib, &java_src)?;
    println!("✅ Kotlin bindings written to {}", java_src.display());
    Ok(())
}

/// Resolve the freshly built host cdylib, choosing the platform extension.
fn host_library(root: &Path) -> Result<PathBuf> {
    let release = root.join("target/release");
    let lib = if cfg!(target_os = "macos") {
        release.join("libbedrock.dylib")
    } else if cfg!(target_os = "linux") {
        release.join("libbedrock.so")
    } else {
        bail!("unsupported host OS for Kotlin bindings");
    };
    if !lib.exists() {
        bail!("expected host library not found at {}", lib.display());
    }
    Ok(lib)
}

/// Run `uniffi-bindgen` to emit Kotlin sources from `library` into `out_dir`.
fn generate_bindings(root: &Path, library: &Path, out_dir: &Path) -> Result<()> {
    println!("🟡 Generating Kotlin bindings via uniffi-bindgen");
    run(Command::new("cargo")
        .current_dir(root)
        .args(["run", "-p", "uniffi-bindgen", "generate"])
        .arg(library)
        .args([
            "--library",
            "--language",
            "kotlin",
            "--no-format",
            "--out-dir",
        ])
        .arg(out_dir))?;
    Ok(())
}

/// Build host bindings and run the foreign Kotlin (JUnit) suite via Gradle.
pub fn test() -> Result<()> {
    let kotlin = kotlin_dir();
    let results = kotlin.join("bedrock-tests/build/test-results/test");
    if results.exists() {
        std::fs::remove_dir_all(&results)?;
    }

    set_java_home_if_unset();

    println!("🔨 Building Kotlin bindings");
    host_build()?;

    ensure_gradle_wrapper(&kotlin)?;

    println!("🧪 Running Kotlin tests...");
    let (_, status) = run_streamed(
        Command::new(kotlin.join("gradlew"))
            .current_dir(&kotlin)
            .args(["--no-daemon", "bedrock-tests:test", "--info", "--continue"]),
        is_gradle_output_interesting,
    )?;

    let summary = parse_test_summary(&results)?;
    print_test_summary(&summary);

    if summary.total == 0 {
        bail!(
            "Gradle did not execute any test cases (results: {})",
            results.display()
        );
    }
    if summary.failed > 0 || summary.errors > 0 {
        bail!(
            "{} test(s) failed and {} test error(s)",
            summary.failed,
            summary.errors
        );
    }
    if !status.success() {
        bail!("gradle test run failed ({status})");
    }
    println!();
    println!("🎉 All tests passed!");
    Ok(())
}

/// Build Android bindings and publish the AAR to the local Maven repository.
pub fn local(version: &str) -> Result<()> {
    let kotlin = kotlin_dir();
    ensure_gradle_wrapper(&kotlin)?;

    println!("Building Bedrock Android SDK (version {version})...");
    build()?;

    println!("Publishing to Maven Local...");
    run(Command::new(kotlin.join("gradlew"))
        .current_dir(&kotlin)
        .args(["--no-daemon", ":bedrock-android:publishToMavenLocal"])
        .arg(format!("-PversionName={version}")))?;

    println!();
    println!("✅ Successfully published {version} to Maven Local!");
    println!("   ~/.m2/repository/com/toolsforhumanity/bedrock/{version}/");
    println!("   implementation 'com.toolsforhumanity:bedrock:{version}'");
    Ok(())
}

/// Whitelist filter for Gradle's verbose `--info` stream: surface task
/// boundaries, per-test outcomes, build results, and compiler diagnostics.
fn is_gradle_output_interesting(line: &str) -> bool {
    let trim = line.trim_start();
    trim.starts_with("> Task")
        || trim.starts_with("BUILD ")
        || trim.contains("PASSED")
        || trim.contains("FAILED")
        || trim.contains("FAILURE")
        || line.contains("e: ")
        || line.contains("w: ")
}

struct TestSummary {
    total: usize,
    failed: usize,
    errors: usize,
}

/// Aggregate the JUnit XML reports in `results_dir` into a single summary.
fn parse_test_summary(results_dir: &Path) -> Result<TestSummary> {
    let mut summary = TestSummary {
        total: 0,
        failed: 0,
        errors: 0,
    };
    if !results_dir.exists() {
        return Ok(summary);
    }
    for entry in std::fs::read_dir(results_dir)? {
        let path = entry?.path();
        if path.extension() != Some(OsStr::new("xml")) {
            continue;
        }
        let xml = std::fs::read_to_string(&path)?;
        summary.total += sum_attr(&xml, "tests=");
        summary.failed += sum_attr(&xml, "failures=");
        summary.errors += sum_attr(&xml, "errors=");
    }
    Ok(summary)
}

/// Sum the integer value of every `name="N"` attribute occurrence in `xml`.
fn sum_attr(xml: &str, name: &str) -> usize {
    let mut total = 0;
    for chunk in xml.split(name).skip(1) {
        let digits: String = chunk
            .trim_start_matches('"')
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        total += digits.parse::<usize>().unwrap_or(0);
    }
    total
}

fn print_test_summary(s: &TestSummary) {
    let passed = s.total.saturating_sub(s.failed).saturating_sub(s.errors);
    println!("✅ Tests passed: {passed}");
    println!("❌ Tests failed: {}", s.failed);
    if s.errors > 0 {
        println!("⚠️  Test errors: {}", s.errors);
    }
}

/// Populate `JAVA_HOME` when unset so Gradle can locate a JDK.
fn set_java_home_if_unset() {
    if std::env::var_os("JAVA_HOME").is_some() {
        return;
    }
    if let Some(home) = homebrew_jdk17().or_else(java_from_path) {
        println!("🔧 Setting JAVA_HOME to: {}", home.display());
        std::env::set_var("JAVA_HOME", home);
    } else {
        println!("⚠️  JAVA_HOME not set and no JDK detected");
    }
}

/// Locate the newest Homebrew `openjdk@17` install on macOS, if present.
fn homebrew_jdk17() -> Option<PathBuf> {
    let cellar = Path::new("/opt/homebrew/Cellar/openjdk@17");
    let mut versions: Vec<PathBuf> = std::fs::read_dir(cellar)
        .ok()?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(OsStr::to_str)
                .is_some_and(|name| name.starts_with("17."))
        })
        .collect();
    versions.sort();
    let latest = versions.pop()?;
    let home = latest.join("libexec/openjdk.jdk/Contents/Home");
    home.exists().then_some(home)
}

/// Derive `JAVA_HOME` from the resolved `java` binary on `PATH` (`<home>/bin/java`).
fn java_from_path() -> Option<PathBuf> {
    let java = capture(Command::new("which").arg("java")).ok()?;
    let java = std::fs::canonicalize(java.trim()).ok()?;
    Some(java.parent()?.parent()?.to_path_buf())
}

/// Generate a Gradle wrapper for `project` if one is not already present.
fn ensure_gradle_wrapper(project: &Path) -> Result<()> {
    if project.join("gradlew").is_file() {
        return Ok(());
    }
    let version =
        std::env::var("GRADLE_VERSION").unwrap_or_else(|_| GRADLE_VERSION.to_owned());
    println!("Gradle wrapper missing, bootstrapping Gradle {version}...");

    let tmp = std::env::temp_dir().join(format!("gradle-bootstrap-{version}"));
    reset_dir(&tmp)?;
    let zip = tmp.join("gradle.zip");
    let url =
        format!("https://services.gradle.org/distributions/gradle-{version}-bin.zip");
    run(Command::new("curl").args(["-sSL", &url, "-o"]).arg(&zip))?;
    run(Command::new("unzip")
        .arg("-q")
        .arg(&zip)
        .arg("-d")
        .arg(&tmp))?;

    run(
        Command::new(tmp.join(format!("gradle-{version}/bin/gradle")))
            .arg("-p")
            .arg(project)
            .args(["wrapper", "--gradle-version", &version]),
    )?;
    std::fs::remove_dir_all(&tmp)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sums_repeated_attribute_occurrences() {
        let xml = r#"<testsuite tests="3" failures="1" errors="0"/>
<testsuite tests="2" failures="0" errors="1"/>"#;
        assert_eq!(sum_attr(xml, "tests="), 5);
        assert_eq!(sum_attr(xml, "failures="), 1);
        assert_eq!(sum_attr(xml, "errors="), 1);
    }

    #[test]
    fn missing_attribute_sums_to_zero() {
        assert_eq!(sum_attr("<testsuite name=\"x\"/>", "tests="), 0);
    }
}
