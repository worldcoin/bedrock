//! Swift bindings and packaging tasks.

use std::ffi::OsStr;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::common::{capture, in_ci, project_root, reset_dir, run, run_streamed};

const IOS_DEPLOYMENT_TARGET: &str = "13.0";
const IOS_RUSTFLAGS: &str = "-C link-arg=-Wl,-application_extension";
const IOS_TARGETS: &[&str] = &[
    "aarch64-apple-ios-sim",
    "aarch64-apple-ios",
    "x86_64-apple-ios",
];
const FRAMEWORK_NAME: &str = "BedrockFFI";

/// Absolute path to the `swift/` directory inside the workspace.
fn swift_dir() -> PathBuf {
    project_root().join("swift")
}

/// Build the entire output for Swift bindings into `Bedrock.xcframework`.
pub fn build(out_dir: Option<&Path>) -> Result<()> {
    let root = project_root();
    let swift = swift_dir();
    let out_dir = match out_dir {
        Some(p) if p.is_absolute() => p.to_path_buf(),
        Some(p) => swift.join(p),
        None => swift.clone(),
    };

    let ios_build = swift.join("ios_build");
    let sources_dir = out_dir.join("Sources/Bedrock");
    let headers_dir = ios_build.join("Headers/Bedrock");
    let bindings_dir = ios_build.join("bindings");
    let sim_universal_dir = ios_build.join("target/universal-ios-sim/release");
    let framework_out = out_dir.join("Bedrock.xcframework");

    println!(
        "Building Bedrock.xcframework -> {}",
        framework_out.display()
    );

    if ios_build.exists() {
        std::fs::remove_dir_all(&ios_build)?;
    }
    if framework_out.exists() {
        std::fs::remove_dir_all(&framework_out)?;
    }
    for dir in [
        &bindings_dir,
        &sim_universal_dir,
        &sources_dir,
        &headers_dir,
    ] {
        std::fs::create_dir_all(dir)?;
    }

    build_ios_static_libs(&root)?;
    let sim_universal = lipo_universal_sim(&root, &sim_universal_dir)?;
    generate_uniffi_bindings(&root, &bindings_dir)?;
    assemble_ffi_module(&bindings_dir, &sources_dir, &headers_dir)?;
    create_xcframework(
        &root.join("target/aarch64-apple-ios/release/libbedrock.a"),
        &sim_universal,
        &headers_dir,
        &ios_build.join("Frameworks"),
        &framework_out,
    )?;

    std::fs::remove_dir_all(&ios_build)?;
    println!(
        "✅ Swift framework built successfully at: {}",
        framework_out.display()
    );
    Ok(())
}

/// `cargo build` the `bedrock` crate for every iOS target (device, arm sim, x86 sim).
fn build_ios_static_libs(root: &Path) -> Result<()> {
    for target in IOS_TARGETS {
        run(Command::new("cargo")
            .current_dir(root)
            .args(["build", "--package", "bedrock", "--release", "--target"])
            .arg(target)
            .env("IPHONEOS_DEPLOYMENT_TARGET", IOS_DEPLOYMENT_TARGET)
            .env("RUSTFLAGS", IOS_RUSTFLAGS))?;
    }
    Ok(())
}

/// Combine the arm + x86 simulator static libs into a universal binary at `out_dir/libbedrock.a`.
fn lipo_universal_sim(root: &Path, out_dir: &Path) -> Result<PathBuf> {
    let sim_arm = root.join("target/aarch64-apple-ios-sim/release/libbedrock.a");
    let sim_x86 = root.join("target/x86_64-apple-ios/release/libbedrock.a");
    let universal = out_dir.join("libbedrock.a");
    run(Command::new("lipo")
        .arg("-create")
        .args([&sim_arm, &sim_x86])
        .arg("-output")
        .arg(&universal))?;
    run(Command::new("lipo").arg("-info").arg(&universal))?;
    Ok(universal)
}

/// Run `uniffi-bindgen` against the simulator dylib to emit Swift sources and FFI headers.
fn generate_uniffi_bindings(root: &Path, out_dir: &Path) -> Result<()> {
    println!("Generating Swift bindings...");
    let sim_dylib = root.join("target/aarch64-apple-ios-sim/release/libbedrock.dylib");
    run(Command::new("cargo")
        .current_dir(root)
        .args(["run", "-p", "uniffi-bindgen", "generate"])
        .arg(&sim_dylib)
        .args([
            "--library",
            "--language",
            "swift",
            "--no-format",
            "--out-dir",
        ])
        .arg(out_dir))?;
    Ok(())
}

/// Xcode 16's explicit-module scanner resolves a single clang module per SPM
/// `.binaryTarget`, so multiple top-level FFI modules in one xcframework would
/// leave all but one unresolved. Collapse the per-crate uniffi headers into one
/// umbrella module named `BedrockFFI` and rewrite the matching `import ...FFI`
/// lines in the generated Swift sources.
fn assemble_ffi_module(
    bindings_dir: &Path,
    sources_dir: &Path,
    headers_dir: &Path,
) -> Result<()> {
    let mut ffi_headers: Vec<String> = Vec::new();
    for entry in std::fs::read_dir(bindings_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name
            .to_str()
            .with_context(|| {
                format!("non-utf8 binding filename: {}", entry.path().display())
            })?
            .to_owned();
        if name.ends_with("FFI.h") {
            ffi_headers.push(name);
        }
    }
    ffi_headers.sort();
    if ffi_headers.is_empty() {
        bail!("uniffi-bindgen did not emit any *FFI.h headers");
    }

    rewrite_swift_imports(bindings_dir, sources_dir)?;
    write_umbrella_modulemap(&headers_dir.join("module.modulemap"), &ffi_headers)?;
    for header in &ffi_headers {
        std::fs::rename(bindings_dir.join(header), headers_dir.join(header))?;
    }
    Ok(())
}

/// Assemble both platform slices as real `BedrockFFI.framework` bundles and hand them to
/// `xcodebuild -create-xcframework`.
fn create_xcframework(
    device_lib: &Path,
    sim_lib: &Path,
    headers_dir: &Path,
    frameworks_dir: &Path,
    out: &Path,
) -> Result<()> {
    println!("Creating XCFramework...");
    let device_framework = frameworks_dir
        .join("ios-arm64")
        .join(format!("{FRAMEWORK_NAME}.framework"));
    let sim_framework = frameworks_dir
        .join("ios-arm64_x86_64-simulator")
        .join(format!("{FRAMEWORK_NAME}.framework"));

    make_framework(&device_framework, device_lib, "iPhoneOS", headers_dir)?;
    make_framework(&sim_framework, sim_lib, "iPhoneSimulator", headers_dir)?;

    run(Command::new("xcodebuild")
        .arg("-create-xcframework")
        .arg("-framework")
        .arg(&device_framework)
        .arg("-framework")
        .arg(&sim_framework)
        .arg("-output")
        .arg(out))?;
    Ok(())
}

/// Assemble one `BedrockFFI.framework` slice from a static library and the umbrella
/// header/modulemap, as a real framework bundle (`Headers/`, `Modules/module.modulemap`,
/// `Info.plist`) rather than a flat headers dir.
fn make_framework(
    framework_dir: &Path,
    static_lib: &Path,
    platform: &str,
    headers_dir: &Path,
) -> Result<()> {
    reset_dir(framework_dir)?;
    let headers_out = framework_dir.join("Headers");
    let modules_out = framework_dir.join("Modules");
    std::fs::create_dir_all(&headers_out)?;
    std::fs::create_dir_all(&modules_out)?;

    std::fs::copy(static_lib, framework_dir.join(FRAMEWORK_NAME))?;

    for entry in std::fs::read_dir(headers_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() == Some(OsStr::new("h")) {
            std::fs::copy(&path, headers_out.join(path.file_name().expect("named")))?;
        }
    }
    std::fs::copy(
        headers_dir.join("module.modulemap"),
        modules_out.join("module.modulemap"),
    )?;

    std::fs::write(
        framework_dir.join("Info.plist"),
        framework_info_plist(FRAMEWORK_NAME, platform),
    )?;
    Ok(())
}

/// Render an `Info.plist` for a static-library framework bundle.
fn framework_info_plist(name: &str, platform: &str) -> String {
    include_str!("templates/swift_framework_info.plist")
        .replace("__NAME__", name)
        .replace("__PLATFORM__", platform)
        .replace("__IOS_DEPLOYMENT_TARGET__", IOS_DEPLOYMENT_TARGET)
}

/// Move each generated `.swift` file into `sources_dir`, rewriting the
/// per-crate FFI module imports to the single umbrella `BedrockFFI` module.
fn rewrite_swift_imports(bindings_dir: &Path, sources_dir: &Path) -> Result<()> {
    for entry in std::fs::read_dir(bindings_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("swift")) {
            continue;
        }
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .with_context(|| format!("bad swift filename: {}", path.display()))?;
        let per_crate = format!("{stem}FFI");
        let content = std::fs::read_to_string(&path)?
            .replace(&format!("canImport({per_crate})"), "canImport(BedrockFFI)")
            .replace(&format!("import {per_crate}"), "import BedrockFFI");
        let dest =
            sources_dir.join(path.file_name().expect("read_dir entry has a name"));
        std::fs::write(&dest, content)?;
        std::fs::remove_file(&path)?;
    }
    Ok(())
}

/// Emit a clang modulemap declaring a single `BedrockFFI` framework module over all FFI
/// headers. Declared as a `framework module` (rather than a plain `module`) because this
/// modulemap is only ever consumed from inside the real `BedrockFFI.framework` bundle built by
/// `make_framework`.
fn write_umbrella_modulemap(path: &Path, headers: &[String]) -> Result<()> {
    let mut out = String::from("framework module BedrockFFI {\n");
    for h in headers {
        writeln!(out, "    header \"{h}\"").expect("writing to String is infallible");
    }
    out.push_str("    export *\n");
    out.push_str("    use \"Darwin\"\n");
    out.push_str("    use \"_Builtin_stdbool\"\n");
    out.push_str("    use \"_Builtin_stdint\"\n");
    out.push_str("}\n");
    std::fs::write(path, out)?;
    Ok(())
}

/// Build the package into `swift/local_build/bedrock-swift/` for SPM `file://` consumption.
pub fn local() -> Result<()> {
    let local_build = swift_dir().join("local_build/bedrock-swift");
    if local_build.exists() {
        std::fs::remove_dir_all(&local_build)?;
    }
    std::fs::create_dir_all(&local_build)?;

    build(Some(&local_build))?;
    let binary_target = r#".binaryTarget(
            name: "BedrockFFI",
            path: "Bedrock.xcframework"
        )"#;
    std::fs::write(
        local_build.join("Package.swift"),
        render_package_swift(binary_target),
    )?;

    println!();
    println!("✅ Swift package built successfully!");
    println!();
    println!("📦 Package location: {}", local_build.display());
    println!();
    println!("Add it to your iOS app via either:");
    println!("  • Xcode: File → Add Package Dependencies → Add Local…");
    println!(
        "  • Package.swift: .package(path: \"{}\")",
        local_build.display()
    );
    Ok(())
}

/// Render the shared `Package.swift` scaffold, splicing in a `.binaryTarget(...)` body.
fn render_package_swift(binary_target: &str) -> String {
    format!(
        r#"// swift-tools-version: 5.7
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Bedrock",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(
            name: "Bedrock",
            targets: ["Bedrock"]),
    ],
    targets: [
        .target(
            name: "Bedrock",
            dependencies: ["BedrockFFI"],
            path: "Sources/Bedrock"
        ),
        {binary_target}
    ]
)
"#
    )
}

/// Write a `Package.swift` to the current directory referencing the hosted xcframework asset.
pub fn archive(asset_url: &str, checksum: &str, release_version: &str) -> Result<()> {
    println!("🔧 Creating Package.swift with:");
    println!("   Asset URL: {asset_url}");
    println!("   Checksum: {checksum}");
    println!("   Release Version: {release_version}");

    let binary_target = format!(
        r#".binaryTarget(
            name: "BedrockFFI",
            url: "{asset_url}",
            checksum: "{checksum}"
        )"#
    );
    let contents = format!(
        "{}// Release version: {release_version}\n",
        render_package_swift(&binary_target)
    );
    std::fs::write("Package.swift", contents)?;
    println!("✅ Package.swift built successfully for version {release_version}!");
    Ok(())
}

/// Build the bindings and run the foreign Swift test suite on an iOS simulator.
pub fn test() -> Result<()> {
    println!("🔨 Building Swift bindings");
    build(None)?;
    run_tests()
}

/// Run the foreign Swift test suite against an already-built `Bedrock.xcframework`
pub fn run_tests() -> Result<()> {
    let swift = swift_dir();
    let tests = swift.join("tests");

    let sdks = capture(Command::new("xcodebuild").arg("-showsdks"))?;
    if !sdks.contains("iphonesimulator") {
        bail!("No iOS Simulator SDK installed. Available SDKs:\n{sdks}");
    }

    let framework = swift.join("Bedrock.xcframework");
    if !framework.exists() {
        bail!(
            "Bedrock.xcframework not found at {} — run `cargo xtask swift build` first",
            framework.display()
        );
    }

    println!("📦 Copying generated Swift files to test package");
    let src_sources = swift.join("Sources/Bedrock");
    let dest_sources = tests.join("Sources/Bedrock");
    std::fs::create_dir_all(&dest_sources)?;
    let mut copied = 0_usize;
    for entry in std::fs::read_dir(&src_sources)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() == Some(OsStr::new("swift")) {
            std::fs::copy(&path, dest_sources.join(path.file_name().expect("named")))?;
            copied += 1;
        }
    }
    if copied == 0 {
        bail!(
            "Could not find any generated Swift bindings in: {}",
            src_sources.display()
        );
    }
    println!("✅ Copied {copied} Swift binding file(s) to test package");

    reset_dir(&tests.join(".build"))?;
    clear_derived_data("BedrockForeignTestPackage-")?;

    let simulator_id = pick_simulator()?;
    println!("📱 Using simulator ID: {simulator_id}");

    if in_ci() {
        println!("🧹 Running simulator hygiene (CI environment detected)...");
        // `simctl shutdown` returns a non-zero exit if the simulator is already
        // shut down; treat that as success.
        let _ = Command::new("xcrun")
            .args(["simctl", "shutdown", &simulator_id])
            .status();
        run(Command::new("xcrun").args(["simctl", "erase", &simulator_id]))?;
        run(Command::new("xcrun").args(["simctl", "boot", &simulator_id]))?;
        run(Command::new("xcrun").args(["simctl", "bootstatus", &simulator_id, "-b"]))?;
    }

    println!("🚀 Running tests on iOS Simulator...");
    let (output, status) = run_streamed(
        Command::new("xcodebuild")
            .current_dir(&tests)
            .arg("test")
            .args(["-scheme", "BedrockForeignTestPackage"])
            .arg("-destination")
            .arg(format!("platform=iOS Simulator,id={simulator_id}"))
            .args(["-sdk", "iphonesimulator", "CODE_SIGNING_ALLOWED=NO"]),
        is_test_output_interesting,
    )?;

    let summary = parse_test_summary(&output);
    print_test_summary(&summary);

    if !status.success() {
        bail!("xcodebuild test failed ({status})");
    }
    if summary.total == 0 {
        bail!("xcodebuild reported success but did not execute any test cases");
    }
    if summary.failed > 0 || summary.suites_failed > 0 {
        bail!(
            "{} test case(s) and {} test suite(s) failed",
            summary.failed,
            summary.suites_failed
        );
    }
    println!();
    println!("🎉 All tests passed!");
    Ok(())
}

/// Whitelist filter: show only lines from xcodebuild that matter to the user
/// (test progress, the final summary line, failures, and compiler diagnostics).
/// Hides build-phase chatter like `CompileSwiftSources`, `ExtractAppIntentsMetadata`,
/// `CodeSign`, etc.
fn is_test_output_interesting(line: &str) -> bool {
    let trim = line.trim_start();
    trim.starts_with("Test Suite")
        || trim.starts_with("Test Case")
        || trim.starts_with("Executed ")
        || trim.starts_with("** TEST ")
        || trim.starts_with("** BUILD FAILED")
        || line.contains(": error:")
        || line.contains(": warning:")
        || line.contains(": FAILED")
}

struct TestSummary {
    total: usize,
    passed: usize,
    failed: usize,
    suites_failed: usize,
}

/// Count test cases and suites from xcodebuild's test output.
fn parse_test_summary(output: &str) -> TestSummary {
    let count = |needle: &str, status: &str| -> usize {
        output
            .lines()
            .filter(|l| l.contains(needle) && l.contains(status))
            .count()
    };
    TestSummary {
        total: count("Test Case", "started"),
        passed: count("Test Case", "passed"),
        failed: count("Test Case", "failed"),
        suites_failed: count("Test Suite", "failed"),
    }
}

fn print_test_summary(s: &TestSummary) {
    println!("✅ Tests passed: {}", s.passed);
    println!("❌ Tests failed: {}", s.failed);
    if s.suites_failed > 0 {
        println!("📦 Test suites failed: {}", s.suites_failed);
    }
}

/// Remove Xcode `DerivedData` directories whose names start with `prefix`.
/// Stale data from prior runs occasionally caused the simulator test runner
/// to never start ("never began executing tests after launching" timeout).
fn clear_derived_data(prefix: &str) -> Result<()> {
    let Some(home) = std::env::var_os("HOME") else {
        return Ok(());
    };
    let derived = PathBuf::from(home).join("Library/Developer/Xcode/DerivedData");
    if !derived.exists() {
        return Ok(());
    }
    for entry in std::fs::read_dir(&derived)? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(prefix) {
            std::fs::remove_dir_all(entry.path())?;
        }
    }
    Ok(())
}

/// Pick the first available iPhone simulator (preferring iPhone 16).
fn pick_simulator() -> Result<String> {
    let listing = capture(Command::new("xcrun").args([
        "simctl",
        "list",
        "devices",
        "available",
    ]))?;
    let preferred = listing
        .lines()
        .find(|line| line.contains("iPhone 16"))
        .or_else(|| listing.lines().find(|line| line.contains("iPhone")));
    let line = preferred.context("no iPhone simulator available")?;
    // Each line ends in `(UUID) (state)`. Grab the last parenthesised UUID.
    let id = line
        .rsplit('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .with_context(|| format!("could not parse simulator UUID from: {line}"))?;
    Ok(id.to_owned())
}

/// Rebuild locally, then patch every consumer `Package.swift` under `consumer_path` to
/// depend on the local build instead of the hosted `worldcoin/bedrock-swift` package.
pub fn link_local(consumer_path: &Path) -> Result<()> {
    local()?;
    let local_build = swift_dir().join("local_build/bedrock-swift");

    let grep = Command::new("grep")
        .args([
            "-rl",
            "worldcoin/bedrock-swift",
            "--include=Package.swift",
            "--exclude-dir=.build",
            "--exclude-dir=.git",
        ])
        .arg(consumer_path)
        .output()
        .context("failed to spawn grep")?;
    if grep.status.code() != Some(0) {
        bail!(
            "No Package.swift referencing worldcoin/bedrock-swift found in {}",
            consumer_path.display()
        );
    }

    for line in String::from_utf8(grep.stdout)?.lines() {
        let path = Path::new(line);
        let contents = std::fs::read_to_string(path)?;
        let rewritten = rewrite_consumer_package(&contents, &local_build);
        if rewritten == contents {
            continue;
        }
        println!("Patching {}...", path.display());
        std::fs::write(path, rewritten)?;
    }
    println!(
        "Done! In Xcode, make sure package resolution succeeds (via the Issue Navigator)."
    );
    Ok(())
}

/// Replace each `.package(url: "...worldcoin/bedrock-swift...", ...)` dependency
/// declaration with `.package(path: "<local-build>")`
fn rewrite_consumer_package(contents: &str, local_build: &Path) -> String {
    let mut out = String::with_capacity(contents.len());
    let replacement = format!(".package(path: \"{}\"),", local_build.display());
    for line in contents.split_inclusive('\n') {
        let trimmed = line.trim_start();
        let is_pkg_decl = trimmed.starts_with(".package(url:")
            && line.contains("worldcoin/bedrock-swift");
        if !is_pkg_decl {
            out.push_str(line);
            continue;
        }
        let indent = &line[..line.len() - trimmed.len()];
        out.push_str(indent);
        out.push_str(&replacement);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture() -> &'static str {
        r#"dependencies: [
    .package(url: "https://github.com/worldcoin/bedrock-swift", exact: "0.4.0"),
    .package(url: "https://github.com/other/dep", from: "1.0.0"),
],
"#
    }

    #[test]
    fn preserves_trailing_comma_and_neighbours() {
        let out = rewrite_consumer_package(fixture(), Path::new("/tmp/local"));
        assert!(out.contains(".package(path: \"/tmp/local\"),"));
        assert!(out.contains(".package(url: \"https://github.com/other/dep\""));
    }

    #[test]
    fn no_match_leaves_file_untouched() {
        let unrelated = "let package = Package(name: \"X\")\n";
        assert_eq!(
            rewrite_consumer_package(unrelated, Path::new("/tmp/local")),
            unrelated
        );
    }

    #[test]
    fn leaves_comments_mentioning_the_repo_untouched() {
        let src = "// pinned via worldcoin/bedrock-swift release notes\n";
        assert_eq!(rewrite_consumer_package(src, Path::new("/tmp/local")), src);
    }

    #[test]
    fn always_emits_trailing_comma_even_when_source_lacks_one() {
        let line = "    .package(url: \"https://github.com/worldcoin/bedrock-swift\", exact: \"0.4.0\")\n";
        let out = rewrite_consumer_package(line, Path::new("/tmp/local"));
        assert_eq!(out, "    .package(path: \"/tmp/local\"),\n");
    }

    #[test]
    fn umbrella_modulemap_declares_a_framework_module() {
        let dir = std::env::temp_dir().join("bedrock_swift_test_umbrella_modulemap");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("module.modulemap");
        write_umbrella_modulemap(
            &path,
            &["bedrockFFI.h".to_owned(), "siegel_uniffiFFI.h".to_owned()],
        )
        .unwrap();
        let contents = std::fs::read_to_string(&path).unwrap();
        std::fs::remove_dir_all(&dir).unwrap();

        assert!(contents.starts_with("framework module BedrockFFI {\n"));
        assert!(contents.contains("header \"bedrockFFI.h\"\n"));
        assert!(contents.contains("header \"siegel_uniffiFFI.h\"\n"));
    }

    #[test]
    fn framework_info_plist_sets_executable_and_platform() {
        let plist = framework_info_plist("BedrockFFI", "iPhoneSimulator");
        assert!(plist
            .contains("<key>CFBundleExecutable</key>\n\t<string>BedrockFFI</string>"));
        assert!(
            plist.contains("<key>CFBundlePackageType</key>\n\t<string>FMWK</string>")
        );
        assert!(plist.contains("<string>iPhoneSimulator</string>"));
        assert!(plist.contains(&format!("<string>{IOS_DEPLOYMENT_TARGET}</string>")));
    }
}
