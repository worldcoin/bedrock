#![deny(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_errors_doc)]

//! Build and release tasks for the Swift and Kotlin bindings.

mod common;
mod kotlin;
mod swift;

use std::path::PathBuf;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "xtask", about = "Build automation for bedrock")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Swift bindings and packaging.
    Swift {
        #[command(subcommand)]
        cmd: SwiftCmd,
    },
    /// Kotlin/Android bindings and packaging.
    Kotlin {
        #[command(subcommand)]
        cmd: KotlinCmd,
    },
}

#[derive(Subcommand)]
enum SwiftCmd {
    /// Build `Bedrock.xcframework` + generated Swift sources.
    Build {
        /// Output directory (defaults to `swift/`).
        #[arg(long)]
        out_dir: Option<PathBuf>,
    },
    /// Build a local Swift package importable via SPM `file://` URLs.
    Local,
    /// Build bindings and run the foreign Swift test suite on a simulator.
    Test,
    /// Run the foreign Swift test suite against an already-built `Bedrock.xcframework`.
    RunTests,
    /// Emit `Package.swift` referencing a hosted xcframework asset.
    Archive {
        #[arg(long)]
        asset_url: String,
        #[arg(long)]
        checksum: String,
        #[arg(long)]
        release_version: String,
    },
    /// Patch a consumer `Package.swift` to depend on the local build.
    LinkLocal {
        /// Path to the consumer project (e.g. an iOS app checkout) whose
        /// `Package.swift` should be rewritten to point at the local build.
        #[arg(long, env = "CONSUMER_PATH")]
        consumer_path: PathBuf,
    },
}

#[derive(Subcommand)]
enum KotlinCmd {
    /// Cross-compile the Android `jniLibs` + generate Kotlin bindings.
    Build,
    /// Build host bindings and run the foreign Kotlin (JUnit) test suite.
    Test,
    /// Build Android bindings and publish to the local Maven repository.
    Local {
        /// Maven version name to publish under (e.g. `0.2.10-SNAPSHOT`).
        #[arg(long, env = "VERSION")]
        version: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Swift { cmd } => match cmd {
            SwiftCmd::Build { out_dir } => swift::build(out_dir.as_deref()),
            SwiftCmd::Local => swift::local(),
            SwiftCmd::Test => swift::test(),
            SwiftCmd::RunTests => swift::run_tests(),
            SwiftCmd::Archive {
                asset_url,
                checksum,
                release_version,
            } => swift::archive(&asset_url, &checksum, &release_version),
            SwiftCmd::LinkLocal { consumer_path } => swift::link_local(&consumer_path),
        },
        Cmd::Kotlin { cmd } => match cmd {
            KotlinCmd::Build => kotlin::build(),
            KotlinCmd::Test => kotlin::test(),
            KotlinCmd::Local { version } => kotlin::local(&version),
        },
    }
}
