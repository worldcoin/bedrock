use std::path::PathBuf;
use std::process::Command;

pub fn resolve_forge_bin() -> Option<String> {
    if let Ok(p) = std::env::var("FORGE_BIN") {
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    if let Some(found) = which_on_path("forge") {
        return Some(found);
    }
    if let Ok(home) = std::env::var("HOME") {
        let candidate = format!("{home}/.foundry/bin/forge");
        if std::path::Path::new(&candidate).is_file() {
            return Some(candidate);
        }
    }
    None
}

fn which_on_path(bin: &str) -> Option<String> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p: PathBuf = dir.join(bin);
        if p.is_file() {
            return Some(p.to_string_lossy().to_string());
        }
    }
    None
}

pub fn forge_create_checker(
    private_key_hex: &str,
    rpc_url: &str,
) -> anyhow::Result<String> {
    let forge_bin = resolve_forge_bin().ok_or_else(|| {
        anyhow::anyhow!("forge binary not found (set FORGE_BIN or install foundry)")
    })?;

    let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has no parent dir");
    let solidity_dir = workspace_root.join("solidity");

    let out = Command::new(&forge_bin)
        .args([
            "create",
            "--json",
            "src/NonceV1Checker.sol:NonceV1Checker",
            "--private-key",
            private_key_hex,
            "--rpc-url",
            rpc_url,
        ])
        .current_dir(&solidity_dir)
        .output()?;

    if !out.status.success() {
        return Err(anyhow::anyhow!(
            "forge create failed: {}",
            String::from_utf8_lossy(&out.stderr)
        ));
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(&stdout)
        .map_err(|e| anyhow::anyhow!("forge json parse failed: {e}: {stdout}"))?;
    if let Some(addr) = v.get("deployedTo").and_then(|s| s.as_str()) {
        return Ok(addr.to_string());
    }
    Err(anyhow::anyhow!("forge output missing deployedTo: {stdout}"))
}

pub fn ensure_anvil_on_path() -> anyhow::Result<()> {
    // If `anvil` is already on PATH, nothing to do
    if which_on_path("anvil").is_some() {
        return Ok(());
    }
    // Try common Foundry install dir
    if let Ok(home) = std::env::var("HOME") {
        let bin_dir = format!("{home}/.foundry/bin");
        let candidate = format!("{bin_dir}/anvil");
        if std::path::Path::new(&candidate).is_file() {
            // Prepend to PATH for this process
            let orig = std::env::var_os("PATH").unwrap_or_default();
            let mut new_path = std::ffi::OsString::from(bin_dir);
            new_path.push(std::ffi::OsString::from(if cfg!(target_os = "windows") { ";" } else { ":" }));
            new_path.push(orig);
            std::env::set_var("PATH", new_path);
            return Ok(());
        }
    }
    Err(anyhow::anyhow!(
        "anvil not found on PATH; install Foundry or expose ~/.foundry/bin in PATH"
    ))
}
