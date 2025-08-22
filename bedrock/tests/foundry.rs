use std::path::PathBuf;
use std::process::Command;

pub fn resolve_forge_bin() -> Option<String> {
    // Try FORGE_BIN env var first
    if let Ok(p) = std::env::var("FORGE_BIN") {
        if std::path::Path::new(&p).is_file() {
            return Some(p);
        }
    }
    // Otherwise, search PATH for "forge"
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let p: PathBuf = dir.join("forge");
        if p.is_file() {
            return Some(p.to_string_lossy().to_string());
        }
    }
    None
}

/// Result of a `forge create` invocation.
/// Builder for running `forge create` in tests.
pub struct ForgeCreate {
    contract: String, // e.g. "solidity/src/NonceV1Checker.sol:NonceV1Checker"
}

impl ForgeCreate {
    pub fn new(contract: impl Into<String>) -> Self {
        Self {
            contract: contract.into(),
        }
    }

    pub fn run(
        self,
        private_key_hex: impl Into<String>,
        rpc_url: impl Into<String>,
    ) -> anyhow::Result<String> {
        let forge_bin = resolve_forge_bin().ok_or_else(|| {
            anyhow::anyhow!("forge binary not found (set FORGE_BIN or install foundry)")
        })?;
        let rpc_url: String = rpc_url.into();
        let private_key_hex: String = private_key_hex.into();

        let workspace_root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("crate has no parent dir");
        let solidity_dir = workspace_root.join("solidity");

        let mut args: Vec<String> = vec!["create".into()];
        args.push("--json".into());
        args.push("--broadcast".into());
        args.push(self.contract.clone());
        args.push("--private-key".into());
        args.push(private_key_hex);
        args.push("--rpc-url".into());
        args.push(rpc_url);

        let out_json = Command::new(&forge_bin)
            .args(args.clone())
            .current_dir(&solidity_dir)
            .output()?;

        if out_json.status.success() {
            if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&out_json.stdout)
            {
                if let Some(addr) = v.get("deployedTo").and_then(|s| s.as_str()) {
                    return Ok(addr.to_string());
                }
            }
        }

        let plain_args = args
            .into_iter()
            .filter(|a| a != "--json")
            .collect::<Vec<_>>();
        let out_plain = Command::new(&forge_bin)
            .args(&plain_args)
            .current_dir(&solidity_dir)
            .output()?;

        if !out_plain.status.success() {
            return Err(anyhow::anyhow!(
                "forge create failed: {}",
                String::from_utf8_lossy(&out_plain.stderr)
            ));
        }

        let stdout = String::from_utf8_lossy(&out_plain.stdout);
        if let Some(addr) = parse_deployed_to(&stdout) {
            return Ok(addr);
        }
        Err(anyhow::anyhow!(
            "forge output missing deployed address; stdout: {}",
            stdout
        ))
    }
}

fn parse_deployed_to(stdout: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some(idx) = line.find("Deployed to:") {
            let rest = line[idx + "Deployed to:".len()..].trim();
            if let Some(pos) = rest.find("0x") {
                let addr = &rest[pos..];
                let candidate = if addr.len() >= 42 { &addr[..42] } else { addr };
                return Some(candidate.to_string());
            }
        }
    }
    None
}
