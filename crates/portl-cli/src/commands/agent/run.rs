use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::Result;

const NO_TRUST_ROOTS_WARNING: &str = "portl agent run: starting with default config; no trust roots configured, handshakes will reject legitimate tickets. Provide --config or set PORTL_AGENT_CONFIG env var.";

pub fn run(config: Option<&Path>) -> Result<ExitCode> {
    let cfg = load_config(config)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        portl_agent::run(cfg).await?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn load_config(config: Option<&Path>) -> Result<portl_agent::AgentConfig> {
    let config_path = config
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("PORTL_AGENT_CONFIG").map(PathBuf::from));

    let mut warned = false;
    let cfg = if let Some(path) = config_path {
        portl_agent::AgentConfig::from_toml_path(&path)?
    } else {
        eprintln!("{NO_TRUST_ROOTS_WARNING}");
        warned = true;
        portl_agent::AgentConfig::default()
    };

    if cfg.trust_roots.is_empty() && !warned {
        eprintln!("{NO_TRUST_ROOTS_WARNING}");
    }

    Ok(cfg)
}
