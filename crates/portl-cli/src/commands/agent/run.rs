use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::AgentModeArg;

const NO_TRUST_ROOTS_WARNING: &str = "portl agent run: starting with default config; no trust roots configured, handshakes will reject legitimate tickets. Provide --config or set PORTL_AGENT_CONFIG env var.";

pub fn run(
    config: Option<&Path>,
    mode: Option<AgentModeArg>,
    upstream_url: Option<&str>,
) -> Result<ExitCode> {
    let cfg = load_config(config, mode, upstream_url)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        portl_agent::run(cfg).await?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn load_config(
    config: Option<&Path>,
    mode: Option<AgentModeArg>,
    upstream_url: Option<&str>,
) -> Result<portl_agent::AgentConfig> {
    let config_path = config
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("PORTL_AGENT_CONFIG").map(PathBuf::from));

    let mut warned = false;
    let mut cfg = if let Some(path) = config_path {
        portl_agent::AgentConfig::from_toml_path(&path)?
    } else {
        eprintln!("{NO_TRUST_ROOTS_WARNING}");
        warned = true;
        portl_agent::AgentConfig::default()
    };

    if let Some(mode) = mode {
        cfg.mode = match mode {
            AgentModeArg::Listener => portl_agent::AgentMode::Listener,
            AgentModeArg::Gateway => {
                let url = upstream_url.context("--upstream-url is required when --mode gateway")?;
                let parsed = reqwest::Url::parse(url)
                    .with_context(|| format!("parse gateway upstream URL {url}"))?;
                let host = parsed
                    .host_str()
                    .map(ToOwned::to_owned)
                    .context("gateway upstream URL must include a host")?;
                let port = parsed
                    .port_or_known_default()
                    .context("gateway upstream URL must include a port")?;
                portl_agent::AgentMode::Gateway {
                    upstream_url: url.to_owned(),
                    upstream_host: host,
                    upstream_port: port,
                }
            }
        };
    } else if upstream_url.is_some() {
        bail!("--upstream-url requires --mode gateway");
    }

    if cfg.trust_roots.is_empty() && !warned {
        eprintln!("{NO_TRUST_ROOTS_WARNING}");
    }

    Ok(cfg)
}
