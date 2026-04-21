use std::process::ExitCode;

use anyhow::{Context, Result, bail};

use crate::AgentModeArg;

const NO_TRUST_ROOTS_WARNING: &str = "portl agent run: no trust roots configured, handshakes will reject legitimate tickets. Set PORTL_TRUST_ROOTS.";

pub fn run(mode: Option<AgentModeArg>, upstream_url: Option<&str>) -> Result<ExitCode> {
    let cfg = load_config(mode, upstream_url)?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        portl_agent::run(cfg).await?;
        Ok(ExitCode::SUCCESS)
    })
}

pub fn load_config(
    mode: Option<AgentModeArg>,
    upstream_url: Option<&str>,
) -> Result<portl_agent::AgentConfig> {
    let mut cfg = portl_agent::AgentConfig::from_env()?;

    if let Some(mode) = mode {
        cfg.mode = match mode {
            AgentModeArg::Listener => portl_agent::AgentMode::Listener,
            AgentModeArg::Gateway => {
                let url = upstream_url.context("--upstream-url is required when --mode gateway")?;
                portl_agent::config::parse_gateway_mode(url)?
            }
        };
    } else if upstream_url.is_some() {
        bail!("--upstream-url requires --mode gateway");
    }

    if cfg.trust_roots.is_empty() {
        eprintln!("{NO_TRUST_ROOTS_WARNING}");
    }

    Ok(cfg)
}
