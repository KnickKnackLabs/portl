use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;

pub fn run(config: Option<&Path>) -> Result<ExitCode> {
    if let Some(path) = config {
        eprintln!(
            "warning: --config={} is accepted but not yet parsed in M2; using defaults",
            path.display()
        );
    }

    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async {
        portl_agent::run(portl_agent::AgentConfig::default()).await?;
        Ok(ExitCode::SUCCESS)
    })
}
