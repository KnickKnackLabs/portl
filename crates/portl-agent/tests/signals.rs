use std::time::Duration;

use anyhow::Result;
use portl_agent::{AgentConfig, DiscoveryConfig, run_with_shutdown};
use portl_core::endpoint::Endpoint;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn agent_run_returns_promptly_when_shutdown_token_is_cancelled() -> Result<()> {
    let endpoint = Endpoint::bind().await?;
    let shutdown = CancellationToken::new();
    let task = tokio::spawn(run_with_shutdown(
        AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(endpoint.clone()),
            ..AgentConfig::default()
        },
        shutdown.clone(),
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;
    shutdown.cancel();

    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .expect("agent should stop within 3 seconds")??;
    Ok(())
}
