use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result};
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

#[cfg(unix)]
#[tokio::test]
async fn agent_run_stops_on_sigterm_even_when_not_pid1() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD").as_deref() {
        Ok("TERM") => run_signal_child("TERM").await,
        _ => signal_shutdown_subprocess("agent_run_stops_on_sigterm_even_when_not_pid1", "TERM"),
    }
}

#[cfg(unix)]
#[tokio::test]
async fn agent_run_stops_on_sigint_even_when_not_pid1() -> Result<()> {
    match std::env::var("PORTL_SIGNAL_CHILD").as_deref() {
        Ok("INT") => run_signal_child("INT").await,
        _ => signal_shutdown_subprocess("agent_run_stops_on_sigint_even_when_not_pid1", "INT"),
    }
}

#[cfg(unix)]
fn signal_shutdown_subprocess(test_name: &str, signal_name: &str) -> Result<()> {
    let output = Command::new(std::env::current_exe().context("resolve current test binary")?)
        .env("PORTL_SIGNAL_CHILD", signal_name)
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .output()
        .context("spawn signal shutdown subprocess")?;

    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(unix)]
async fn run_signal_child(signal_name: &str) -> Result<()> {
    use nix::sys::signal::{Signal, kill};
    use nix::unistd::Pid;

    let endpoint = Endpoint::bind().await?;
    let task = tokio::spawn(run_with_shutdown(
        AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(endpoint.clone()),
            ..AgentConfig::default()
        },
        CancellationToken::new(),
    ));

    tokio::time::sleep(Duration::from_millis(100)).await;
    let signal = match signal_name {
        "TERM" => Signal::SIGTERM,
        "INT" => Signal::SIGINT,
        other => anyhow::bail!("unsupported signal child marker {other}"),
    };
    kill(Pid::this(), signal).context("deliver signal to test process")?;

    tokio::time::timeout(Duration::from_secs(3), task)
        .await
        .context("signal shutdown join timeout")??
        .context("signal child agent run failed")?;
    Ok(())
}
