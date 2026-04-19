use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow};
use docker_portl::{DockerBootstrapper, DockerHandle};
use portl_core::bootstrap::{Bootstrapper, ProvisionSpec, TargetStatus};
use serde_json::json;

#[tokio::test]
#[ignore = "requires a live docker daemon and test image"]
async fn provision_cycle_smoke_test() -> Result<()> {
    let bootstrapper = DockerBootstrapper::connect_with_local_defaults(vec![[1; 32]])?;
    let handle = bootstrapper
        .provision(&ProvisionSpec {
            name: format!("portl-live-{}", std::process::id()),
            adapter_params: json!({
                "image": "portl-agent:local",
                "network": "bridge",
            }),
            labels: vec![],
        })
        .await?;

    let status = bootstrapper.resolve(&handle).await?;
    assert!(matches!(status, TargetStatus::Running));
    bootstrapper.teardown(&handle).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live docker daemon and test image"]
async fn agent_graceful_shutdown_on_sigterm() -> Result<()> {
    let bootstrapper = DockerBootstrapper::connect_with_local_defaults(vec![[1; 32]])?;
    let handle = bootstrapper
        .provision(&ProvisionSpec {
            name: format!("portl-sigterm-{}", std::process::id()),
            adapter_params: json!({
                "image": "portl-agent:local",
                "network": "bridge",
            }),
            labels: vec![],
        })
        .await?;
    let docker_handle = DockerHandle::from_handle(&handle)?;

    let started = Instant::now();
    let stop_output = Command::new("docker")
        .args(["stop", "--time=15", &docker_handle.container_id])
        .output()
        .context("run docker stop")?;
    if !stop_output.status.success() {
        return Err(anyhow!(
            "docker stop failed: stdout={} stderr={}",
            String::from_utf8_lossy(&stop_output.stdout),
            String::from_utf8_lossy(&stop_output.stderr)
        ));
    }

    let inspect_output = Command::new("docker")
        .args([
            "inspect",
            &docker_handle.container_id,
            "--format",
            "{{.State.Status}} {{.State.ExitCode}}",
        ])
        .output()
        .context("inspect stopped container")?;
    if !inspect_output.status.success() {
        return Err(anyhow!(
            "docker inspect failed: stdout={} stderr={}",
            String::from_utf8_lossy(&inspect_output.stdout),
            String::from_utf8_lossy(&inspect_output.stderr)
        ));
    }

    let state = String::from_utf8(inspect_output.stdout).context("decode docker inspect")?;
    let mut parts = state.split_whitespace();
    let status = parts.next().unwrap_or_default();
    let exit_code = parts
        .next()
        .unwrap_or_default()
        .parse::<i32>()
        .context("parse docker exit code")?;

    assert!(started.elapsed() <= Duration::from_secs(12));
    assert_eq!(status, "exited");
    assert!(
        matches!(exit_code, 0 | 143),
        "unexpected exit code {exit_code}"
    );

    bootstrapper.teardown(&handle).await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a live docker daemon and test image"]
async fn list_reports_actual_network() -> Result<()> {
    let bootstrapper = DockerBootstrapper::connect_with_local_defaults(vec![[1; 32]])?;

    let bridge = bootstrapper
        .provision(&ProvisionSpec {
            name: format!("portl-bridge-{}", std::process::id()),
            adapter_params: json!({
                "image": "portl-agent:local",
                "network": "bridge",
            }),
            labels: vec![],
        })
        .await?;
    let bridge_handle = DockerHandle::from_handle(&bridge)?;

    let listed = bootstrapper.list_portl_containers().await?;
    let bridge_listed = listed
        .iter()
        .find(|handle| handle.container_id == bridge_handle.container_id)
        .context("bridge container missing from list")?;
    assert_eq!(bridge_listed.network, "bridge");

    bootstrapper.teardown(&bridge).await?;

    #[cfg(target_os = "linux")]
    if std::env::var_os("PORTL_TEST_HOST_NETWORK").is_some() {
        let host = bootstrapper
            .provision(&ProvisionSpec {
                name: format!("portl-host-{}", std::process::id()),
                adapter_params: json!({
                    "image": "portl-agent:local",
                    "network": "host",
                }),
                labels: vec![],
            })
            .await?;
        let host_handle = DockerHandle::from_handle(&host)?;

        let listed = bootstrapper.list_portl_containers().await?;
        let host_listed = listed
            .iter()
            .find(|handle| handle.container_id == host_handle.container_id)
            .context("host container missing from list")?;
        assert_eq!(host_listed.network, "host");

        bootstrapper.teardown(&host).await?;
    }

    Ok(())
}
