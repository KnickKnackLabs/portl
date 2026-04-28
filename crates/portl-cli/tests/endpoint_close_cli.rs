use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iroh_tickets::Ticket;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::{Identity, store};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use tempfile::tempdir;

#[tokio::test]
#[ignore = "slow e2e smoke; run before release tagging with `mise run release:verify -- VERSION --full`"]
async fn cli_closes_endpoint_after_dial_timeout() -> Result<()> {
    let (_client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;

    let home = tempdir()?;
    store::save(&operator, &home.path().join("identity.bin"))?;

    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let ticket = mint_root(
        operator.signing_key(),
        server.addr(),
        meta_caps(),
        now,
        now + 300,
        None,
    )?;
    let ticket_uri = ticket.serialize();

    let output = Command::new(assert_cmd::cargo::cargo_bin("portl"))
        .env("PORTL_HOME", home.path())
        .env("PORTL_DISCOVERY", "none")
        .args(["status", "--timeout", "500ms", &ticket_uri])
        .output()?;

    assert!(
        !output.status.success(),
        "status probe unexpectedly succeeded"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Endpoint dropped without calling `Endpoint::close`"),
        "endpoint close warning leaked to stderr: {stderr}"
    );

    server.inner().close().await;
    tokio::time::timeout(std::time::Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-cli-session-close-revocations-{}.json",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos()
    ));
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        ..AgentConfig::default()
    })
    .await
}

fn meta_caps() -> Capabilities {
    Capabilities {
        presence: 0b0010_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: Some(MetaCaps {
            ping: true,
            info: true,
        }),
    }
}
