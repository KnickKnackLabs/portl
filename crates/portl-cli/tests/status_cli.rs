use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use iroh_tickets::Ticket;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::{Identity, store};
use portl_core::test_util::pair;
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use tempfile::tempdir;

#[tokio::test]
async fn status_command_reports_cached_ticket_peer() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&operator, &identity_path)?;

    server.inner().online().await;

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

    let ticket_uri_for_status = ticket_uri.clone();
    let identity_path_for_status = identity_path.clone();
    let code = tokio::task::spawn_blocking(move || {
        portl_cli::run_status_with_identity_path(
            &ticket_uri_for_status,
            Some(identity_path_for_status.as_path()),
        )
    })
    .await??;
    assert_eq!(code, ExitCode::SUCCESS);

    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[tokio::test]
async fn status_command_reports_bare_endpoint_peer() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;

    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&operator, &identity_path)?;

    let peer = hex::encode(server.id().as_bytes());
    let client_endpoint = client.inner().clone();
    let identity_path_for_status = identity_path.clone();
    let code = tokio::task::spawn_blocking(move || {
        portl_cli::run_status_with_identity_path_and_endpoint(
            &peer,
            Some(identity_path_for_status.as_path()),
            client_endpoint,
        )
    })
    .await??;
    assert_eq!(code, ExitCode::SUCCESS);

    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[tokio::test]
async fn status_refuses_delegated_tickets() -> Result<()> {
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    let operator = Identity::new();
    store::save(&operator, &identity_path)?;

    let (_, server) = pair().await?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let root = mint_root(
        operator.signing_key(),
        server.addr(),
        meta_caps(),
        now,
        now + 300,
        None,
    )?;
    let delegated = mint_delegated(
        operator.signing_key(),
        &root,
        meta_caps(),
        now,
        now + 300,
        None,
    )?;
    let delegated_uri = delegated.serialize();
    let identity_path_for_status = identity_path.clone();

    let err = tokio::task::spawn_blocking(move || {
        portl_cli::run_status_with_identity_path(
            &delegated_uri,
            Some(identity_path_for_status.as_path()),
        )
    })
    .await?
    .expect_err("delegated status should fail before dialing");

    assert!(
        format!("{err:#}").contains(
            "delegated tickets not yet supported by status; use the root ticket or pass --chain"
        ),
        "unexpected error: {err:#}"
    );

    server.inner().close().await;
    Ok(())
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-cli-test-revocations-{}.json",
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
