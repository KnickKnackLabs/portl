#[allow(dead_code)]
mod common;

use std::os::unix::fs::PermissionsExt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{
    UnixListenOptions, accept_unix_reverse_once, open_ticket_v1, open_unix, open_unix_listen,
    open_unix_listen_with_options, run_unix_reverse_forward,
};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortlTicket, UnixCaps, UnixPathRule};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[tokio::test]
async fn unix_connect_forward_echo() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let echo_path = temp.path().join("echo.sock");
    let echo_task = spawn_unix_echo(echo_path.clone())?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        unix_caps(vec![path_rule(&echo_path)], vec![]),
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let (mut send, mut recv) = open_unix(&connection, &session, path_str(&echo_path)?).await?;
    send.write_all(b"hello over unix").await?;
    send.finish()?;

    let mut echoed = Vec::new();
    AsyncReadExt::read_to_end(&mut recv, &mut echoed).await?;
    assert_eq!(echoed, b"hello over unix");

    echo_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn unix_listen_reverse_forward_echo() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let local_echo_path = temp.path().join("local-echo.sock");
    let remote_listen_path = temp.path().join("remote-listen.sock");
    let echo_task = spawn_unix_echo(local_echo_path.clone())?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        unix_caps(vec![], vec![path_rule(&remote_listen_path)]),
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control =
        open_unix_listen(&connection, &session, path_str(&remote_listen_path)?, true).await?;
    let reverse_task = tokio::spawn({
        let connection = connection.clone();
        let session = session.clone();
        let remote_path = path_str(&remote_listen_path)?.to_owned();
        let local_path = path_str(&local_echo_path)?.to_owned();
        async move { accept_unix_reverse_once(&connection, &session, &remote_path, &local_path).await }
    });

    let mut remote = UnixStream::connect(&remote_listen_path).await?;
    remote.write_all(b"hello via reverse unix").await?;
    remote.shutdown().await?;
    let mut echoed = Vec::new();
    remote.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"hello via reverse unix");

    reverse_task.await??;
    control.close()?;
    echo_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn agent_forward_listen_creates_private_remote_dir_and_cleans_up() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let local_echo_path = temp.path().join("local-agent.sock");
    let remote_dir =
        std::path::PathBuf::from(format!("/tmp/portl-agent-{:016x}", rand::random::<u64>()));
    let remote_agent_path = remote_dir.join("agent.sock");
    let _ = std::fs::remove_dir_all(&remote_dir);
    let echo_task = spawn_unix_echo(local_echo_path.clone())?;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        unix_caps(vec![], vec![path_rule(&remote_agent_path)]),
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_unix_listen_with_options(
        &connection,
        &session,
        path_str(&remote_agent_path)?,
        UnixListenOptions {
            cleanup: true,
            ssh_agent: true,
        },
    )
    .await?;
    let metadata = std::fs::symlink_metadata(&remote_dir)?;
    assert!(metadata.file_type().is_dir());
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);

    let reverse_task = tokio::spawn({
        let connection = connection.clone();
        let session = session.clone();
        let remote_path = path_str(&remote_agent_path)?.to_owned();
        let local_path = path_str(&local_echo_path)?.to_owned();
        async move { accept_unix_reverse_once(&connection, &session, &remote_path, &local_path).await }
    });

    let mut remote = UnixStream::connect(&remote_agent_path).await?;
    remote.write_all(b"agent request").await?;
    remote.shutdown().await?;
    let mut echoed = Vec::new();
    remote.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"agent request");

    reverse_task.await??;
    control.close()?;
    wait_until_removed(&remote_dir).await?;
    assert!(!remote_agent_path.exists());
    assert!(!remote_dir.exists());
    echo_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn agent_forward_reverse_loop_survives_missing_local_agent() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let local_agent_path = temp.path().join("late-local-agent.sock");
    let remote_dir =
        std::path::PathBuf::from(format!("/tmp/portl-agent-{:016x}", rand::random::<u64>()));
    let remote_agent_path = remote_dir.join("agent.sock");
    let _ = std::fs::remove_dir_all(&remote_dir);

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        unix_caps(vec![], vec![path_rule(&remote_agent_path)]),
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_unix_listen_with_options(
        &connection,
        &session,
        path_str(&remote_agent_path)?,
        UnixListenOptions {
            cleanup: true,
            ssh_agent: true,
        },
    )
    .await?;
    let reverse_task = tokio::spawn({
        let connection = connection.clone();
        let session = session.clone();
        let remote_path = path_str(&remote_agent_path)?.to_owned();
        let local_path = path_str(&local_agent_path)?.to_owned();
        async move { run_unix_reverse_forward(connection, session, remote_path, local_path).await }
    });

    let mut failed_request = UnixStream::connect(&remote_agent_path).await?;
    let _ = failed_request.write_all(b"agent before local exists").await;
    failed_request.shutdown().await.ok();
    let mut ignored = Vec::new();
    let failed_read = tokio::time::timeout(
        Duration::from_secs(1),
        failed_request.read_to_end(&mut ignored),
    )
    .await
    .context("failed request should close promptly")?;
    if let Err(err) = failed_read
        && err.kind() != std::io::ErrorKind::ConnectionReset
    {
        return Err(err.into());
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(
        !reverse_task.is_finished(),
        "missing local agent socket must not terminate forwarding loop"
    );

    let echo_task = spawn_unix_echo(local_agent_path.clone())?;
    let mut remote = UnixStream::connect(&remote_agent_path).await?;
    remote.write_all(b"agent after local exists").await?;
    remote.shutdown().await?;
    let mut echoed = Vec::new();
    remote.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"agent after local exists");

    echo_task.await??;
    control.close()?;
    reverse_task.abort();
    let _ = reverse_task.await;
    wait_until_removed(&remote_dir).await?;
    shutdown(connection, client, server, agent).await
}

fn spawn_unix_echo(path: std::path::PathBuf) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let listener = UnixListener::bind(path)?;
    Ok(tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buf = Vec::new();
        socket.read_to_end(&mut buf).await?;
        socket.write_all(&buf).await?;
        socket.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    }))
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-unix-revocations-{}.json",
        rand::random::<u64>()
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

fn root_ticket(
    operator: &Identity,
    addr: iroh_base::EndpointAddr,
    caps: Capabilities,
) -> PortlTicket {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs();
    mint_root(operator.signing_key(), addr, caps, now, now + 300, None).expect("mint root")
}

fn unix_caps(connect: Vec<UnixPathRule>, listen: Vec<UnixPathRule>) -> Capabilities {
    Capabilities {
        presence: 0b0100_0000,
        shell: None,
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix: Some(UnixCaps { connect, listen }),
    }
}

fn path_rule(path: &std::path::Path) -> UnixPathRule {
    UnixPathRule {
        path: path_str(path).expect("test paths are utf-8").to_owned(),
    }
}

fn path_str(path: &std::path::Path) -> Result<&str> {
    path.to_str().context("unix socket path must be utf-8")
}

async fn wait_until_removed(path: &std::path::Path) -> Result<()> {
    for _ in 0..40 {
        if !path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    anyhow::bail!("path was not removed: {}", path.display())
}

async fn shutdown(
    connection: iroh::endpoint::Connection,
    client: portl_core::endpoint::Endpoint,
    server: portl_core::endpoint::Endpoint,
    agent: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let join_result = tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .context("agent join timeout")?;
    let run_result = join_result.context("agent join error")?;
    run_result?;
    Ok(())
}
