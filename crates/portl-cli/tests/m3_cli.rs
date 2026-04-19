use std::io::Write;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use assert_cmd::cargo::CommandCargoExt;
use iroh_tickets::Ticket;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::{Identity, store};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, EnvPolicy, PortRule, PortlTicket, ShellCaps};
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::test]
async fn exec_command_connects_and_returns_output() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps()).serialize();
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&Identity::new(), &identity_path)?;

    let ticket_for_command = ticket.clone();
    let identity_path_for_command = identity_path.clone();
    let output = tokio::task::spawn_blocking(move || -> Result<std::process::Output> {
        Ok(Command::cargo_bin("portl")?
            .env("PORTL_IDENTITY_KEY", &identity_path_for_command)
            .args([
                "exec",
                ticket_for_command.as_str(),
                "--",
                "/bin/sh",
                "-c",
                "echo hi",
            ])
            .output()?)
    })
    .await??;

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(String::from_utf8(output.stdout)?, "hi\n");

    shutdown(client, server, agent).await
}

#[tokio::test]
async fn shell_command_connects_and_dispatches_noninteractive_session() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_caps()).serialize();
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&Identity::new(), &identity_path)?;

    let ticket_for_command = ticket.clone();
    let identity_path_for_command = identity_path.clone();
    let output = tokio::task::spawn_blocking(move || -> Result<std::process::Output> {
        let mut child = Command::cargo_bin("portl")?
            .env("PORTL_IDENTITY_KEY", &identity_path_for_command)
            .args(["shell", ticket_for_command.as_str()])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;

        child
            .stdin
            .take()
            .context("take shell stdin")?
            .write_all(b"echo hi\nexit\n")?;

        Ok(child.wait_with_output()?)
    })
    .await??;

    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout)?;
    assert!(stdout.contains("hi"), "stdout was {stdout:?}");

    shutdown(client, server, agent).await
}

#[tokio::test]
async fn tcp_command_connects_and_forwards_bytes() -> Result<()> {
    let remote_listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let remote_port = remote_listener.local_addr()?.port();
    let remote_task = tokio::spawn(async move {
        loop {
            let (mut socket, _) = remote_listener.accept().await?;
            let mut buf = [0_u8; 16];
            let read = socket.read(&mut buf).await?;
            if read == 0 {
                continue;
            }
            socket.write_all(&buf[..read]).await?;
            socket.shutdown().await?;
            return Ok::<_, anyhow::Error>(());
        }
    });

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(remote_port)).serialize();
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&Identity::new(), &identity_path)?;

    let local_port = reserve_local_port()?;
    let spec = format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}");
    let mut child = Command::cargo_bin("portl")?
        .env("PORTL_IDENTITY_KEY", &identity_path)
        .args(["tcp", ticket.as_str(), "-L", spec.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    wait_for_forward(&mut child, local_port).await?;

    let mut forwarded = TcpStream::connect(("127.0.0.1", local_port)).await?;
    forwarded.write_all(b"z").await?;
    forwarded.shutdown().await?;

    let mut echoed = Vec::new();
    forwarded.read_to_end(&mut echoed).await?;
    assert_eq!(echoed, b"z");

    remote_task.await??;
    child.kill().context("kill tcp command")?;
    let _status = child.wait().context("wait for killed tcp command")?;

    shutdown(client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-cli-m3-revocations-{}.json",
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

fn shell_caps() -> Capabilities {
    Capabilities {
        presence: 0b0000_0001,
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: None,
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn tcp_caps(port: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: port,
            port_max: port,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn reserve_local_port() -> Result<u16> {
    let listener = std::net::TcpListener::bind(("127.0.0.1", 0))?;
    let port = listener.local_addr()?.port();
    drop(listener);
    Ok(port)
}

async fn wait_for_forward(child: &mut std::process::Child, local_port: u16) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match TcpStream::connect(("127.0.0.1", local_port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(_) if tokio::time::Instant::now() < deadline => {
                if let Some(status) = child.try_wait().context("poll tcp command")? {
                    let stderr = read_child_stderr(child)?;
                    bail!("tcp command exited early with {status}: {stderr}");
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(err) => {
                let stderr = read_child_stderr(child)?;
                return Err(anyhow!(
                    "timed out waiting for tcp forward on {local_port}: {err}; stderr: {stderr}"
                ));
            }
        }
    }
}

fn read_child_stderr(child: &mut std::process::Child) -> Result<String> {
    use std::io::Read;

    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        pipe.read_to_string(&mut stderr)?;
    }
    Ok(stderr)
}

async fn shutdown(
    client: portl_core::endpoint::Endpoint,
    server: portl_core::endpoint::Endpoint,
    agent: tokio::task::JoinHandle<Result<()>>,
) -> Result<()> {
    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .context("agent join timeout")?
        .context("agent join error")??;
    Ok(())
}
