use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use assert_cmd::cargo::CommandCargoExt;
use iroh_tickets::Ticket;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::{Identity, store};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortRule, PortlTicket};
use tempfile::tempdir;
use tokio::net::UdpSocket;

#[tokio::test]
async fn udp_command_connects_and_forwards_datagrams() -> Result<()> {
    let remote = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let remote_port = remote.local_addr()?.port();
    let remote_task = tokio::spawn(async move {
        let mut buf = [0_u8; 2048];
        loop {
            let (read, from) = remote.recv_from(&mut buf).await?;
            if read == 0 {
                continue;
            }
            remote.send_to(&buf[..read], from).await?;
            if &buf[..read] == b"z" {
                return Ok::<_, anyhow::Error>(());
            }
        }
    });

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(remote_port)).serialize();
    let home = tempdir()?;
    let identity_path = home.path().join("identity.bin");
    store::save(&Identity::new(), &identity_path)?;

    let local_port = reserve_udp_port()?;
    let spec = format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}");
    let mut child = Command::cargo_bin("portl")?
        .env("PORTL_IDENTITY_KEY", &identity_path)
        .args(["udp", ticket.as_str(), "-L", spec.as_str()])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()?;

    wait_for_udp_forward(&mut child, local_port).await?;

    let app = UdpSocket::bind(("127.0.0.1", 0)).await?;
    app.send_to(b"z", ("127.0.0.1", local_port)).await?;

    let mut echoed = [0_u8; 16];
    let (read, _) = app.recv_from(&mut echoed).await?;
    assert_eq!(&echoed[..read], b"z");

    remote_task.await??;
    child.kill().context("kill udp command")?;
    let _status = child.wait().context("wait for killed udp command")?;

    shutdown(client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-cli-udp-revocations-{}.json",
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

fn udp_caps(port: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0100,
        shell: None,
        tcp: None,
        udp: Some(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min: port,
            port_max: port,
        }]),
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn reserve_udp_port() -> Result<u16> {
    let socket = std::net::UdpSocket::bind(("127.0.0.1", 0))?;
    let port = socket.local_addr()?.port();
    drop(socket);
    Ok(port)
}

async fn wait_for_udp_forward(child: &mut std::process::Child, local_port: u16) -> Result<()> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let probe = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let mut buf = [0_u8; 64];
    loop {
        probe.send_to(b"probe", ("127.0.0.1", local_port)).await?;
        if let Ok(Ok((read, _))) =
            tokio::time::timeout(Duration::from_millis(200), probe.recv_from(&mut buf)).await
            && &buf[..read] == b"probe"
        {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            let stderr = read_child_stderr(child)?;
            return Err(anyhow!(
                "timed out waiting for udp forward on {local_port}; stderr: {stderr}"
            ));
        }
        if let Some(status) = child.try_wait().context("poll udp command")? {
            let stderr = read_child_stderr(child)?;
            bail!("udp command exited early with {status}: {stderr}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
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
