use std::net::UdpSocket as StdUdpSocket;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use bytes::Bytes;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{open_ticket_v1, open_udp, run_local_udp_forward};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortRule, PortlTicket};
use portl_proto::udp_v1::{UdpBind, UdpDatagram};
use tokio::net::UdpSocket;

#[tokio::test]
async fn udp_ctl_roundtrip() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_udp(
        &connection,
        &session,
        None,
        vec![udp_bind(echo.port, echo.port)],
    )
    .await?;

    assert_ne!(control.session_id, [0; 8]);

    close_connection(&connection);
    echo.task.abort();
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_echo_single_datagram() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let forward_port = reserve_udp_port()?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_udp(
        &connection,
        &session,
        None,
        vec![udp_bind(forward_port, echo.port)],
    )
    .await?;
    let forward_addr = format!("127.0.0.1:{forward_port}");
    let forward_connection = connection.clone();
    let forward = tokio::spawn(async move {
        run_local_udp_forward(forward_connection, control, &forward_addr, echo.port).await
    });

    let app = UdpSocket::bind(("127.0.0.1", 0)).await?;
    app.send_to(b"0123456789", ("127.0.0.1", forward_port))
        .await?;

    let mut buf = [0_u8; 64];
    let (read, _) = tokio::time::timeout(Duration::from_secs(5), app.recv_from(&mut buf)).await??;
    assert_eq!(&buf[..read], b"0123456789");

    forward.abort();
    close_connection(&connection);
    echo.task.abort();
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_large_burst_no_loss_loopback() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let forward_port = reserve_udp_port()?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_udp(
        &connection,
        &session,
        None,
        vec![udp_bind(forward_port, echo.port)],
    )
    .await?;
    let forward_addr = format!("127.0.0.1:{forward_port}");
    let forward_connection = connection.clone();
    let forward = tokio::spawn(async move {
        run_local_udp_forward(forward_connection, control, &forward_addr, echo.port).await
    });

    let app = std::sync::Arc::new(UdpSocket::bind(("127.0.0.1", 0)).await?);
    app.connect(("127.0.0.1", forward_port)).await?;

    let sender = {
        let app = std::sync::Arc::clone(&app);
        tokio::spawn(async move {
            for seq in 0_u32..10_000 {
                let mut payload = vec![0_u8; 100];
                payload[..4].copy_from_slice(&seq.to_be_bytes());
                app.send(&payload).await?;
                tokio::time::sleep(Duration::from_micros(100)).await;
            }
            Ok::<_, anyhow::Error>(())
        })
    };

    let mut seen = vec![false; 10_000];
    let mut buf = vec![0_u8; 256];
    while seen.iter().any(|present| !present) {
        let read = tokio::time::timeout(Duration::from_secs(10), app.recv(&mut buf)).await??;
        let seq = u32::from_be_bytes(buf[..4].try_into().expect("4 byte seq"));
        seen[seq as usize] = true;
        assert_eq!(read, 100);
    }
    sender.await??;
    assert!(seen.iter().all(|present| *present));

    forward.abort();
    close_connection(&connection);
    echo.task.abort();
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_session_linger_survives_control_close() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection1, session1) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control1 = open_udp(
        &connection1,
        &session1,
        None,
        vec![udp_bind(echo.port, echo.port)],
    )
    .await?;
    let session_id = control1.session_id;

    send_udp_datagram(&connection1, session_id, echo.port, 1, b"first").await?;
    let echoed1 = recv_udp_datagram(&connection1).await?;
    assert_eq!(echoed1.payload, b"first");

    control1.close()?;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let (connection2, session2) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control2 = open_udp(
        &connection2,
        &session2,
        Some(session_id),
        vec![udp_bind(echo.port, echo.port)],
    )
    .await?;
    assert_eq!(control2.session_id, session_id);

    send_udp_datagram(&connection2, session_id, echo.port, 1, b"second").await?;
    let echoed2 = recv_udp_datagram(&connection2).await?;
    assert_eq!(echoed2.payload, b"second");

    close_connection(&connection1);
    close_connection(&connection2);
    echo.task.abort();
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_session_expires_after_linger() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, Some(1)).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection1, session1) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control1 = open_udp(
        &connection1,
        &session1,
        None,
        vec![udp_bind(echo.port, echo.port)],
    )
    .await?;
    let session_id = control1.session_id;
    control1.close()?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let (connection2, session2) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control2 = open_udp(
        &connection2,
        &session2,
        Some(session_id),
        vec![udp_bind(echo.port, echo.port)],
    )
    .await?;

    assert_ne!(control2.session_id, session_id);

    close_connection(&connection1);
    close_connection(&connection2);
    echo.task.abort();
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_rejects_destination_not_permitted_by_caps() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(53, 53));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let err = open_udp(&connection, &session, None, vec![udp_bind(5000, 80)])
        .await
        .expect_err("udp bind should be rejected");
    assert!(err.to_string().contains("rejected"));

    close_connection(&connection);
    shutdown(client, server, agent).await
}

#[tokio::test]
async fn udp_oversize_payload_rejected() -> Result<()> {
    let echo = start_udp_echo_server().await?;
    let forward_port = reserve_udp_port()?;
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator, None).await?;
    let ticket = root_ticket(&operator, server.addr(), udp_caps(echo.port, echo.port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let control = open_udp(
        &connection,
        &session,
        None,
        vec![udp_bind(forward_port, echo.port)],
    )
    .await?;
    let forward_addr = format!("127.0.0.1:{forward_port}");
    let forward_connection = connection.clone();
    let forward = tokio::spawn(async move {
        run_local_udp_forward(forward_connection, control, &forward_addr, echo.port).await
    });

    let app = UdpSocket::bind(("127.0.0.1", 0)).await?;
    app.send_to(&[7_u8; 2000], ("127.0.0.1", forward_port))
        .await?;

    let mut buf = vec![0_u8; 256];
    let (read, _) = tokio::time::timeout(Duration::from_secs(5), app.recv_from(&mut buf)).await??;
    let message = String::from_utf8(buf[..read].to_vec())?;
    assert!(message.contains("payload too large"));

    forward.abort();
    close_connection(&connection);
    echo.task.abort();
    shutdown(client, server, agent).await
}

struct EchoServer {
    port: u16,
    task: tokio::task::JoinHandle<Result<()>>,
}

async fn start_udp_echo_server() -> Result<EchoServer> {
    let socket = UdpSocket::bind(("127.0.0.1", 0)).await?;
    let port = socket.local_addr()?.port();
    let task = tokio::spawn(async move {
        let mut buf = vec![0_u8; 64 * 1024];
        loop {
            let (read, from) = socket.recv_from(&mut buf).await?;
            socket.send_to(&buf[..read], from).await?;
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    });
    Ok(EchoServer { port, task })
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
    linger_secs: Option<u64>,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-udp-revocations-{}.json",
        rand::random::<u64>()
    ));
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        udp_session_linger_secs: linger_secs,
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

fn udp_caps(port_min: u16, port_max: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0100,
        shell: None,
        tcp: None,
        udp: Some(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min,
            port_max,
        }]),
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn udp_bind(local_port: u16, remote_port: u16) -> UdpBind {
    UdpBind {
        local_port_range: (local_port, local_port),
        target_host: "127.0.0.1".to_owned(),
        target_port_range: (remote_port, remote_port),
    }
}

async fn send_udp_datagram(
    connection: &iroh::endpoint::Connection,
    session_id: [u8; 8],
    target_port: u16,
    src_tag: u32,
    payload: &[u8],
) -> Result<()> {
    connection
        .send_datagram_wait(Bytes::from(postcard::to_stdvec(&UdpDatagram {
            session_id,
            target_port,
            src_tag,
            payload: payload.to_vec(),
        })?))
        .await
        .context("send udp datagram")?;
    Ok(())
}

async fn recv_udp_datagram(connection: &iroh::endpoint::Connection) -> Result<UdpDatagram> {
    let bytes = tokio::time::timeout(Duration::from_secs(5), connection.read_datagram())
        .await
        .context("timed out waiting for udp datagram")??;
    Ok(postcard::from_bytes(&bytes)?)
}

fn reserve_udp_port() -> Result<u16> {
    let socket = StdUdpSocket::bind(("127.0.0.1", 0))?;
    let port = socket.local_addr()?.port();
    drop(socket);
    Ok(port)
}

fn close_connection(connection: &iroh::endpoint::Connection) {
    connection.close(0u32.into(), b"done");
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
