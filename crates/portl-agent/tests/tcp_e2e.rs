use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{open_tcp, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, PortRule, PortlTicket};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn tcp_forward_echo() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut buf = Vec::new();
        socket.read_to_end(&mut buf).await?;
        socket.write_all(&buf).await?;
        socket.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(port, port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let (mut send, mut recv) = open_tcp(&connection, &session, "127.0.0.1", port).await?;
    send.write_all(b"hello over tcp").await?;
    send.finish()?;

    let mut echoed = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut echoed).await?;
    assert_eq!(echoed, b"hello over tcp");

    echo_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn tcp_forward_large_transfer_10mb_no_corruption() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let (digest_tx, digest_rx) = tokio::sync::oneshot::channel();
    let echo_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        let mut hasher = Sha256::new();
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            let read = socket.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            hasher.update(&buf[..read]);
            socket.write_all(&buf[..read]).await?;
        }
        socket.shutdown().await?;
        let _ = digest_tx.send(hasher.finalize().to_vec());
        Ok::<_, anyhow::Error>(())
    });

    let payload = random_payload(10 * 1024 * 1024);
    let client_digest = Sha256::digest(&payload).to_vec();

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(port, port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let (mut send, mut recv) = open_tcp(&connection, &session, "127.0.0.1", port).await?;
    let send_task = tokio::spawn(async move {
        send.write_all(&payload).await?;
        send.finish()?;
        Ok::<_, anyhow::Error>(())
    });

    let mut echoed = Vec::with_capacity(10 * 1024 * 1024);
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut echoed).await?;
    send_task.await??;

    let echoed_digest = Sha256::digest(&echoed).to_vec();
    let server_digest = digest_rx.await.context("server digest channel")?;

    assert_eq!(client_digest, echoed_digest);
    assert_eq!(client_digest, server_digest);

    echo_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn tcp_preserves_server_data_sent_immediately_after_ack() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let server_task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await?;
        socket.write_all(b"HELLO\n").await?;

        let mut buf = [0_u8; 1024];
        loop {
            let read = socket.read(&mut buf).await?;
            if read == 0 {
                break;
            }
            socket.write_all(&buf[..read]).await?;
        }
        socket.shutdown().await?;
        Ok::<_, anyhow::Error>(())
    });

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(port, port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let (mut send, mut recv) = open_tcp(&connection, &session, "127.0.0.1", port).await?;

    let mut banner = [0_u8; 6];
    recv.read_exact(&mut banner).await?;
    assert_eq!(&banner, b"HELLO\n");

    send.write_all(b"echo").await?;
    send.finish()?;

    let mut echoed = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut echoed).await?;
    assert_eq!(echoed, b"echo");

    server_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn tcp_forward_propagates_eof_both_directions() -> Result<()> {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let port = listener.local_addr()?.port();
    let (client_seen_tx, client_seen_rx) = tokio::sync::oneshot::channel();
    let server_task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await?;
        let (mut read_half, mut write_half) = socket.into_split();
        write_half.write_all(b"server hello").await?;
        write_half.shutdown().await?;

        let mut client_payload = Vec::new();
        read_half.read_to_end(&mut client_payload).await?;
        let _ = client_seen_tx.send(client_payload);
        Ok::<_, anyhow::Error>(())
    });

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(port, port));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let (mut send, mut recv) = open_tcp(&connection, &session, "127.0.0.1", port).await?;
    send.write_all(b"client hello").await?;
    send.finish()?;

    let mut server_payload = Vec::new();
    tokio::io::AsyncReadExt::read_to_end(&mut recv, &mut server_payload).await?;
    let client_payload = client_seen_rx.await.context("client payload channel")?;

    assert_eq!(server_payload, b"server hello");
    assert_eq!(client_payload, b"client hello");

    server_task.await??;
    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn tcp_rejects_destination_not_permitted_by_caps() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), tcp_caps(22, 22));

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let err = open_tcp(&connection, &session, "127.0.0.1", 80)
        .await
        .expect_err("tcp destination should be rejected");
    assert!(err.to_string().contains("rejected"));

    shutdown(connection, client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-tcp-revocations-{}.json",
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

fn tcp_caps(port_min: u16, port_max: u16) -> Capabilities {
    Capabilities {
        presence: 0b0000_0010,
        shell: None,
        tcp: Some(vec![PortRule {
            host_glob: "127.0.0.1".to_owned(),
            port_min,
            port_max,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
    }
}

fn random_payload(len: usize) -> Vec<u8> {
    let mut payload = vec![0_u8; len];
    rand::thread_rng().fill_bytes(&mut payload);
    payload
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
