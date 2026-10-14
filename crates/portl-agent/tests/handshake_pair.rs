#[allow(dead_code)]
mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{AckReason, TicketHandshakeError, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps, PortlTicket};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};

#[tokio::test]
async fn handshake_pair_accepts_and_serves_meta() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        meta_caps(),
        unix_now_secs(),
        unix_now_secs() + 300,
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    assert_eq!(session.effective_caps, meta_caps());

    let ping = meta_request(
        &connection,
        session.peer_token,
        MetaReq::Ping { t_client_us: 7 },
    )
    .await?;
    assert!(matches!(ping, MetaResp::Pong { .. }));

    let info = meta_request(&connection, session.peer_token, MetaReq::Info).await?;
    match info {
        MetaResp::Info {
            agent_version,
            supported_alpns,
            uptime_s,
            ..
        } => {
            assert_eq!(agent_version, env!("CARGO_PKG_VERSION"));
            assert!(supported_alpns.contains(&"portl/meta/v1".to_owned()));
            assert!(supported_alpns.contains(&"portl/tcp/v2".to_owned()));
            assert!(uptime_s <= 5);
        }
        other => panic!("unexpected info response: {other:?}"),
    }

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[tokio::test]
async fn handshake_pair_serves_concurrent_meta_streams() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(
        &operator,
        server.addr(),
        meta_caps(),
        unix_now_secs(),
        unix_now_secs() + 300,
    );

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;

    let (mut stalled_send, _stalled_recv) = connection.open_bi().await?;
    let ping = tokio::time::timeout(
        Duration::from_secs(2),
        meta_request(
            &connection,
            session.peer_token,
            MetaReq::Ping { t_client_us: 7 },
        ),
    )
    .await
    .expect("second meta stream should not head-of-line block")?;
    assert!(matches!(ping, MetaResp::Pong { .. }));

    stalled_send.reset(0u32.into())?;
    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[tokio::test]
async fn handshake_pair_rejects_expired_ticket() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let now = unix_now_secs();
    let ticket = root_ticket(&operator, server.addr(), meta_caps(), now - 300, now - 1);

    let err = open_ticket_v1(&client, &ticket, &[], &operator)
        .await
        .expect_err("expired ticket should fail");
    assert_eq!(downcast_reason(err), Some(AckReason::Expired));

    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

#[tokio::test]
async fn handshake_pair_rejects_bad_signature() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let now = unix_now_secs();
    let mut ticket = root_ticket(&operator, server.addr(), meta_caps(), now, now + 300);
    ticket.body.not_after += 1;

    let err = open_ticket_v1(&client, &ticket, &[], &operator)
        .await
        .expect_err("tampered ticket should fail");
    assert_eq!(downcast_reason(err), Some(AckReason::BadSignature));

    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

/// A peer that sends its QUIC Initial and then goes silent (a roaming client
/// that switched networks mid-handshake) must not block later connections.
#[tokio::test]
async fn stalled_incoming_handshake_does_not_block_later_connections() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;

    // Black-hole proxy: forwards client datagrams to the agent from a separate
    // socket and never relays replies, so the agent's handshake stays half-open.
    let server_addr = server
        .inner()
        .bound_sockets()
        .into_iter()
        .find(std::net::SocketAddr::is_ipv4)
        .expect("agent bound an IPv4 socket");
    let front = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let back = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let proxy_addr = front.local_addr()?;
    let (forwarded_tx, mut forwarded_rx) = tokio::sync::watch::channel(0_usize);
    let proxy = tokio::spawn(async move {
        let mut buf = vec![0_u8; 65_536];
        let mut forwarded = 0;
        while let Ok((len, _)) = front.recv_from(&mut buf).await {
            if back.send_to(&buf[..len], server_addr).await.is_ok() {
                forwarded += 1;
                let _ = forwarded_tx.send(forwarded);
            }
        }
    });

    let stalled_client = portl_core::test_util::endpoint().await?;
    let stalled_addr = iroh_base::EndpointAddr::new(server.id()).with_ip_addr(proxy_addr);
    let stalled_connect = tokio::spawn(async move {
        let _ = stalled_client
            .inner()
            .connect(stalled_addr, portl_proto::ticket_v1::ALPN_TICKET_V1)
            .await;
    });
    tokio::time::timeout(
        Duration::from_secs(5),
        forwarded_rx.wait_for(|count| *count > 0),
    )
    .await
    .expect("stalled client Initial reached the agent")?;
    // Let the agent's accept loop take the half-open handshake first.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let ticket = root_ticket(
        &operator,
        server.addr(),
        meta_caps(),
        unix_now_secs(),
        unix_now_secs() + 300,
    );
    let (connection, _session) = tokio::time::timeout(
        Duration::from_secs(5),
        open_ticket_v1(&client, &ticket, &[], &operator),
    )
    .await
    .expect("second connection accepted while another handshake is stalled")?;

    connection.close(0u32.into(), b"done");
    stalled_connect.abort();
    proxy.abort();
    client.inner().close().await;
    server.inner().close().await;
    tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .expect("agent join timeout")??;
    Ok(())
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-test-revocations-{}.json",
        rand::random::<u64>()
    ));
    let handle = run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        endpoint: Some(server),
        ..AgentConfig::default()
    })
    .await?;
    Ok(handle)
}

fn root_ticket(
    operator: &Identity,
    addr: iroh_base::EndpointAddr,
    caps: Capabilities,
    not_before: u64,
    not_after: u64,
) -> PortlTicket {
    mint_root(
        operator.signing_key(),
        addr,
        caps,
        not_before,
        not_after,
        None,
    )
    .expect("mint root")
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
        unix: None,
    }
}

fn downcast_reason(err: anyhow::Error) -> Option<AckReason> {
    err.downcast::<TicketHandshakeError>()
        .ok()
        .and_then(|err| err.reason)
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

async fn meta_request(
    connection: &iroh::endpoint::Connection,
    peer_token: [u8; 16],
    req: MetaReq,
) -> Result<MetaResp> {
    let envelope = MetaEnvelope {
        preamble: StreamPreamble {
            peer_token,
            alpn: "portl/meta/v1".to_owned(),
        },
        req,
    };
    let bytes = postcard::to_stdvec(&envelope)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&bytes).await?;
    send.finish()?;
    let response = recv.read_to_end(64 * 1024).await?;
    Ok(postcard::from_bytes(&response)?)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaEnvelope {
    preamble: StreamPreamble,
    req: MetaReq,
}
