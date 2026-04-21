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
