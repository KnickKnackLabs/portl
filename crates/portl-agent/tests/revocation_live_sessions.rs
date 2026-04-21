#[allow(dead_code)]
mod common;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::shell_client::PtyCfg;
use portl_core::net::{open_shell, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::hash::ticket_id;
use portl_core::ticket::mint::{mint_delegated, mint_root};
use portl_core::ticket::schema::{Capabilities, EnvPolicy, MetaCaps, PortlTicket, ShellCaps};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};

#[tokio::test]
async fn revocation_cancels_live_shell_session_within_2s() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_and_meta_caps());

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut shell = open_shell(
        &connection,
        &session,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    shell
        .stdin
        .write_all(b"trap 'exit 0' HUP TERM\nwhile :; do sleep 1; done\n")
        .await?;

    let response = publish_revocations(
        &connection,
        session.peer_token,
        vec![ticket_id(&ticket.sig).to_vec()],
    )
    .await?;
    assert!(matches!(response, MetaResp::PublishedRevocations { .. }));

    let _exit = tokio::time::timeout(Duration::from_secs(2), shell.wait_exit())
        .await
        .context("shell session was not cancelled within 2s")??;

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn revocation_of_parent_ticket_cancels_delegated_session() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent(server.clone(), &operator).await?;
    let parent = root_ticket(&operator, server.addr(), shell_and_meta_caps());
    // Mint the delegated child strictly inside the parent's window so
    // the test doesn't race the wall-clock second boundary between the
    // two `unix_now_secs()` calls.
    let delegated = mint_delegated(
        operator.signing_key(),
        &parent,
        shell_and_meta_caps(),
        parent.body.not_before,
        parent.body.not_after,
        None,
    )
    .expect("mint delegated ticket");

    let parent_chain = vec![parent.clone()];
    let (connection, session) =
        open_ticket_v1(&client, &delegated, &parent_chain, &operator).await?;
    let mut shell = open_shell(
        &connection,
        &session,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    shell
        .stdin
        .write_all(b"trap 'exit 0' HUP TERM\nwhile :; do sleep 1; done\n")
        .await?;

    let response = publish_revocations(
        &connection,
        session.peer_token,
        vec![ticket_id(&parent.sig).to_vec()],
    )
    .await?;
    assert!(matches!(response, MetaResp::PublishedRevocations { .. }));

    let _exit = tokio::time::timeout(Duration::from_secs(2), shell.wait_exit())
        .await
        .context("delegated shell session was not cancelled within 2s")??;

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn local_revocation_file_append_cancels_live_shell_session_within_2s() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let revocations_path = std::env::temp_dir().join(format!(
        "portl-agent-local-revocations-{}.jsonl",
        rand::random::<u64>()
    ));
    let agent = start_agent_at_path(
        server.clone(),
        &operator,
        revocations_path.clone(),
        portl_agent::revocations::DEFAULT_REVOCATIONS_MAX_BYTES,
    )
    .await?;
    let ticket = root_ticket(&operator, server.addr(), shell_and_meta_caps());

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let mut shell = open_shell(
        &connection,
        &session,
        None,
        None,
        PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        },
    )
    .await?;
    shell
        .stdin
        .write_all(b"trap 'exit 0' HUP TERM\nwhile :; do sleep 1; done\n")
        .await?;

    portl_agent::revocations::append_record(
        &revocations_path,
        &portl_agent::RevocationRecord::new(
            ticket_id(&ticket.sig),
            "manual",
            unix_now_secs(),
            None,
        ),
    )?;

    let _exit = tokio::time::timeout(Duration::from_secs(2), shell.wait_exit())
        .await
        .context("shell session was not cancelled from local file append within 2s")??;

    shutdown(connection, client, server, agent).await
}

#[tokio::test]
async fn publish_revocations_replies_resource_exhausted_on_ceiling() -> Result<()> {
    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = start_agent_with_max_bytes(server.clone(), &operator, 1).await?;
    let ticket = root_ticket(&operator, server.addr(), shell_and_meta_caps());

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator).await?;
    let response = publish_revocations(
        &connection,
        session.peer_token,
        vec![ticket_id(&ticket.sig).to_vec()],
    )
    .await?;

    match response {
        MetaResp::Error(err) => {
            assert_eq!(err.kind, portl_proto::error::ErrorKind::ResourceExhausted);
        }
        other => anyhow::bail!("unexpected response: {other:?}"),
    }

    shutdown(connection, client, server, agent).await
}

async fn start_agent(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    start_agent_with_max_bytes(
        server,
        operator,
        portl_agent::revocations::DEFAULT_REVOCATIONS_MAX_BYTES,
    )
    .await
}

async fn start_agent_with_max_bytes(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
    revocations_max_bytes: u64,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    start_agent_at_path(
        server,
        operator,
        std::env::temp_dir().join(format!(
            "portl-agent-live-revocations-{}.jsonl",
            rand::random::<u64>()
        )),
        revocations_max_bytes,
    )
    .await
}

async fn start_agent_at_path(
    server: portl_core::endpoint::Endpoint,
    operator: &Identity,
    revocations_path: std::path::PathBuf,
    revocations_max_bytes: u64,
) -> Result<tokio::task::JoinHandle<Result<()>>> {
    run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        revocations_path: Some(revocations_path),
        revocations_max_bytes: Some(revocations_max_bytes),
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
    let now = unix_now_secs();
    mint_root(operator.signing_key(), addr, caps, now, now + 300, None).expect("mint root")
}

fn shell_and_meta_caps() -> Capabilities {
    Capabilities {
        presence: 0b0010_0001,
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
        meta: Some(MetaCaps {
            ping: true,
            info: true,
        }),
    }
}

fn unix_now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("unix time")
        .as_secs()
}

async fn publish_revocations(
    connection: &iroh::endpoint::Connection,
    peer_token: [u8; 16],
    items: Vec<Vec<u8>>,
) -> Result<MetaResp> {
    let envelope = MetaEnvelope {
        preamble: StreamPreamble {
            peer_token,
            alpn: "portl/meta/v1".to_owned(),
        },
        req: MetaReq::PublishRevocations { items },
    };

    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(&postcard::to_stdvec(&envelope.preamble)?)
        .await?;
    send.write_all(&postcard::to_stdvec(&envelope.req)?).await?;
    send.finish()?;

    let bytes = recv
        .read_to_end(64 * 1024)
        .await
        .context("read publish revocations response")?;
    let response = postcard::from_bytes::<MetaResp>(&bytes)?;
    Ok(response)
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
    let _ = tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .context("agent join timeout")??;
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
struct MetaEnvelope {
    preamble: StreamPreamble,
    req: MetaReq,
}
