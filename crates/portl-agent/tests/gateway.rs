use std::time::Duration;

use anyhow::{Context, Result};
use portl_agent::{AgentConfig, AgentMode, DiscoveryConfig, run_task};
use portl_core::id::Identity;
use portl_core::net::{open_tcp, open_ticket_v1};
use portl_core::test_util::pair;
use portl_core::ticket::master::mint_master;
use portl_core::ticket::schema::{Capabilities, PortRule};
use tokio::io::AsyncReadExt;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test]
#[ignore = "iroh tcp/v1 gateway forwarding remains flaky under in-process test endpoints"]
async fn gateway_injects_authorization_header_from_master_ticket() -> Result<()> {
    let upstream = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/"))
        .respond_with(ResponseTemplate::new(200).set_body_string("ok"))
        .mount(&upstream)
        .await;

    let (client, server) = pair().await?;
    let operator = Identity::new();
    let agent = run_task(AgentConfig {
        discovery: DiscoveryConfig::in_process(),
        trust_roots: vec![operator.verifying_key()],
        mode: AgentMode::Gateway {
            upstream_url: upstream.uri(),
            upstream_host: "127.0.0.1".to_owned(),
            upstream_port: upstream.address().port(),
        },
        endpoint: Some(server.clone()),
        ..AgentConfig::default()
    })
    .await?;

    let ticket = mint_master(
        operator.signing_key(),
        server.addr(),
        gateway_caps(upstream.address().port()),
        b"slicer-token".to_vec(),
        300,
        Some(operator.verifying_key()),
    )?;

    let (connection, session) = open_ticket_v1(&client, &ticket, &[], &operator)
        .await
        .context("open master ticket session")?;
    let (mut send, mut recv) = open_tcp(
        &connection,
        &session,
        "127.0.0.1",
        upstream.address().port(),
    )
    .await
    .context("open gateway tcp stream")?;

    send.write_all(b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
        .await?;
    send.finish()?;

    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(1), recv.read_to_end(&mut response)).await;
    tokio::time::sleep(Duration::from_millis(100)).await;

    connection.close(0u32.into(), b"done");
    client.inner().close().await;
    server.inner().close().await;
    let run_result = tokio::time::timeout(Duration::from_secs(5), agent)
        .await
        .context("gateway agent join timeout")?
        .context("gateway agent join error")?;
    run_result?;
    let requests = upstream
        .received_requests()
        .await
        .expect("received requests");
    assert_eq!(requests.len(), 1, "expected exactly one upstream request");
    let auth = requests[0]
        .headers
        .get("authorization")
        .expect("authorization header present");
    assert_eq!(
        auth.to_str().expect("header is utf-8"),
        "Bearer 736c696365722d746f6b656e"
    );
    Ok(())
}

fn gateway_caps(port: u16) -> Capabilities {
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
