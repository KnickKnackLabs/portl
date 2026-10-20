//! The agent endpoint's relay connection honors portl's proxy setting.
//!
//! Runs a local iroh relay plus an in-process recording HTTP CONNECT
//! proxy, then checks that relay traffic goes through the proxy when one
//! is configured, and bypasses it when `direct` is forced even though
//! `HTTPS_PROXY` & co. point at it.

#[allow(dead_code)]
mod common;

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use iroh_base::{EndpointAddr, RelayUrl};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use portl_agent::{AgentConfig, DiscoveryConfig};
use portl_core::id::Identity;
use portl_core::proxy::{ProxySetting, ProxySource, ProxyUrl};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const ALPN: &[u8] = b"portl-test/proxy-echo";

/// Both tests rewrite process-wide proxy state; keep them apart under
/// `cargo test` (nextest already isolates them per process).
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

struct RecordingProxy {
    addr: SocketAddr,
    /// Request heads in arrival order.
    requests: Arc<Mutex<Vec<String>>>,
}

impl RecordingProxy {
    /// `tunnel = false` answers every request with 403 (a proxy portl
    /// must not use).
    async fn spawn(tunnel: bool) -> Result<Self> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&requests);
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let _ = serve_proxy_client(socket, tunnel, log).await;
                });
            }
        });
        Ok(Self { addr, requests })
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("proxy log").clone()
    }
}

async fn serve_proxy_client(
    mut client: TcpStream,
    tunnel: bool,
    log: Arc<Mutex<Vec<String>>>,
) -> Result<()> {
    let mut head = Vec::new();
    let mut byte = [0_u8];
    while !head.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).await?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head)?;
    log.lock().expect("proxy log").push(head.clone());
    if !tunnel {
        client
            .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await?;
        return Ok(());
    }
    let mut parts = head.split_whitespace();
    let (method, target) = (
        parts.next().unwrap_or_default(),
        parts.next().unwrap_or_default(),
    );
    let mut upstream;
    if method == "CONNECT" {
        upstream = TcpStream::connect(target).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
    } else {
        // Absolute-form plain-HTTP request (e.g. net-report probes of an
        // http:// relay): forward it in origin form.
        let url = url::Url::parse(target)?;
        let authority = format!(
            "{}:{}",
            url.host_str().unwrap_or_default(),
            url.port_or_known_default().unwrap_or(80)
        );
        upstream = TcpStream::connect(authority).await?;
        let origin_form = head.replacen(target, &url[url::Position::BeforePath..], 1);
        upstream.write_all(origin_form.as_bytes()).await?;
    }
    tokio::io::copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

/// A plain-HTTP iroh relay on loopback.
async fn spawn_relay() -> Result<(Server, RelayUrl, SocketAddr)> {
    let mut config = ServerConfig::default();
    config.relay = Some(RelayConfig::new((Ipv4Addr::LOCALHOST, 0)));
    config.quic = None;
    config.metrics_addr = None;
    let server = Server::spawn(config).await.context("spawn relay")?;
    let addr = server.http_addr().context("relay http addr")?;
    let url = format!("http://{addr}/").parse()?;
    Ok((server, url, addr))
}

/// An endpoint built by the production agent path, relay-only.
async fn agent_endpoint(relay: &RelayUrl) -> Result<iroh::Endpoint> {
    let cfg = AgentConfig {
        bind_addr: Some("127.0.0.1:0".parse()?),
        discovery: DiscoveryConfig {
            relays: vec![relay.clone()],
            ..DiscoveryConfig::in_process()
        },
        ..AgentConfig::default()
    };
    let endpoint = portl_agent::endpoint::bind(&cfg, &Identity::new()).await?;
    endpoint.set_alpns(vec![ALPN.to_vec()]);
    if tokio::time::timeout(Duration::from_secs(10), endpoint.online())
        .await
        .is_err()
    {
        use iroh::Watcher as _;
        let errors = endpoint
            .home_relay_status()
            .get()
            .iter()
            .map(|relay| format!("{}: {:?}", relay.url(), relay.last_error()))
            .collect::<Vec<_>>();
        bail!("endpoint never connected to its home relay: {errors:?}");
    }
    Ok(endpoint)
}

/// Dial `server` by relay URL only and round-trip a message.
async fn echo_via_relay(
    client: &iroh::Endpoint,
    server: &iroh::Endpoint,
    relay: &RelayUrl,
) -> Result<()> {
    let accept = {
        let server = server.clone();
        tokio::spawn(async move {
            let connection = server.accept().await.context("accept")?.await?;
            let (mut send, mut recv) = connection.accept_bi().await?;
            let msg = recv.read_to_end(64).await?;
            send.write_all(&msg).await?;
            send.finish()?;
            connection.closed().await;
            anyhow::Ok(())
        })
    };
    let addr = EndpointAddr::new(server.id()).with_relay_url(relay.clone());
    let connection = client.connect(addr, ALPN).await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(b"via relay").await?;
    send.finish()?;
    let echoed = recv.read_to_end(64).await?;
    if echoed != b"via relay" {
        bail!("unexpected echo {echoed:?}");
    }
    connection.close(0u32.into(), b"done");
    let _ = tokio::time::timeout(Duration::from_secs(2), accept).await;
    Ok(())
}

async fn close(endpoints: [iroh::Endpoint; 2]) {
    for endpoint in endpoints {
        let _ = tokio::time::timeout(Duration::from_secs(2), endpoint.close()).await;
    }
}

#[tokio::test]
async fn relay_connections_go_through_configured_proxy() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let (_relay, relay_url, relay_addr) = spawn_relay().await?;
    let proxy = RecordingProxy::spawn(true).await?;
    let proxy_url = format!("http://user:pass@{}", proxy.addr);

    let cfg = portl_core::proxy::init_process(
        Some(ProxySetting::Proxy(ProxyUrl::parse(&proxy_url)?)),
        None,
    )?;
    assert_eq!(cfg.source(), ProxySource::Flag);
    // iroh's own reqwest clients (pkarr, net-report) read these.
    assert_eq!(std::env::var("HTTPS_PROXY")?, format!("{proxy_url}/"));

    let server = agent_endpoint(&relay_url).await?;
    let client = agent_endpoint(&relay_url).await?;
    echo_via_relay(&client, &server, &relay_url).await?;

    let connects = proxy
        .requests()
        .into_iter()
        .filter(|head| head.starts_with(&format!("CONNECT {relay_addr} HTTP/1.1\r\n")))
        .collect::<Vec<_>>();
    assert!(
        connects.len() >= 2,
        "both endpoints must reach the relay through the proxy; proxy saw {:?}",
        proxy.requests()
    );
    // base64("user:pass"); header names are case-insensitive.
    assert!(
        connects.iter().all(|head| head
            .lines()
            .any(|line| line.split_once(':').is_some_and(|(name, value)| name
                .eq_ignore_ascii_case("proxy-authorization")
                && value.trim() == "Basic dXNlcjpwYXNz"))),
        "{connects:?}"
    );
    close([client, server]).await;
    Ok(())
}

#[tokio::test]
#[allow(unsafe_code)]
async fn forced_direct_ignores_standard_proxy_env() -> Result<()> {
    let _serial = SERIAL.lock().await;
    let (_relay, relay_url, _) = spawn_relay().await?;
    let trap = RecordingProxy::spawn(false).await?;
    let trap_url = format!("http://{}", trap.addr);
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
    ] {
        // SAFETY: serialized by SERIAL; no other test thread touches env.
        unsafe { std::env::set_var(name, &trap_url) };
    }
    // SAFETY: as above.
    unsafe { std::env::set_var("PORTL_PROXY", "direct") };

    let cfg = portl_core::proxy::init_process(None, Some("http://ignored-file-proxy:1"))?;
    assert_eq!(cfg.source(), ProxySource::PortlProxyEnv);
    assert!(std::env::var_os("HTTPS_PROXY").is_none());
    assert!(std::env::var_os("HTTP_PROXY").is_none());

    let server = agent_endpoint(&relay_url).await?;
    let client = agent_endpoint(&relay_url).await?;
    echo_via_relay(&client, &server, &relay_url).await?;

    assert_eq!(
        trap.requests(),
        Vec::<String>::new(),
        "forced direct must not touch the env proxy"
    );
    close([client, server]).await;
    Ok(())
}
