use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
use iroh::address_lookup::AddressLookupFailed;
use iroh::endpoint::Connection;
use iroh_base::{EndpointAddr, EndpointId, TransportAddr};
use iroh_tickets::Ticket;
use n0_future::StreamExt;
use portl_core::endpoint::Endpoint;
use portl_core::id::{Identity, store};
use portl_core::net::{PeerSession, open_ticket_v1};
use portl_core::ticket::mint::mint_root;
use portl_core::ticket::schema::{Capabilities, MetaCaps, PortlTicket};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};

use crate::alias_store::AliasStore;

pub fn run(peer: Option<&str>, relay: bool, json: bool, watch: Option<u64>) -> Result<ExitCode> {
    if let Some(p) = peer {
        if json || watch.is_some() {
            bail!("--json and --watch are only supported on the no-arg dashboard form");
        }
        run_with_identity_path_mode(p, None, relay)
    } else {
        if relay {
            bail!("--relay requires <peer>");
        }
        run_dashboard(json, watch)
    }
}

pub fn run_with_identity_path(peer: &str, identity_path: Option<&Path>) -> Result<ExitCode> {
    run_with_identity_path_mode(peer, identity_path, false)
}

/// No-peer-arg dashboard: pull from the agent's IPC socket and
/// render either as a human table or as JSON.
fn run_dashboard(json: bool, watch: Option<u64>) -> Result<ExitCode> {
    if json && watch.is_some() {
        bail!("--watch --json is not supported (watching JSON is meaningless)");
    }
    let Some(interval_secs) = watch else {
        return render_once(json);
    };
    if !(1..=3600).contains(&interval_secs) {
        bail!("--watch interval must be between 1 and 3600 seconds");
    }
    let is_tty = std::io::IsTerminal::is_terminal(&std::io::stdout());
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(async move {
        let mut tick = 0u64;
        let ctrl_c = tokio::signal::ctrl_c();
        tokio::pin!(ctrl_c);
        loop {
            if is_tty {
                print!("\x1b[2J\x1b[H");
            } else {
                println!("--- tick {tick} ---");
            }
            match dashboard_snapshot().await {
                Ok(snap) => println!("{}", render_dashboard_human(&snap)),
                Err(e) => {
                    eprintln!("(status unavailable: {e:#}) — retrying in {interval_secs}s");
                }
            }
            tokio::select! {
                () = tokio::time::sleep(std::time::Duration::from_secs(interval_secs)) => {}
                _ = &mut ctrl_c => break,
            }
            tick += 1;
        }
        Ok::<(), anyhow::Error>(())
    })?;
    Ok(ExitCode::SUCCESS)
}

fn render_once(json: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let snap = runtime.block_on(async { dashboard_snapshot().await })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&snap)?);
    } else {
        println!("{}", render_dashboard_human(&snap));
    }
    Ok(ExitCode::SUCCESS)
}

async fn dashboard_snapshot() -> Result<portl_agent::status_schema::StatusResponse> {
    let socket = crate::agent_ipc::default_socket_path();
    crate::agent_ipc::fetch_status(&socket)
        .await
        .with_context(|| format!("contact agent at {}", socket.display()))
}

fn render_dashboard_human(snap: &portl_agent::status_schema::StatusResponse) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(snap.agent.started_at_unix);
    let up = now.saturating_sub(snap.agent.started_at_unix);
    let _ = writeln!(
        s,
        "agent:          pid {} v{} up {}",
        snap.agent.pid,
        snap.agent.version,
        humantime::format_duration(std::time::Duration::from_secs(up))
    );
    let _ = writeln!(s, "                home: {}", snap.agent.home);
    let _ = writeln!(s, "                metrics: {}", snap.agent.metrics_socket);
    let _ = writeln!(s);
    let _ = writeln!(
        s,
        "network:        discovery: dns={} pkarr={} local={}",
        snap.network.discovery.dns, snap.network.discovery.pkarr, snap.network.discovery.local
    );
    if snap.network.relays.is_empty() {
        let _ = writeln!(s, "                relays:    (disabled)");
    } else {
        let _ = writeln!(
            s,
            "                relays:    {}",
            snap.network.relays.join(", ")
        );
    }
    let _ = writeln!(s);
    let _ = writeln!(s, "connections:    {} active", snap.connections.len());
    for c in &snap.connections {
        let rtt = c
            .rtt_micros
            .map_or_else(|| "—".to_owned(), |u| format!("{}ms", u / 1000));
        let up_secs = now.saturating_sub(c.up_since_unix);
        let _ = writeln!(
            s,
            "                - {eid_short}…  path={path}  rtt={rtt}  up={up_secs}s  rx={rx}B tx={tx}B",
            eid_short = &c.peer_eid[..16.min(c.peer_eid.len())],
            path = c.path.as_str(),
            rx = c.bytes_rx,
            tx = c.bytes_tx,
        );
    }
    s
}

fn run_with_identity_path_mode(
    peer: &str,
    identity_path: Option<&Path>,
    relay: bool,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let identity_path = resolve_identity_path(identity_path);
    runtime.block_on(async move {
        let identity = store::load(&identity_path).context("load local identity")?;
        let raw_endpoint =
            portl_agent::endpoint::bind(&portl_agent::AgentConfig::default(), &identity)
                .await
                .context("bind client endpoint")?;
        run_with_endpoint(peer, identity, raw_endpoint, relay).await
    })
}

pub fn run_with_identity_path_and_endpoint(
    peer: &str,
    identity_path: Option<&Path>,
    raw_endpoint: iroh::Endpoint,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let identity_path = resolve_identity_path(identity_path);
    runtime.block_on(async move {
        let identity = store::load(&identity_path).context("load local identity")?;
        run_with_endpoint(peer, identity, raw_endpoint, false).await
    })
}

async fn run_with_endpoint(
    peer: &str,
    identity: Identity,
    raw_endpoint: iroh::Endpoint,
    relay: bool,
) -> Result<ExitCode> {
    let endpoint = Endpoint::from(raw_endpoint.clone());
    let resolved = resolve_peer(peer, &identity, &raw_endpoint, relay).await?;
    let (connection, session) = open_ticket_v1(&endpoint, &resolved.ticket, &[], &identity)
        .await
        .context("run ticket handshake")?;
    let rtt = ping(&connection, &session).await?;
    let info = info(&connection, &session).await?;
    let path = path_label(&connection);
    print_status(
        connection.remote_id(),
        &path,
        rtt,
        &resolved.discovery,
        &info,
    );

    connection.close(0u32.into(), b"status complete");
    raw_endpoint.close().await;
    Ok(ExitCode::SUCCESS)
}

struct ResolvedPeer {
    ticket: PortlTicket,
    discovery: String,
}

async fn resolve_peer(
    peer: &str,
    identity: &Identity,
    endpoint: &iroh::Endpoint,
    relay: bool,
) -> Result<ResolvedPeer> {
    if let Ok(ticket) = <PortlTicket as Ticket>::deserialize(peer) {
        if ticket.body.parent.is_some() {
            bail!(
                "delegated tickets not yet supported by status; use the root ticket or pass --chain"
            );
        }
        return Ok(ResolvedPeer {
            ticket: maybe_force_relay_ticket(ticket, relay)?,
            discovery: "cached".to_owned(),
        });
    }

    if let Some(alias) = AliasStore::default().get(peer)? {
        if let Some(spec) = AliasStore::default().get_spec(peer)?
            && let Some(ticket_path) = spec.ticket_file_path
        {
            let raw = std::fs::read_to_string(&ticket_path)
                .with_context(|| format!("read stored ticket {}", ticket_path.display()))?;
            let ticket = <PortlTicket as Ticket>::deserialize(raw.trim())
                .map_err(|err| anyhow!("parse stored ticket {}: {err}", ticket_path.display()))?;
            return Ok(ResolvedPeer {
                ticket: maybe_force_relay_ticket(ticket, relay)?,
                discovery: "stored-ticket".to_owned(),
            });
        }
        let endpoint_id = parse_endpoint_id(&alias.endpoint_id)?;
        let (addr, provenance) = resolve_endpoint_addr(endpoint, endpoint_id, relay).await?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock is before unix epoch")?
            .as_secs();
        let ticket = mint_root(
            identity.signing_key(),
            addr,
            meta_caps(),
            now,
            now + 300,
            None,
        )
        .context("mint ephemeral status ticket")?;

        return Ok(ResolvedPeer {
            ticket,
            discovery: normalize_discovery_source(&provenance),
        });
    }

    let endpoint_id = parse_endpoint_id(peer)?;
    let (addr, provenance) = resolve_endpoint_addr(endpoint, endpoint_id, relay).await?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_secs();
    let ticket = mint_root(
        identity.signing_key(),
        addr,
        meta_caps(),
        now,
        now + 300,
        None,
    )
    .context("mint ephemeral status ticket")?;

    Ok(ResolvedPeer {
        ticket,
        discovery: normalize_discovery_source(&provenance),
    })
}

async fn resolve_endpoint_addr(
    endpoint: &iroh::Endpoint,
    endpoint_id: EndpointId,
    relay: bool,
) -> Result<(EndpointAddr, String)> {
    if relay && relay_discovery_disabled() {
        bail!(
            "PORTL_DISCOVERY=none disables relay discovery and DNS lookups; unset it or pass a ticket with a relay address"
        );
    }

    let mut stream = endpoint
        .address_lookup()
        .context("access address lookup")?
        .resolve(endpoint_id);
    while let Some(item) = stream.next().await {
        match item {
            Ok(Ok(item)) => {
                let provenance = item.provenance().to_owned();
                let addr = item.into_endpoint_addr();
                let addr = maybe_force_relay_addr(endpoint_id, addr, relay)?;
                return Ok((addr, provenance));
            }
            Ok(Err(_)) => {}
            Err(AddressLookupFailed::NoServiceConfigured { .. }) => {
                if relay {
                    bail!(
                        "no discovery services configured for relay probing; unset PORTL_DISCOVERY=none or pass a ticket with a relay address"
                    );
                }
                bail!("no discovery services configured")
            }
            Err(AddressLookupFailed::NoResults { errors, .. }) => {
                let detail = errors
                    .into_iter()
                    .map(|err| err.to_string())
                    .collect::<Vec<_>>()
                    .join("; ");
                bail!("discovery failed: {detail}")
            }
            Err(err) => return Err(anyhow!(err)),
        }
    }

    bail!("discovery returned no addresses")
}

fn maybe_force_relay_ticket(mut ticket: PortlTicket, relay: bool) -> Result<PortlTicket> {
    if relay {
        ticket.addr = relay_only_addr(ticket.addr.id, &ticket.addr)?;
    }
    Ok(ticket)
}

fn maybe_force_relay_addr(
    endpoint_id: EndpointId,
    addr: EndpointAddr,
    relay: bool,
) -> Result<EndpointAddr> {
    if relay {
        return relay_only_addr(endpoint_id, &addr);
    }
    Ok(addr)
}

fn relay_only_addr(endpoint_id: EndpointId, addr: &EndpointAddr) -> Result<EndpointAddr> {
    let relay_url = addr.relay_urls().next().cloned().context(
        "peer does not advertise a relay address; rerun without --relay or use a ticket with relay information",
    )?;
    Ok(EndpointAddr::new(endpoint_id).with_relay_url(relay_url))
}

fn relay_discovery_disabled() -> bool {
    matches!(std::env::var("PORTL_DISCOVERY"), Ok(value) if value.trim() == "none")
}

fn parse_endpoint_id(spec: &str) -> Result<EndpointId> {
    let bytes = hex::decode(spec).context("endpoint id must be hex or a portl ticket URI")?;
    let bytes: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("endpoint id must be exactly 32 bytes"))?;
    EndpointId::from_bytes(&bytes).context("invalid endpoint id")
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

async fn ping(connection: &Connection, session: &PeerSession) -> Result<std::time::Duration> {
    let started = Instant::now();
    let response = meta_request(
        connection,
        session,
        MetaReq::Ping {
            t_client_us: unix_now_micros()?,
        },
    )
    .await?;
    match response {
        MetaResp::Pong { .. } => Ok(started.elapsed()),
        MetaResp::Error(error) => bail!("meta ping failed: {} ({:?})", error.message, error.kind),
        other => bail!("unexpected ping response: {other:?}"),
    }
}

async fn info(connection: &Connection, session: &PeerSession) -> Result<InfoView> {
    let response = meta_request(connection, session, MetaReq::Info).await?;
    match response {
        MetaResp::Info {
            agent_version,
            supported_alpns: _,
            uptime_s,
            hostname,
            os,
            tags: _,
        } => Ok(InfoView {
            agent_version,
            uptime_s,
            hostname,
            os,
        }),
        MetaResp::Error(error) => bail!("meta info failed: {} ({:?})", error.message, error.kind),
        other => bail!("unexpected info response: {other:?}"),
    }
}

async fn meta_request(
    connection: &Connection,
    session: &PeerSession,
    req: MetaReq,
) -> Result<MetaResp> {
    let envelope = MetaEnvelope {
        preamble: StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).into_owned(),
        },
        req,
    };
    let bytes = postcard::to_stdvec(&envelope).context("encode meta request")?;
    let (mut send, mut recv) = connection.open_bi().await.context("open meta stream")?;
    send.write_all(&bytes).await.context("write meta request")?;
    send.finish().context("finish meta request")?;
    let response_bytes = recv
        .read_to_end(64 * 1024)
        .await
        .context("read meta response")?;
    postcard::from_bytes(&response_bytes).context("decode meta response")
}

fn path_label(connection: &Connection) -> String {
    let path = connection
        .paths()
        .into_iter()
        .find(iroh::endpoint::PathInfo::is_selected)
        .or_else(|| connection.paths().into_iter().next());
    match path.map(|path| path.remote_addr().clone()) {
        Some(TransportAddr::Relay(url)) => format!("relay {url}"),
        Some(_) | None => "direct".to_owned(),
    }
}

fn normalize_discovery_source(source: &str) -> String {
    match source {
        "mdns" => "local".to_owned(),
        other => other.to_owned(),
    }
}

fn print_status(
    endpoint_id: EndpointId,
    path: &str,
    rtt: std::time::Duration,
    discovery: &str,
    info: &InfoView,
) {
    println!("{:<18}{}", "endpoint:", hex::encode(endpoint_id.as_bytes()));
    println!("{:<18}{}", "path:", path);
    println!("{:<18}{}ms", "rtt:", rtt.as_millis());
    println!("{:<18}{}", "discovery:", discovery);
    println!("{:<18}{}", "agent_version:", info.agent_version);
    println!(
        "{:<18}{}",
        "uptime:",
        humantime::format_duration(std::time::Duration::from_secs(info.uptime_s))
    );
    println!("{:<18}{}", "hostname:", info.hostname);
    println!("{:<18}{}", "os:", info.os);
}

fn resolve_identity_path(explicit: Option<&Path>) -> PathBuf {
    explicit
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os("PORTL_IDENTITY_KEY").map(PathBuf::from))
        .unwrap_or_else(store::default_path)
}

fn unix_now_micros() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before unix epoch")?
        .as_micros()
        .try_into()
        .context("micros overflow u64")
}

#[derive(Debug)]
struct InfoView {
    agent_version: String,
    uptime_s: u64,
    hostname: String,
    os: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct MetaEnvelope {
    preamble: StreamPreamble,
    req: MetaReq,
}
