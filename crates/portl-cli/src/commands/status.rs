use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use iroh_base::{EndpointId, TransportAddr};
use portl_core::endpoint::Endpoint;
use portl_core::id::{Identity, store};
use portl_core::net::{PeerSession, open_ticket_v1};
use portl_core::peer_store::PeerStore;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};

use crate::commands::peer_resolve::{ResolveOpts, resolve_peer};

pub fn run(
    target: Option<&str>,
    relay: bool,
    json: bool,
    watch: Option<u64>,
    count: u32,
    timeout: Duration,
) -> Result<ExitCode> {
    if let Some(target) = target {
        run_target_count(target, relay, json, count.max(1), timeout)
    } else {
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
                () = tokio::time::sleep(Duration::from_secs(interval_secs)) => {}
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
        humantime::format_duration(Duration::from_secs(up))
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
    if snap.relay.enabled {
        let addr = snap.relay.http_addr.as_deref().unwrap_or("(bind pending)");
        let policy = snap.relay.policy.as_deref().unwrap_or("peers-only");
        let _ = writeln!(s, "relay:          enabled, policy={policy}, bind={addr}");
        if let Some(hostname) = &snap.relay.hostname {
            let _ = writeln!(s, "                hostname: {hostname}");
        }
        if snap.relay.pairs_only_pending_v034 {
            let _ = writeln!(
                s,
                "                note: pairs-only falls back to peers-only until v0.3.4"
            );
        }
        let _ = writeln!(s);
    }
    let _ = writeln!(s, "connections:    {} active", snap.connections.len());
    for c in &snap.connections {
        let rtt = c
            .rtt_micros
            .map_or_else(|| "—".to_owned(), |u| format!("{}ms", u / 1000));
        let up_secs = now.saturating_sub(c.up_since_unix);
        let _ = writeln!(
            s,
            "                - {eid_short} #{cid:x}  path={path}  rtt={rtt}  up={up_secs}s  rx={rx}B tx={tx}B",
            eid_short = crate::eid::format_short(&c.peer_eid),
            cid = c.connection_id,
            path = c.path.as_str(),
            rx = c.bytes_rx,
            tx = c.bytes_tx,
        );
    }
    s
}

fn run_target_count(
    peer: &str,
    relay: bool,
    json: bool,
    count: u32,
    timeout: Duration,
) -> Result<ExitCode> {
    let mut any_success = false;
    for seq in 0..count {
        let started = Instant::now();
        let result = run_with_identity_path_mode_timeout(peer, None, relay, timeout);
        match result {
            Ok(code) if code == ExitCode::SUCCESS => {
                any_success = true;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema": 1,
                            "kind": "status.probe",
                            "seq": seq,
                            "target": peer,
                            "path": if relay { "relay" } else { "unknown" },
                            "rtt_ms": started.elapsed().as_secs_f64() * 1000.0,
                            "ok": true,
                        })
                    );
                }
            }
            Ok(code) if json => {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": 1,
                        "kind": "status.probe",
                        "seq": seq,
                        "target": peer,
                        "rtt_ms": null,
                        "ok": false,
                        "error": format!("probe exited with {code:?}"),
                    })
                );
            }
            Err(err) if json => {
                println!(
                    "{}",
                    serde_json::json!({
                        "schema": 1,
                        "kind": "status.probe",
                        "seq": seq,
                        "target": peer,
                        "rtt_ms": null,
                        "ok": false,
                        "error": format!("{err:#}"),
                    })
                );
            }
            Err(err) => return Err(err),
            Ok(code) => return Ok(code),
        }
        if seq + 1 < count {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    Ok(if any_success {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

fn run_with_identity_path_mode(
    peer: &str,
    identity_path: Option<&Path>,
    relay: bool,
) -> Result<ExitCode> {
    run_with_identity_path_mode_timeout(peer, identity_path, relay, Duration::from_secs(5))
}

fn run_with_identity_path_mode_timeout(
    peer: &str,
    identity_path: Option<&Path>,
    relay: bool,
    timeout: Duration,
) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let identity_path = resolve_identity_path(identity_path);
    runtime.block_on(async move {
        let identity = store::load(&identity_path).context("load local identity")?;
        let raw_endpoint = crate::client_endpoint::bind_client_endpoint(&identity).await?;
        tokio::time::timeout(
            timeout,
            run_with_endpoint(peer, identity, raw_endpoint, relay),
        )
        .await
        .with_context(|| format!("timeout after {}", humantime::format_duration(timeout)))?
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
    let resolved = resolve_peer(
        peer,
        &ResolveOpts {
            caps: meta_caps(),
            force_relay: relay,
            identity: &identity,
            endpoint: &raw_endpoint,
        },
    )
    .await?;
    let (connection, session) = open_ticket_v1(&endpoint, &resolved.ticket, &[], &identity)
        .await
        .context("run ticket handshake")?;
    let rtt = ping(&connection, &session).await?;
    let info = info(&connection, &session).await?;
    let path = path_label(&connection);
    let remote_id = connection.remote_id();
    let relationship = peer_relationship_label(peer, remote_id.as_bytes());
    print_status(
        remote_id,
        &path,
        rtt,
        &resolved.discovery,
        relationship.as_deref(),
        &info,
    );

    connection.close(0u32.into(), b"status complete");
    raw_endpoint.close().await;
    Ok(ExitCode::SUCCESS)
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

async fn ping(connection: &Connection, session: &PeerSession) -> Result<Duration> {
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

fn print_status(
    endpoint_id: EndpointId,
    path: &str,
    rtt: Duration,
    discovery: &str,
    relationship: Option<&str>,
    info: &InfoView,
) {
    println!("{:<18}{}", "endpoint:", hex::encode(endpoint_id.as_bytes()));
    println!("{:<18}{}", "path:", path);
    println!("{:<18}{}ms", "rtt:", rtt.as_millis());
    println!("{:<18}{}", "discovery:", discovery);
    if let Some(relationship) = relationship {
        println!("{:<18}{}", "relationship:", relationship);
    }
    println!("{:<18}{}", "agent_version:", info.agent_version);
    println!(
        "{:<18}{}",
        "uptime:",
        humantime::format_duration(Duration::from_secs(info.uptime_s))
    );
    println!("{:<18}{}", "hostname:", info.hostname);
    println!("{:<18}{}", "os:", info.os);
}

fn peer_relationship_label(target: &str, endpoint_id: &[u8; 32]) -> Option<String> {
    let peers = PeerStore::load(&PeerStore::default_path()).ok()?;
    peers
        .get_by_label(target)
        .or_else(|| peers.get_by_endpoint(endpoint_id))
        .filter(|entry| !entry.is_self)
        .map(|entry| entry.relationship().to_owned())
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
