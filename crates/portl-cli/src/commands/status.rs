use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use iroh_base::TransportAddr;
use portl_core::endpoint::Endpoint;
use portl_core::id::{Identity, store};
use portl_core::net::{PeerSession, open_ticket_v1};
use portl_core::peer_store::PeerStore;
use portl_core::ticket::schema::{Capabilities, MetaCaps};
use portl_proto::meta_v1::{MetaReq, MetaResp};
use portl_proto::wire::StreamPreamble;
use serde::{Deserialize, Serialize};

use crate::commands::peer_resolve::{ResolveOpts, close_client_endpoint, resolve_peer};

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
        .map_or(snap.agent.started_at_unix, |d| d.as_secs());
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
    render_provider_summary(&mut s, &snap.session_providers);
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

fn render_provider_summary(
    out: &mut String,
    providers: &portl_agent::status_schema::SessionProvidersInfo,
) {
    use std::fmt::Write;
    let default = providers.default_provider.as_deref().unwrap_or("-");
    let _ = writeln!(out, "providers:      default={default}");
    if let Some(user) = &providers.default_user {
        let _ = writeln!(
            out,
            "                user={} home={} shell={}",
            user.name, user.home, user.shell
        );
    }
    for provider in &providers.providers {
        let state = if provider.detected {
            "detected"
        } else {
            "missing"
        };
        let source = provider.source.as_deref().unwrap_or("-");
        let path = provider.path.as_deref().unwrap_or("-");
        let notes = provider.notes.as_deref().unwrap_or("");
        if notes.is_empty() {
            let _ = writeln!(
                out,
                "                {}: {state} source={source} path={path}",
                provider.name
            );
        } else {
            let _ = writeln!(
                out,
                "                {}: {state} source={source} path={path} ({notes})",
                provider.name
            );
        }
    }
}

fn run_target_count(
    peer: &str,
    relay: bool,
    json: bool,
    count: u32,
    timeout: Duration,
) -> Result<ExitCode> {
    let mut any_success = false;
    let mut reports = Vec::new();
    for seq in 0..count {
        let result = run_probe_with_identity_path_mode_timeout(peer, None, relay, timeout);
        match result {
            Ok(mut report) => {
                report.seq = seq;
                any_success = true;
                if !json {
                    print_status(&report);
                }
                reports.push(report);
            }
            Err(err) if json => {
                reports.push(ProbeReport::failure(seq, peer, format!("{err:#}")));
            }
            Err(err) => return Err(err),
        }
        if seq + 1 < count {
            std::thread::sleep(Duration::from_secs(1));
        }
    }
    if json {
        println!("{}", render_probe_json_envelope(reports, count));
    } else if count > 1 {
        print_probe_summary(&ProbeSummary::from_reports(&reports));
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
    let report = run_probe_with_identity_path_mode_timeout(peer, identity_path, relay, timeout)?;
    print_status(&report);
    Ok(ExitCode::SUCCESS)
}

fn run_probe_with_identity_path_mode_timeout(
    peer: &str,
    identity_path: Option<&Path>,
    relay: bool,
    timeout: Duration,
) -> Result<ProbeReport> {
    let runtime = tokio::runtime::Runtime::new()?;
    let identity_path = resolve_identity_path(identity_path);
    let result = runtime.block_on(async move {
        let identity = store::load(&identity_path).context("load local identity")?;
        let raw_endpoint = crate::client_endpoint::bind_client_endpoint(&identity).await?;
        let outcome = tokio::time::timeout(
            timeout,
            probe_with_endpoint(peer, identity, raw_endpoint.clone(), relay),
        )
        .await;
        close_client_endpoint(raw_endpoint, "status command").await;
        outcome.with_context(|| format!("timeout after {}", humantime::format_duration(timeout)))?
    });
    portl_core::runtime::record_status_probe(match &result {
        Ok(_) => "success",
        Err(err) if err.to_string().contains("timeout after") => "timeout",
        Err(_) => "failure",
    });
    result
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
        let report = probe_with_endpoint(peer, identity, raw_endpoint, false).await?;
        print_status(&report);
        Ok(ExitCode::SUCCESS)
    })
}

async fn probe_with_endpoint(
    peer: &str,
    identity: Identity,
    raw_endpoint: iroh::Endpoint,
    relay: bool,
) -> Result<ProbeReport> {
    let endpoint = Endpoint::from(raw_endpoint.clone());
    let resolved = resolve_peer(
        peer,
        &ResolveOpts {
            caps: meta_caps(),
            force_relay: relay,
            identity: &identity,
            endpoint: &raw_endpoint,
            quiet: false,
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
    connection.close(0u32.into(), b"status complete");
    Ok(ProbeReport {
        schema: 1,
        kind: "status.probe".to_owned(),
        seq: 0,
        target: peer.to_owned(),
        ok: true,
        rtt_ms: Some(rtt.as_secs_f64() * 1000.0),
        path: Some(path),
        endpoint_id: Some(hex::encode(remote_id.as_bytes())),
        discovery: Some(resolved.discovery),
        relationship,
        agent_version: Some(info.agent_version),
        uptime_s: Some(info.uptime_s),
        hostname: Some(info.hostname),
        os: Some(info.os),
        error: None,
    })
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

fn print_status(report: &ProbeReport) {
    if let Some(endpoint_id) = &report.endpoint_id {
        println!("{:<18}{}", "endpoint:", endpoint_id);
    }
    if let Some(path) = &report.path {
        println!("{:<18}{}", "path:", path);
    }
    if let Some(rtt_ms) = report.rtt_ms {
        println!("{:<18}{}ms", "rtt:", rtt_ms.round());
    }
    if let Some(discovery) = &report.discovery {
        println!("{:<18}{}", "discovery:", discovery);
    }
    if let Some(relationship) = &report.relationship {
        println!("{:<18}{}", "relationship:", relationship);
    }
    if let Some(agent_version) = &report.agent_version {
        println!("{:<18}{}", "agent_version:", agent_version);
    }
    if let Some(uptime_s) = report.uptime_s {
        println!(
            "{:<18}{}",
            "uptime:",
            humantime::format_duration(Duration::from_secs(uptime_s))
        );
    }
    if let Some(hostname) = &report.hostname {
        println!("{:<18}{}", "hostname:", hostname);
    }
    if let Some(os) = &report.os {
        println!("{:<18}{}", "os:", os);
    }
}

fn render_probe_json(report: &ProbeReport) -> String {
    serde_json::to_string(report).expect("serialize probe report")
}

fn print_probe_summary(summary: &ProbeSummary) {
    println!();
    println!(
        "{:<18}{}/{} ok · {} failed · quality={}",
        "summary:", summary.successes, summary.total, summary.failures, summary.quality
    );
    if let (Some(min), Some(avg), Some(max), Some(range), Some(jitter)) = (
        summary.rtt_min_ms,
        summary.rtt_avg_ms,
        summary.rtt_max_ms,
        summary.rtt_range_ms,
        summary.rtt_jitter_ms,
    ) {
        println!(
            "{:<18}min={}ms avg={}ms max={}ms range={}ms jitter={}ms",
            "rtt:",
            format_ms(min),
            format_ms(avg),
            format_ms(max),
            format_ms(range),
            format_ms(jitter)
        );
    } else {
        println!("{:<18}—", "rtt:");
    }
    if summary.paths.is_empty() {
        println!("{:<18}—", "paths:");
    } else {
        let paths = summary
            .paths
            .iter()
            .map(|path| format!("{} x{}", path.path, path.count))
            .collect::<Vec<_>>()
            .join(", ");
        println!("{:<18}{paths}", "paths:");
    }
}

fn render_probe_json_envelope(reports: Vec<ProbeReport>, count: u32) -> String {
    if count == 1 && reports.len() == 1 {
        let Some(report) = reports.into_iter().next() else {
            unreachable!("single report vector contains a report")
        };
        return render_probe_json(&report);
    }
    let summary = ProbeSummary::from_reports(&reports);
    serde_json::to_string(&serde_json::json!({
        "schema": 1,
        "kind": "status.probes",
        "summary": summary,
        "probes": reports,
    }))
    .expect("serialize probe report envelope")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeSummary {
    total: usize,
    successes: usize,
    failures: usize,
    rtt_min_ms: Option<f64>,
    rtt_avg_ms: Option<f64>,
    rtt_max_ms: Option<f64>,
    rtt_range_ms: Option<f64>,
    rtt_jitter_ms: Option<f64>,
    paths: Vec<PathCount>,
    quality: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PathCount {
    path: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProbeReport {
    schema: u32,
    kind: String,
    seq: u32,
    target: String,
    ok: bool,
    rtt_ms: Option<f64>,
    path: Option<String>,
    endpoint_id: Option<String>,
    discovery: Option<String>,
    relationship: Option<String>,
    agent_version: Option<String>,
    uptime_s: Option<u64>,
    hostname: Option<String>,
    os: Option<String>,
    error: Option<String>,
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

impl ProbeSummary {
    fn from_reports(reports: &[ProbeReport]) -> Self {
        let total = reports.len();
        let successes = reports.iter().filter(|report| report.ok).count();
        let failures = total.saturating_sub(successes);
        let rtts = reports
            .iter()
            .filter_map(|report| report.rtt_ms)
            .collect::<Vec<_>>();
        let (rtt_min_ms, rtt_avg_ms, rtt_max_ms, rtt_range_ms, rtt_jitter_ms) =
            summarize_rtts(&rtts);
        let paths = summarize_paths(reports);
        let quality = classify_probe_quality(successes, failures, rtt_avg_ms, rtt_range_ms);
        Self {
            total,
            successes,
            failures,
            rtt_min_ms,
            rtt_avg_ms,
            rtt_max_ms,
            rtt_range_ms,
            rtt_jitter_ms,
            paths,
            quality: quality.to_owned(),
        }
    }
}

fn summarize_rtts(
    rtts: &[f64],
) -> (
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
    Option<f64>,
) {
    if rtts.is_empty() {
        return (None, None, None, None, None);
    }
    let min = rtts.iter().copied().fold(f64::INFINITY, f64::min);
    let max = rtts.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    let range = max - min;
    let jitter = if rtts.len() > 1 {
        rtts.windows(2)
            .map(|pair| (pair[1] - pair[0]).abs())
            .sum::<f64>()
            / (rtts.len() - 1) as f64
    } else {
        0.0
    };
    (
        Some(round_ms(min)),
        Some(round_ms(avg)),
        Some(round_ms(max)),
        Some(round_ms(range)),
        Some(round_ms(jitter)),
    )
}

fn summarize_paths(reports: &[ProbeReport]) -> Vec<PathCount> {
    let mut counts = BTreeMap::<String, usize>::new();
    for path in reports.iter().filter_map(|report| report.path.as_ref()) {
        *counts.entry(path.clone()).or_default() += 1;
    }
    counts
        .into_iter()
        .map(|(path, count)| PathCount { path, count })
        .collect()
}

fn classify_probe_quality(
    successes: usize,
    failures: usize,
    rtt_avg_ms: Option<f64>,
    rtt_range_ms: Option<f64>,
) -> &'static str {
    if successes == 0 {
        return "down";
    }
    if failures > 0 {
        return "degraded";
    }
    let avg = rtt_avg_ms.unwrap_or(f64::INFINITY);
    let range = rtt_range_ms.unwrap_or(f64::INFINITY);
    if avg <= 50.0 && range <= 25.0 {
        "excellent"
    } else if avg <= 150.0 && range <= 75.0 {
        "good"
    } else if avg <= 300.0 && range <= 150.0 {
        "fair"
    } else {
        "poor"
    }
}

fn round_ms(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn format_ms(value: f64) -> String {
    if value >= 100.0 {
        format!("{}", value.round())
    } else {
        format!("{value:.1}")
    }
}

impl ProbeReport {
    fn failure(seq: u32, target: &str, error: String) -> Self {
        Self {
            schema: 1,
            kind: "status.probe".to_owned(),
            seq,
            target: target.to_owned(),
            ok: false,
            rtt_ms: None,
            path: None,
            endpoint_id: None,
            discovery: None,
            relationship: None,
            agent_version: None,
            uptime_s: None,
            hostname: None,
            os: None,
            error: Some(error),
        }
    }
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

#[cfg(test)]
mod tests {
    use serde_json::Value;

    use portl_agent::status_schema::{
        AgentInfo, DefaultUserInfo, DiscoveryInfo, NetworkHealthInfo, NetworkInfo,
        SessionProviderInfo, SessionProviderSearchPath, SessionProvidersInfo, StatusResponse,
    };

    #[test]
    fn target_status_json_emits_single_json_object_without_human_prefix() {
        let report = super::ProbeReport {
            schema: 1,
            kind: "status.probe".to_owned(),
            seq: 0,
            target: "vn3".to_owned(),
            ok: true,
            rtt_ms: Some(12.5),
            path: Some("direct".to_owned()),
            endpoint_id: Some("abc".to_owned()),
            discovery: Some("stored+configured-relay".to_owned()),
            relationship: Some("mutual".to_owned()),
            agent_version: Some("0.8.2".to_owned()),
            uptime_s: Some(42),
            hostname: Some("vn3".to_owned()),
            os: Some("linux".to_owned()),
            error: None,
        };

        let rendered = super::render_probe_json(&report);
        let parsed: Value = serde_json::from_str(&rendered).expect("parse probe json");
        assert_eq!(parsed["kind"], "status.probe");
        assert_eq!(parsed["hostname"], "vn3");
        assert_eq!(parsed["endpoint_id"], "abc");
        assert!(!rendered.contains("endpoint:"));
    }

    #[test]
    fn target_status_json_count_emits_single_envelope() {
        let rendered = super::render_probe_json_envelope(
            vec![
                super::ProbeReport::failure(0, "vn3", "one".to_owned()),
                super::ProbeReport::failure(1, "vn3", "two".to_owned()),
            ],
            2,
        );
        let parsed: Value = serde_json::from_str(&rendered).expect("parse probe json envelope");
        assert_eq!(parsed["kind"], "status.probes");
        assert_eq!(parsed["probes"].as_array().expect("probes array").len(), 2);
        assert_eq!(parsed["summary"]["total"], 2);
        assert_eq!(parsed["summary"]["successes"], 0);
        assert_eq!(parsed["summary"]["failures"], 2);
        assert_eq!(parsed["summary"]["quality"], "down");
    }

    #[test]
    fn probe_summary_calculates_latency_paths_and_quality() {
        let reports = vec![
            super::ProbeReport {
                schema: 1,
                kind: "status.probe".to_owned(),
                seq: 0,
                target: "vn3".to_owned(),
                ok: true,
                rtt_ms: Some(40.0),
                path: Some("direct".to_owned()),
                endpoint_id: Some("abc".to_owned()),
                discovery: None,
                relationship: None,
                agent_version: None,
                uptime_s: None,
                hostname: None,
                os: None,
                error: None,
            },
            super::ProbeReport {
                schema: 1,
                kind: "status.probe".to_owned(),
                seq: 1,
                target: "vn3".to_owned(),
                ok: true,
                rtt_ms: Some(55.0),
                path: Some("direct".to_owned()),
                endpoint_id: Some("abc".to_owned()),
                discovery: None,
                relationship: None,
                agent_version: None,
                uptime_s: None,
                hostname: None,
                os: None,
                error: None,
            },
            super::ProbeReport {
                schema: 1,
                kind: "status.probe".to_owned(),
                seq: 2,
                target: "vn3".to_owned(),
                ok: true,
                rtt_ms: Some(70.0),
                path: Some("relay https://example".to_owned()),
                endpoint_id: Some("abc".to_owned()),
                discovery: None,
                relationship: None,
                agent_version: None,
                uptime_s: None,
                hostname: None,
                os: None,
                error: None,
            },
        ];

        let summary = super::ProbeSummary::from_reports(&reports);

        assert_eq!(summary.total, 3);
        assert_eq!(summary.successes, 3);
        assert_eq!(summary.failures, 0);
        assert_eq!(summary.rtt_min_ms, Some(40.0));
        assert_eq!(summary.rtt_avg_ms, Some(55.0));
        assert_eq!(summary.rtt_max_ms, Some(70.0));
        assert_eq!(summary.rtt_range_ms, Some(30.0));
        assert_eq!(summary.rtt_jitter_ms, Some(15.0));
        assert_eq!(summary.quality, "good");
        assert_eq!(summary.paths[0].path, "direct");
        assert_eq!(summary.paths[0].count, 2);
        assert_eq!(summary.paths[1].path, "relay https://example");
        assert_eq!(summary.paths[1].count, 1);
    }

    #[test]
    fn dashboard_renders_session_provider_discovery() {
        let snap = StatusResponse::new(
            AgentInfo {
                pid: 42,
                version: "0.6.7".to_owned(),
                started_at_unix: 1_704_067_200,
                home: "/Users/demo/.portl".to_owned(),
                metrics_socket: "/Users/demo/.portl/run/metrics.sock".to_owned(),
            },
            Vec::new(),
            NetworkInfo {
                relays: Vec::new(),
                discovery: DiscoveryInfo {
                    dns: true,
                    pkarr: true,
                    local: true,
                },
            },
            NetworkHealthInfo::disabled(),
            SessionProvidersInfo {
                default_provider: Some("zmx".to_owned()),
                default_user: Some(DefaultUserInfo {
                    name: "demo".to_owned(),
                    home: "/Users/demo".to_owned(),
                    shell: "/bin/zsh".to_owned(),
                }),
                providers: vec![SessionProviderInfo {
                    name: "zmx".to_owned(),
                    detected: true,
                    path: Some("/Users/demo/.local/share/mise/shims/zmx".to_owned()),
                    source: Some("mise_shim".to_owned()),
                    notes: None,
                }],
                search_paths: vec![SessionProviderSearchPath {
                    provider: "zmx".to_owned(),
                    path: "/Users/demo/.local/share/mise/shims/zmx".to_owned(),
                    source: "mise_shim".to_owned(),
                    exists: true,
                }],
            },
            portl_agent::relay::RelayStatus::disabled(),
        );

        let rendered = super::render_dashboard_human(&snap);

        assert!(rendered.contains("providers:"));
        assert!(rendered.contains("default=zmx"));
        assert!(rendered.contains("zmx: detected"));
        assert!(rendered.contains("mise_shim"));
    }
}
