//! In-process metrics registry + unix socket server.
//!
//! Exposes `OpenMetrics` on a local unix socket at
//! `$PORTL_HOME/metrics.sock` (mode 0600). The surface is small and
//! deliberately not configurable for v0.1: counters on the hot paths
//! (tickets accepted, rejected-by-reason, shell/tcp/udp opened) plus
//! a handful of gauges for active resource counts. Collectors live
//! behind an `Arc<Metrics>` that the relevant handlers can increment
//! cheaply.

use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use prometheus_client::encoding::EncodeLabelSet;
use prometheus_client::encoding::text::encode;
use prometheus_client::metrics::counter::Counter;
use prometheus_client::metrics::family::Family;
use prometheus_client::metrics::gauge::Gauge;
use prometheus_client::registry::Registry;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::status_schema::{
    AgentInfo, ConnectionsResponse, ErrorResponse, NetworkInfo, NetworkResponse, RelayResponse,
    SessionProvidersInfo, StatusResponse,
};

#[derive(Clone, Hash, PartialEq, Eq, Debug, EncodeLabelSet)]
pub struct AckReasonLabel {
    pub reason: String,
}

pub struct Metrics {
    registry: Registry,
    pub tickets_accepted: Counter,
    pub tickets_rejected_total: Family<AckReasonLabel, Counter>,
    pub shell_sessions_opened: Counter,
    pub tcp_streams_opened: Counter,
    pub udp_sessions_opened: Counter,
    pub active_connections: Gauge,
    pub active_udp_sessions: Gauge,
    /// Relay endpoint authorization counters. Incremented by the
    /// embedded relay's access-gate closure on each connect
    /// attempt.
    pub relay_accepts_total: Counter,
    pub relay_rejects_total: Family<AckReasonLabel, Counter>,
}

impl Default for Metrics {
    fn default() -> Self {
        let mut registry = Registry::with_prefix("portl");

        let tickets_accepted = Counter::default();
        registry.register(
            "tickets_accepted",
            "Number of ticket/v1 offers accepted",
            tickets_accepted.clone(),
        );

        let tickets_rejected_total = Family::<AckReasonLabel, Counter>::default();
        registry.register(
            "tickets_rejected",
            "Number of ticket/v1 offers rejected by reason",
            tickets_rejected_total.clone(),
        );

        let shell_sessions_opened = Counter::default();
        registry.register(
            "shell_sessions_opened",
            "Number of shell/v1 sessions accepted",
            shell_sessions_opened.clone(),
        );

        let tcp_streams_opened = Counter::default();
        registry.register(
            "tcp_streams_opened",
            "Number of tcp/v1 streams forwarded",
            tcp_streams_opened.clone(),
        );

        let udp_sessions_opened = Counter::default();
        registry.register(
            "udp_sessions_opened",
            "Number of udp/v1 sessions created",
            udp_sessions_opened.clone(),
        );

        let active_connections = Gauge::default();
        registry.register(
            "active_connections",
            "QUIC connections currently live",
            active_connections.clone(),
        );

        let active_udp_sessions = Gauge::default();
        registry.register(
            "active_udp_sessions",
            "UDP sessions in the session registry",
            active_udp_sessions.clone(),
        );

        let relay_accepts_total = Counter::default();
        registry.register(
            "relay_accepts_total",
            "Relay endpoint authorization decisions that allowed the connection",
            relay_accepts_total.clone(),
        );

        let relay_rejects_total = Family::<AckReasonLabel, Counter>::default();
        registry.register(
            "relay_rejects_total",
            "Relay endpoint authorization decisions that denied the connection, by reason",
            relay_rejects_total.clone(),
        );

        portl_core::runtime::register_metrics(&mut registry);

        Self {
            registry,
            tickets_accepted,
            tickets_rejected_total,
            shell_sessions_opened,
            tcp_streams_opened,
            udp_sessions_opened,
            active_connections,
            active_udp_sessions,
            relay_accepts_total,
            relay_rejects_total,
        }
    }
}

impl Metrics {
    pub fn encode_text(&self) -> Result<String> {
        let mut buf = String::new();
        encode(&mut buf, &self.registry).context("encode metrics")?;
        Ok(buf)
    }
}

/// Resolve the unix socket path: `$PORTL_HOME/metrics.sock`.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    let home = if let Some(override_home) = std::env::var_os("PORTL_HOME") {
        PathBuf::from(override_home)
    } else if let Some(dirs) = directories::ProjectDirs::from("computer", "KnickKnackLabs", "portl")
    {
        dirs.data_dir().to_path_buf()
    } else {
        PathBuf::from(".")
    };
    home.join("metrics.sock")
}

/// Abstraction over "what the agent knows right now" for the
/// `/status` IPC routes. Implemented by `AgentState`; tests can
/// supply a stub.
pub trait StatusSource: Send + Sync + 'static {
    fn agent_info(&self) -> AgentInfo;
    fn connections(&self) -> Vec<crate::conn_registry::ConnectionSnapshot>;
    fn network_info(&self) -> NetworkInfo;
    fn session_providers_info(&self) -> SessionProvidersInfo;
    fn relay_status(&self) -> crate::relay::RelayStatus;
    /// Number of live QUIC connections. Drives the
    /// `portl_active_connections` gauge at scrape time.
    fn active_connection_count(&self) -> usize;
    /// Number of UDP sessions currently in the registry. Drives the
    /// `portl_active_udp_sessions` gauge at scrape time.
    fn active_udp_session_count(&self) -> usize;
}

/// Run the metrics server on the given unix socket path. Blocks until
/// `shutdown` fires. On drop, removes the socket file.
pub async fn serve(
    metrics: Arc<Metrics>,
    path: PathBuf,
    shutdown: CancellationToken,
) -> Result<()> {
    serve_with_status(metrics, path, shutdown, None::<Arc<NoStatus>>).await
}

/// Variant that also exposes `/status*` routes backed by `status`.
pub async fn serve_with_status<S: StatusSource>(
    metrics: Arc<Metrics>,
    path: PathBuf,
    shutdown: CancellationToken,
    status: Option<Arc<S>>,
) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create metrics socket parent {}", parent.display()))?;
    }
    // Clean up any stale socket left behind by a prior agent.
    let _ = std::fs::remove_file(&path);

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind metrics socket at {}", path.display()))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Immediately lock the socket down to 0o600. The brief
        // window between bind() and this chmod is tolerable in v0.1
        // because the socket path lives in $PORTL_HOME (default
        // ProjectDirs data_dir), which is already expected to be
        // owner-only. A stricter mitigation using a per-process
        // umask guard tripped concurrent file creation in other
        // threads under tokio test harnesses; track for v0.2.
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&path, perms)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }

    let socket_guard = SocketGuard { path: path.clone() };
    debug!(path = %path.display(), "metrics server ready");

    loop {
        tokio::select! {
            () = shutdown.cancelled() => break,
            incoming = listener.accept() => {
                let (stream, _) = match incoming {
                    Ok(v) => v,
                    Err(err) => {
                        warn!(?err, "metrics accept failed");
                        continue;
                    }
                };
                let metrics = Arc::clone(&metrics);
                let status = status.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_one(stream, metrics, status).await {
                        debug!(?err, "metrics client handler ended");
                    }
                });
            }
        }
    }
    drop(socket_guard);
    Ok(())
}

struct SocketGuard {
    path: PathBuf,
}

impl Drop for SocketGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

async fn serve_one<S: StatusSource>(
    mut stream: UnixStream,
    metrics: Arc<Metrics>,
    status: Option<Arc<S>>,
) -> Result<()> {
    let mut buf = [0u8; 8192];
    let read_result =
        tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;
    let n = match read_result {
        Ok(Ok(n)) => n,
        _ => 0,
    };
    let request = std::str::from_utf8(&buf[..n]).unwrap_or("");
    let path = parse_request_path(request);

    // Sync derived gauges from the live registries before rendering
    // Prometheus output, so `portl_active_connections` and
    // `portl_active_udp_sessions` always match what `/status`
    // reports without manual inc/dec bookkeeping.
    if let Some(s) = status.as_ref() {
        metrics
            .active_connections
            .set(i64::try_from(s.active_connection_count()).unwrap_or(i64::MAX));
        metrics
            .active_udp_sessions
            .set(i64::try_from(s.active_udp_session_count()).unwrap_or(i64::MAX));
    }

    let response = match path.as_deref() {
        Some("/" | "/metrics") => render_metrics(&metrics)?,
        Some("/status") => match status.as_ref() {
            Some(s) => render_json(&StatusResponse::new(
                s.agent_info(),
                s.connections(),
                s.network_info(),
                s.session_providers_info(),
                s.relay_status(),
            ))?,
            None => render_error(
                503,
                "status_unavailable",
                "agent is too young to expose status",
            ),
        },
        Some("/status/connections") => match status.as_ref() {
            Some(s) => render_json(&ConnectionsResponse::new(s.connections()))?,
            None => render_error(
                503,
                "status_unavailable",
                "agent is too young to expose status",
            ),
        },
        Some("/status/network") => match status.as_ref() {
            Some(s) => render_json(&NetworkResponse::new(s.network_info()))?,
            None => render_error(
                503,
                "status_unavailable",
                "agent is too young to expose status",
            ),
        },
        Some("/status/relay") => match status.as_ref() {
            Some(s) => render_json(&RelayResponse::new(s.relay_status()))?,
            None => render_error(
                503,
                "status_unavailable",
                "agent is too young to expose status",
            ),
        },
        Some(_) => render_error(404, "not_found", "no such route"),
        None => render_error(400, "bad_request", "could not parse HTTP request"),
    };

    stream
        .write_all(response.as_bytes())
        .await
        .context("write IPC response")?;
    stream.shutdown().await.context("shutdown IPC stream")?;
    Ok(())
}

/// Extract the path component from an HTTP request line, e.g. "GET
/// /status HTTP/1.1\r\n…" → Some("/status"). Returns `None` if the
/// request couldn't be parsed.
fn parse_request_path(request: &str) -> Option<String> {
    let line = request.lines().next()?;
    let mut parts = line.split_ascii_whitespace();
    let _method = parts.next()?;
    let path_with_query = parts.next()?;
    // Strip query string if present.
    let path = path_with_query
        .split_once('?')
        .map_or(path_with_query, |(p, _)| p);
    Some(path.to_owned())
}

fn render_metrics(metrics: &Metrics) -> Result<String> {
    let body = metrics.encode_text()?;
    Ok(format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn render_json<T: serde::Serialize>(payload: &T) -> Result<String> {
    let body = serde_json::to_string(payload).context("serialize JSON IPC response")?;
    Ok(format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    ))
}

fn render_error(code: u16, error_code: &'static str, message: &str) -> String {
    let body =
        serde_json::to_string(&ErrorResponse::new(error_code, message)).unwrap_or_else(|_| {
            String::from(
                r#"{"schema":1,"kind":"error","error":{"code":"serialize_failed","message":""}}"#,
            )
        });
    let reason = match code {
        400 => "Bad Request",
        404 => "Not Found",
        503 => "Service Unavailable",
        _ => "Error",
    };
    format!(
        "HTTP/1.1 {code} {reason}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

/// Sentinel `StatusSource` for callers that don't supply one. Returns
/// `503` for `/status*` routes by virtue of `Option::None`.
pub struct NoStatus;

impl StatusSource for NoStatus {
    fn agent_info(&self) -> AgentInfo {
        unreachable!("NoStatus is never invoked")
    }
    fn connections(&self) -> Vec<crate::conn_registry::ConnectionSnapshot> {
        unreachable!("NoStatus is never invoked")
    }
    fn network_info(&self) -> NetworkInfo {
        unreachable!("NoStatus is never invoked")
    }
    fn session_providers_info(&self) -> SessionProvidersInfo {
        unreachable!("NoStatus is never invoked")
    }
    fn relay_status(&self) -> crate::relay::RelayStatus {
        unreachable!("NoStatus is never invoked")
    }
    fn active_connection_count(&self) -> usize {
        0
    }
    fn active_udp_session_count(&self) -> usize {
        0
    }
}

#[cfg(test)]
mod ipc_tests {
    use super::*;

    #[test]
    fn parse_request_path_handles_basic_get() {
        let req = "GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
        assert_eq!(parse_request_path(req).as_deref(), Some("/status"));
    }

    #[test]
    fn parse_request_path_strips_query_string() {
        let req = "GET /status?foo=bar HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request_path(req).as_deref(), Some("/status"));
    }

    #[test]
    fn parse_request_path_handles_root() {
        let req = "GET / HTTP/1.1\r\n\r\n";
        assert_eq!(parse_request_path(req).as_deref(), Some("/"));
    }

    #[test]
    fn parse_request_path_returns_none_on_garbage() {
        assert_eq!(parse_request_path(""), None);
        assert_eq!(parse_request_path("garbage"), None);
    }

    #[test]
    fn render_error_response_is_well_formed_http() {
        let resp = render_error(404, "not_found", "no");
        assert!(resp.starts_with("HTTP/1.1 404 Not Found\r\n"));
        assert!(resp.contains("Content-Type: application/json"));
        assert!(resp.contains(r#""kind":"error""#));
        assert!(resp.contains(r#""code":"not_found""#));
    }

    #[test]
    fn render_metrics_response_uses_openmetrics_content_type() {
        let m = Metrics::default();
        let resp = render_metrics(&m).expect("render");
        assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(resp.contains("application/openmetrics-text"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_socket_path_ends_with_expected_name() {
        let p = default_socket_path();
        assert!(p.to_string_lossy().ends_with("metrics.sock"));
    }

    #[test]
    fn metrics_encode_contains_prefix() {
        let m = Metrics::default();
        m.tickets_accepted.inc();
        m.udp_sessions_opened.inc();
        let text = m.encode_text().unwrap();
        assert!(text.contains("portl_tickets_accepted"));
        assert!(text.contains("portl_udp_sessions_opened"));
    }
}
