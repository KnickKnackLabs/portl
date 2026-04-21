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

/// Run the metrics server on the given unix socket path. Blocks until
/// `shutdown` fires. On drop, removes the socket file.
pub async fn serve(
    metrics: Arc<Metrics>,
    path: PathBuf,
    shutdown: CancellationToken,
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
                tokio::spawn(async move {
                    if let Err(err) = serve_one(stream, metrics).await {
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

async fn serve_one(mut stream: UnixStream, metrics: Arc<Metrics>) -> Result<()> {
    let mut buf = [0u8; 8192];
    // Best-effort read of the HTTP request line + headers. We don't
    // actually branch on the path; any request returns metrics.
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf)).await;

    let body = metrics.encode_text()?;
    let response = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream
        .write_all(response.as_bytes())
        .await
        .context("write metrics response")?;
    stream.shutdown().await.context("shutdown metrics stream")?;
    Ok(())
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
