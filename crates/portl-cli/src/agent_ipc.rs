//! Client-side helpers for speaking to the agent's IPC surface
//! (`$PORTL_HOME/metrics.sock`).
//!
//! v0.3.2 adds structured JSON routes on the same socket that
//! previously served only `OpenMetrics`. This module is a thin
//! HTTP-over-UDS client that hits those routes and deserializes
//! responses into the shared `portl_agent::status_schema` types.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use portl_agent::status_schema::{ConnectionsResponse, NetworkResponse, StatusResponse};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Resolve the agent's metrics socket path. Honors `PORTL_HOME`; falls
/// back to the platform default home dir.
#[must_use]
pub fn default_socket_path() -> PathBuf {
    let home = std::env::var_os("PORTL_HOME")
        .map_or_else(portl_agent::config::default_home_dir, PathBuf::from);
    home.join("metrics.sock")
}

/// Fetch `/status` from the agent's IPC socket.
pub async fn fetch_status(socket: &Path) -> Result<StatusResponse> {
    let body = get(socket, "/status").await?;
    serde_json::from_str::<StatusResponse>(&body).context("decode /status JSON")
}

/// Fetch `/status/connections`.
///
/// Not yet consumed by a CLI verb; present so `portl status
/// connections` (a focused section) can land as an isolated change
/// without touching the IPC client.
#[allow(dead_code)]
pub async fn fetch_connections(socket: &Path) -> Result<ConnectionsResponse> {
    let body = get(socket, "/status/connections").await?;
    serde_json::from_str::<ConnectionsResponse>(&body).context("decode /status/connections JSON")
}

/// Fetch `/status/network`.
///
/// Not yet consumed by a CLI verb; present for `portl status
/// network` in a follow-up change.
#[allow(dead_code)]
pub async fn fetch_network(socket: &Path) -> Result<NetworkResponse> {
    let body = get(socket, "/status/network").await?;
    serde_json::from_str::<NetworkResponse>(&body).context("decode /status/network JSON")
}

/// Perform a minimal HTTP/1.1 GET over the given UDS path. Reads
/// response entirely, parses status line + headers + body. Returns
/// body as `String` (IPC responses are always utf-8 JSON).
async fn get(socket: &Path, path: &str) -> Result<String> {
    let mut stream = tokio::time::timeout(Duration::from_secs(2), UnixStream::connect(socket))
        .await
        .with_context(|| format!("connect to {} timed out", socket.display()))?
        .with_context(|| format!("connect to {}", socket.display()))?;

    let request = format!("GET {path} HTTP/1.1\r\nHost: portl\r\nConnection: close\r\n\r\n");
    stream
        .write_all(request.as_bytes())
        .await
        .context("write IPC request")?;
    stream.shutdown().await.ok();

    let mut buf = Vec::with_capacity(16 * 1024);
    tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut buf))
        .await
        .context("read IPC response timed out")?
        .context("read IPC response")?;

    let text = std::str::from_utf8(&buf).context("IPC response not utf-8")?;
    parse_http_response(text)
}

/// Split a minimal HTTP/1.1 response into (status, body). Errors if
/// status is non-2xx; returns body as owned `String`.
fn parse_http_response(text: &str) -> Result<String> {
    let (head, body) = text
        .split_once("\r\n\r\n")
        .ok_or_else(|| anyhow!("malformed IPC response: no header/body separator"))?;
    let status_line = head
        .lines()
        .next()
        .ok_or_else(|| anyhow!("empty response"))?;
    let mut parts = status_line.split_ascii_whitespace();
    let _version = parts.next();
    let code: u16 = parts
        .next()
        .ok_or_else(|| anyhow!("missing status code"))?
        .parse()
        .context("parse status code")?;
    if !(200..300).contains(&code) {
        bail!("agent returned HTTP {code}: {body}");
    }
    Ok(body.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_http_response_accepts_200() {
        let resp = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
        assert_eq!(parse_http_response(resp).expect("parse"), "hello");
    }

    #[test]
    fn parse_http_response_rejects_404() {
        let resp = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
        assert!(parse_http_response(resp).is_err());
    }

    #[test]
    fn parse_http_response_rejects_malformed() {
        assert!(parse_http_response("not an http response").is_err());
    }
}
