//! In-process iroh-relay server, peer-store authenticated.
//!
//! v0.3.3 ships an HTTP-only relay bound to a user-chosen socket.
//! Authorization piggy-backs on the agent's existing `PeerStore`:
//! `AccessConfig::Restricted` calls into a closure that consults
//! `state.trust_roots`. Because `trust_roots` is swapped live by
//! the peer-store reload task, relay access updates with zero
//! restart.
//!
//! HTTPS and Let's Encrypt are deferred to v0.3.3.1 — the wire is
//! identical, and the gating hook is identical. Operators needing
//! HTTPS today should front the agent with a terminating proxy
//! (`nginx` or `caddy`) and point the proxy at the HTTP bind addr.
//!
//! Policy tiers:
//! - `open`       — `AccessConfig::Everyone`; for isolated LANs only.
//! - `peers-only` — endpoint must be in the agent's `trust_roots`.
//! - `pairs-only` — v0.3.3 behaves like peers-only (enforcement
//!   requires v0.3.4 pair protocol). Flagged in `portl status
//!   relay` so operators know.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh_base::EndpointId;
use iroh_relay::server::{
    Access, AccessConfig, RelayConfig, Server, ServerConfig as IrohServerConfig,
};
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument, warn};

use crate::AgentState;

/// Relay policy tier. See module docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelayPolicy {
    Open,
    PeersOnly,
    PairsOnly,
}

impl RelayPolicy {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::PeersOnly => "peers-only",
            Self::PairsOnly => "pairs-only",
        }
    }
}

impl FromStr for RelayPolicy {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "open" => Ok(Self::Open),
            "peers-only" | "peers" => Ok(Self::PeersOnly),
            "pairs-only" | "pairs" => Ok(Self::PairsOnly),
            other => bail!("unknown relay policy {other:?} (expected open|peers-only|pairs-only)"),
        }
    }
}

/// Startup-time configuration for the embedded relay.
///
/// Absent from `AgentConfig::relay_server` when the relay is
/// disabled (default). Populated from `PORTL_RELAY_*` env vars.
#[derive(Debug, Clone)]
pub struct RelayServerConfig {
    /// HTTP bind addr. Example: `0.0.0.0:3340`.
    pub http_bind: SocketAddr,
    /// Advertised hostname, for `portl status relay` and (later)
    /// for peer-hint propagation. Pure metadata in v0.3.3.
    pub hostname: String,
    /// Access policy tier.
    pub policy: RelayPolicy,
}

/// Spawn the in-process relay. Returns a handle whose drop tears
/// down the server. Blocks briefly on startup, not on serving.
#[instrument(skip_all, fields(bind = %cfg.http_bind, policy = %cfg.policy.as_str()))]
pub(crate) async fn spawn(
    cfg: RelayServerConfig,
    state: Arc<AgentState>,
    shutdown: CancellationToken,
) -> Result<RelayHandle> {
    let access = match cfg.policy {
        RelayPolicy::Open => AccessConfig::Everyone,
        // v0.3.3: pairs-only falls back to peers-only behavior;
        // full enforcement requires the v0.3.4 pair protocol.
        RelayPolicy::PeersOnly | RelayPolicy::PairsOnly => {
            let state_for_gate = Arc::clone(&state);
            AccessConfig::Restricted(Box::new(move |eid: EndpointId| {
                let s = Arc::clone(&state_for_gate);
                Box::pin(async move {
                    if is_trusted(&s, eid) {
                        Access::Allow
                    } else {
                        Access::Deny
                    }
                })
            }))
        }
    };

    let relay = RelayConfig::<(), ()> {
        http_bind_addr: cfg.http_bind,
        tls: None, // HTTPS deferred to v0.3.3.1
        limits: iroh_relay::server::Limits::default(),
        key_cache_capacity: None,
        access,
    };
    let server_cfg = IrohServerConfig::<(), ()> {
        relay: Some(relay),
        quic: None,
        // iroh-relay's `server` feature unconditionally exposes a
        // metrics-server toggle. We don't use it (portl exposes
        // its own metrics on `metrics.sock`).
        metrics_addr: None,
    };

    let server = Server::spawn(server_cfg)
        .await
        .context("spawn in-process iroh-relay server")?;

    info!(
        http_addr = ?server.http_addr(),
        https_addr = ?server.https_addr(),
        hostname = %cfg.hostname,
        policy = cfg.policy.as_str(),
        "relay listening"
    );

    let handle = RelayHandle {
        server: Some(server),
        cfg: cfg.clone(),
        shutdown_task: {
            let shutdown = shutdown.clone();
            Some(tokio::spawn(async move {
                shutdown.cancelled().await;
            }))
        },
    };

    Ok(handle)
}

fn is_trusted(state: &AgentState, eid: EndpointId) -> bool {
    let bytes = *eid.as_bytes();
    match state.trust_roots.read() {
        Ok(roots) => roots.0.contains(&bytes),
        Err(err) => {
            warn!(?err, "trust_roots poisoned; denying relay access");
            false
        }
    }
}

/// Live relay server. Drop to shutdown (abort-on-drop on the
/// iroh-relay handle).
pub struct RelayHandle {
    server: Option<Server>,
    cfg: RelayServerConfig,
    shutdown_task: Option<tokio::task::JoinHandle<()>>,
}

impl RelayHandle {
    #[must_use]
    pub fn http_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().and_then(Server::http_addr)
    }

    #[must_use]
    pub fn config(&self) -> &RelayServerConfig {
        &self.cfg
    }

    /// Graceful shutdown; waits for the server to drain.
    pub async fn shutdown(mut self) -> Result<()> {
        if let Some(task) = self.shutdown_task.take() {
            task.abort();
        }
        if let Some(server) = self.server.take() {
            server
                .shutdown()
                .await
                .context("shutdown in-process iroh-relay server")?;
        }
        Ok(())
    }
}

impl Drop for RelayHandle {
    fn drop(&mut self) {
        if let Some(task) = self.shutdown_task.take() {
            task.abort();
        }
        // `Server` is AbortOnDropHandle-backed; its own Drop aborts
        // the supervisor. No explicit shutdown needed.
    }
}

/// Snapshot of relay state for the `/status/relay` IPC route.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayStatus {
    pub enabled: bool,
    /// Omitted when disabled.
    pub policy: Option<String>,
    pub http_addr: Option<String>,
    pub hostname: Option<String>,
    /// `true` when policy is `pairs-only` but enforcement falls
    /// back to peers-only (v0.3.3 limitation).
    pub pairs_only_pending_v034: bool,
}

impl RelayStatus {
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            enabled: false,
            policy: None,
            http_addr: None,
            hostname: None,
            pairs_only_pending_v034: false,
        }
    }

    #[must_use]
    pub fn from_handle(handle: &RelayHandle) -> Self {
        let cfg = handle.config();
        Self {
            enabled: true,
            policy: Some(cfg.policy.as_str().to_owned()),
            http_addr: handle.http_addr().map(|a| a.to_string()),
            hostname: Some(cfg.hostname.clone()),
            pairs_only_pending_v034: matches!(cfg.policy, RelayPolicy::PairsOnly),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_parses_canonical_forms() {
        assert_eq!(RelayPolicy::from_str("open").unwrap(), RelayPolicy::Open);
        assert_eq!(
            RelayPolicy::from_str("peers-only").unwrap(),
            RelayPolicy::PeersOnly
        );
        assert_eq!(
            RelayPolicy::from_str("pairs-only").unwrap(),
            RelayPolicy::PairsOnly
        );
    }

    #[test]
    fn policy_parses_short_aliases() {
        assert_eq!(
            RelayPolicy::from_str("peers").unwrap(),
            RelayPolicy::PeersOnly
        );
        assert_eq!(
            RelayPolicy::from_str("pairs").unwrap(),
            RelayPolicy::PairsOnly
        );
    }

    #[test]
    fn policy_rejects_unknown() {
        assert!(RelayPolicy::from_str("fully-open").is_err());
        assert!(RelayPolicy::from_str("").is_err());
        assert!(RelayPolicy::from_str("PEERS-ONLY").is_err()); // case-sensitive
    }

    #[test]
    fn policy_roundtrips_via_as_str() {
        for p in [
            RelayPolicy::Open,
            RelayPolicy::PeersOnly,
            RelayPolicy::PairsOnly,
        ] {
            assert_eq!(RelayPolicy::from_str(p.as_str()).unwrap(), p);
        }
    }

    #[test]
    fn relay_status_disabled_shape() {
        let s = RelayStatus::disabled();
        assert!(!s.enabled);
        assert!(s.policy.is_none());
        assert!(s.http_addr.is_none());
        assert!(s.hostname.is_none());
        assert!(!s.pairs_only_pending_v034);
    }

    #[test]
    fn relay_status_disabled_json_is_stable() {
        let s = RelayStatus::disabled();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""enabled":false"#));
    }
}
