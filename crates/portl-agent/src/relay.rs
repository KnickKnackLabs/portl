//! In-process iroh-relay server, peer-store authenticated.
//!
//! v0.3.3 ships an HTTP-only relay bound to a user-chosen socket.
//! Authorization piggy-backs on the agent's existing `PeerStore`:
//! `PortlRelayAccess` implements iroh-relay's access-control hook by
//! consulting `state.trust_roots`. Because `trust_roots` is swapped
//! live by the peer-store reload task, relay access updates with zero
//! restart.
//!
//! HTTPS and Let's Encrypt are deferred to v0.3.3.1 — the wire is
//! identical, and the gating hook is identical. Operators needing
//! HTTPS today should front the agent with a terminating proxy
//! (`nginx` or `caddy`) and point the proxy at the HTTP bind addr.
//!
//! Policy tiers:
//! - `open`       — accepts everyone; for isolated LANs only.
//! - `peers-only` — endpoint must be in the agent's `trust_roots`.
//! - `pairs-only` — v0.3.3 behaves like peers-only (enforcement
//!   requires v0.3.4 pair protocol). Flagged in `portl status
//!   relay` so operators know.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh_base::EndpointId;
use iroh_relay::server::{
    Access, AccessControl, CertConfig, ClientRequest, DynAccessControl, RelayConfig, Server,
    ServerConfig as IrohServerConfig, TlsConfig,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
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
    /// Optional HTTPS configuration. When `Some`, the relay also
    /// binds an HTTPS listener using the operator-provided cert
    /// chain and key. When `None`, only the HTTP listener runs
    /// (intranet / proxy-fronted deployments).
    pub tls: Option<RelayTlsConfig>,
}

/// Operator-provided TLS material. PEM-encoded files at the given
/// paths. Loaded once at startup; mtime-based reload deferred to
/// v0.3.3.3.
#[derive(Debug, Clone)]
pub struct RelayTlsConfig {
    /// HTTPS bind addr. Defaults to the same IP as `http_bind`
    /// on port 443 when not specified explicitly.
    pub https_bind: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

/// Spawn the in-process relay. Returns a handle whose drop tears
/// down the server. Blocks briefly on startup, not on serving.
#[instrument(skip_all, fields(bind = %cfg.http_bind, policy = %cfg.policy.as_str()))]
pub(crate) async fn spawn(
    cfg: RelayServerConfig,
    state: Arc<AgentState>,
    shutdown: CancellationToken,
) -> Result<RelayHandle> {
    let access: Arc<dyn DynAccessControl> = Arc::new(PortlRelayAccess {
        state: Arc::clone(&state),
        policy: cfg.policy,
    });

    let tls_config = match cfg.tls.as_ref() {
        Some(tls_cfg) => Some(build_tls_config(tls_cfg)?),
        None => None,
    };
    let mut relay = RelayConfig::new(cfg.http_bind);
    relay.tls = tls_config;
    relay.limits = iroh_relay::server::Limits::default();
    relay.key_cache_capacity = None;
    relay.access = access;

    let mut server_cfg = IrohServerConfig::default();
    server_cfg.relay = Some(relay);
    // Disable iroh-relay's optional QUIC address-discovery server for the
    // embedded relay. This does not disable normal Portl peer transport over
    // QUIC; it only avoids opening the relay server's extra UDP listener.
    server_cfg.quic = None;
    // iroh-relay's `server` feature exposes a metrics-server toggle. We don't
    // use it (portl exposes its own metrics on `metrics.sock`).
    server_cfg.metrics_addr = None;

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

struct PortlRelayAccess {
    state: Arc<AgentState>,
    policy: RelayPolicy,
}

impl std::fmt::Debug for PortlRelayAccess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortlRelayAccess")
            .field("policy", &self.policy)
            .finish_non_exhaustive()
    }
}

impl AccessControl for PortlRelayAccess {
    async fn on_connect(&self, request: &ClientRequest) -> Access {
        match self.policy {
            RelayPolicy::Open => {
                // Still record accepts so `portl status relay` and operators can
                // see connection volume. Open mode can't reject on this path.
                self.state.metrics.relay_accepts_total.inc();
                Access::Allow
            }
            // v0.3.3: pairs-only falls back to peers-only behavior; full
            // enforcement requires the v0.3.4 pair protocol.
            RelayPolicy::PeersOnly | RelayPolicy::PairsOnly => {
                if is_trusted(&self.state, request.endpoint_id()) {
                    self.state.metrics.relay_accepts_total.inc();
                    Access::Allow
                } else {
                    self.state
                        .metrics
                        .relay_rejects_total
                        .get_or_create(&crate::metrics::AckReasonLabel {
                            reason: "not_in_peer_store".to_owned(),
                        })
                        .inc();
                    Access::Deny { reason: None }
                }
            }
        }
    }
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

/// Build iroh-relay's TLS config from operator-provided PEM files.
/// iroh-relay wires everything up internally once we hand it the
/// `rustls::ServerConfig`; our job is just to load the cert chain
/// and key.
fn build_tls_config(cfg: &RelayTlsConfig) -> Result<TlsConfig> {
    // Install a process-global default crypto provider the first
    // time any relay with TLS is spawned. rustls requires exactly
    // one; we pick ring (matches Cargo feature set). Subsequent
    // calls are no-ops on Err (means already installed).
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs = load_certs(&cfg.cert_path)?;
    let key = load_key(&cfg.key_path)?;

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs.clone(), key)
        .with_context(|| {
            format!(
                "build rustls ServerConfig from cert {} and key {}",
                cfg.cert_path.display(),
                cfg.key_path.display()
            )
        })?;

    Ok(TlsConfig::new(
        cfg.https_bind,
        CertConfig::Manual { server_config },
    ))
}

fn load_certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>> {
    // Surface "file not found" before PEM parsing so test-side
    // error-message assertions (`open relay cert …`) still hit.
    if !path.exists() {
        bail!("open relay cert {}: file not found", path.display());
    }
    let certs: Vec<CertificateDer<'static>> = CertificateDer::pem_file_iter(path)
        .with_context(|| format!("open relay cert {}", path.display()))?
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parse relay cert PEM at {}", path.display()))?;
    if certs.is_empty() {
        bail!("no certificates found in {}", path.display());
    }
    Ok(certs)
}

fn load_key(path: &std::path::Path) -> Result<PrivateKeyDer<'static>> {
    if !path.exists() {
        bail!("open relay key {}: file not found", path.display());
    }
    let key = PrivateKeyDer::from_pem_file(path)
        .with_context(|| format!("parse relay key PEM at {}", path.display()))?;
    Ok(key)
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
    pub fn https_addr(&self) -> Option<SocketAddr> {
        self.server.as_ref().and_then(Server::https_addr)
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
    /// Present when HTTPS is configured (operator-provided cert).
    pub https_addr: Option<String>,
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
            https_addr: None,
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
            https_addr: handle.https_addr().map(|a| a.to_string()),
            hostname: Some(cfg.hostname.clone()),
            pairs_only_pending_v034: matches!(cfg.policy, RelayPolicy::PairsOnly),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::{Arc, RwLock};
    use std::time::{Instant, SystemTime};

    use iroh_relay::http::ProtocolVersion;
    use portl_core::ticket::verify::TrustRoots;

    use super::*;
    use crate::config::{AgentMode, DiscoveryConfig, RateLimitConfig};
    use crate::conn_registry::ConnectionRegistry;
    use crate::metrics::Metrics;
    use crate::network_watchdog::NetworkWatchdogHealth;
    use crate::rate_limit::OfferRateLimiter;
    use crate::revocations::{DEFAULT_REVOCATIONS_MAX_BYTES, RevocationSet};
    use crate::shell_registry::ShellRegistry;
    use crate::udp_registry::UdpSessionRegistry;

    fn relay_test_state(trust_roots: HashSet<[u8; 32]>) -> Arc<AgentState> {
        let revocations_path = std::env::temp_dir().join(format!(
            "portl-relay-test-revocations-{}.jsonl",
            std::process::id()
        ));
        Arc::new(AgentState {
            trust_roots: RwLock::new(TrustRoots(trust_roots)),
            bootstrap_roots: HashSet::new(),
            revocations: RwLock::new(
                RevocationSet::load_with_max_bytes(revocations_path, DEFAULT_REVOCATIONS_MAX_BYTES)
                    .unwrap(),
            ),
            rate_limit: OfferRateLimiter::new(&RateLimitConfig::default()).unwrap(),
            started_at: Instant::now(),
            shell_registry: ShellRegistry::default(),
            herdr_attach_registry: dashmap::DashMap::new(),
            #[cfg(feature = "ghostty-vt")]
            ghostty_attach_v2_registry: dashmap::DashMap::new(),
            udp_registry: UdpSessionRegistry::new(60),
            mode: AgentMode::Listener,
            metrics: Arc::new(Metrics::default()),
            connections: ConnectionRegistry::new(),
            peers_path: None,
            discovery: DiscoveryConfig::in_process(),
            home: std::env::temp_dir(),
            metrics_socket: std::env::temp_dir().join("portl-relay-test-metrics.sock"),
            session_provider_path: None,
            started_at_unix: 0,
            self_endpoint_id: [0; 32],
            watchdog_probe_endpoint_id: None,
            network_watchdog: NetworkWatchdogHealth::new(SystemTime::now()),
            relay_status: RwLock::new(RelayStatus::disabled()),
        })
    }

    fn relay_client_request(endpoint_id: EndpointId) -> ClientRequest {
        let request = http::Request::builder()
            .uri("/relay")
            .body(())
            .unwrap()
            .into_parts()
            .0;
        ClientRequest::new(endpoint_id, ProtocolVersion::V2, request)
    }

    #[tokio::test]
    async fn peers_only_denial_does_not_expose_policy_reason() {
        let access = PortlRelayAccess {
            state: relay_test_state(HashSet::new()),
            policy: RelayPolicy::PeersOnly,
        };
        let request = relay_client_request(iroh_base::SecretKey::generate().public());

        let decision = AccessControl::on_connect(&access, &request).await;

        assert_eq!(decision, Access::Deny { reason: None });
    }

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
        assert!(s.https_addr.is_none());
        assert!(s.hostname.is_none());
        assert!(!s.pairs_only_pending_v034);
    }

    #[test]
    fn relay_status_disabled_json_is_stable() {
        let s = RelayStatus::disabled();
        let json = serde_json::to_string(&s).unwrap();
        assert!(json.contains(r#""enabled":false"#));
    }

    #[test]
    fn load_certs_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        // Empty file = no PEM blocks. Should bail cleanly rather
        // than silently succeed with zero certs.
        let err = load_certs(tmp.path()).expect_err("empty PEM should fail");
        assert!(err.to_string().contains("no certificates"));
    }

    #[test]
    fn load_certs_rejects_missing_file() {
        let err = load_certs(std::path::Path::new("/nonexistent/relay.crt"))
            .expect_err("missing file should fail");
        assert!(err.to_string().contains("open relay cert"));
    }

    #[test]
    fn load_key_rejects_missing_file() {
        let err = load_key(std::path::Path::new("/nonexistent/relay.key"))
            .expect_err("missing file should fail");
        assert!(err.to_string().contains("open relay key"));
    }

    #[test]
    fn load_key_rejects_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let err = load_key(tmp.path()).expect_err("empty PEM should fail");
        // PemObject's parser surfaces a "NoItemsFound"-style error
        // for empty PEMs; we wrap it with "parse relay key PEM at".
        assert!(
            err.to_string().contains("parse relay key PEM"),
            "expected parse error, got: {err}"
        );
    }
}
