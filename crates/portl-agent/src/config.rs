use std::env::VarError;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use iroh_base::RelayUrl;
use portl_core::endpoint::Endpoint;
use portl_core::peer_store::PeerStore;
use serde::{Deserialize, Serialize};

use crate::config_file::PortlConfig;
use crate::relay::{RelayPolicy, RelayServerConfig, RelayTlsConfig};
use crate::udp_registry::DEFAULT_UDP_SESSION_LINGER_SECS;

const DEFAULT_LISTEN_ADDR: &str = "[::]:0";
const DEFAULT_RELAY_BIND: &str = "0.0.0.0:3340";
const DEFAULT_RELAY_HTTPS_BIND: &str = "0.0.0.0:443";
#[cfg(test)]
const AGENT_ENV_VARS: &[&str] = &[
    "PORTL_HOME",
    "PORTL_IDENTITY_SECRET_HEX",
    "PORTL_TRUST_ROOTS",
    "PORTL_LISTEN_ADDR",
    "PORTL_DISCOVERY",
    "PORTL_METRICS",
    "PORTL_REVOCATIONS_PATH",
    "PORTL_REVOCATIONS_MAX_BYTES",
    "PORTL_RATE_LIMIT",
    "PORTL_UDP_SESSION_LINGER_SECS",
    "PORTL_SESSION_PROVIDER",
    "PORTL_SESSION_PROVIDER_PATH",
    "PORTL_MODE",
    "PORTL_AGENT_WATCHDOG",
    "PORTL_AGENT_WATCHDOG_INTERVAL",
    "PORTL_AGENT_WATCHDOG_TIMEOUT",
    "PORTL_AGENT_WATCHDOG_FAILURES",
    "PORTL_RELAY_ENABLE",
    "PORTL_RELAY_BIND",
    "PORTL_RELAY_HOSTNAME",
    "PORTL_RELAY_POLICY",
    "PORTL_RELAY_HTTPS_BIND",
    "PORTL_RELAY_CERT",
    "PORTL_RELAY_KEY",
];

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub identity_path: Option<PathBuf>,
    #[doc(hidden)]
    pub identity_secret: Option<[u8; 32]>,
    pub bind_addr: Option<SocketAddr>,
    pub discovery: DiscoveryConfig,
    /// Populated at startup from `peers.json`. v0.3.0 removed the
    /// `PORTL_TRUST_ROOTS` env var — the peer store is the only
    /// source of truth. Leave as empty `Vec` in tests that don't
    /// care about trust policy.
    pub trust_roots: Vec<[u8; 32]>,
    /// Path to the peer store. Defaults to `<home>/data/peers.json`,
    /// overridable via explicit assignment in tests.
    pub peers_path: Option<PathBuf>,
    pub revocations_path: Option<PathBuf>,
    pub revocations_max_bytes: Option<u64>,
    pub rate_limit: RateLimitConfig,
    pub mode: AgentMode,
    #[doc(hidden)]
    pub endpoint: Option<Endpoint>,
    #[doc(hidden)]
    pub udp_session_linger_secs: Option<u64>,
    pub metrics_enabled: Option<bool>,
    pub metrics_socket_path: Option<PathBuf>,
    /// Optional preferred target-side persistent-session provider.
    /// The first v0.4 slice supports `zmx`.
    pub session_provider: Option<String>,
    /// Optional absolute path to the target-side persistent-session provider CLI.
    /// The first v0.4 slice treats this as a zmx path when set.
    pub session_provider_path: Option<PathBuf>,
    /// Lightweight self-healing endpoint watchdog.
    pub watchdog: crate::network_watchdog::WatchdogConfig,
    /// Optional in-process relay server. `None` = disabled
    /// (the default). See `PORTL_RELAY_ENABLE` + related vars.
    pub relay_server: Option<RelayServerConfig>,
}

impl AgentConfig {
    /// Load config from env vars only, for backward-compat with tests
    /// and any caller that explicitly wants the pre-v0.3.1.2 layering.
    /// Skips the `portl.toml` file load entirely.
    #[cfg(test)]
    pub fn from_env_only() -> Result<Self> {
        Self::build(None)
    }

    /// Load effective config. Order of precedence (high to low):
    ///
    /// 1. Environment variables (`PORTL_*`)
    /// 2. `portl.toml` at `$PORTL_HOME/config/portl.toml` (if present)
    /// 3. Compiled defaults
    ///
    /// CLI flags sit above this layer and are merged by the
    /// caller after `from_env` returns.
    pub fn from_env() -> Result<Self> {
        Self::from_env_maybe_migrate(true)
    }

    /// Load effective config without migrating legacy layout. Intended
    /// for diagnostic-only commands such as `portl doctor`, where merely
    /// inspecting state must not move durable files out from under an old
    /// still-running agent.
    pub fn from_env_without_layout_migration() -> Result<Self> {
        Self::from_env_maybe_migrate(false)
    }

    fn from_env_maybe_migrate(migrate_layout: bool) -> Result<Self> {
        #[cfg(not(test))]
        if migrate_layout {
            portl_core::paths::ensure_layout_migrated()?;
        }
        #[cfg(test)]
        let _ = migrate_layout;
        // Resolve home up-front so we know where to look for the
        // file. We duplicate the logic from `build` here but it's
        // short and avoids a two-pass structure.
        let home = env_path("PORTL_HOME").unwrap_or_else(default_home_dir);
        let file_path = PortlConfig::default_path(&home);
        let file = PortlConfig::load(&file_path)
            .with_context(|| format!("load config from {}", file_path.display()))?;
        Self::build(Some(&file))
    }

    #[allow(clippy::too_many_lines)]
    fn build(file: Option<&PortlConfig>) -> Result<Self> {
        let identity_secret = env_string("PORTL_IDENTITY_SECRET_HEX")
            .and_then(|value| value.map(|value| parse_secret_hex(&value)).transpose())?;
        let persistent = identity_secret.is_none();
        let home = env_path("PORTL_HOME").unwrap_or_else(|| {
            if persistent {
                default_home_dir()
            } else {
                std::env::temp_dir().join(format!("portl-ephemeral-{}", std::process::id()))
            }
        });
        let paths = portl_core::paths::for_home(&home);
        let identity_path = paths.identity_path();

        if identity_secret.is_some() && identity_path.exists() {
            bail!(
                "PORTL_IDENTITY_SECRET_HEX is mutually exclusive with an existing {}",
                identity_path.display()
            );
        }

        let peers_path = paths.peers_path();
        // Load trust_roots from the peer store. Missing file = empty
        // roots: an agent with no peers refuses every ticket, which
        // is the correct fail-closed default. Installers are expected
        // to seed the self-row via `portl install --apply` and
        // operators add peers via `portl accept` / `portl peer add-unsafe-raw`.
        let peer_store = PeerStore::load(&peers_path)
            .with_context(|| format!("load peer store at {}", peers_path.display()))?;
        // `PORTL_TRUST_ROOTS` is honored as a *bootstrap* mechanism
        // layered on top of the peer store — containerized /
        // ephemeral agents (docker, slicer) inject it at spawn-time
        // because they can't seed peers.json inside the target
        // before the agent starts. The peer store remains the
        // primary policy surface; the env var just adds extra
        // roots on startup and is ignored once set on subsequent
        // runs because the peer store persists.
        let env_roots = env_string("PORTL_TRUST_ROOTS")?
            .map(|value| parse_trust_roots(&value))
            .transpose()?
            .unwrap_or_default();
        let mut trust_roots: Vec<[u8; 32]> = peer_store.trust_roots().into_iter().collect();
        for root in env_roots {
            if !trust_roots.contains(&root) {
                trust_roots.push(root);
            }
        }

        let bind_addr_value = env_string("PORTL_LISTEN_ADDR")?
            .or_else(|| file.and_then(|f| f.agent.listen_addr.clone()))
            .unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned());
        let bind_addr = bind_addr_value.parse().with_context(|| {
            format!("parse PORTL_LISTEN_ADDR as socket address: {bind_addr_value}")
        })?;
        let discovery = if let Some(value) = env_string("PORTL_DISCOVERY")? {
            parse_discovery(&value)?
        } else if let Some(section) = file.and_then(|f| f.agent.discovery.as_ref()) {
            build_discovery_from_file(section)?
        } else {
            DiscoveryConfig::default()
        };
        let revocations_path =
            env_path("PORTL_REVOCATIONS_PATH").unwrap_or_else(|| paths.revocations_path());
        let rate_limit = if let Some(value) = env_string("PORTL_RATE_LIMIT")? {
            parse_rate_limit(&value)?
        } else if let Some(section) = file.and_then(|f| f.agent.rate_limit.as_ref()) {
            RateLimitConfig {
                rps: section.rps.unwrap_or(RateLimitConfig::default().rps),
                burst: section.burst.unwrap_or(RateLimitConfig::default().burst),
            }
        } else {
            RateLimitConfig::default()
        };
        let revocations_max_bytes = env_string("PORTL_REVOCATIONS_MAX_BYTES")?
            .map(|value| {
                value.parse::<u64>().with_context(|| {
                    format!("parse PORTL_REVOCATIONS_MAX_BYTES as an integer: {value}")
                })
            })
            .transpose()?
            .unwrap_or(crate::revocations::DEFAULT_REVOCATIONS_MAX_BYTES);
        let udp_session_linger_secs =
            if let Some(value) = env_string("PORTL_UDP_SESSION_LINGER_SECS")? {
                value.parse::<u64>().with_context(|| {
                    format!("parse PORTL_UDP_SESSION_LINGER_SECS as an integer: {value}")
                })?
            } else {
                file.and_then(|f| f.agent.udp.as_ref())
                    .and_then(|u| u.session_linger_secs)
                    .unwrap_or(DEFAULT_UDP_SESSION_LINGER_SECS)
            };
        let metrics_enabled = env_string("PORTL_METRICS")?
            .map(|value| parse_bool_env("PORTL_METRICS", &value))
            .transpose()?
            .unwrap_or(persistent);
        let session_provider = env_string("PORTL_SESSION_PROVIDER")?
            .or_else(|| file.and_then(|f| f.agent.session_provider.clone()))
            .map(|value| parse_session_provider(&value))
            .transpose()?;
        let session_provider_path = env_path("PORTL_SESSION_PROVIDER_PATH")
            .or_else(|| file.and_then(|f| f.agent.session_provider_path.clone()));
        let mode = env_string("PORTL_MODE")?
            .map(|value| parse_listener_mode(&value))
            .transpose()?
            .unwrap_or(AgentMode::Listener);
        let watchdog = parse_watchdog_config(&mode)?;

        let relay_server = parse_relay_server_config()?;

        Ok(Self {
            identity_path: persistent.then_some(identity_path),
            identity_secret,
            bind_addr: Some(bind_addr),
            discovery,
            trust_roots,
            peers_path: Some(peers_path),
            revocations_path: Some(revocations_path),
            revocations_max_bytes: Some(revocations_max_bytes),
            rate_limit,
            mode,
            endpoint: None,
            udp_session_linger_secs: Some(udp_session_linger_secs),
            metrics_enabled: Some(metrics_enabled),
            metrics_socket_path: Some(paths.metrics_socket_path()),
            session_provider,
            session_provider_path,
            watchdog,
            relay_server,
        })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentMode {
    #[default]
    Listener,
    Gateway {
        upstream_url: String,
        upstream_host: String,
        upstream_port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryConfig {
    pub dns: bool,
    pub pkarr: bool,
    pub local: bool,
    /// Ordered list of relay URLs. Empty vec = relay disabled.
    /// First entry is the preferred relay (iroh's `RelayMode::Custom`
    /// accepts any iterable; preference inside the list is determined
    /// by iroh's relay-selection heuristic, typically RTT-based).
    ///
    /// Populated via `PORTL_DISCOVERY`:
    ///
    /// - `relay` (bare): n0's default relay
    /// - `relay:https://mine.com`: custom URL
    /// - `relay,relay:https://mine.com`: both (n0 + custom; order preserved)
    /// - `relay:https://a.com,relay:https://b.com`: two customs
    ///
    /// Duplicates are silently deduplicated (first occurrence wins
    /// its position).
    pub relays: Vec<RelayUrl>,
}

impl DiscoveryConfig {
    #[must_use]
    pub fn in_process() -> Self {
        Self {
            dns: false,
            pkarr: false,
            local: false,
            relays: Vec::new(),
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        let relays = iroh::endpoint::default_relay_mode()
            .relay_map()
            .urls::<Vec<_>>()
            .into_iter()
            .collect();
        Self {
            dns: true,
            pkarr: true,
            local: true,
            relays,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub rps: u32,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self { rps: 1, burst: 10 }
    }
}

pub fn parse_gateway_mode(url: &str) -> Result<AgentMode> {
    let parsed =
        url::Url::parse(url).with_context(|| format!("parse gateway upstream URL {url}"))?;
    let host = parsed
        .host_str()
        .map(ToOwned::to_owned)
        .context("gateway upstream URL must include a host")?;
    let port = parsed
        .port_or_known_default()
        .context("gateway upstream URL must include a port")?;
    Ok(AgentMode::Gateway {
        upstream_url: url.to_owned(),
        upstream_host: host,
        upstream_port: port,
    })
}

pub fn default_home_dir() -> PathBuf {
    portl_core::paths::default_home_dir()
}

fn env_string(name: &str) -> Result<Option<String>> {
    match std::env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(VarError::NotPresent) => Ok(None),
        Err(VarError::NotUnicode(_)) => Err(anyhow!("{name} must be valid UTF-8")),
    }
}

fn env_path(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).map(PathBuf::from)
}

fn parse_listener_mode(mode: &str) -> Result<AgentMode> {
    match mode {
        "listener" => Ok(AgentMode::Listener),
        "gateway" => Err(anyhow!(
            "PORTL_MODE=gateway has been removed; use the portl-gateway entrypoint"
        )),
        other => Err(anyhow!("unsupported PORTL_MODE: {other}")),
    }
}

fn parse_discovery(value: &str) -> Result<DiscoveryConfig> {
    if value.trim() == "none" {
        return Ok(DiscoveryConfig::in_process());
    }

    let mut discovery = DiscoveryConfig::in_process();
    let default_relays = DiscoveryConfig::default().relays;
    let mut saw_entry = false;
    for item in value
        .split(',')
        .map(str::trim)
        .filter(|item| !item.is_empty())
    {
        saw_entry = true;
        match item {
            "dns" => discovery.dns = true,
            "pkarr" => discovery.pkarr = true,
            "local" => discovery.local = true,
            "relay" => {
                // Bare `relay` token appends iroh's default relay(s).
                // Dedup against what's already collected so
                // `relay,relay` or `relay:<same>,relay` don't
                // double-insert.
                for url in &default_relays {
                    if !discovery.relays.contains(url) {
                        discovery.relays.push(url.clone());
                    }
                }
            }
            other if other.starts_with("relay:") || other.starts_with("relay=") => {
                // v0.3.1.2: accept explicit relay URL via
                // `relay:https://relay.mynet.com` (or `relay=<url>`).
                // Parsed via `RelayUrl::from_str` so invalid URLs
                // surface a clear error rather than silently
                // falling back to the default.
                let url_str = &other["relay:".len()..];
                let url = url_str.parse::<RelayUrl>().with_context(|| {
                    format!("parse relay URL from PORTL_DISCOVERY entry `{other}`")
                })?;
                if !discovery.relays.contains(&url) {
                    discovery.relays.push(url);
                }
            }
            other => bail!("unsupported PORTL_DISCOVERY backend: {other}"),
        }
    }

    if !saw_entry {
        bail!("PORTL_DISCOVERY must not be empty");
    }

    Ok(discovery)
}

/// Build a [`DiscoveryConfig`] from a `[agent.discovery]` TOML
/// section. Missing fields fall back to [`DiscoveryConfig::default`]
/// per-field, matching the env-var precedence model.
///
/// Special relay tokens recognized in the `relays` array:
///
/// - `"default"` — append iroh's built-in n0 relays
/// - `"disabled"` (alone) — empty list, relay disabled
/// - any other string — parsed as a `RelayUrl`
fn build_discovery_from_file(
    section: &crate::config_file::DiscoverySection,
) -> Result<DiscoveryConfig> {
    let defaults = DiscoveryConfig::default();
    let mut cfg = DiscoveryConfig {
        dns: section.dns.unwrap_or(defaults.dns),
        pkarr: section.pkarr.unwrap_or(defaults.pkarr),
        local: section.local.unwrap_or(defaults.local),
        relays: Vec::new(),
    };

    let entries = if let Some(list) = section.relays.as_ref() {
        list.clone()
    } else {
        cfg.relays = defaults.relays;
        return Ok(cfg);
    };

    if entries.len() == 1 && entries[0].trim() == "disabled" {
        return Ok(cfg);
    }

    let default_relays = defaults.relays;
    for entry in entries {
        let trimmed = entry.trim();
        if trimmed == "default" {
            for url in &default_relays {
                if !cfg.relays.contains(url) {
                    cfg.relays.push(url.clone());
                }
            }
        } else if trimmed == "disabled" {
            // Ignored when not the only entry; logged for visibility.
            tracing::warn!(
                "ignoring `disabled` in [agent.discovery].relays mixed with other entries"
            );
        } else {
            let url = trimmed.parse::<RelayUrl>().with_context(|| {
                format!("parse relay URL `{trimmed}` from [agent.discovery].relays")
            })?;
            if !cfg.relays.contains(&url) {
                cfg.relays.push(url);
            }
        }
    }

    Ok(cfg)
}

fn parse_trust_roots(value: &str) -> Result<Vec<[u8; 32]>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_trust_root_hex)
        .collect()
}

fn parse_trust_root_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid trust root hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("trust root must decode to exactly 32 bytes: {value}"))
}

fn parse_rate_limit(value: &str) -> Result<RateLimitConfig> {
    let mut rps = None;
    let mut burst = None;
    for part in value
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
    {
        let (key, raw_value) = part
            .split_once('=')
            .with_context(|| format!("PORTL_RATE_LIMIT entries must be key=value pairs: {part}"))?;
        match key {
            "rps" => {
                rps = Some(raw_value.parse::<u32>().with_context(|| {
                    format!("parse PORTL_RATE_LIMIT rps as an integer: {raw_value}")
                })?);
            }
            "burst" => {
                burst = Some(raw_value.parse::<u32>().with_context(|| {
                    format!("parse PORTL_RATE_LIMIT burst as an integer: {raw_value}")
                })?);
            }
            other => bail!("unsupported PORTL_RATE_LIMIT key: {other}"),
        }
    }

    Ok(RateLimitConfig {
        rps: rps.context("PORTL_RATE_LIMIT requires rps=<n>")?,
        burst: burst.context("PORTL_RATE_LIMIT requires burst=<n>")?,
    })
}

fn parse_session_provider(value: &str) -> Result<String> {
    match value.trim() {
        "zmx" => Ok("zmx".to_owned()),
        other => bail!("unsupported PORTL_SESSION_PROVIDER '{other}' (supported: zmx)"),
    }
}

fn parse_bool_env(name: &str, value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(anyhow!("{name} must be one of 0,1,false,true,no,yes")),
    }
}

fn parse_watchdog_config(mode: &AgentMode) -> Result<crate::network_watchdog::WatchdogConfig> {
    let mut config = crate::network_watchdog::WatchdogConfig {
        enabled: matches!(mode, AgentMode::Listener),
        ..Default::default()
    };
    if let Some(value) = env_string("PORTL_AGENT_WATCHDOG")? {
        config.enabled = match value.as_str() {
            "auto" => matches!(mode, AgentMode::Listener),
            "off" | "0" | "false" | "no" => false,
            "on" | "1" | "true" | "yes" => true,
            other => bail!(
                "PORTL_AGENT_WATCHDOG must be auto, off, on, 0, 1, false, true, no, or yes (got {other})"
            ),
        };
    }
    if let Some(value) = env_string("PORTL_AGENT_WATCHDOG_INTERVAL")? {
        config.interval = humantime::parse_duration(&value)
            .with_context(|| format!("parse PORTL_AGENT_WATCHDOG_INTERVAL duration: {value}"))?;
        if config.interval < std::time::Duration::from_secs(1) {
            bail!("PORTL_AGENT_WATCHDOG_INTERVAL must be at least 1s");
        }
    }
    if let Some(value) = env_string("PORTL_AGENT_WATCHDOG_TIMEOUT")? {
        config.timeout = humantime::parse_duration(&value)
            .with_context(|| format!("parse PORTL_AGENT_WATCHDOG_TIMEOUT duration: {value}"))?;
        if config.timeout < std::time::Duration::from_millis(100) {
            bail!("PORTL_AGENT_WATCHDOG_TIMEOUT must be at least 100ms");
        }
    }
    if let Some(value) = env_string("PORTL_AGENT_WATCHDOG_FAILURES")? {
        config.failures_before_refresh = value.parse::<u32>().with_context(|| {
            format!("parse PORTL_AGENT_WATCHDOG_FAILURES as a positive integer: {value}")
        })?;
        if config.failures_before_refresh == 0 {
            bail!("PORTL_AGENT_WATCHDOG_FAILURES must be at least 1");
        }
    }
    Ok(config)
}

fn parse_secret_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)
        .with_context(|| format!("invalid PORTL_IDENTITY_SECRET_HEX hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("PORTL_IDENTITY_SECRET_HEX must decode to exactly 32 bytes: {value}"))
}

/// Parse the `PORTL_RELAY_*` surface. Returns `None` when the relay
/// is disabled (the default).
fn parse_relay_server_config() -> Result<Option<RelayServerConfig>> {
    let enabled = match env_string("PORTL_RELAY_ENABLE")? {
        Some(value) => parse_bool_env("PORTL_RELAY_ENABLE", &value)?,
        None => false,
    };
    if !enabled {
        return Ok(None);
    }
    let http_bind_value =
        env_string("PORTL_RELAY_BIND")?.unwrap_or_else(|| DEFAULT_RELAY_BIND.to_owned());
    let http_bind: SocketAddr = http_bind_value
        .parse()
        .with_context(|| format!("parse PORTL_RELAY_BIND as socket address: {http_bind_value}"))?;
    let hostname =
        env_string("PORTL_RELAY_HOSTNAME")?.unwrap_or_else(|| http_bind.ip().to_string());
    let policy = match env_string("PORTL_RELAY_POLICY")? {
        Some(value) => value.parse::<RelayPolicy>()?,
        None => RelayPolicy::PeersOnly,
    };
    let tls = parse_relay_tls_config(http_bind)?;
    Ok(Some(RelayServerConfig {
        http_bind,
        hostname,
        policy,
        tls,
    }))
}

/// Parse the `PORTL_RELAY_CERT` / `PORTL_RELAY_KEY` /
/// `PORTL_RELAY_HTTPS_BIND` triple. Returns `None` when no cert path
/// is set (HTTP-only mode). Both cert and key must be set when
/// either is; bailing here early gives operators a clear error
/// instead of a confusing TLS failure later.
#[allow(clippy::similar_names)]
fn parse_relay_tls_config(http_bind: SocketAddr) -> Result<Option<RelayTlsConfig>> {
    let cert = env_path("PORTL_RELAY_CERT");
    let key = env_path("PORTL_RELAY_KEY");
    match (cert, key) {
        (None, None) => Ok(None),
        (Some(_), None) => {
            bail!("PORTL_RELAY_CERT is set but PORTL_RELAY_KEY is not; set both or neither")
        }
        (None, Some(_)) => {
            bail!("PORTL_RELAY_KEY is set but PORTL_RELAY_CERT is not; set both or neither")
        }
        (Some(cert_path), Some(key_path)) => {
            let explicit_https = env_string("PORTL_RELAY_HTTPS_BIND")?;
            let https_bind_value = explicit_https
                .clone()
                .unwrap_or_else(|| DEFAULT_RELAY_HTTPS_BIND.to_owned());
            let mut https_bind: SocketAddr = https_bind_value.parse().with_context(|| {
                format!("parse PORTL_RELAY_HTTPS_BIND as socket address: {https_bind_value}")
            })?;
            // If the operator didn't explicitly override the HTTPS
            // bind but did set the HTTP bind to something
            // non-default, inherit the IP for HTTPS too. Keeps the
            // common case "bind both on 127.0.0.1" ergonomic.
            if explicit_https.is_none() {
                https_bind.set_ip(http_bind.ip());
            }
            Ok(Some(RelayTlsConfig {
                https_bind,
                cert_path,
                key_path,
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex};

    use tempfile::tempdir;

    use super::{AGENT_ENV_VARS, AgentConfig, AgentMode, DiscoveryConfig, RateLimitConfig};
    use crate::udp_registry::DEFAULT_UDP_SESSION_LINGER_SECS;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn from_env_parses_defaults_in_empty_env() {
        let tmp = tempdir().expect("tempdir");
        with_env(
            &[("PORTL_HOME", Some(tmp.path().as_os_str().to_os_string()))],
            || {
                let config = AgentConfig::from_env().expect("parse empty env");
                let home = tmp.path().to_path_buf();

                let paths = portl_core::paths::for_home(&home);
                assert_eq!(config.identity_path, Some(paths.identity_path()));
                assert_eq!(
                    config.bind_addr,
                    Some("[::]:0".parse().expect("default listen addr"))
                );
                assert_eq!(config.discovery, DiscoveryConfig::default());
                assert!(config.trust_roots.is_empty());
                assert_eq!(config.revocations_path, Some(paths.revocations_path()));
                assert_eq!(
                    config.revocations_max_bytes,
                    Some(crate::revocations::DEFAULT_REVOCATIONS_MAX_BYTES)
                );
                assert_eq!(config.rate_limit, RateLimitConfig::default());
                assert_eq!(config.mode, AgentMode::Listener);
                assert_eq!(
                    config.udp_session_linger_secs,
                    Some(DEFAULT_UDP_SESSION_LINGER_SECS)
                );
                assert_eq!(config.metrics_enabled, Some(true));
                assert_eq!(
                    config.metrics_socket_path,
                    Some(paths.metrics_socket_path())
                );
                assert!(config.watchdog.enabled);
                assert_eq!(config.watchdog.interval, std::time::Duration::from_mins(5));
                assert_eq!(config.watchdog.timeout, std::time::Duration::from_secs(5));
                assert_eq!(config.watchdog.failures_before_refresh, 3);
            },
        );
    }

    #[test]
    fn watchdog_env_can_disable_and_tune() {
        let home = tempdir().expect("tempdir");
        with_env(
            &[
                ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                ("PORTL_AGENT_WATCHDOG", Some(OsString::from("off"))),
                ("PORTL_AGENT_WATCHDOG_INTERVAL", Some(OsString::from("30s"))),
                ("PORTL_AGENT_WATCHDOG_TIMEOUT", Some(OsString::from("2s"))),
                ("PORTL_AGENT_WATCHDOG_FAILURES", Some(OsString::from("2"))),
            ],
            || {
                let config = AgentConfig::from_env().expect("parse watchdog env");
                assert!(!config.watchdog.enabled);
                assert_eq!(config.watchdog.interval, std::time::Duration::from_secs(30));
                assert_eq!(config.watchdog.timeout, std::time::Duration::from_secs(2));
                assert_eq!(config.watchdog.failures_before_refresh, 2);
            },
        );
    }

    #[test]
    fn watchdog_env_accepts_false_aliases() {
        for value in ["0", "false", "no"] {
            let home = tempdir().expect("tempdir");
            with_env(
                &[
                    ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                    ("PORTL_AGENT_WATCHDOG", Some(OsString::from(value))),
                ],
                || {
                    let config = AgentConfig::from_env().expect("parse watchdog false alias");
                    assert!(
                        !config.watchdog.enabled,
                        "value {value} should disable watchdog"
                    );
                },
            );
        }
    }

    #[test]
    fn watchdog_env_rejects_zero_interval_and_timeout() {
        for (name, value, expected) in [
            (
                "PORTL_AGENT_WATCHDOG_INTERVAL",
                "0s",
                "PORTL_AGENT_WATCHDOG_INTERVAL must be at least 1s",
            ),
            (
                "PORTL_AGENT_WATCHDOG_TIMEOUT",
                "0ms",
                "PORTL_AGENT_WATCHDOG_TIMEOUT must be at least 100ms",
            ),
        ] {
            let home = tempdir().expect("tempdir");
            with_env(
                &[
                    ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                    (name, Some(OsString::from(value))),
                ],
                || {
                    let err = AgentConfig::from_env().expect_err("invalid watchdog duration");
                    assert!(
                        err.to_string().contains(expected),
                        "unexpected error: {err:#}"
                    );
                },
            );
        }
    }

    #[test]
    fn watchdog_env_rejects_zero_failures() {
        let home = tempdir().expect("tempdir");
        with_env(
            &[
                ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                ("PORTL_AGENT_WATCHDOG_FAILURES", Some(OsString::from("0"))),
            ],
            || {
                let err = AgentConfig::from_env().expect_err("zero failures must fail");
                assert!(
                    err.to_string()
                        .contains("PORTL_AGENT_WATCHDOG_FAILURES must be at least 1"),
                    "unexpected error: {err:#}"
                );
            },
        );
    }

    #[test]
    fn from_env_rejects_both_identity_and_home() {
        let home = tempdir().expect("tempdir");
        let paths = portl_core::paths::for_home(home.path());
        std::fs::create_dir_all(paths.data_dir()).expect("create data dir");
        std::fs::write(paths.identity_path(), [7_u8; 32]).expect("write identity");

        with_env(
            &[
                ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                (
                    "PORTL_IDENTITY_SECRET_HEX",
                    Some(OsString::from(hex::encode([9_u8; 32]))),
                ),
            ],
            || {
                let err =
                    AgentConfig::from_env().expect_err("identity file + env secret must fail");
                assert!(
                    err.to_string()
                        .contains("PORTL_IDENTITY_SECRET_HEX is mutually exclusive"),
                    "unexpected error: {err:#}"
                );
            },
        );
    }

    #[test]
    fn from_env_parses_rate_limit_compact_form() {
        with_env(
            &[("PORTL_RATE_LIMIT", Some(OsString::from("rps=7,burst=13")))],
            || {
                let config = AgentConfig::from_env().expect("parse rate limit env");
                assert_eq!(config.rate_limit, RateLimitConfig { rps: 7, burst: 13 });
            },
        );
    }

    #[test]
    fn from_env_parses_discovery_list() {
        with_env(
            &[("PORTL_DISCOVERY", Some(OsString::from("local,relay")))],
            || {
                let config = AgentConfig::from_env().expect("parse discovery env");
                assert!(!config.discovery.dns);
                assert!(!config.discovery.pkarr);
                assert!(config.discovery.local);
                assert!(!config.discovery.relays.is_empty());
            },
        );
    }

    #[test]
    fn from_env_parses_discovery_with_custom_relay_url() {
        // v0.3.1.2: `relay:<url>` syntax overrides the default n0
        // relay with an operator-provided one. Parser MUST round-
        // trip to the same URL via RelayUrl::from_str.
        with_env(
            &[(
                "PORTL_DISCOVERY",
                Some(OsString::from("relay:https://relay.mynet.com./")),
            )],
            || {
                let config = AgentConfig::from_env().expect("parse custom relay env");
                let relays = &config.discovery.relays;
                assert_eq!(
                    relays.len(),
                    1,
                    "expected exactly one relay, got {relays:?}"
                );
                assert_eq!(relays[0].as_str(), "https://relay.mynet.com./");
            },
        );
    }

    #[test]
    fn from_env_parses_discovery_with_custom_relay_url_alt_separator() {
        // Accept `relay=<url>` as an alias for `relay:<url>` so users
        // who instinctively reach for `=` aren't surprised.
        with_env(
            &[(
                "PORTL_DISCOVERY",
                Some(OsString::from("dns,relay=https://relay.mynet.com./")),
            )],
            || {
                let config = AgentConfig::from_env().expect("parse custom relay env");
                let relays = &config.discovery.relays;
                assert_eq!(relays.len(), 1);
                assert_eq!(relays[0].as_str(), "https://relay.mynet.com./");
                assert!(config.discovery.dns);
            },
        );
    }

    #[test]
    fn from_env_rejects_invalid_custom_relay_url() {
        with_env(
            &[("PORTL_DISCOVERY", Some(OsString::from("relay:not a url")))],
            || {
                let err = AgentConfig::from_env().expect_err("invalid url must error");
                assert!(
                    err.to_string().contains("parse relay URL"),
                    "expected parse-relay-URL error, got: {err}"
                );
            },
        );
    }

    #[test]
    fn from_env_parses_discovery_with_multiple_custom_relays() {
        // v0.3.1.2: multiple `relay:<url>` entries produce an ordered
        // list. First entry first, in the order written, deduplicated.
        with_env(
            &[(
                "PORTL_DISCOVERY",
                Some(OsString::from(
                    "relay:https://a.example./,relay:https://b.example./",
                )),
            )],
            || {
                let config = AgentConfig::from_env().expect("parse env");
                let relays = &config.discovery.relays;
                assert_eq!(relays.len(), 2, "expected 2 relays, got {relays:?}");
                assert_eq!(relays[0].as_str(), "https://a.example./");
                assert_eq!(relays[1].as_str(), "https://b.example./");
            },
        );
    }

    #[test]
    fn from_env_parses_discovery_mixing_default_and_custom_relays() {
        // The most useful combo: keep n0's default relay for
        // bootstrap + fallback, add your own custom one too.
        with_env(
            &[(
                "PORTL_DISCOVERY",
                Some(OsString::from("relay,relay:https://mine.example./")),
            )],
            || {
                let config = AgentConfig::from_env().expect("parse env");
                let relays = &config.discovery.relays;
                assert!(
                    relays.len() >= 2,
                    "expected n0 default + custom, got {relays:?}"
                );
                let has_custom = relays
                    .iter()
                    .any(|u| u.as_str() == "https://mine.example./");
                assert!(has_custom, "custom relay missing from {relays:?}");
            },
        );
    }

    #[test]
    fn from_env_deduplicates_relays() {
        // Same URL listed twice produces only one entry.
        with_env(
            &[(
                "PORTL_DISCOVERY",
                Some(OsString::from(
                    "relay:https://a.example./,relay:https://a.example./",
                )),
            )],
            || {
                let config = AgentConfig::from_env().expect("parse env");
                assert_eq!(config.discovery.relays.len(), 1);
            },
        );
    }

    #[test]
    fn from_env_populates_trust_roots_from_peer_store() {
        // With v0.3.0's filesystem-backed model: writing a peers.json
        // into PORTL_HOME/data is the only path to populating trust_roots.
        // Empty store → empty roots; no warnings, no crashes.
        let home = tempdir().expect("tempdir");
        let peers = portl_core::peer_store::PeerStore::new();
        let paths = portl_core::paths::for_home(home.path());
        peers.save(&paths.peers_path()).expect("seed peer store");
        with_env(
            &[("PORTL_HOME", Some(home.path().as_os_str().to_os_string()))],
            || {
                let config = AgentConfig::from_env().expect("parse env with empty peer store");
                assert!(config.trust_roots.is_empty());
                assert_eq!(config.peers_path, Some(paths.peers_path()));
            },
        );
    }

    #[allow(unsafe_code)]
    fn with_env(vars: &[(&str, Option<OsString>)], f: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved = AGENT_ENV_VARS
            .iter()
            .map(|name| (*name, std::env::var_os(name)))
            .collect::<Vec<_>>();
        for name in AGENT_ENV_VARS {
            // SAFETY: tests serialize environment mutation with ENV_LOCK.
            unsafe { std::env::remove_var(name) };
        }
        for (name, value) in vars {
            match value {
                Some(value) => {
                    // SAFETY: tests serialize environment mutation with ENV_LOCK.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: tests serialize environment mutation with ENV_LOCK.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }

        f();

        for (name, value) in saved {
            match value {
                Some(value) => {
                    // SAFETY: tests serialize environment mutation with ENV_LOCK.
                    unsafe { std::env::set_var(name, value) };
                }
                None => {
                    // SAFETY: tests serialize environment mutation with ENV_LOCK.
                    unsafe { std::env::remove_var(name) };
                }
            }
        }
    }
}
