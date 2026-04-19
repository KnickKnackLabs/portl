use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow};
use iroh_base::RelayUrl;
use portl_core::endpoint::Endpoint;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub identity_path: Option<PathBuf>,
    pub bind_addr: Option<SocketAddr>,
    pub discovery: DiscoveryConfig,
    pub trust_roots: Vec<[u8; 32]>,
    pub revocations_path: Option<PathBuf>,
    pub rate_limit: RateLimitConfig,
    pub mode: AgentMode,
    #[doc(hidden)]
    pub endpoint: Option<Endpoint>,
}

impl AgentConfig {
    pub fn from_toml_path(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("read agent config {}", path.display()))?;
        Self::from_toml_str(&contents)
            .with_context(|| format!("parse agent config {}", path.display()))
    }

    pub fn from_toml_str(contents: &str) -> Result<Self> {
        let file: AgentConfigFile = toml::from_str(contents).context("decode agent config TOML")?;
        let trust_roots = file
            .trust_roots
            .unwrap_or_default()
            .into_iter()
            .map(|value| parse_trust_root_hex(&value))
            .collect::<Result<Vec<_>>>()?;

        let mut config = Self {
            identity_path: file.identity_path,
            bind_addr: file.bind_addr,
            discovery: DiscoveryConfig::default(),
            trust_roots,
            revocations_path: file.revocations_path,
            rate_limit: RateLimitConfig::default(),
            mode: AgentMode::Listener,
            endpoint: None,
        };

        if let Some(discovery) = file.discovery {
            if let Some(dns) = discovery.dns {
                config.discovery.dns = dns;
            }
            if let Some(pkarr) = discovery.pkarr {
                config.discovery.pkarr = pkarr;
            }
            if let Some(local) = discovery.local {
                config.discovery.local = local;
            }
            if let Some(relay) = discovery.relay {
                config.discovery.relay = Some(relay);
            }
        }

        if let Some(rate_limit) = file.rate_limit {
            if let Some(period_secs) = rate_limit.period_secs {
                config.rate_limit.replenish_secs = period_secs;
            }
            if let Some(burst) = rate_limit.burst {
                config.rate_limit.burst = burst;
            }
        }

        if let Some(mode) = file.mode.as_deref() {
            config.mode = parse_mode(
                mode,
                file.upstream_url.as_deref(),
                file.upstream_host.as_deref(),
                file.upstream_port,
            )?;
        }

        Ok(config)
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
    pub relay: Option<RelayUrl>,
}

impl DiscoveryConfig {
    #[must_use]
    pub fn in_process() -> Self {
        Self {
            dns: false,
            pkarr: false,
            local: false,
            relay: None,
        }
    }
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        let relay = iroh::endpoint::default_relay_mode()
            .relay_map()
            .urls::<Vec<_>>()
            .into_iter()
            .next();
        Self {
            dns: true,
            pkarr: true,
            local: true,
            relay,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimitConfig {
    pub replenish_secs: u64,
    pub burst: u32,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            replenish_secs: 5,
            burst: 10,
        }
    }
}

#[derive(Debug, Deserialize)]
struct AgentConfigFile {
    identity_path: Option<PathBuf>,
    bind_addr: Option<SocketAddr>,
    revocations_path: Option<PathBuf>,
    trust_roots: Option<Vec<String>>,
    discovery: Option<DiscoveryConfigFile>,
    rate_limit: Option<RateLimitConfigFile>,
    mode: Option<String>,
    upstream_url: Option<String>,
    upstream_host: Option<String>,
    upstream_port: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct DiscoveryConfigFile {
    dns: Option<bool>,
    pkarr: Option<bool>,
    local: Option<bool>,
    relay: Option<RelayUrl>,
}

#[derive(Debug, Deserialize)]
struct RateLimitConfigFile {
    period_secs: Option<u64>,
    burst: Option<u32>,
}

fn parse_mode(
    mode: &str,
    upstream_url: Option<&str>,
    upstream_host: Option<&str>,
    upstream_port: Option<u16>,
) -> Result<AgentMode> {
    match mode {
        "listener" => Ok(AgentMode::Listener),
        "gateway" => {
            let url = upstream_url.context("gateway mode requires upstream_url")?;
            let parsed = reqwest::Url::parse(url)
                .with_context(|| format!("parse gateway upstream_url {url}"))?;
            let host = upstream_host
                .map(ToOwned::to_owned)
                .or_else(|| parsed.host_str().map(ToOwned::to_owned))
                .context("gateway mode requires an upstream host")?;
            let port = upstream_port
                .or_else(|| parsed.port_or_known_default())
                .context("gateway mode requires an upstream port")?;
            Ok(AgentMode::Gateway {
                upstream_url: url.to_owned(),
                upstream_host: host,
                upstream_port: port,
            })
        }
        other => Err(anyhow!("unsupported agent mode: {other}")),
    }
}

fn parse_trust_root_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid trust root hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("trust root must decode to exactly 32 bytes: {value}"))
}
