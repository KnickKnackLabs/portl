use std::env::VarError;
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result, anyhow, bail};
use directories::ProjectDirs;
use iroh_base::RelayUrl;
use portl_core::endpoint::Endpoint;
use serde::{Deserialize, Serialize};

use crate::udp_registry::DEFAULT_UDP_SESSION_LINGER_SECS;

const DEFAULT_LISTEN_ADDR: &str = "[::]:0";
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
    "PORTL_MODE",
];

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub identity_path: Option<PathBuf>,
    #[doc(hidden)]
    pub identity_secret: Option<[u8; 32]>,
    pub bind_addr: Option<SocketAddr>,
    pub discovery: DiscoveryConfig,
    pub trust_roots: Vec<[u8; 32]>,
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
}

impl AgentConfig {
    pub fn from_env() -> Result<Self> {
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
        let identity_path = home.join("identity.bin");

        if identity_secret.is_some() && identity_path.exists() {
            bail!(
                "PORTL_IDENTITY_SECRET_HEX is mutually exclusive with an existing {}",
                identity_path.display()
            );
        }

        let trust_roots = env_string("PORTL_TRUST_ROOTS")?
            .map(|value| parse_trust_roots(&value))
            .transpose()?
            .unwrap_or_default();
        if identity_secret.is_some() && trust_roots.is_empty() {
            bail!("PORTL_TRUST_ROOTS is required when PORTL_IDENTITY_SECRET_HEX is set");
        }

        let bind_addr_value =
            env_string("PORTL_LISTEN_ADDR")?.unwrap_or_else(|| DEFAULT_LISTEN_ADDR.to_owned());
        let bind_addr = bind_addr_value.parse().with_context(|| {
            format!("parse PORTL_LISTEN_ADDR as socket address: {bind_addr_value}")
        })?;
        let discovery = env_string("PORTL_DISCOVERY")?
            .map(|value| parse_discovery(&value))
            .transpose()?
            .unwrap_or_default();
        let revocations_path =
            env_path("PORTL_REVOCATIONS_PATH").unwrap_or_else(|| home.join("revocations.jsonl"));
        let rate_limit = env_string("PORTL_RATE_LIMIT")?
            .map(|value| parse_rate_limit(&value))
            .transpose()?
            .unwrap_or_default();
        let revocations_max_bytes = env_string("PORTL_REVOCATIONS_MAX_BYTES")?
            .map(|value| {
                value.parse::<u64>().with_context(|| {
                    format!("parse PORTL_REVOCATIONS_MAX_BYTES as an integer: {value}")
                })
            })
            .transpose()?
            .unwrap_or(crate::revocations::DEFAULT_REVOCATIONS_MAX_BYTES);
        let udp_session_linger_secs = env_string("PORTL_UDP_SESSION_LINGER_SECS")?
            .map(|value| {
                value.parse::<u64>().with_context(|| {
                    format!("parse PORTL_UDP_SESSION_LINGER_SECS as an integer: {value}")
                })
            })
            .transpose()?
            .unwrap_or(DEFAULT_UDP_SESSION_LINGER_SECS);
        let metrics_enabled = env_string("PORTL_METRICS")?
            .map(|value| parse_bool_env("PORTL_METRICS", &value))
            .transpose()?
            .unwrap_or(persistent);
        let mode = env_string("PORTL_MODE")?
            .map(|value| parse_listener_mode(&value))
            .transpose()?
            .unwrap_or(AgentMode::Listener);

        Ok(Self {
            identity_path: persistent.then_some(identity_path),
            identity_secret,
            bind_addr: Some(bind_addr),
            discovery,
            trust_roots,
            revocations_path: Some(revocations_path),
            revocations_max_bytes: Some(revocations_max_bytes),
            rate_limit,
            mode,
            endpoint: None,
            udp_session_linger_secs: Some(udp_session_linger_secs),
            metrics_enabled: Some(metrics_enabled),
            metrics_socket_path: Some(home.join("metrics.sock")),
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
        reqwest::Url::parse(url).with_context(|| format!("parse gateway upstream URL {url}"))?;
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

fn default_home_dir() -> PathBuf {
    ProjectDirs::from("computer", "KnickKnackLabs", "portl")
        .map_or_else(|| PathBuf::from("."), |dirs| dirs.data_dir().to_path_buf())
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
    let default_relay = DiscoveryConfig::default().relay;
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
            "relay" => discovery.relay.clone_from(&default_relay),
            other => bail!("unsupported PORTL_DISCOVERY backend: {other}"),
        }
    }

    if !saw_entry {
        bail!("PORTL_DISCOVERY must not be empty");
    }

    Ok(discovery)
}

fn parse_trust_roots(value: &str) -> Result<Vec<[u8; 32]>> {
    value
        .split(',')
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(parse_trust_root_hex)
        .collect()
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

fn parse_bool_env(name: &str, value: &str) -> Result<bool> {
    match value {
        "1" | "true" | "yes" => Ok(true),
        "0" | "false" | "no" => Ok(false),
        _ => Err(anyhow!("{name} must be one of 0,1,false,true,no,yes")),
    }
}

fn parse_secret_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value)
        .with_context(|| format!("invalid PORTL_IDENTITY_SECRET_HEX hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("PORTL_IDENTITY_SECRET_HEX must decode to exactly 32 bytes: {value}"))
}

fn parse_trust_root_hex(value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value).with_context(|| format!("invalid trust root hex: {value}"))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("trust root must decode to exactly 32 bytes: {value}"))
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;
    use std::sync::{LazyLock, Mutex};

    use tempfile::tempdir;

    use super::{AGENT_ENV_VARS, AgentConfig, AgentMode, DiscoveryConfig, RateLimitConfig};
    use crate::udp_registry::DEFAULT_UDP_SESSION_LINGER_SECS;

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn from_env_parses_defaults_in_empty_env() {
        with_env(&[], || {
            let config = AgentConfig::from_env().expect("parse empty env");
            let home = default_home();

            assert_eq!(config.identity_path, Some(home.join("identity.bin")));
            assert_eq!(
                config.bind_addr,
                Some("[::]:0".parse().expect("default listen addr"))
            );
            assert_eq!(config.discovery, DiscoveryConfig::default());
            assert!(config.trust_roots.is_empty());
            assert_eq!(
                config.revocations_path,
                Some(home.join("revocations.jsonl"))
            );
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
            assert_eq!(config.metrics_socket_path, Some(home.join("metrics.sock")));
        });
    }

    #[test]
    fn from_env_rejects_both_identity_and_home() {
        let home = tempdir().expect("tempdir");
        std::fs::write(home.path().join("identity.bin"), [7_u8; 32]).expect("write identity");

        with_env(
            &[
                ("PORTL_HOME", Some(home.path().as_os_str().to_os_string())),
                (
                    "PORTL_IDENTITY_SECRET_HEX",
                    Some(OsString::from(hex::encode([9_u8; 32]))),
                ),
                (
                    "PORTL_TRUST_ROOTS",
                    Some(OsString::from(hex::encode([3_u8; 32]))),
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
                assert!(config.discovery.relay.is_some());
            },
        );
    }

    #[test]
    fn from_env_requires_trust_roots_in_ephemeral_mode() {
        with_env(
            &[(
                "PORTL_IDENTITY_SECRET_HEX",
                Some(OsString::from(hex::encode([5_u8; 32]))),
            )],
            || {
                let err = AgentConfig::from_env()
                    .expect_err("ephemeral mode without trust roots must fail");
                assert!(
                    err.to_string().contains(
                        "PORTL_TRUST_ROOTS is required when PORTL_IDENTITY_SECRET_HEX is set"
                    ),
                    "unexpected error: {err:#}"
                );
            },
        );
    }

    fn default_home() -> PathBuf {
        directories::ProjectDirs::from("computer", "KnickKnackLabs", "portl")
            .map_or_else(|| PathBuf::from("."), |dirs| dirs.data_dir().to_path_buf())
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
