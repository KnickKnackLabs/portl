//! `portl.toml` — the single-file config story.
//!
//! Lives at `$PORTL_HOME/portl.toml`. All keys are optional; missing
//! keys fall back to env vars, then compiled defaults. The file
//! itself is optional — a fresh install has no `portl.toml` and
//! runs on compiled defaults alone.
//!
//! ## Precedence (high to low)
//!
//! 1. CLI flags
//! 2. Environment variables (`PORTL_*`)
//! 3. `portl.toml`
//! 4. Compiled defaults
//!
//! ## Schema
//!
//! Top-level `schema = 1` is required on write but tolerated on
//! read (missing → assumed `1`). Future schema bumps will add an
//! explicit migration note.
//!
//! ```toml
//! schema = 1
//!
//! [agent.discovery]
//! dns    = true
//! pkarr  = true
//! local  = true
//! relays = ["default", "https://relay.mynet.com./"]
//!
//! [agent.rate_limit]
//! rps   = 1
//! burst = 10
//!
//! [agent.udp]
//! session_linger_secs = 60
//! ```
//!
//! ## Unknown keys
//!
//! Parser warns-but-does-not-fail on unknown fields (serde
//! `deny_unknown_fields` is *off*). This keeps forward-compat when
//! users write keys that newer portl versions understand.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Current schema version. Bump on breaking changes.
pub const CURRENT_SCHEMA: u32 = 1;

/// Conventional filename under `$PORTL_HOME`.
pub const FILENAME: &str = "portl.toml";

/// Top-level shape of `portl.toml`.
///
/// Each nested struct maps to a TOML section. Every field is
/// optional; unset fields fall through to env-var / compiled
/// defaults.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct PortlConfig {
    /// Schema version. Assumed `1` when missing.
    #[serde(default = "default_schema")]
    pub schema: u32,

    #[serde(default)]
    pub agent: AgentSection,

    /// Reserved for future CLI-side config; present so the parser
    /// doesn't reject a hand-written `[cli]` table.
    #[serde(default)]
    pub cli: CliSection,
}

fn default_schema() -> u32 {
    CURRENT_SCHEMA
}

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AgentSection {
    /// Override `PORTL_LISTEN_ADDR` — socket to bind the QUIC
    /// listener on. Default: `"[::]:0"`.
    pub listen_addr: Option<String>,
    /// Preferred persistent-session provider. v0.4 supports `zmx`.
    pub session_provider: Option<String>,
    /// Absolute path to the provider CLI on the target host.
    pub session_provider_path: Option<PathBuf>,

    #[serde(default)]
    pub discovery: Option<DiscoverySection>,

    #[serde(default)]
    pub rate_limit: Option<RateLimitSection>,

    #[serde(default)]
    pub udp: Option<UdpSection>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DiscoverySection {
    /// Publish + resolve endpoint IDs via n0's DNS service.
    pub dns: Option<bool>,
    /// Publish + resolve endpoint IDs via pkarr.
    pub pkarr: Option<bool>,
    /// Advertise + discover via mDNS on the local network.
    pub local: Option<bool>,
    /// Ordered list of relay entries. Each entry is either:
    ///
    /// - `"default"` — iroh's built-in n0 relay(s)
    /// - `"disabled"` — no relay (overrides any other entry if
    ///   `relays = ["disabled"]` alone; ignored otherwise)
    /// - `<url>` — any parseable `RelayUrl`
    ///
    /// Example: `["default", "https://relay.mynet.com./"]`
    pub relays: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RateLimitSection {
    /// Ticket-accept requests per second (steady state).
    pub rps: Option<u32>,
    /// Burst capacity above `rps`.
    pub burst: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct UdpSection {
    /// Idle seconds before a UDP session is torn down.
    pub session_linger_secs: Option<u64>,
}

/// Reserved CLI-side config section. Empty today.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct CliSection {}

impl PortlConfig {
    /// Load from a path. Missing file returns `Ok(Self::default())`
    /// so callers can treat "no config" identically to "empty
    /// config."
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(text) => {
                Self::parse_toml(&text).with_context(|| format!("parse {}", path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    /// Resolve the conventional path under a given `PORTL_HOME`.
    #[must_use]
    pub fn default_path(home: &Path) -> PathBuf {
        home.join(FILENAME)
    }

    /// Parse from a TOML string. Separate from [`Self::load`] so
    /// tests can exercise the parser without touching disk.
    pub fn parse_toml(text: &str) -> Result<Self> {
        let cfg: Self = toml::from_str(text).context("parse portl.toml")?;
        if cfg.schema != CURRENT_SCHEMA {
            // Forward-compat: log but don't fail on unknown schema.
            // Downgrade semantics: a v0.3.x agent reading a v0.4.x
            // file warns; fields it doesn't understand are ignored.
            tracing::warn!(
                file_schema = cfg.schema,
                supported_schema = CURRENT_SCHEMA,
                "portl.toml schema version mismatch; proceeding with best-effort parse"
            );
        }
        Ok(cfg)
    }

    /// Emit a commented template suitable for piping into
    /// `portl.toml` via `portl config default`.
    #[must_use]
    pub fn default_template() -> &'static str {
        include_str!("config_file_template.toml")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_file_parses_to_defaults() {
        let cfg = PortlConfig::parse_toml("").expect("empty parses");
        assert_eq!(cfg.schema, CURRENT_SCHEMA);
        assert!(cfg.agent.discovery.is_none());
    }

    #[test]
    fn minimal_discovery_section_parses() {
        let text = r#"
schema = 1

[agent.discovery]
relays = ["default", "https://relay.mynet.com./"]
"#;
        let cfg = PortlConfig::parse_toml(text).expect("parse");
        let relays = cfg
            .agent
            .discovery
            .expect("discovery")
            .relays
            .expect("relays");
        assert_eq!(relays.len(), 2);
        assert_eq!(relays[0], "default");
    }

    #[test]
    fn full_example_roundtrips() {
        let text = r#"
schema = 1

[agent]
listen_addr = "[::]:0"

[agent.discovery]
dns    = true
pkarr  = true
local  = true
relays = ["default"]

[agent.rate_limit]
rps   = 2
burst = 20

[agent.udp]
session_linger_secs = 120
"#;
        let cfg = PortlConfig::parse_toml(text).expect("parse");
        assert_eq!(cfg.agent.listen_addr.as_deref(), Some("[::]:0"));
        let rl = cfg.agent.rate_limit.expect("rate_limit");
        assert_eq!(rl.rps, Some(2));
        assert_eq!(rl.burst, Some(20));
        let udp = cfg.agent.udp.expect("udp");
        assert_eq!(udp.session_linger_secs, Some(120));
    }

    #[test]
    fn unknown_section_does_not_fail() {
        // Forward-compat: a v0.3.2 agent reading a future-version
        // config with new sections should not crash.
        let text = r#"
schema = 1

[agent.future_thing]
some_key = "some_value"
"#;
        // serde by default drops unknown fields silently; we just
        // assert it doesn't error.
        PortlConfig::parse_toml(text).expect("forward-compat parse");
    }

    #[test]
    fn default_path_is_portl_home_slash_portl_toml() {
        let home = Path::new("/opt/portl-home");
        assert_eq!(
            PortlConfig::default_path(home),
            PathBuf::from("/opt/portl-home/portl.toml")
        );
    }

    #[test]
    fn load_missing_file_returns_default() {
        let path = Path::new("/does/not/exist/portl.toml");
        let cfg = PortlConfig::load(path).expect("missing = empty");
        assert_eq!(cfg, PortlConfig::default());
    }

    #[test]
    fn syntactically_invalid_toml_errors() {
        let text = "this is not = = valid toml [[";
        assert!(PortlConfig::parse_toml(text).is_err());
    }

    #[test]
    fn default_template_parses() {
        // Every generated template must be loadable with no edits.
        let template = PortlConfig::default_template();
        PortlConfig::parse_toml(template).expect("default template must parse");
    }
}
