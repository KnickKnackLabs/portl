use std::net::SocketAddr;
use std::path::PathBuf;

use iroh_base::RelayUrl;
use portl_core::endpoint::Endpoint;

#[derive(Debug, Clone, Default)]
pub struct AgentConfig {
    pub identity_path: Option<PathBuf>,
    pub bind_addr: Option<SocketAddr>,
    pub discovery: DiscoveryConfig,
    pub trust_roots: Vec<[u8; 32]>,
    pub revocations_path: Option<PathBuf>,
    pub rate_limit: RateLimitConfig,
    #[doc(hidden)]
    pub endpoint: Option<Endpoint>,
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
