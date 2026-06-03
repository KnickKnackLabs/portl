use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::{Context, Result};
use iroh::address_lookup::{DnsAddressLookup, PkarrResolver};
use iroh::dns::DnsResolver;
use iroh::endpoint::{RelayMode, presets};
use iroh_base::SecretKey;
use iroh_mdns_address_lookup::MdnsAddressLookup;
use portl_core::id::Identity;

pub(crate) fn load_client_config() -> Result<portl_agent::AgentConfig> {
    let mut cfg = portl_agent::AgentConfig::from_env().context("load client discovery config")?;
    // CLI client dials should honor discovery config but must not
    // inherit the daemon's fixed listen address; otherwise a local
    // client can collide with the running agent's socket bind.
    cfg.bind_addr = None;
    cfg.endpoint = None;
    cfg.relay_server = None;
    Ok(cfg)
}

fn local_only_dns_resolver() -> DnsResolver {
    DnsResolver::with_nameserver(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)))
}

pub(crate) async fn bind_client_endpoint(identity: &Identity) -> Result<iroh::Endpoint> {
    let cfg = load_client_config()?;
    bind_client_endpoint_with_config(identity, &cfg).await
}

pub(crate) async fn bind_client_endpoint_with_config(
    _identity: &Identity,
    cfg: &portl_agent::AgentConfig,
) -> Result<iroh::Endpoint> {
    tracing::debug!(
        dns = cfg.discovery.dns,
        pkarr = cfg.discovery.pkarr,
        local = cfg.discovery.local,
        relays = cfg.discovery.relays.len(),
        "binding CLI client endpoint"
    );
    let mut builder = iroh::Endpoint::builder(presets::Minimal).secret_key(SecretKey::generate());

    builder = if cfg.discovery.relays.is_empty() {
        builder.relay_mode(RelayMode::Disabled)
    } else {
        builder.relay_mode(RelayMode::custom(cfg.discovery.relays.iter().cloned()))
    };

    if cfg.discovery.relays.is_empty() && !cfg.discovery.dns && !cfg.discovery.pkarr {
        builder = builder.dns_resolver(local_only_dns_resolver());
    }

    if cfg.discovery.pkarr {
        builder = builder.address_lookup(PkarrResolver::n0_dns());
    }
    if cfg.discovery.dns {
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    }
    if cfg.discovery.local {
        builder = builder.address_lookup(MdnsAddressLookup::builder().advertise(false));
    }
    if let Some(bind_addr) = cfg.bind_addr {
        builder = builder.bind_addr(bind_addr)?;
    }

    builder.bind().await.context("bind client endpoint")
}

pub(crate) async fn bind_pairing_client_endpoint_with_config(
    identity: &Identity,
    cfg: &portl_agent::AgentConfig,
) -> Result<iroh::Endpoint> {
    tracing::debug!(
        dns = cfg.discovery.dns,
        pkarr = cfg.discovery.pkarr,
        local = cfg.discovery.local,
        relays = cfg.discovery.relays.len(),
        "binding CLI pairing endpoint"
    );
    // Pairing v1 identifies the acceptor by the Iroh transport identity
    // observed by the inviter. Keep pairing on the stable machine key until
    // a future pair protocol carries a separately signed stable identity.
    portl_agent::endpoint::bind(cfg, identity)
        .await
        .context("bind pairing client endpoint")
}

pub(crate) fn preferred_relay_hint(cfg: &portl_agent::AgentConfig) -> Option<String> {
    cfg.discovery.relays.first().map(ToString::to_string)
}

#[cfg(test)]
#[allow(unsafe_code)]
mod tests {
    use std::ffi::OsString;
    use std::sync::{LazyLock, Mutex};

    static ENV_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

    #[test]
    fn load_client_config_honors_portl_discovery_env() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old = std::env::var_os("PORTL_DISCOVERY");
        unsafe { std::env::set_var("PORTL_DISCOVERY", "none") };

        let cfg = super::load_client_config().expect("load client config");

        assert!(!cfg.discovery.dns);
        assert!(!cfg.discovery.pkarr);
        assert!(!cfg.discovery.local);
        assert!(cfg.discovery.relays.is_empty());
        restore_env("PORTL_DISCOVERY", old);
    }

    #[test]
    fn load_client_config_ignores_agent_listen_addr() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let old = std::env::var_os("PORTL_LISTEN_ADDR");
        unsafe { std::env::set_var("PORTL_LISTEN_ADDR", "127.0.0.1:7") };

        let cfg = super::load_client_config().expect("load client config");

        assert_eq!(cfg.bind_addr, None);
        restore_env("PORTL_LISTEN_ADDR", old);
    }

    #[tokio::test]
    async fn bind_client_endpoint_with_config_uses_ephemeral_transport_identity() {
        let identity = portl_core::id::Identity::new();
        let cfg = portl_agent::AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("bind addr")),
            discovery: portl_agent::DiscoveryConfig::in_process(),
            ..portl_agent::AgentConfig::default()
        };

        let endpoint = super::bind_client_endpoint_with_config(&identity, &cfg)
            .await
            .expect("bind CLI endpoint");

        assert_ne!(endpoint.id().as_bytes(), &identity.verifying_key());
        if tokio::time::timeout(std::time::Duration::from_millis(500), endpoint.close())
            .await
            .is_err()
        {
            std::mem::forget(endpoint);
        }
    }

    #[tokio::test]
    async fn bind_pairing_client_endpoint_with_config_uses_stable_transport_identity() {
        let identity = portl_core::id::Identity::new();
        let cfg = portl_agent::AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("bind addr")),
            discovery: portl_agent::DiscoveryConfig::in_process(),
            ..portl_agent::AgentConfig::default()
        };

        let endpoint = super::bind_pairing_client_endpoint_with_config(&identity, &cfg)
            .await
            .expect("bind pairing endpoint");

        assert_eq!(endpoint.id().as_bytes(), &identity.verifying_key());
        if tokio::time::timeout(std::time::Duration::from_millis(500), endpoint.close())
            .await
            .is_err()
        {
            std::mem::forget(endpoint);
        }
    }

    fn restore_env(name: &str, value: Option<OsString>) {
        unsafe {
            if let Some(value) = value {
                std::env::set_var(name, value);
            } else {
                std::env::remove_var(name);
            }
        }
    }
}
