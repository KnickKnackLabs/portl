use anyhow::{Context, Result};
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

pub(crate) async fn bind_client_endpoint(identity: &Identity) -> Result<iroh::Endpoint> {
    let cfg = load_client_config()?;
    bind_client_endpoint_with_config(identity, &cfg).await
}

pub(crate) async fn bind_client_endpoint_with_config(
    identity: &Identity,
    cfg: &portl_agent::AgentConfig,
) -> Result<iroh::Endpoint> {
    tracing::debug!(
        dns = cfg.discovery.dns,
        pkarr = cfg.discovery.pkarr,
        local = cfg.discovery.local,
        relays = cfg.discovery.relays.len(),
        "binding CLI client endpoint"
    );
    portl_agent::endpoint::bind(cfg, identity)
        .await
        .context("bind client endpoint")
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
