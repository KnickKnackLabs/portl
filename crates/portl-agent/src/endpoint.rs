use anyhow::Result;
use iroh::address_lookup::{DnsAddressLookup, MdnsAddressLookup, PkarrPublisher};
use iroh::endpoint::{RelayMode, presets};
use iroh_base::SecretKey;
use portl_core::id::Identity;
use tracing::instrument;

use crate::config::AgentConfig;

#[instrument(skip_all)]
pub async fn bind(cfg: &AgentConfig, identity: &Identity) -> Result<iroh::Endpoint> {
    let mut builder = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.signing_key().to_bytes()))
        .alpns(vec![portl_proto::ticket_v1::ALPN_TICKET_V1.to_vec()]);

    builder = match &cfg.discovery.relay {
        Some(relay) => builder.relay_mode(RelayMode::custom([relay.clone()])),
        None => builder.relay_mode(RelayMode::Disabled),
    };

    if cfg.discovery.pkarr {
        builder = builder.address_lookup(PkarrPublisher::n0_dns());
    }
    if cfg.discovery.dns {
        builder = builder.address_lookup(DnsAddressLookup::n0_dns());
    }
    if cfg.discovery.local {
        builder = builder.address_lookup(MdnsAddressLookup::builder());
    }
    if let Some(bind_addr) = cfg.bind_addr {
        builder = builder.bind_addr(bind_addr)?;
    }

    builder.bind().await.map_err(Into::into)
}

#[cfg(test)]
mod tests {
    use portl_core::id::Identity;

    use super::bind;
    use crate::config::{AgentConfig, DiscoveryConfig};

    #[tokio::test]
    async fn bind_uses_identity_key_and_can_disable_discovery() {
        let identity = Identity::new();
        let cfg = AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().expect("bind addr")),
            discovery: DiscoveryConfig::in_process(),
            ..AgentConfig::default()
        };

        let endpoint = bind(&cfg, &identity).await.expect("bind endpoint");

        assert_eq!(endpoint.id().as_bytes(), &identity.verifying_key());
        assert!(
            endpoint
                .address_lookup()
                .expect("address lookup")
                .is_empty()
        );
        endpoint.close().await;
    }
}
