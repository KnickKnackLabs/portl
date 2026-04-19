use std::time::Duration;

use anyhow::{Context, Result, bail};
use iroh::address_lookup::AddressLookupFailed;
use n0_future::StreamExt;
use portl_agent::{AgentConfig, DiscoveryConfig};
use portl_core::id::Identity;

#[tokio::test]
#[ignore = "mDNS on localhost can be flaky in CI"]
async fn local_discovery_resolves_endpoint_id_over_mdns() -> Result<()> {
    let discovery = DiscoveryConfig {
        dns: false,
        pkarr: false,
        local: true,
        relay: None,
    };
    let cfg = AgentConfig {
        bind_addr: Some("127.0.0.1:0".parse().expect("bind addr")),
        discovery,
        ..AgentConfig::default()
    };

    let first = portl_agent::endpoint::bind(&cfg, &Identity::new())
        .await
        .context("bind first endpoint")?;
    let second = portl_agent::endpoint::bind(&cfg, &Identity::new())
        .await
        .context("bind second endpoint")?;

    let lookup = second.address_lookup().context("access address lookup")?;
    let mut stream = lookup.resolve(first.id());
    let resolved = tokio::time::timeout(Duration::from_secs(10), async move {
        while let Some(item) = stream.next().await {
            match item {
                Ok(Ok(item)) => return Ok(item.into_endpoint_addr()),
                Ok(Err(_)) | Err(AddressLookupFailed::NoResults { .. }) => {}
                Err(err) => return Err(anyhow::Error::from(err)),
            }
        }
        bail!("discovery returned no addresses")
    })
    .await
    .context("timed out waiting for local discovery")??;

    assert_eq!(resolved.id, first.id());

    first.close().await;
    second.close().await;
    Ok(())
}
