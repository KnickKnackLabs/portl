use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use anyhow::Result;
use iroh::address_lookup::{DnsAddressLookup, PkarrPublisher, PkarrResolver};
use iroh::dns::DnsResolver;
use iroh::endpoint::{RelayMode, presets};
use iroh_base::SecretKey;
use portl_core::id::Identity;
use tracing::instrument;

use crate::config::AgentConfig;

fn local_only_dns_resolver() -> DnsResolver {
    DnsResolver::with_nameserver(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)))
}

#[instrument(skip_all)]
pub async fn bind(cfg: &AgentConfig, identity: &Identity) -> Result<iroh::Endpoint> {
    let mut builder = iroh::Endpoint::builder(presets::Minimal)
        .secret_key(SecretKey::from_bytes(&identity.signing_key().to_bytes()))
        .transport_config(portl_core::endpoint::transport_config())
        .alpns(vec![
            portl_proto::ticket_v1::ALPN_TICKET_V1.to_vec(),
            portl_proto::pair_v1::ALPN_PAIR_V1.to_vec(),
        ]);

    builder = if cfg.discovery.relays.is_empty() {
        builder.relay_mode(RelayMode::Disabled)
    } else {
        builder.relay_mode(RelayMode::custom(cfg.discovery.relays.iter().cloned()))
    };
    builder = portl_core::proxy::configure_endpoint(builder, &cfg.discovery.relays);

    if cfg.discovery.relays.is_empty()
        && cfg.discovery.dns.is_empty()
        && cfg.discovery.pkarr.is_empty()
    {
        builder = builder.dns_resolver(local_only_dns_resolver());
    }

    for url in &cfg.discovery.pkarr {
        builder = builder
            .address_lookup(PkarrPublisher::builder(url.clone()))
            .address_lookup(PkarrResolver::builder(url.clone()));
    }
    for origin in &cfg.discovery.dns {
        let mut lookup = DnsAddressLookup::builder(origin.origin.clone());
        if let Some(nameserver) = origin.nameserver {
            lookup = lookup.dns_resolver(DnsResolver::with_nameserver(nameserver));
        }
        builder = builder.address_lookup(lookup);
    }
    if cfg.discovery.local {
        builder = builder.address_lookup(crate::mdns::ScopedMdns {
            policy: cfg.discovery.local_policy.clone(),
            advertise: true,
            status: cfg.mdns_status.clone(),
        });
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
    async fn bind_dns_queries_each_origin_using_its_selected_nameserver() {
        use futures_util::StreamExt as _;
        use tokio::net::UdpSocket;

        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let cfg = AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            discovery: DiscoveryConfig {
                dns: vec![
                    crate::DnsOrigin {
                        origin: "first.example".into(),
                        nameserver: Some(first.local_addr().unwrap()),
                    },
                    crate::DnsOrigin {
                        origin: "second.example".into(),
                        nameserver: Some(second.local_addr().unwrap()),
                    },
                ],
                ..DiscoveryConfig::in_process()
            },
            ..AgentConfig::default()
        };
        let endpoint = bind(&cfg, &Identity::new()).await.unwrap();
        let lookups = endpoint.address_lookup().unwrap();
        let stream = lookups.resolve(iroh_base::SecretKey::generate().public());
        tokio::pin!(stream);
        let receive_queries = async {
            let mut first_query = [0; 512];
            let mut second_query = [0; 512];
            let (first_result, second_result) = tokio::join!(
                first.recv_from(&mut first_query),
                second.recv_from(&mut second_query),
            );
            let (len, _) = first_result.unwrap();
            assert!(
                first_query[..len]
                    .windows(15)
                    .any(|w| w == b"\x05first\x07example\0")
            );
            let (len, _) = second_result.unwrap();
            assert!(
                second_query[..len]
                    .windows(16)
                    .any(|w| w == b"\x06second\x07example\0")
            );
        };
        tokio::select! {
            result = tokio::time::timeout(std::time::Duration::from_secs(5), receive_queries) => result.expect("both custom nameservers receive TXT queries"),
            result = stream.next() => panic!("lookup ended before sending queries: {result:?}"),
        }
        endpoint.close().await;
    }

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

    #[tokio::test]
    async fn bind_publishes_and_resolves_signed_records_at_every_custom_endpoint() {
        use futures_util::StreamExt as _;
        use iroh::address_lookup::EndpointInfo;
        use std::time::Duration;
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("PUT"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let cfg = AgentConfig {
            bind_addr: Some("127.0.0.1:0".parse().unwrap()),
            discovery: DiscoveryConfig {
                pkarr: ["first", "second"]
                    .iter()
                    .map(|prefix| format!("{}/{prefix}", server.uri()).parse().unwrap())
                    .collect(),
                ..DiscoveryConfig::in_process()
            },
            ..AgentConfig::default()
        };
        let endpoint = bind(&cfg, &Identity::new()).await.unwrap();
        let paths =
            ["first", "second"].map(|prefix| format!("/{prefix}/{}", endpoint.id().to_z32()));
        let packets = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let requests = server.received_requests().await.unwrap();
                let packets: Vec<_> = paths
                    .iter()
                    .filter_map(|path| {
                        requests
                            .iter()
                            .find(|request| request.method == "PUT" && request.url.path() == path)
                            .map(|request| request.body.clone())
                    })
                    .collect();
                if packets.len() == 2 {
                    break packets;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("both custom pkarr URLs receive signed PUTs");
        for (url_path, packet) in paths.iter().zip(packets) {
            assert!(!packet.is_empty());
            Mock::given(method("GET"))
                .and(path(url_path))
                .respond_with(ResponseTemplate::new(200).set_body_bytes(packet))
                .expect(1)
                .mount(&server)
                .await;
        }
        let lookups = endpoint.address_lookup().unwrap();
        let stream = lookups.resolve(endpoint.id());
        tokio::pin!(stream);
        for _ in 0..2 {
            let item = tokio::time::timeout(Duration::from_secs(5), stream.next())
                .await
                .unwrap()
                .unwrap()
                .unwrap()
                .unwrap();
            // With relays disabled the default publisher filter strips IPs.
            // Successful decoding verifies each HTTP response's signature/key.
            assert_eq!(item.endpoint_info(), &EndpointInfo::new(endpoint.id()));
        }
        endpoint.close().await;
        server.verify().await;
    }
}
