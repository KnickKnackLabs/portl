//! In-process test helpers.
//!
//! Exposes [`pair`], a zero-configuration way to get two live
//! `Endpoint`s wired up for integration tests. Replaces the
//! loopback-crate approach considered during design review —
//! a thin helper here covers every v0.1 test scenario.

use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use iroh::RelayMode;
use iroh::address_lookup::memory::MemoryLookup;
use iroh::dns::DnsResolver;
use iroh::endpoint::presets;

use crate::endpoint::Endpoint;

fn test_dns_resolver() -> DnsResolver {
    DnsResolver::with_nameserver(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 9)))
}

/// Returns a freshly-bound local-only endpoint.
///
/// Test endpoints use iroh's minimal preset with relay mode disabled and no
/// default DNS/PKARR address lookup. This keeps in-process tests independent of
/// n0 relay/DNS infrastructure and avoids platform DNS setup overhead.
///
/// # Errors
///
/// Returns [`iroh::endpoint::BindError`] if the endpoint fails to bind its
/// local sockets.
pub async fn endpoint() -> Result<Endpoint, iroh::endpoint::BindError> {
    Ok(Endpoint::from(
        iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .dns_resolver(test_dns_resolver())
            .bind()
            .await?,
    ))
}

/// Returns two freshly-bound endpoints wired by an in-memory address lookup.
///
/// Each endpoint is independent, with its own identity and local sockets. They
/// can reach each other via the standard iroh connect / accept flow using only
/// the shared [`MemoryLookup`]; no default DNS, PKARR publication, or relay
/// configuration is installed.
///
/// # Errors
///
/// Returns the first [`iroh::endpoint::BindError`] encountered if either
/// endpoint fails to bind its local sockets.
pub async fn pair() -> Result<(Endpoint, Endpoint), iroh::endpoint::BindError> {
    let lookup = MemoryLookup::with_provenance("test_pair");
    let a = Endpoint::from(
        iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .dns_resolver(test_dns_resolver())
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );
    let b = Endpoint::from(
        iroh::Endpoint::builder(presets::Minimal)
            .relay_mode(RelayMode::Disabled)
            .dns_resolver(test_dns_resolver())
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );

    lookup.add_endpoint_info(a.addr());
    lookup.add_endpoint_info(b.addr());

    Ok((a, b))
}
