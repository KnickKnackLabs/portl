//! In-process test helpers.
//!
//! Exposes [`pair`], a zero-configuration way to get two live
//! `Endpoint`s wired up for integration tests. Replaces the
//! loopback-crate approach considered during design review —
//! a thin helper here covers every v0.1 test scenario.
//!
//! # Preset choice
//!
//! Uses [`presets::Minimal`] rather than [`presets::N0`]. `Minimal`
//! sets only the mandatory `crypto_provider`; it does **not** add the
//! n0 `PkarrPublisher` / `DnsAddressLookup` services or enable the n0
//! relay servers. Combined with [`iroh::endpoint::Builder::empty`]'s
//! default `RelayMode::Disabled`, this keeps integration tests fully
//! on loopback — no TLS handshakes to `*.relay.n0.iroh-canary.iroh.link`,
//! no DNS lookups, no network-flake surface. Peers reach each other
//! exclusively through the shared `MemoryLookup` populated below.

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;

use crate::endpoint::Endpoint;

/// Returns two freshly-bound endpoints.
///
/// Each endpoint is an independent [`iroh::Endpoint`] bound with the
/// [`presets::Minimal`] preset (crypto provider only, no relay, no
/// pkarr/DNS lookup) and a shared [`MemoryLookup`] registry. They can
/// reach each other via the standard iroh connect / accept flow using
/// the counterpart's [`iroh::endpoint::EndpointAddr`].
///
/// # Errors
///
/// Returns the first [`iroh::endpoint::BindError`] encountered if
/// either endpoint fails to bind its sockets.
pub async fn pair() -> Result<(Endpoint, Endpoint), iroh::endpoint::BindError> {
    let lookup = MemoryLookup::with_provenance("test_pair");
    let a = Endpoint::from(
        iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );
    let b = Endpoint::from(
        iroh::Endpoint::builder(presets::Minimal)
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );

    lookup.add_endpoint_info(a.addr());
    lookup.add_endpoint_info(b.addr());

    Ok((a, b))
}
