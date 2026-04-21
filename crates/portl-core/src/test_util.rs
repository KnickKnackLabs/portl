//! In-process test helpers.
//!
//! Exposes [`pair`], a zero-configuration way to get two live
//! `Endpoint`s wired up for integration tests. Replaces the
//! loopback-crate approach considered during design review —
//! a thin helper here covers every v0.1 test scenario.

use iroh::address_lookup::memory::MemoryLookup;
use iroh::endpoint::presets;

use crate::endpoint::Endpoint;

/// Returns two freshly-bound endpoints.
///
/// Each endpoint is an independent [`iroh::Endpoint`] bound with
/// portl's default preset, with its own identity and sockets.
/// They can reach each other via the standard iroh connect / accept
/// flow using the counterpart's [`iroh::endpoint::EndpointAddr`].
///
/// # Errors
///
/// Returns the first [`iroh::endpoint::BindError`] encountered if
/// either endpoint fails to bind its sockets.
pub async fn pair() -> Result<(Endpoint, Endpoint), iroh::endpoint::BindError> {
    let lookup = MemoryLookup::with_provenance("test_pair");
    let a = Endpoint::from(
        iroh::Endpoint::builder(presets::N0)
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );
    let b = Endpoint::from(
        iroh::Endpoint::builder(presets::N0)
            .address_lookup(lookup.clone())
            .bind()
            .await?,
    );

    lookup.add_endpoint_info(a.addr());
    lookup.add_endpoint_info(b.addr());

    Ok((a, b))
}
