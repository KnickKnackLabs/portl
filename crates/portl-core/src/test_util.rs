//! In-process test helpers.
//!
//! Exposes [`pair`], a zero-configuration way to get two live
//! `Endpoint`s wired up for integration tests. Replaces the
//! loopback-crate approach considered during design review —
//! a thin helper here covers every v0.1 test scenario.

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
    let a = Endpoint::bind().await?;
    let b = Endpoint::bind().await?;
    Ok((a, b))
}
