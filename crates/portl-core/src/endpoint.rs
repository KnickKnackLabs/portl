//! Thin newtype over [`iroh::Endpoint`].
//!
//! Downstream crates depend on a portl-owned type so that
//! (a) portl-specific configuration (ALPN registration,
//! discovery defaults, ticket hooks) has a stable home as it
//! lands across M2+, and (b) iroh's version isn't exposed at the
//! portl-core API boundary. For M0 the wrapper is intentionally
//! thin — construction delegates to iroh's default preset and
//! accessors pass through.

use iroh::EndpointId;
use iroh::endpoint::presets;
use iroh_base::EndpointAddr;

/// A portl endpoint. Thin newtype over [`iroh::Endpoint`].
#[derive(Debug, Clone)]
pub struct Endpoint(iroh::Endpoint);

impl From<iroh::Endpoint> for Endpoint {
    fn from(value: iroh::Endpoint) -> Self {
        Self(value)
    }
}

impl Endpoint {
    /// Bind a new endpoint using portl's default preset.
    ///
    /// Delegates to [`iroh::Endpoint::bind`] with the `N0` preset
    /// (n0-operated relays + DNS discovery). Future milestones
    /// will swap in a portl-specific preset that adds Local/mDNS
    /// discovery; callers are expected to use this method rather
    /// than building iroh endpoints directly.
    pub async fn bind() -> Result<Self, iroh::endpoint::BindError> {
        let inner = iroh::Endpoint::bind(presets::N0).await?;
        Ok(Self(inner))
    }

    /// Returns this endpoint's [`EndpointId`].
    pub fn id(&self) -> EndpointId {
        self.0.id()
    }

    /// Returns this endpoint's currently observed [`EndpointAddr`].
    pub fn addr(&self) -> EndpointAddr {
        self.0.addr()
    }

    /// Borrow the inner [`iroh::Endpoint`].
    ///
    /// Escape hatch for callers that need iroh APIs which aren't
    /// yet wrapped by portl-core (e.g. `connect`, `accept`). As
    /// the wrapper grows, direct use of `inner()` should shrink.
    pub fn inner(&self) -> &iroh::Endpoint {
        &self.0
    }
}
