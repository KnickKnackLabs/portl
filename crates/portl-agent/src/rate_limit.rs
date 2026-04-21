use std::num::NonZeroU32;

use anyhow::{Context, Result};
use governor::Quota;
use governor::RateLimiter;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;

use crate::config::RateLimitConfig;
use crate::pipeline::RateLimitGate;

#[derive(Debug)]
pub struct OfferRateLimiter {
    inner: RateLimiter<[u8; 32], DashMapStateStore<[u8; 32]>, DefaultClock>,
}

impl OfferRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        let rps = NonZeroU32::new(config.rps).context("rps must be > 0")?;
        let burst = NonZeroU32::new(config.burst).context("burst must be > 0")?;
        let quota = Quota::per_second(rps).allow_burst(burst);
        Ok(Self {
            inner: RateLimiter::keyed(quota),
        })
    }

    #[must_use]
    pub fn check(&self, source_id: [u8; 32]) -> bool {
        self.inner.check_key(&source_id).is_ok()
    }
}

impl RateLimitGate for OfferRateLimiter {
    fn check(&self, source_id: [u8; 32]) -> bool {
        self.check(source_id)
    }
}
