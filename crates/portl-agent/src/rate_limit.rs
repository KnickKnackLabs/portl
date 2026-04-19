use std::net::IpAddr;
use std::num::NonZeroU32;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use governor::Quota;
use governor::RateLimiter;
use governor::clock::DefaultClock;
use governor::state::keyed::DashMapStateStore;

use crate::config::RateLimitConfig;
use crate::pipeline::RateLimitGate;

#[derive(Debug)]
pub struct OfferRateLimiter {
    inner: RateLimiter<IpAddr, DashMapStateStore<IpAddr>, DefaultClock>,
}

impl OfferRateLimiter {
    pub fn new(config: &RateLimitConfig) -> Result<Self> {
        ensure!(config.replenish_secs > 0, "replenish_secs must be > 0");
        let burst = NonZeroU32::new(config.burst).context("burst must be > 0")?;
        let quota = Quota::with_period(Duration::from_secs(config.replenish_secs))
            .context("invalid replenish period")?
            .allow_burst(burst);
        Ok(Self {
            inner: RateLimiter::keyed(quota),
        })
    }

    #[must_use]
    pub fn check(&self, source_ip: IpAddr) -> bool {
        self.inner.check_key(&source_ip).is_ok()
    }
}

impl RateLimitGate for OfferRateLimiter {
    fn check(&self, source_ip: IpAddr) -> bool {
        self.check(source_ip)
    }
}
