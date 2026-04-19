use std::net::{IpAddr, Ipv4Addr};

use portl_agent::{OfferRateLimiter, RateLimitConfig};

#[test]
fn keyed_limiter_allows_initial_burst_then_rejects() {
    let limiter = OfferRateLimiter::new(&RateLimitConfig::default()).expect("build limiter");
    let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10));

    let results: Vec<_> = (0..20).map(|_| limiter.check(ip)).collect();

    assert!(results.iter().take(10).all(|allowed| *allowed));
    assert!(results.iter().skip(10).all(|allowed| !allowed));
}
