use portl_agent::{OfferRateLimiter, RateLimitConfig};

#[test]
fn keyed_limiter_allows_initial_burst_then_rejects() {
    let limiter = OfferRateLimiter::new(&RateLimitConfig::default()).expect("build limiter");
    let node_id = [9; 32];

    let results: Vec<_> = (0..20).map(|_| limiter.check(node_id)).collect();

    assert!(results.iter().take(10).all(|allowed| *allowed));
    assert!(results.iter().skip(10).all(|allowed| !allowed));
}
