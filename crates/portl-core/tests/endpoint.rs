//! Integration tests for `portl_core::endpoint::Endpoint`.
//!
//! Verifies the thin newtype wrapper over `iroh::Endpoint` exposes the minimal
//! accessor surface required by downstream crates in M0. These tests use the
//! local-only test endpoint helper so they don't depend on real DNS/relay setup.

use portl_core::test_util;

#[tokio::test]
async fn local_endpoint_has_stable_id() {
    let endpoint = test_util::endpoint().await.expect("bind should succeed");
    // Two calls to `.id()` on the same endpoint must return the
    // same value — the identity is fixed at bind time.
    let id1 = endpoint.id();
    let id2 = endpoint.id();
    assert_eq!(id1, id2, "endpoint id must be stable across calls");
}

#[tokio::test]
async fn local_endpoints_have_distinct_identities() {
    let a = test_util::endpoint().await.expect("first bind");
    let b = test_util::endpoint().await.expect("second bind");
    assert_ne!(
        a.id(),
        b.id(),
        "two independently-bound endpoints must have distinct ids"
    );
}

#[tokio::test]
async fn addr_reports_same_id_as_endpoint() {
    let endpoint = test_util::endpoint().await.expect("bind");
    let addr = endpoint.addr();
    assert_eq!(addr.id, endpoint.id(), "addr().id must match endpoint.id()");
}

#[tokio::test]
async fn inner_exposes_underlying_iroh_endpoint() {
    let endpoint = test_util::endpoint().await.expect("bind");
    let iroh_ep: &iroh::Endpoint = endpoint.inner();
    assert_eq!(
        iroh_ep.id(),
        endpoint.id(),
        "inner().id() must match wrapper id()"
    );
}
