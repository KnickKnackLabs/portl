//! Integration tests for `portl_core::test_util::pair`.
//!
//! The helper exists so downstream crates can get two live
//! endpoints in-process with zero boilerplate. The test proves
//! two things M0 promised: distinct identities, and real
//! bidirectional QUIC connectivity (no stubs).

use portl_core::test_util::pair;

const TEST_ALPN: &[u8] = b"portl/test-util-pair/v1";

#[tokio::test]
async fn pair_returns_two_distinct_endpoints() {
    let (a, b) = pair().await.expect("pair bind");
    assert_ne!(
        a.id(),
        b.id(),
        "pair() must return endpoints with distinct ids"
    );
}

#[tokio::test]
async fn pair_endpoints_can_connect_to_each_other() {
    let (a, b) = pair().await.expect("pair bind");

    // Register the test ALPN on `b` so it accepts connections.
    b.inner().set_alpns(vec![TEST_ALPN.to_vec()]);

    let b_addr = b.addr();

    // Spawn the acceptor before dialing.
    let accept_task = tokio::spawn({
        let b = b.clone();
        async move {
            let incoming = b
                .inner()
                .accept()
                .await
                .expect("accept should yield an incoming connection");
            let conn = incoming.await.expect("handshake");
            conn.close(0u32.into(), b"bye");
        }
    });

    // Dial from `a` to `b`.
    let conn = a
        .inner()
        .connect(b_addr, TEST_ALPN)
        .await
        .expect("connect should succeed between pair() endpoints");

    conn.close(0u32.into(), b"bye");

    // Wait for the acceptor to finish so we don't race shutdown.
    tokio::time::timeout(std::time::Duration::from_secs(5), accept_task)
        .await
        .expect("accept task did not complete in 5s")
        .expect("accept task panicked");
}
