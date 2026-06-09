use std::time::{Duration, Instant};

use criterion::{Criterion, criterion_group, criterion_main};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use portl_core::endpoint::Endpoint;

const TEST_ALPN: &[u8] = b"portl/bench/stream-priority-latency/v1";
const LOW_PRIORITY: i32 = -20;
const HIGH_PRIORITY: i32 = 30;
const LOW_BYTES: usize = 2 * 1024 * 1024;

struct BenchPair {
    client_endpoint: Endpoint,
    server_endpoint: Endpoint,
    client_conn: Connection,
    server_conn: Connection,
}

async fn connected_pair() -> BenchPair {
    let (client, server) = portl_core::test_util::pair()
        .await
        .expect("bind in-process endpoints");
    server.inner().set_alpns(vec![TEST_ALPN.to_vec()]);
    let server_addr = server.addr();
    let accept_server = server.clone();
    let accept = tokio::spawn(async move {
        let incoming = accept_server
            .inner()
            .accept()
            .await
            .expect("accept incoming benchmark connection");
        incoming.await.expect("complete benchmark handshake")
    });
    let client_conn = client
        .inner()
        .connect(server_addr, TEST_ALPN)
        .await
        .expect("connect benchmark endpoints");
    let server_conn = accept.await.expect("join benchmark accept task");
    BenchPair {
        client_endpoint: client,
        server_endpoint: server,
        client_conn,
        server_conn,
    }
}

async fn drain_low_stream(mut recv: RecvStream) {
    let mut buf = vec![0_u8; 16 * 1024];
    while recv.read(&mut buf).await.ok().flatten().is_some() {}
}

async fn read_high_marker(mut recv: RecvStream) -> Instant {
    let mut marker = [0_u8; 1];
    recv.read_exact(&mut marker)
        .await
        .expect("read high-priority marker");
    assert_eq!(marker, [b'H']);
    Instant::now()
}

async fn accept_until_high_marker(server_conn: Connection) -> Instant {
    loop {
        let (_send, mut recv) = server_conn.accept_bi().await.expect("accept stream");
        let mut tag = [0_u8; 1];
        recv.read_exact(&mut tag).await.expect("read stream tag");
        match tag[0] {
            b'L' => tokio::spawn(drain_low_stream(recv)),
            b'H' => return read_high_marker(recv).await,
            other => panic!("unexpected benchmark stream tag {other}"),
        };
    }
}

async fn write_low_flood(mut send: SendStream) {
    send.set_priority(LOW_PRIORITY)
        .expect("set low stream priority");
    if send.write_all(b"L").await.is_err() {
        return;
    }
    let chunk = vec![0_u8; 16 * 1024];
    let mut remaining = LOW_BYTES;
    while remaining > 0 {
        let take = remaining.min(chunk.len());
        if send.write_all(&chunk[..take]).await.is_err() {
            return;
        }
        remaining -= take;
    }
    let _ = send.finish();
}

async fn one_priority_latency_sample() -> Duration {
    let BenchPair {
        client_endpoint,
        server_endpoint,
        client_conn,
        server_conn,
    } = connected_pair().await;
    let accept_high = tokio::spawn(accept_until_high_marker(server_conn.clone()));

    let (low_send, _low_recv) = client_conn.open_bi().await.expect("open low stream");
    let low_task = tokio::spawn(write_low_flood(low_send));
    tokio::task::yield_now().await;

    let (mut high_send, _high_recv) = client_conn.open_bi().await.expect("open high stream");
    high_send
        .set_priority(HIGH_PRIORITY)
        .expect("set high stream priority");
    high_send.write_all(b"HH").await.expect("write marker");
    let started = Instant::now();
    high_send.finish().expect("finish high stream");

    let received = accept_high.await.expect("join high marker reader");
    client_conn.close(0u32.into(), b"bench done");
    server_conn.close(0u32.into(), b"bench done");
    drop(client_endpoint);
    drop(server_endpoint);
    low_task.abort();
    let _ = low_task.await;
    received.saturating_duration_since(started)
}

fn bench_high_priority_marker_under_low_priority_flood(c: &mut Criterion) {
    let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
    let mut group = c.benchmark_group("stream_priority_latency");
    group.sample_size(10);
    group.measurement_time(Duration::from_secs(5));
    group.bench_function("high_marker_under_low_flood", |b| {
        b.iter_custom(|iters| {
            runtime.block_on(async {
                let mut total = Duration::ZERO;
                for _ in 0..iters {
                    total += one_priority_latency_sample().await;
                }
                total
            })
        });
    });
    group.finish();
}

criterion_group!(benches, bench_high_priority_marker_under_low_priority_flood);
criterion_main!(benches);
