use super::*;

#[tokio::test]
async fn permanent_setup_error_stops_after_one_attempt() {
    let (client, server) = portl_core::test_util::pair().await.unwrap();
    let mut changes = NetworkChanges::new(futures_util::stream::pending());
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let mut shutdown = std::future::pending::<Result<()>>();
    let mut attempts = 0;
    let error = supervise(
        &mut forwards,
        &mut shutdown,
        client.inner(),
        &mut changes,
        || {
            attempts += 1;
            std::future::ready(Err(
                anyhow::anyhow!("invalid target").context(network_lifecycle::RetryClass::Permanent)
            ))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts, 1);
    assert!(format!("{error:#}").contains("invalid target"));
    forwards.shutdown().await;
    client.inner().close().await;
    server.inner().close().await;
}

#[tokio::test]
async fn shutdown_cancels_pending_peer_setup() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    struct Cancelled(Arc<AtomicBool>);
    impl Drop for Cancelled {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let (client, server) = portl_core::test_util::pair().await.unwrap();
    let mut changes = NetworkChanges::new(futures_util::stream::pending());
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let (started, observed) = tokio::sync::oneshot::channel();
    let mut started = Some(started);
    let mut shutdown = Box::pin(async { observed.await.context("observe setup start") });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        supervise(
            &mut forwards,
            &mut shutdown,
            client.inner(),
            &mut changes,
            || {
                let started = started.take().unwrap();
                let cancelled = Arc::clone(&cancelled);
                async move {
                    let _guard = Cancelled(cancelled);
                    started.send(()).unwrap();
                    std::future::pending::<Result<super::super::peer_resolve::ConnectedPeer>>()
                        .await
                }
            },
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
    assert!(cancelled.load(Ordering::SeqCst));
    forwards.shutdown().await;
    client.inner().close().await;
    server.inner().close().await;
}

#[tokio::test]
async fn network_change_cancels_stalled_setup_and_redials_before_deadline() {
    let (client, server) = portl_core::test_util::pair().await.unwrap();
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let mut shutdown = std::future::pending::<Result<()>>();
    let (signal, mut received) = tokio::sync::mpsc::unbounded_channel();
    let mut changes = NetworkChanges::new(futures_util::stream::poll_fn(move |cx| {
        received.poll_recv(cx)
    }));
    let (owner, mut dropped) = tokio::sync::oneshot::channel::<()>();
    let mut owner = Some(owner);
    let mut attempts = 0;
    let error = tokio::time::timeout(
        Duration::from_secs(1),
        supervise(
            &mut forwards,
            &mut shutdown,
            client.inner(),
            &mut changes,
            || {
                attempts += 1;
                let owner = owner.take();
                let signal = signal.clone();
                async move {
                    if let Some(owner) = owner {
                        let _owner = owner;
                        signal.send(Ok(())).unwrap();
                        network_lifecycle::setup("stalled peer setup", std::future::pending()).await
                    } else {
                        Err(anyhow::anyhow!("fresh attempt")
                            .context(network_lifecycle::RetryClass::Permanent))
                    }
                }
            },
        ),
    )
    .await
    .expect("network change must preempt the 30-second setup timeout")
    .unwrap_err();
    assert_eq!(attempts, 2);
    assert!(format!("{error:#}").contains("fresh attempt"));
    assert!(matches!(
        dropped.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    forwards.shutdown().await;
    client.inner().close().await;
    server.inner().close().await;
}

#[tokio::test]
async fn network_change_interrupts_backoff_and_resets_the_next_delay() {
    let (client, server) = portl_core::test_util::pair().await.unwrap();
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let mut shutdown = std::future::pending::<Result<()>>();
    let (signal, mut received) = tokio::sync::mpsc::unbounded_channel();
    let mut changes = NetworkChanges::new(futures_util::stream::poll_fn(move |cx| {
        received.poll_recv(cx)
    }));
    tokio::time::pause();
    let mut changed_at = None;
    let mut attempts = 0;
    supervise(
        &mut forwards,
        &mut shutdown,
        client.inner(),
        &mut changes,
        || {
            attempts += 1;
            if attempts == 8 {
                changed_at = Some(tokio::time::Instant::now());
                signal.send(Ok(())).unwrap();
            }
            std::future::ready(Err(anyhow::anyhow!("setup failed").context(
                if attempts == 10 {
                    network_lifecycle::RetryClass::Permanent
                } else {
                    network_lifecycle::RetryClass::Transient
                },
            )))
        },
    )
    .await
    .unwrap_err();
    assert_eq!(attempts, 10);
    let elapsed = changed_at.unwrap().elapsed();
    assert!(elapsed >= Duration::from_millis(50));
    // Tokio rounds timer deadlines to milliseconds.
    assert!(elapsed <= Duration::from_millis(101));
    tokio::time::resume();
    forwards.shutdown().await;
    client.inner().close().await;
    server.inner().close().await;
}

#[tokio::test]
async fn stalled_peer_setup_gets_a_fresh_attempt_before_its_deadline() {
    let (client, server) = portl_core::test_util::pair().await.unwrap();
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let mut shutdown = std::future::pending::<Result<()>>();
    let mut changes = NetworkChanges::new(futures_util::stream::pending());
    let (owner, mut dropped) = tokio::sync::oneshot::channel::<()>();
    let mut owner = Some(owner);
    let mut attempts = Vec::new();
    tokio::time::pause();
    let started = tokio::time::Instant::now();
    let error = supervise(
        &mut forwards,
        &mut shutdown,
        client.inner(),
        &mut changes,
        || {
            attempts.push(started.elapsed());
            let owner = owner.take();
            async move {
                if let Some(owner) = owner {
                    // A dial begun while the peer was down: it never notices the
                    // peer is back and would hold the 30-second setup deadline.
                    let _owner = owner;
                    network_lifecycle::setup("stalled peer setup", std::future::pending()).await
                } else {
                    Err(anyhow::anyhow!("fresh attempt")
                        .context(network_lifecycle::RetryClass::Permanent))
                }
            }
        },
    )
    .await
    .unwrap_err();
    tokio::time::resume();
    assert!(format!("{error:#}").contains("fresh attempt"));
    assert_eq!(attempts.len(), 2);
    assert!(attempts[1] >= CONNECT_HEDGE_INTERVAL);
    // Tokio rounds timer deadlines to milliseconds.
    assert!(attempts[1] <= CONNECT_HEDGE_INTERVAL + Duration::from_millis(1));
    assert!(matches!(
        dropped.try_recv(),
        Err(tokio::sync::oneshot::error::TryRecvError::Closed)
    ));
    forwards.shutdown().await;
    client.inner().close().await;
    server.inner().close().await;
}
