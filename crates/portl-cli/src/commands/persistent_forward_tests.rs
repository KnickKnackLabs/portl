use super::*;

#[tokio::test]
async fn permanent_setup_error_stops_after_one_attempt() {
    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let mut shutdown = std::future::pending::<Result<()>>();
    let mut attempts = 0;
    let error = supervise(&mut forwards, &mut shutdown, || {
        attempts += 1;
        std::future::ready(Err(
            anyhow::anyhow!("invalid target").context(network_lifecycle::RetryClass::Permanent)
        ))
    })
    .await
    .unwrap_err();
    assert_eq!(attempts, 1);
    assert!(format!("{error:#}").contains("invalid target"));
    forwards.shutdown().await;
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

    let mut forwards = ForwardPlan::default().start_persistent().await.unwrap();
    let cancelled = Arc::new(AtomicBool::new(false));
    let (started, observed) = tokio::sync::oneshot::channel();
    let mut started = Some(started);
    let mut shutdown = Box::pin(async { observed.await.context("observe setup start") });
    let result = tokio::time::timeout(
        Duration::from_secs(1),
        supervise(&mut forwards, &mut shutdown, || {
            let started = started.take().unwrap();
            let cancelled = Arc::clone(&cancelled);
            async move {
                let _guard = Cancelled(cancelled);
                started.send(()).unwrap();
                std::future::pending::<Result<super::super::peer_resolve::ConnectedPeer>>().await
            }
        }),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(result, ExitCode::SUCCESS);
    assert!(cancelled.load(Ordering::SeqCst));
    forwards.shutdown().await;
}
