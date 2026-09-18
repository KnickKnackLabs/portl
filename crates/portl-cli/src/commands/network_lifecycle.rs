//! Shared mechanisms; each command still owns its recovery policy.

use std::time::Duration;

use anyhow::{Context, Result};
use portl_core::net::client::TicketHandshakeError;
use portl_core::wire::AckReason;
use tokio::time::Instant;

pub(crate) const SETUP_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetryClass {
    Permanent,
    Transient,
}

impl std::fmt::Display for RetryClass {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Permanent => "permanent peer configuration or authorization failure",
            Self::Transient => "temporary peer discovery failure",
        })
    }
}

impl std::error::Error for RetryClass {}

pub(crate) fn retryable(error: &anyhow::Error) -> bool {
    if let Some(class) = error.downcast_ref::<RetryClass>() {
        return *class == RetryClass::Transient;
    }
    if error
        .downcast_ref::<portl_core::net::udp_client::UdpRequestRejected>()
        .is_some()
    {
        return false;
    }
    if let Some(error) = error.downcast_ref::<TicketHandshakeError>() {
        return matches!(
            error.reason,
            Some(AckReason::RateLimited | AckReason::InternalError { .. })
        );
    }
    true
}

pub(crate) async fn before_deadline<T>(
    deadline: Instant,
    stage: &'static str,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout_at(deadline, operation)
        .await
        .with_context(|| format!("{stage} deadline exceeded"))?
}

pub(crate) async fn setup<T>(
    stage: &'static str,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    before_deadline(Instant::now() + SETUP_TIMEOUT, stage, operation).await
}

pub(crate) async fn cancellable_setup<T>(
    stage: &'static str,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::select! {
        result = setup(stage, operation) => result,
        signal = shutdown_signal() => {
            signal?;
            anyhow::bail!("{stage} interrupted; remote completion may be unknown");
        }
    }
}

pub(crate) struct Backoff {
    ceiling: Duration,
}

impl Default for Backoff {
    fn default() -> Self {
        Self {
            ceiling: Duration::from_millis(100),
        }
    }
}

impl Backoff {
    pub(crate) fn next(&mut self) -> Duration {
        let delay = self.ceiling.mul_f64(0.5 + rand::random::<f64>() * 0.5);
        self.ceiling = (self.ceiling * 2).min(Duration::from_secs(5));
        delay
    }

    pub(crate) fn reset(&mut self) {
        *self = Self::default();
    }
}

pub(crate) async fn shutdown_signal() -> Result<()> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("watch SIGTERM")?;
    tokio::select! {
        result = tokio::signal::ctrl_c() => result.context("watch Ctrl-C"),
        _ = terminate.recv() => Ok(()),
    }
}

#[cfg(test)]
pub(super) async fn test_connection_pair() -> (
    portl_core::endpoint::Endpoint,
    portl_core::endpoint::Endpoint,
    iroh::endpoint::Connection,
    iroh::endpoint::Connection,
) {
    let (client, server) = portl_core::test_util::pair()
        .await
        .expect("loopback endpoints");
    let alpn = b"lifecycle-test";
    server.inner().set_alpns(vec![alpn.to_vec()]);
    let (local, remote) = tokio::time::timeout(Duration::from_secs(2), async {
        tokio::join!(client.inner().connect(server.addr(), alpn), async {
            server.inner().accept().await.expect("incoming").await
        })
    })
    .await
    .expect("loopback connection deadline");
    (
        client,
        server,
        local.expect("connect"),
        remote.expect("accept"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ticket_rejections_have_explicit_retry_policy() {
        for reason in [
            AckReason::Expired,
            AckReason::Revoked,
            AckReason::BadSignature,
        ] {
            assert!(!retryable(
                &anyhow::Error::new(TicketHandshakeError {
                    reason: Some(reason)
                })
                .context("connect")
            ));
        }
        assert!(!retryable(&anyhow::Error::new(TicketHandshakeError {
            reason: None
        })));
        for reason in [
            AckReason::RateLimited,
            AckReason::InternalError { detail: None },
        ] {
            assert!(retryable(
                &TicketHandshakeError {
                    reason: Some(reason)
                }
                .into()
            ));
        }
        assert!(!retryable(
            &anyhow::anyhow!("bad target").context(RetryClass::Permanent)
        ));
        assert!(retryable(
            &anyhow::anyhow!("lookup unavailable").context(RetryClass::Transient)
        ));
    }

    #[tokio::test(start_paused = true)]
    async fn one_shot_deadline_drops_pending_request_without_replay() {
        let (owner, mut dropped) = tokio::sync::oneshot::channel::<()>();
        let mut attempts = 0;
        let started = Instant::now();
        let error = cancellable_setup::<()>("session request", async {
            attempts += 1;
            let _owner = owner;
            std::future::pending().await
        })
        .await
        .expect_err("request deadline");
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
        assert_eq!(started.elapsed(), SETUP_TIMEOUT);
        assert_eq!(attempts, 1);
        assert!(matches!(
            dropped.try_recv(),
            Err(tokio::sync::oneshot::error::TryRecvError::Closed)
        ));
    }

    #[test]
    fn retry_delay_is_bounded_nonzero_and_resettable() {
        let mut backoff = Backoff::default();
        for _ in 0..100 {
            let delay = backoff.next();
            assert!(delay >= Duration::from_millis(50));
            assert!(delay <= Duration::from_secs(5));
        }
        backoff.reset();
        assert!(backoff.next() <= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn application_exchange_obeys_absolute_deadline() {
        let error = before_deadline(
            Instant::now() + Duration::from_millis(20),
            "ticket acknowledgement",
            std::future::pending::<Result<()>>(),
        )
        .await
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("ticket acknowledgement deadline exceeded")
        );
        assert!(
            error
                .downcast_ref::<tokio::time::error::Elapsed>()
                .is_some()
        );
    }
}
