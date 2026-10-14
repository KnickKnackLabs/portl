//! One peer owner for all persistent listeners in a command.

#[cfg(test)]
#[path = "persistent_forward_tests.rs"]
mod tests;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::stream::FuturesUnordered;
use futures_util::{Stream, StreamExt};
use iroh::endpoint::ConnectionError;
use portl_core::id::store;
use portl_core::ticket::schema::Capabilities;

use super::forwarding::{ForwardPlan, ForwardRuntime};
use super::network_lifecycle::{self, Backoff, NetworkChanges};
use super::peer_resolve::{
    bind_client_endpoint, close_client_endpoint, close_connected_connection,
    connect_peer_with_endpoint, resolve_identity_path,
};

pub(crate) async fn run(peer: &str, plan: ForwardPlan, caps: Capabilities) -> Result<ExitCode> {
    let identity = store::load(&resolve_identity_path(None)).context("load local identity")?;
    let mut forwards = plan.start_persistent().await?;
    let shutdown = network_lifecycle::shutdown_signal();
    tokio::pin!(shutdown);
    let (endpoint, monitor) = tokio::select! {
        result = &mut shutdown => {
            forwards.shutdown().await;
            result?;
            return Ok(ExitCode::SUCCESS);
        }
        result = network_lifecycle::setup("client endpoint setup", async {
            let monitor = netwatch::netmon::Monitor::new()
                .await
                .context("watch local network changes")?;
            let endpoint = bind_client_endpoint(&identity).await?;
            Ok((endpoint, monitor))
        }) => match result {
            Ok(ready) => ready,
            Err(error) => {
                forwards.shutdown().await;
                return Err(error);
            }
        }
    };
    let mut changes = network_lifecycle::network_changes(&monitor);
    let mut quiet = false;
    let result = supervise(
        &mut forwards,
        &mut shutdown,
        &endpoint,
        &mut changes,
        || {
            let attempt =
                connect_peer_with_endpoint(peer, caps.clone(), &identity, &endpoint, quiet);
            quiet = true;
            attempt
        },
    )
    .await;
    forwards.shutdown().await;
    close_client_endpoint(endpoint, "persistent forward stopped").await;
    result
}

enum PeerEnd {
    Closed(ConnectionError),
    Signal(Result<()>),
    Worker(anyhow::Error),
}

pub(super) async fn supervise<F, Fut, S>(
    forwards: &mut ForwardRuntime,
    shutdown: &mut (impl Future<Output = Result<()>> + Unpin),
    endpoint: &iroh::Endpoint,
    changes: &mut NetworkChanges<S>,
    mut connect: F,
) -> Result<ExitCode>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<super::peer_resolve::ConnectedPeer>>,
    S: Stream<Item = Result<()>> + Unpin,
{
    let mut backoff = Backoff::default();
    loop {
        tracing::info!(state = "connecting", "persistent forward peer state");
        let connected = tokio::select! {
            biased;
            result = &mut *shutdown => { result?; return Ok(ExitCode::SUCCESS); },
            error = forwards.failed() => return Err(error),
            change = changes.changed() => { change?; None },
            result = hedged_connect(&mut connect) => Some(result),
        };
        let Some(connected) = connected else {
            tracing::info!(
                state = "reconnecting",
                "local network changed; restarting peer setup"
            );
            backoff.reset();
            network_lifecycle::refresh_network(endpoint).await?;
            continue;
        };
        match connected {
            Err(error) if !network_lifecycle::retryable(&error) => return Err(error),
            Err(error) => {
                tracing::warn!(error = %portl_core::diagnostics::redact_text(&format!("{error:#}")), state = "reconnecting", "peer setup failed");
            }
            Ok(connected) => {
                forwards.reconnect(&connected);
                tracing::info!(state = "connected", "persistent forward peer state");
                let started = Instant::now();
                let end = tokio::select! {
                    result = &mut *shutdown => PeerEnd::Signal(result),
                    error = forwards.failed() => PeerEnd::Worker(error),
                    error = connected.connection.closed() => {
                        tracing::warn!(%error, state = "reconnecting", "forward peer closed");
                        PeerEnd::Closed(error)
                    },
                };
                forwards.disconnected();
                close_connected_connection(connected, b"persistent forward reconnect or stop")
                    .await;
                match end {
                    PeerEnd::Signal(result) => {
                        result?;
                        return Ok(ExitCode::SUCCESS);
                    }
                    PeerEnd::Worker(error) => return Err(error),
                    // Transport loss after a working session: redial now. A peer that
                    // closes right after setup keeps the backoff so it cannot spin.
                    PeerEnd::Closed(error)
                        if started.elapsed() >= Duration::from_secs(5)
                            && matches!(
                                error,
                                ConnectionError::TransportError(_)
                                    | ConnectionError::ConnectionClosed(_)
                                    | ConnectionError::Reset
                                    | ConnectionError::TimedOut
                            ) =>
                    {
                        backoff.reset();
                        continue;
                    }
                    PeerEnd::Closed(_) => {}
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    backoff.reset();
                }
            }
        }
        let network_changed = tokio::select! {
            biased;
            result = &mut *shutdown => { result?; return Ok(ExitCode::SUCCESS); },
            error = forwards.failed() => return Err(error),
            change = changes.changed() => { change?; true },
            () = tokio::time::sleep(backoff.next()) => false,
        };
        if network_changed {
            tracing::info!(
                state = "reconnecting",
                "local network changed; retrying now"
            );
            backoff.reset();
            network_lifecycle::refresh_network(endpoint).await?;
        }
    }
}

/// Delay before a pending peer setup gets a fresh sibling attempt.
const CONNECT_HEDGE_INTERVAL: Duration = Duration::from_secs(5);

/// A dial started while the peer was unreachable can stay stuck after the
/// peer returns, while a fresh dial on the same endpoint connects at once.
/// Add a fresh attempt every interval, keep each attempt's own deadline, and
/// take the first result; dropping the others cancels them.
async fn hedged_connect<F, Fut, T>(connect: &mut F) -> Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    let mut attempts = FuturesUnordered::new();
    attempts.push(connect());
    let mut hedge = tokio::time::interval_at(
        tokio::time::Instant::now() + CONNECT_HEDGE_INTERVAL,
        CONNECT_HEDGE_INTERVAL,
    );
    hedge.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(result) = attempts.next() => return result,
            _ = hedge.tick() => {
                tracing::info!(state = "connecting", "peer setup still pending; starting a fresh attempt");
                attempts.push(connect());
            }
        }
    }
}
