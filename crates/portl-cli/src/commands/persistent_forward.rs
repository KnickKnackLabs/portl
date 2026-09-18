//! One peer owner for all persistent listeners in a command.

#[cfg(test)]
#[path = "persistent_forward_tests.rs"]
mod tests;

use std::process::ExitCode;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use portl_core::id::store;
use portl_core::ticket::schema::Capabilities;

use super::forwarding::{ForwardPlan, ForwardRuntime};
use super::network_lifecycle::{self, Backoff};
use super::peer_resolve::{
    bind_client_endpoint, close_client_endpoint, close_connected_connection,
    connect_peer_with_endpoint, resolve_identity_path,
};

pub(crate) async fn run(peer: &str, plan: ForwardPlan, caps: Capabilities) -> Result<ExitCode> {
    let identity = store::load(&resolve_identity_path(None)).context("load local identity")?;
    let mut forwards = plan.start_persistent().await?;
    let shutdown = network_lifecycle::shutdown_signal();
    tokio::pin!(shutdown);
    let endpoint = tokio::select! {
        result = &mut shutdown => {
            forwards.shutdown().await;
            result?;
            return Ok(ExitCode::SUCCESS);
        }
        result = network_lifecycle::setup("client endpoint setup", bind_client_endpoint(&identity)) => match result {
            Ok(endpoint) => endpoint,
            Err(error) => {
                forwards.shutdown().await;
                return Err(error);
            }
        }
    };
    let mut quiet = false;
    let result = supervise(&mut forwards, &mut shutdown, || {
        let attempt = connect_peer_with_endpoint(peer, caps.clone(), &identity, &endpoint, quiet);
        quiet = true;
        attempt
    })
    .await;
    forwards.shutdown().await;
    close_client_endpoint(endpoint, "persistent forward stopped").await;
    result
}

enum PeerEnd {
    Closed,
    Signal(Result<()>),
    Worker(anyhow::Error),
}

pub(super) async fn supervise<F, Fut>(
    forwards: &mut ForwardRuntime,
    shutdown: &mut (impl Future<Output = Result<()>> + Unpin),
    mut connect: F,
) -> Result<ExitCode>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<super::peer_resolve::ConnectedPeer>>,
{
    let mut backoff = Backoff::default();
    loop {
        tracing::info!(state = "connecting", "persistent forward peer state");
        let connected = tokio::select! {
            result = &mut *shutdown => { result?; return Ok(ExitCode::SUCCESS); },
            error = forwards.failed() => return Err(error),
            result = connect() => result,
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
                        PeerEnd::Closed
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
                    PeerEnd::Closed => {}
                }
                if started.elapsed() >= Duration::from_secs(30) {
                    backoff.reset();
                }
            }
        }
        tokio::select! {
            result = &mut *shutdown => { result?; return Ok(ExitCode::SUCCESS); },
            error = forwards.failed() => return Err(error),
            () = tokio::time::sleep(backoff.next()) => {},
        }
    }
}
