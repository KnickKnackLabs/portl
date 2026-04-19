use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use portl_core::id::{Identity, store};
use portl_core::ticket::verify::TrustRoots;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{instrument, warn};

pub mod audit;
pub mod caps_enforce;
pub mod config;
pub mod endpoint;
pub mod meta_handler;
pub mod pipeline;
pub mod rate_limit;
pub mod revocations;
pub mod session;
pub mod shell_handler;
pub mod shell_registry;
pub mod stream_io;
pub mod tcp_handler;
pub mod ticket_handler;

pub use config::{AgentConfig, DiscoveryConfig, RateLimitConfig};
pub use pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
pub use rate_limit::OfferRateLimiter;
pub use revocations::RevocationSet;

#[allow(dead_code)]
pub(crate) struct AgentState {
    pub trust_roots: TrustRoots,
    pub revocations: RevocationSet,
    pub rate_limit: OfferRateLimiter,
    pub started_at: Instant,
    pub shell_registry: shell_registry::ShellRegistry,
}

#[instrument(skip_all)]
pub async fn run(cfg: AgentConfig) -> Result<()> {
    run_with_shutdown(cfg, CancellationToken::new()).await
}

#[instrument(skip_all)]
pub async fn run_with_shutdown(cfg: AgentConfig, shutdown: CancellationToken) -> Result<()> {
    audit::init();

    let state = Arc::new(AgentState {
        trust_roots: TrustRoots(cfg.trust_roots.iter().copied().collect::<HashSet<_>>()),
        revocations: RevocationSet::load(revocations_path(&cfg))?,
        rate_limit: OfferRateLimiter::new(&cfg.rate_limit)?,
        started_at: Instant::now(),
        shell_registry: shell_registry::ShellRegistry::default(),
    });

    let endpoint = if let Some(endpoint) = cfg.endpoint.clone() {
        endpoint
            .inner()
            .set_alpns(vec![portl_proto::ticket_v1::ALPN_TICKET_V1.to_vec()]);
        endpoint.inner().clone()
    } else {
        let identity = load_identity(&cfg)?;
        endpoint::bind(&cfg, &identity).await?
    };

    let signal_tasks = install_signal_tasks(&shutdown)?;

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                break;
            }
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else {
                    break;
                };
                let connection = match incoming.await {
                    Ok(connection) => connection,
                    Err(err) => {
                        warn!(?err, "failed to accept incoming connection");
                        continue;
                    }
                };

                if connection.alpn() == portl_proto::ticket_v1::ALPN_TICKET_V1 {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(err) = ticket_handler::serve_connection(connection, state).await {
                            warn!(?err, "ticket connection failed");
                        }
                    });
                } else {
                    connection.close(0x1003u32.into(), b"unsupported ALPN");
                }
            }
        }
    }

    if shutdown.is_cancelled() {
        graceful_close_endpoint(&endpoint).await;
    }
    signal_tasks.abort();

    Ok(())
}

#[instrument(skip_all)]
pub async fn run_task(cfg: AgentConfig) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move { run(cfg).await }))
}

async fn graceful_close_endpoint(endpoint: &iroh::Endpoint) {
    if let Err(err) =
        tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.close()).await
    {
        warn!(?err, "endpoint close exceeded 10 second shutdown budget");
    }
}

fn install_signal_tasks(shutdown: &CancellationToken) -> Result<SignalTasks> {
    #[cfg(unix)]
    {
        use nix::errno::Errno;
        use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
        use nix::unistd::Pid;
        use tokio::signal::unix::{SignalKind, signal};

        let mut handles = Vec::new();

        let mut sigterm = signal(SignalKind::terminate())?;
        let mut sigint = signal(SignalKind::interrupt())?;
        let shutdown_for_signals = shutdown.clone();
        handles.push(tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => shutdown_for_signals.cancel(),
                _ = sigint.recv() => shutdown_for_signals.cancel(),
                () = shutdown_for_signals.cancelled() => {}
            }
        }));

        if std::process::id() == 1 {
            let mut sigchld = signal(SignalKind::child())?;
            let shutdown_for_reaper = shutdown.clone();
            handles.push(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        () = shutdown_for_reaper.cancelled() => break,
                        signal = sigchld.recv() => {
                            if signal.is_none() {
                                break;
                            }
                            loop {
                                match waitpid(Pid::from_raw(-1), Some(WaitPidFlag::WNOHANG)) {
                                    Ok(WaitStatus::StillAlive) | Err(Errno::ECHILD) => break,
                                    Ok(_) => {}
                                    Err(err) => {
                                        warn!(?err, "failed to reap child process");
                                        break;
                                    }
                                }
                            }
                        }
                    }
                }
            }));
        }

        Ok(SignalTasks { handles })
    }

    #[cfg(not(unix))]
    {
        let _ = shutdown;
        Ok(SignalTasks::default())
    }
}

#[derive(Default)]
struct SignalTasks {
    handles: Vec<JoinHandle<()>>,
}

impl SignalTasks {
    fn abort(self) {
        for handle in self.handles {
            handle.abort();
        }
    }
}

fn load_identity(cfg: &AgentConfig) -> Result<Identity> {
    let path = cfg
        .identity_path
        .clone()
        .unwrap_or_else(store::default_path);
    store::load(&path).map_err(Into::into)
}

fn revocations_path(cfg: &AgentConfig) -> PathBuf {
    cfg.revocations_path.clone().unwrap_or_else(|| {
        cfg.identity_path
            .clone()
            .unwrap_or_else(store::default_path)
            .parent()
            .map_or_else(
                || PathBuf::from("revocations.json"),
                |parent| parent.join("revocations.json"),
            )
    })
}

#[cfg(test)]
mod tests {
    use portl_core::endpoint::Endpoint;
    use tokio_util::sync::CancellationToken;

    use super::{AgentConfig, DiscoveryConfig, run_task, run_with_shutdown};

    #[tokio::test]
    async fn run_task_returns_and_stops_when_endpoint_closes() {
        let endpoint = Endpoint::bind().await.expect("bind endpoint");
        let runtime_endpoint = endpoint.clone();
        let handle = run_task(AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(runtime_endpoint),
            ..AgentConfig::default()
        })
        .await
        .expect("spawn task");

        endpoint.inner().close().await;
        handle.await.expect("join handle").expect("run result");
    }

    #[tokio::test]
    async fn run_with_shutdown_stops_when_token_is_cancelled() {
        let endpoint = Endpoint::bind().await.expect("bind endpoint");
        let shutdown = CancellationToken::new();
        let task = tokio::spawn(run_with_shutdown(
            AgentConfig {
                discovery: DiscoveryConfig::in_process(),
                endpoint: Some(endpoint),
                ..AgentConfig::default()
            },
            shutdown.clone(),
        ));

        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("join timeout")
            .expect("join handle")
            .expect("run result");
    }
}
