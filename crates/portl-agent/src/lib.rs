use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use anyhow::Result;
use portl_core::id::{Identity, store};
use portl_core::ticket::verify::TrustRoots;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument, warn};

pub mod audit;
pub mod caps_enforce;
pub mod config;
pub mod endpoint;
pub mod gateway;
pub mod meta_handler;
pub mod metrics;
pub mod pipeline;
pub mod rate_limit;
pub mod revocations;
pub mod session;
pub mod shell_handler;
pub mod shell_registry;
pub mod stream_io;
pub mod tcp_handler;
pub mod ticket_handler;
pub mod udp_handler;
pub mod udp_registry;

pub use config::{AgentConfig, AgentMode, DiscoveryConfig, RateLimitConfig};
pub use pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
pub use rate_limit::OfferRateLimiter;
pub use revocations::{RevocationRecord, RevocationSet};

/// Gate ALPN dispatch on agent mode.
///
/// Listener mode serves every wire-level ALPN. Gateway mode is
/// strictly a master-ticket-backed HTTP forwarder (see
/// `src/gateway.rs`), so only `meta/v1` and `tcp/v1` streams are
/// dispatched; `shell/v1` and `udp/v1` are closed at dispatch time.
pub(crate) fn alpn_allowed_in_mode(mode: &AgentMode, alpn: &str) -> Result<(), &'static str> {
    match mode {
        AgentMode::Listener => Ok(()),
        AgentMode::Gateway { .. } => {
            let meta = String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1);
            let tcp = String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1);
            if alpn == meta || alpn == tcp {
                Ok(())
            } else {
                Err("gateway mode only serves meta/v1 and tcp/v1 streams")
            }
        }
    }
}

#[cfg(test)]
mod mode_dispatch_tests {
    use super::{AgentMode, alpn_allowed_in_mode};

    fn gateway() -> AgentMode {
        AgentMode::Gateway {
            upstream_url: "http://slicer.test:8080".to_owned(),
            upstream_host: "slicer.test".to_owned(),
            upstream_port: 8080,
        }
    }

    #[test]
    fn listener_allows_every_alpn() {
        for alpn in [
            String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1),
            String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1),
            String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1),
            String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1),
        ] {
            alpn_allowed_in_mode(&AgentMode::Listener, alpn.as_ref())
                .unwrap_or_else(|err| panic!("listener rejected {alpn}: {err}"));
        }
    }

    #[test]
    fn gateway_allows_meta_and_tcp_only() {
        alpn_allowed_in_mode(
            &gateway(),
            String::from_utf8_lossy(portl_proto::meta_v1::ALPN_META_V1).as_ref(),
        )
        .expect("meta/v1 allowed in gateway mode");
        alpn_allowed_in_mode(
            &gateway(),
            String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1).as_ref(),
        )
        .expect("tcp/v1 allowed in gateway mode");
    }

    #[test]
    fn gateway_rejects_shell_and_udp() {
        let err = alpn_allowed_in_mode(
            &gateway(),
            String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).as_ref(),
        )
        .expect_err("shell/v1 must be rejected in gateway mode");
        assert!(err.contains("gateway mode only serves"));
        let err = alpn_allowed_in_mode(
            &gateway(),
            String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1).as_ref(),
        )
        .expect_err("udp/v1 must be rejected in gateway mode");
        assert!(err.contains("gateway mode only serves"));
    }
}

#[allow(dead_code)]
pub(crate) struct AgentState {
    pub trust_roots: TrustRoots,
    pub revocations: std::sync::RwLock<RevocationSet>,
    pub rate_limit: OfferRateLimiter,
    pub started_at: Instant,
    pub shell_registry: shell_registry::ShellRegistry,
    pub udp_registry: udp_registry::UdpSessionRegistry,
    pub mode: AgentMode,
    pub metrics: Arc<metrics::Metrics>,
}

#[instrument(skip_all)]
pub async fn run(cfg: AgentConfig) -> Result<()> {
    maybe_test_panic();
    run_with_shutdown(cfg, CancellationToken::new()).await
}

/// Test-only panic hook. Enabled by the `test-panic-trigger` feature
/// (never enable in production); panics if `PORTL_TEST_PANIC_AT=startup`
/// is set so `tests/panic_abort.rs` can observe the release profile's
/// `panic = "abort"` take effect.
#[cfg(feature = "test-panic-trigger")]
fn maybe_test_panic() {
    assert!(
        std::env::var("PORTL_TEST_PANIC_AT").as_deref() != Ok("startup"),
        "test-only panic trigger",
    );
}

#[cfg(not(feature = "test-panic-trigger"))]
fn maybe_test_panic() {}

#[instrument(skip_all)]
pub async fn run_with_shutdown(cfg: AgentConfig, shutdown: CancellationToken) -> Result<()> {
    audit::init();

    let state = Arc::new(AgentState {
        trust_roots: TrustRoots(cfg.trust_roots.iter().copied().collect::<HashSet<_>>()),
        revocations: std::sync::RwLock::new(RevocationSet::load_with_max_bytes(
            revocations_path(&cfg),
            cfg.revocations_max_bytes
                .unwrap_or(revocations::DEFAULT_REVOCATIONS_MAX_BYTES),
        )?),
        rate_limit: OfferRateLimiter::new(&cfg.rate_limit)?,
        started_at: Instant::now(),
        shell_registry: shell_registry::ShellRegistry::default(),
        udp_registry: udp_registry::UdpSessionRegistry::new(
            cfg.udp_session_linger_secs
                .unwrap_or(udp_registry::DEFAULT_UDP_SESSION_LINGER_SECS),
        ),
        mode: cfg.mode.clone(),
        metrics: Arc::new(metrics::Metrics::default()),
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

    tracing::info!("portl-agent listening");

    let signal_shutdown = Arc::new(AtomicBool::new(false));
    let signal_tasks = install_signal_tasks(&shutdown, &signal_shutdown)?;
    let udp_gc = spawn_udp_gc_task(Arc::clone(&state), shutdown.clone());
    let revocation_gc = spawn_revocation_gc_task(Arc::clone(&state), shutdown.clone());
    let revocation_reload = spawn_revocation_reload_task(Arc::clone(&state), shutdown.clone());
    let metrics_task = spawn_metrics_server(&state, shutdown.clone(), &cfg);

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

    state.udp_registry.shutdown().await;
    if shutdown.is_cancelled() {
        graceful_close_endpoint(&endpoint).await;
    }
    let all_sessions_reaped = if signal_shutdown.load(Ordering::SeqCst) {
        graceful_shutdown_shell_sessions(&state).await
    } else {
        true
    };
    audit::sync_shell_exit_records();
    signal_tasks.abort();
    udp_gc.abort();
    revocation_gc.abort();
    revocation_reload.abort();
    if let Some(metrics) = metrics_task {
        metrics.abort();
    }

    if signal_shutdown.load(Ordering::SeqCst) && !all_sessions_reaped {
        anyhow::bail!("graceful shutdown left live shell sessions unreaped");
    }

    Ok(())
}

#[instrument(skip_all)]
pub async fn run_task(cfg: AgentConfig) -> Result<JoinHandle<Result<()>>> {
    Ok(tokio::spawn(async move { run(cfg).await }))
}

fn spawn_udp_gc_task(state: Arc<AgentState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(10));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    if let Err(err) = state.udp_registry.gc_expired().await {
                        warn!(?err, "udp session gc failed");
                    }
                }
            }
        }
    })
}

/// Runs the revocation GC every 60 minutes so expired entries (by
/// `not_after_of_ticket + REVOCATION_LINGER`) get dropped without an
/// agent restart.
fn spawn_revocation_gc_task(state: Arc<AgentState>, shutdown: CancellationToken) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick; GC already ran at load time.
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let now = match std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                    {
                        Ok(d) => d.as_secs(),
                        Err(_) => continue,
                    };
                    match state.revocations.write() {
                        Ok(mut guard) => {
                            let removed = guard.gc(now);
                            if removed > 0 {
                                if let Err(err) = guard.persist() {
                                    warn!(?err, "persist revocations after gc");
                                } else {
                                    info!(removed, "revocation gc reclaimed expired entries");
                                }
                            }
                        }
                        Err(err) => {
                            warn!(%err, "revocations lock poisoned; skipping gc pass");
                        }
                    }
                }
            }
        }
    })
}

fn spawn_revocation_reload_task(
    state: Arc<AgentState>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    match portl_core::runtime::slow_task(
                        "revocations_reload",
                        tokio::task::spawn_blocking({
                            let state = Arc::clone(&state);
                            move || {
                                let mut revocations = state
                                    .revocations
                                    .write()
                                    .map_err(|err| anyhow::anyhow!("revocations lock poisoned: {err}"))?;
                                revocations.sync_from_disk()
                            }
                        }),
                    ).await {
                        Ok(Ok(added)) if added > 0 => {
                            info!(added, "reloaded revocations from disk");
                        }
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => {
                            warn!(?err, "revocation reload failed");
                        }
                        Err(err) => {
                            warn!(?err, "revocation reload task panicked");
                        }
                    }
                }
            }
        }
    })
}

fn spawn_metrics_server(
    state: &Arc<AgentState>,
    shutdown: CancellationToken,
    cfg: &AgentConfig,
) -> Option<JoinHandle<()>> {
    if !cfg.metrics_enabled.unwrap_or(true) {
        return None;
    }
    let path = cfg
        .metrics_socket_path
        .clone()
        .unwrap_or_else(metrics::default_socket_path);
    let metrics = Arc::clone(&state.metrics);
    Some(tokio::spawn(async move {
        if let Err(err) = metrics::serve(metrics, path, shutdown).await {
            warn!(?err, "metrics server exited with error");
        }
    }))
}

async fn graceful_close_endpoint(endpoint: &iroh::Endpoint) {
    if let Err(err) =
        tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.close()).await
    {
        warn!(?err, "endpoint close exceeded 10 second shutdown budget");
    }
}

async fn graceful_shutdown_shell_sessions(state: &AgentState) -> bool {
    let processes = state
        .shell_registry
        .iter()
        .map(|entry| Arc::clone(entry.value()))
        .collect::<Vec<_>>();
    if processes.is_empty() {
        return true;
    }

    let mut joins = tokio::task::JoinSet::new();
    for process in processes {
        joins.spawn(async move {
            shell_handler::begin_session_shutdown(process.as_ref(), true)
                .reap()
                .await
        });
    }

    (tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let mut all_reaped = true;
        while let Some(result) = joins.join_next().await {
            match result {
                Ok(reaped) => all_reaped &= reaped,
                Err(err) => {
                    warn!(?err, "shell session shutdown task panicked");
                    all_reaped = false;
                }
            }
        }
        all_reaped
    })
    .await)
        .unwrap_or_default()
}

fn install_signal_tasks(
    shutdown: &CancellationToken,
    signal_shutdown: &Arc<AtomicBool>,
) -> Result<SignalTasks> {
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
        let signal_shutdown = Arc::clone(signal_shutdown);
        handles.push(tokio::spawn(async move {
            tokio::select! {
                _ = sigterm.recv() => {
                    signal_shutdown.store(true, Ordering::SeqCst);
                    shutdown_for_signals.cancel();
                }
                _ = sigint.recv() => {
                    signal_shutdown.store(true, Ordering::SeqCst);
                    shutdown_for_signals.cancel();
                }
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
        let _ = (shutdown, signal_shutdown);
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
    if let Some(secret) = cfg.identity_secret {
        return Ok(Identity::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&secret),
        ));
    }

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
                || PathBuf::from("revocations.jsonl"),
                |parent| parent.join("revocations.jsonl"),
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
