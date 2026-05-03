use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Instant, SystemTime};

#[cfg(feature = "ghostty-vt")]
use anyhow::Context as _;
use anyhow::Result;
use portl_core::id::{Identity, store};
use portl_core::ticket::verify::TrustRoots;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{info, instrument, warn};

pub mod audit;
pub mod caps_enforce;
pub mod config;
pub mod config_file;
pub mod conn_registry;
pub mod endpoint;
pub mod gateway;
pub mod meta_handler;
pub mod metrics;
pub mod network_watchdog;
pub mod pair_handler;
pub mod pipeline;
pub mod rate_limit;
pub mod relay;
pub mod revocations;
pub mod session;
pub(crate) mod session_handler;
pub mod shell_handler;
pub mod shell_registry;
pub mod status_schema;
pub mod stream_io;
mod target_context;
pub mod tcp_handler;
pub mod ticket_handler;
pub mod udp_handler;
pub mod udp_registry;

pub use config::{AgentConfig, AgentMode, DiscoveryConfig, RateLimitConfig};

#[cfg(feature = "ghostty-vt")]
pub enum GhosttyAttachInput {
    Data(Vec<u8>),
    Close,
}

#[cfg(feature = "ghostty-vt")]
pub enum GhosttyAttachControl {
    Resize { rows: u16, cols: u16 },
    Close,
}

#[cfg(feature = "ghostty-vt")]
pub struct GhosttyAttachChannels {
    pub pid: u32,
    pub stdin_tx: tokio::sync::mpsc::Sender<GhosttyAttachInput>,
    pub control_tx: tokio::sync::mpsc::UnboundedSender<GhosttyAttachControl>,
    pub stdout_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub stderr_rx: tokio::sync::mpsc::Receiver<Vec<u8>>,
    pub exit_rx: tokio::sync::watch::Receiver<Option<i32>>,
}

#[cfg(feature = "ghostty-vt")]
pub fn ghostty_provider_status() -> portl_proto::session_v1::ProviderStatus {
    session_handler::ghostty::GhosttyProvider::new().status()
}

#[cfg(feature = "ghostty-vt")]
pub async fn ghostty_session_list() -> Result<Vec<portl_proto::session_v1::SessionInfo>> {
    session_handler::ghostty::GhosttyProvider::new()
        .list_detailed()
        .await
}

#[cfg(feature = "ghostty-vt")]
pub async fn ghostty_session_run(
    session: &str,
    cwd: Option<&str>,
    argv: &[String],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    session_handler::ghostty::GhosttyProvider::new()
        .run(session, cwd, argv, Some(std::env::vars().collect()))
        .await
}

#[cfg(feature = "ghostty-vt")]
pub async fn ghostty_session_history(session: &str) -> Result<String> {
    session_handler::ghostty::GhosttyProvider::new()
        .history(session)
        .await
}

#[cfg(feature = "ghostty-vt")]
pub async fn ghostty_session_kill(session: &str) -> Result<()> {
    session_handler::ghostty::GhosttyProvider::new()
        .kill(session)
        .await
}

#[cfg(feature = "ghostty-vt")]
pub async fn ghostty_session_attach(
    session: &str,
    cwd: Option<&str>,
    rows: u16,
    cols: u16,
    argv: &[String],
) -> Result<GhosttyAttachChannels> {
    let pty = portl_proto::shell_v1::PtyCfg {
        term: std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_owned()),
        cols,
        rows,
    };
    let argv = (!argv.is_empty()).then_some(argv);
    let process = session_handler::ghostty::GhosttyProvider::new()
        .attach_process(
            session,
            cwd,
            Some(&pty),
            argv,
            Some(std::env::vars().collect()),
        )
        .await?;
    process.set_started_at(Instant::now());
    let stdout_rx = process
        .stdout_rx
        .lock()
        .await
        .take()
        .context("ghostty stdout already attached")?;
    let stderr_rx = process
        .stderr_rx
        .lock()
        .await
        .take()
        .context("ghostty stderr already attached")?;
    let exit_rx = process.exit_rx();
    let (stdin_tx, mut stdin_rx) = tokio::sync::mpsc::channel(32);
    let process_stdin_tx = process.stdin_tx.clone();
    tokio::spawn(async move {
        while let Some(message) = stdin_rx.recv().await {
            let forwarded = match message {
                GhosttyAttachInput::Data(bytes) => {
                    process_stdin_tx
                        .send(shell_registry::StdinMessage::Data(bytes))
                        .await
                }
                GhosttyAttachInput::Close => {
                    process_stdin_tx
                        .send(shell_registry::StdinMessage::Close)
                        .await
                }
            };
            if forwarded.is_err() {
                break;
            }
        }
    });
    let (control_tx, mut control_rx) = tokio::sync::mpsc::unbounded_channel();
    if let Some(pty_tx) = process.pty_tx.clone() {
        tokio::spawn(async move {
            while let Some(command) = control_rx.recv().await {
                let forwarded = match command {
                    GhosttyAttachControl::Resize { rows, cols } => {
                        pty_tx.send(shell_registry::PtyCommand::Resize { rows, cols })
                    }
                    GhosttyAttachControl::Close => {
                        pty_tx.send(shell_registry::PtyCommand::Close { force: false })
                    }
                };
                if forwarded.is_err() {
                    break;
                }
            }
        });
    }
    Ok(GhosttyAttachChannels {
        pid: process.pid,
        stdin_tx,
        control_tx,
        stdout_rx,
        stderr_rx,
        exit_rx,
    })
}

#[cfg(feature = "ghostty-vt")]
pub async fn run_ghostty_session_helper(
    name: String,
    socket_path: PathBuf,
    state_root: PathBuf,
    cwd: Option<String>,
    rows: u16,
    cols: u16,
    argv: Vec<String>,
) -> Result<()> {
    session_handler::ghostty::run_helper_command(
        name,
        socket_path,
        state_root,
        cwd,
        rows,
        cols,
        argv,
    )
    .await
}

#[must_use]
pub fn session_provider_discovery_info(
    configured_path: Option<&Path>,
) -> status_schema::SessionProvidersInfo {
    session_handler::provider::provider_discovery_info(configured_path)
}
pub use pipeline::{AcceptanceInput, AcceptanceOutcome, evaluate_offer};
pub use rate_limit::OfferRateLimiter;
pub use revocations::{RevocationRecord, RevocationSet};

/// Gate ALPN dispatch on agent mode.
///
/// Listener mode serves every wire-level ALPN. Gateway mode is
/// strictly a master-ticket-backed HTTP forwarder (see
/// `src/gateway.rs`), so only `meta/v1` and `tcp/v1` streams are
/// dispatched; `shell/v1`, `session/v1`, and `udp/v1` are closed at dispatch time.
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
            String::from_utf8_lossy(portl_proto::session_v1::ALPN_SESSION_V1),
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
            String::from_utf8_lossy(portl_proto::session_v1::ALPN_SESSION_V1).as_ref(),
        )
        .expect_err("session/v1 must be rejected in gateway mode");
        assert!(err.contains("gateway mode only serves"));
        let err = alpn_allowed_in_mode(
            &gateway(),
            String::from_utf8_lossy(portl_proto::udp_v1::ALPN_UDP_V1).as_ref(),
        )
        .expect_err("udp/v1 must be rejected in gateway mode");
        assert!(err.contains("gateway mode only serves"));
    }
}

pub(crate) struct AgentState {
    /// Current trust set. Wrapped in `RwLock` so the peer-store
    /// reload task can swap it in live: v0.3.0 made this filesystem-
    /// backed, and `portl peer add-unsafe-raw` etc. take effect
    /// without restarting the agent.
    pub trust_roots: std::sync::RwLock<TrustRoots>,
    /// `PORTL_TRUST_ROOTS` roots captured at startup. The reload
    /// task unions these with the peer store on every reload so
    /// containerized agents (docker / slicer) that bootstrap trust
    /// via env vars don't have their trust set silently cleared
    /// when peers.json is empty.
    pub bootstrap_roots: HashSet<[u8; 32]>,
    pub revocations: std::sync::RwLock<RevocationSet>,
    pub rate_limit: OfferRateLimiter,
    pub started_at: Instant,
    pub shell_registry: shell_registry::ShellRegistry,
    pub udp_registry: udp_registry::UdpSessionRegistry,
    pub mode: AgentMode,
    pub metrics: Arc<metrics::Metrics>,
    /// Per-peer connection tracker. Populated from ticket/shell/tcp/udp
    /// handlers, read by the `/status/connections` IPC route.
    pub connections: conn_registry::ConnectionRegistry,
    /// Path to the peer store so the reload task can re-read it
    /// without threading the config through. `None` in tests that
    /// bypass `run_with_shutdown`.
    pub peers_path: Option<PathBuf>,
    /// Snapshot of discovery config taken at startup. Used by the
    /// `/status/network` IPC route. Discovery reconfig requires a
    /// restart in v0.3.2; that's fine for the dashboard use-case.
    pub discovery: DiscoveryConfig,
    /// Absolute path of `$PORTL_HOME`; surfaced via `/status`.
    pub home: PathBuf,
    /// Absolute path of `metrics.sock`; surfaced via `/status`.
    pub metrics_socket: PathBuf,
    /// Optional target-side zmx CLI path for the first persistent-session provider.
    pub session_provider_path: Option<PathBuf>,
    /// Agent process start time as unix seconds. For `up_since` fields.
    pub started_at_unix: u64,
    /// Local endpoint id, used to avoid counting self-probe traffic as
    /// external reachability evidence.
    pub self_endpoint_id: [u8; 32],
    /// Lightweight endpoint watchdog health surfaced via `/status`.
    pub network_watchdog: network_watchdog::NetworkWatchdogHealth,
    /// Snapshot of the embedded-relay status for `/status/relay`.
    /// Set to `disabled` when the relay is off; swapped to the live
    /// config on startup when enabled. `RwLock` keeps it
    /// trivially cheap to read from the metrics server.
    pub relay_status: std::sync::RwLock<relay::RelayStatus>,
}

impl metrics::StatusSource for AgentState {
    fn agent_info(&self) -> status_schema::AgentInfo {
        status_schema::AgentInfo {
            pid: std::process::id(),
            version: env!("CARGO_PKG_VERSION").to_owned(),
            started_at_unix: self.started_at_unix,
            home: self.home.display().to_string(),
            metrics_socket: self.metrics_socket.display().to_string(),
        }
    }

    fn connections(&self) -> Vec<conn_registry::ConnectionSnapshot> {
        self.connections.snapshot()
    }

    fn network_info(&self) -> status_schema::NetworkInfo {
        status_schema::NetworkInfo {
            relays: self
                .discovery
                .relays
                .iter()
                .map(ToString::to_string)
                .collect(),
            discovery: status_schema::DiscoveryInfo {
                dns: self.discovery.dns,
                pkarr: self.discovery.pkarr,
                local: self.discovery.local,
            },
        }
    }

    fn network_health(&self) -> status_schema::NetworkHealthInfo {
        self.network_watchdog.snapshot(SystemTime::now()).into()
    }

    fn session_providers_info(&self) -> status_schema::SessionProvidersInfo {
        session_handler::provider::provider_discovery_info(self.session_provider_path.as_deref())
    }

    fn relay_status(&self) -> relay::RelayStatus {
        self.relay_status
            .read()
            .map_or_else(|_| relay::RelayStatus::disabled(), |g| g.clone())
    }

    fn active_connection_count(&self) -> usize {
        self.connections.len()
    }

    fn active_udp_session_count(&self) -> usize {
        self.udp_registry.len()
    }
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
#[allow(clippy::too_many_lines)]
pub async fn run_with_shutdown(cfg: AgentConfig, shutdown: CancellationToken) -> Result<()> {
    audit::init();

    let watchdog_enabled = cfg.watchdog.enabled && cfg.endpoint.is_none();
    let identity = if cfg.endpoint.is_some() && !watchdog_enabled {
        None
    } else {
        Some(load_identity(&cfg)?)
    };
    let mut endpoint = if let Some(endpoint) = cfg.endpoint.clone() {
        endpoint.inner().set_alpns(vec![
            portl_proto::ticket_v1::ALPN_TICKET_V1.to_vec(),
            portl_proto::pair_v1::ALPN_PAIR_V1.to_vec(),
        ]);
        endpoint.inner().clone()
    } else {
        endpoint::bind(
            &cfg,
            identity
                .as_ref()
                .expect("identity loaded for owned endpoint"),
        )
        .await?
    };
    let self_endpoint_id = *endpoint.id().as_bytes();

    let state = Arc::new(AgentState {
        trust_roots: std::sync::RwLock::new(TrustRoots(
            cfg.trust_roots.iter().copied().collect::<HashSet<_>>(),
        )),
        // Snapshot the startup trust_roots as the "bootstrap" set.
        // `AgentConfig::from_env` populates `cfg.trust_roots` from
        // peer_store ∪ env_roots; we only need the env-root portion
        // to survive reloads, but it's cheapest to just snapshot
        // the whole union and let the reload task re-union the
        // peer store on top. Peer-store-derived roots that get
        // removed from the file then dropped from the reload task
        // will still survive via bootstrap, but that's fine — the
        // startup snapshot is a subset of "what the operator
        // explicitly asked for" and we shouldn't silently unlink it.
        bootstrap_roots: cfg.trust_roots.iter().copied().collect::<HashSet<_>>(),
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
        connections: conn_registry::ConnectionRegistry::new(),
        peers_path: cfg.peers_path.clone(),
        discovery: cfg.discovery.clone(),
        home: cfg
            .peers_path
            .as_ref()
            .and_then(|path| home_from_peers_path(path))
            .unwrap_or_else(portl_core::paths::home_dir),
        metrics_socket: cfg
            .metrics_socket_path
            .clone()
            .unwrap_or_else(metrics::default_socket_path),
        session_provider_path: cfg.session_provider_path.clone(),
        self_endpoint_id,
        network_watchdog: if watchdog_enabled {
            network_watchdog::NetworkWatchdogHealth::new(SystemTime::now())
        } else {
            network_watchdog::NetworkWatchdogHealth::disabled(SystemTime::now())
        },
        started_at_unix: SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_secs()),
        relay_status: std::sync::RwLock::new(relay::RelayStatus::disabled()),
    });

    tracing::info!("portl-agent listening");

    let signal_shutdown = Arc::new(AtomicBool::new(false));
    let signal_tasks = install_signal_tasks(&shutdown, &signal_shutdown)?;
    let udp_gc = spawn_udp_gc_task(Arc::clone(&state), shutdown.clone());
    let revocation_gc = spawn_revocation_gc_task(Arc::clone(&state), shutdown.clone());
    let revocation_reload = spawn_revocation_reload_task(Arc::clone(&state), shutdown.clone());
    let peer_reload = spawn_peer_store_reload_task(Arc::clone(&state), shutdown.clone());
    let metrics_task = spawn_metrics_server(&state, shutdown.clone(), &cfg);
    let relay_handle = spawn_relay_if_enabled(&state, shutdown.clone(), &cfg).await?;
    let (endpoint_tx, endpoint_rx) = watch::channel(endpoint.clone());
    let (watchdog_refresh_tx, mut watchdog_refresh_rx) = mpsc::unbounded_channel();
    let watchdog_task = watchdog_enabled.then(|| {
        network_watchdog::spawn_watchdog_task(
            cfg.watchdog.clone(),
            state.network_watchdog.clone(),
            identity
                .clone()
                .expect("identity loaded for watchdog endpoint"),
            endpoint_rx,
            watchdog_refresh_tx,
            shutdown.clone(),
        )
    });

    loop {
        tokio::select! {
            biased;
            () = shutdown.cancelled() => {
                break;
            }
            refresh = watchdog_refresh_rx.recv() => {
                let Some(network_watchdog::WatchdogCommand::RefreshEndpoint) = refresh else {
                    break;
                };
                info!("watchdog requested endpoint refresh");
                match endpoint::bind(&cfg, identity.as_ref().expect("identity loaded for endpoint refresh")).await {
                    Ok(new_endpoint) => {
                        let old_endpoint = std::mem::replace(&mut endpoint, new_endpoint);
                        let _ = endpoint_tx.send(endpoint.clone());
                        state.network_watchdog.record_endpoint_refresh_success(SystemTime::now());
                        info!("watchdog endpoint refresh complete");
                        graceful_close_endpoint(&old_endpoint).await;
                    }
                    Err(err) => {
                        state.network_watchdog.record_endpoint_refresh_failure(
                            SystemTime::now(),
                            format!("{err:#}"),
                        );
                        warn!(?err, "watchdog endpoint refresh failed; keeping existing endpoint and retrying later");
                    }
                }
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
                        if let Err(err) = ticket_handler::serve_connection(connection, state).await
                        {
                            warn!(?err, "ticket connection failed");
                        }
                    });
                } else if connection.alpn() == portl_proto::pair_v1::ALPN_PAIR_V1 {
                    let state = Arc::clone(&state);
                    tokio::spawn(async move {
                        if let Err(err) = pair_handler::serve_connection(connection, state).await
                        {
                            warn!(?err, "pair connection failed");
                        }
                    });
                } else {
                    connection.close(0x1003u32.into(), b"unsupported ALPN");
                }
            }
        }
    }

    state.udp_registry.shutdown().await;
    let signal_shutdown_requested = signal_shutdown.load(Ordering::SeqCst);
    let shell_processes = if signal_shutdown_requested {
        collect_shell_processes(&state)
    } else {
        Vec::new()
    };
    if shutdown.is_cancelled() {
        graceful_close_endpoint(&endpoint).await;
    }
    let all_sessions_reaped = if signal_shutdown_requested {
        // Snapshot live shell sessions before closing the endpoint. Endpoint
        // close tears down control streams, whose guards remove entries from
        // the shell registry; if collection happens afterward, signal shutdown
        // can miss a live child and skip its audit.shell_exit record.
        graceful_shutdown_shell_processes(shell_processes).await
    } else {
        true
    };
    audit::sync_shell_exit_records();
    signal_tasks.abort();
    udp_gc.abort();
    revocation_gc.abort();
    revocation_reload.abort();
    peer_reload.abort();
    if let Some(watchdog) = watchdog_task {
        watchdog.abort();
    }
    if let Some(metrics) = metrics_task {
        metrics.abort();
    }
    if let Some(handle) = relay_handle
        && let Err(err) = handle.shutdown().await
    {
        warn!(?err, "relay shutdown reported error");
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
        let mut interval = tokio::time::interval(std::time::Duration::from_hours(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // Skip the immediate first tick; GC already ran at load time.
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let now = match SystemTime::now()
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
    if !metrics_enabled(cfg) {
        return None;
    }
    let path = cfg
        .metrics_socket_path
        .clone()
        .unwrap_or_else(metrics::default_socket_path);
    let metrics = Arc::clone(&state.metrics);
    let status = Arc::clone(state);
    Some(tokio::spawn(async move {
        if let Err(err) = metrics::serve_with_status(metrics, path, shutdown, Some(status)).await {
            warn!(?err, "metrics server exited with error");
        }
    }))
}

fn metrics_enabled(cfg: &AgentConfig) -> bool {
    cfg.metrics_enabled.unwrap_or(false)
}

/// Spawn the in-process iroh-relay if `cfg.relay_server` is
/// populated. Returns the live handle (drop = shutdown) or `None`
/// when the relay is disabled.
async fn spawn_relay_if_enabled(
    state: &Arc<AgentState>,
    shutdown: CancellationToken,
    cfg: &AgentConfig,
) -> Result<Option<relay::RelayHandle>> {
    let Some(relay_cfg) = cfg.relay_server.clone() else {
        return Ok(None);
    };
    let handle = relay::spawn(relay_cfg, Arc::clone(state), shutdown).await?;
    let status = relay::RelayStatus::from_handle(&handle);
    if let Ok(mut guard) = state.relay_status.write() {
        *guard = status;
    }
    Ok(Some(handle))
}

/// Re-read `peers.json` every 500ms and swap the in-memory
/// `TrustRoots` set. This is what makes `portl peer add-unsafe-raw`
/// / `portl peer rm` take effect on the running agent without
/// requiring a restart. Parallels `spawn_revocation_reload_task`.
fn spawn_peer_store_reload_task(
    state: Arc<AgentState>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let Some(path) = state.peers_path.clone() else {
            // No peer store configured (test harness). Nothing to do.
            return;
        };
        let mut interval = tokio::time::interval(std::time::Duration::from_millis(500));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        interval.tick().await;
        loop {
            tokio::select! {
                () = shutdown.cancelled() => break,
                _ = interval.tick() => {
                    let state = Arc::clone(&state);
                    let path = path.clone();
                    // Wrap through `slow_task` so the portl-agent
                    // policy-lint CI step (which forbids unwrapped
                    // `spawn_blocking` in this crate) stays happy,
                    // and so a wedged filesystem during peer-store
                    // reload doesn't silently stall the task.
                    match portl_core::runtime::slow_task(
                        "peers_reload",
                        tokio::task::spawn_blocking(move || -> Result<usize> {
                            let store = portl_core::peer_store::PeerStore::load(&path)?;
                            // Union peer_store roots with the
                            // startup bootstrap set (env-var-seeded)
                            // so reload doesn't silently strip
                            // container-bootstrapped trust.
                            let mut new_roots: HashSet<[u8; 32]> = store.trust_roots();
                            new_roots.extend(state.bootstrap_roots.iter().copied());
                            let mut guard = state.trust_roots.write().map_err(|err| {
                                anyhow::anyhow!("trust roots lock poisoned: {err}")
                            })?;
                            let changed = guard.0 != new_roots;
                            guard.0 = new_roots;
                            Ok(usize::from(changed))
                        }),
                    )
                    .await
                    {
                        Ok(Ok(1)) => info!("peer store reloaded; trust_roots updated"),
                        Ok(Ok(_)) => {}
                        Ok(Err(err)) => warn!(?err, "peer store reload failed"),
                        Err(err) => warn!(?err, "peer store reload task panicked"),
                    }
                }
            }
        }
    })
}

async fn graceful_close_endpoint(endpoint: &iroh::Endpoint) {
    if let Err(err) =
        tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.close()).await
    {
        warn!(?err, "endpoint close exceeded 10 second shutdown budget");
    }
}

fn collect_shell_processes(state: &AgentState) -> Vec<Arc<shell_registry::ShellProcess>> {
    state
        .shell_registry
        .iter()
        .map(|entry| Arc::clone(entry.value()))
        .collect::<Vec<_>>()
}

async fn graceful_shutdown_shell_processes(
    processes: Vec<Arc<shell_registry::ShellProcess>>,
) -> bool {
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

fn home_from_peers_path(path: &Path) -> Option<PathBuf> {
    let parent = path.parent()?;
    if parent.file_name().and_then(|name| name.to_str()) == Some("data") {
        parent.parent().map(Path::to_path_buf)
    } else {
        Some(parent.to_path_buf())
    }
}

fn revocations_path(cfg: &AgentConfig) -> PathBuf {
    cfg.revocations_path
        .clone()
        .unwrap_or_else(portl_core::paths::revocations_path)
}

#[cfg(test)]
mod tests {
    use portl_core::test_util;
    use tokio_util::sync::CancellationToken;

    use super::{AgentConfig, DiscoveryConfig, run_task, run_with_shutdown};

    fn isolate_config_home(config: &mut AgentConfig, home: &std::path::Path) {
        let paths = portl_core::paths::for_home(home);
        config.peers_path = Some(paths.peers_path());
        config.revocations_path = Some(paths.revocations_path());
    }

    #[test]
    fn ad_hoc_agent_config_does_not_enable_metrics_by_default() {
        assert!(!super::metrics_enabled(&AgentConfig::default()));
        assert!(super::metrics_enabled(&AgentConfig {
            metrics_enabled: Some(true),
            ..AgentConfig::default()
        }));
    }

    #[tokio::test]
    async fn run_task_returns_and_stops_when_endpoint_closes() {
        let endpoint = test_util::endpoint().await.expect("bind endpoint");
        let runtime_endpoint = endpoint.clone();
        let home = tempfile::tempdir().expect("temp home");
        let mut config = AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(runtime_endpoint),
            ..AgentConfig::default()
        };
        isolate_config_home(&mut config, home.path());
        let handle = run_task(config).await.expect("spawn task");

        endpoint.inner().close().await;
        handle.await.expect("join handle").expect("run result");
    }

    #[tokio::test]
    async fn run_with_shutdown_stops_when_token_is_cancelled() {
        let endpoint = test_util::endpoint().await.expect("bind endpoint");
        let shutdown = CancellationToken::new();
        let home = tempfile::tempdir().expect("temp home");
        let mut config = AgentConfig {
            discovery: DiscoveryConfig::in_process(),
            endpoint: Some(endpoint),
            ..AgentConfig::default()
        };
        isolate_config_home(&mut config, home.path());
        let task = tokio::spawn(run_with_shutdown(config, shutdown.clone()));

        shutdown.cancel();
        tokio::time::timeout(std::time::Duration::from_secs(3), task)
            .await
            .expect("join timeout")
            .expect("join handle")
            .expect("run result");
    }
}
