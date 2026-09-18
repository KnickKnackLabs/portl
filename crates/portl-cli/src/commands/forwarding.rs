use std::path::PathBuf;
use std::time::Duration;
use std::time::Instant;

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use portl_core::net::PeerSession;
use portl_core::net::{
    LocalUdpForwardHandle, LocalUnixForwardListener, UnixListenControl,
    bind_local_forward_listener, bind_local_unix_listener, open_tcp, open_udp, open_unix,
    open_unix_listen,
    run_local_forward_with_listener_quiet as run_local_tcp_forward_with_listener_quiet,
    run_local_unix_forward_with_listener_quiet, run_unix_reverse_forwards_quiet,
};
use portl_core::ticket::schema::{Capabilities, PortRule};
use portl_proto::udp_v1::UdpBind;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::watch;

use crate::commands::network_lifecycle::{self, Backoff};
use crate::commands::peer_resolve::ConnectedPeer;
use crate::commands::stream_io::forward_stream;
use crate::commands::{socket, tcp, udp};

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ForwardingArgs {
    pub(crate) local: Vec<String>,
    pub(crate) remote: Vec<String>,
}

impl ForwardingArgs {
    pub(crate) fn is_empty(&self) -> bool {
        self.local.is_empty() && self.remote.is_empty()
    }

    pub(crate) fn parse(&self, peer: &str, source_label: &str) -> Result<ForwardPlan> {
        let mut tcp = Vec::new();
        let mut udp = Vec::new();
        let mut unix_l = Vec::new();
        let mut unix_r = Vec::new();

        for spec in &self.local {
            if looks_like_unix_socket_spec(spec) {
                unix_l.push(spec.clone());
            } else if spec.ends_with("/udp") {
                udp.push(udp::parse_local_spec(spec)?);
            } else {
                tcp.push(tcp::parse_local_spec(spec)?);
            }
        }

        for spec in &self.remote {
            if looks_like_unix_socket_spec(spec) {
                unix_r.push(spec.clone());
            } else {
                bail!(
                    "TCP/UDP -R forwarding is not supported yet; use Unix socket -R or an explicit portl socket command"
                );
            }
        }

        let unix = if unix_l.is_empty() && unix_r.is_empty() {
            Vec::new()
        } else {
            socket::parse_new_socket_modes(peer, source_label, &unix_l, &unix_r, false)?
        };

        Ok(ForwardPlan { tcp, udp, unix })
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ForwardPlan {
    pub(crate) tcp: Vec<tcp::LocalForwardSpec>,
    pub(crate) udp: Vec<udp::LocalForwardSpec>,
    pub(crate) unix: Vec<socket::SocketMode>,
}

impl ForwardPlan {
    pub(crate) fn is_empty(&self) -> bool {
        self.tcp.is_empty() && self.udp.is_empty() && self.unix.is_empty()
    }

    pub(crate) fn augment_caps(&self, caps: &mut Capabilities) {
        if !self.tcp.is_empty() {
            caps.presence |= 0b0000_0010;
            let rules = caps.tcp.get_or_insert_with(Vec::new);
            rules.push(PortRule {
                host_glob: "*".to_owned(),
                port_min: 1,
                port_max: u16::MAX,
            });
            sort_dedup_port_rules(rules);
        }
        if !self.udp.is_empty() {
            caps.presence |= 0b0000_0100;
            let rules = caps.udp.get_or_insert_with(Vec::new);
            rules.push(PortRule {
                host_glob: "*".to_owned(),
                port_min: 1,
                port_max: u16::MAX,
            });
            sort_dedup_port_rules(rules);
        }
        if !self.unix.is_empty() {
            let unix_caps = socket::socket_caps_for_modes(&self.unix)
                .unix
                .expect("socket caps contain unix caps");
            caps.presence |= 0b0100_0000;
            let target = caps
                .unix
                .get_or_insert_with(|| portl_core::ticket::schema::UnixCaps {
                    connect: Vec::new(),
                    listen: Vec::new(),
                });
            target.connect.extend(unix_caps.connect);
            target.listen.extend(unix_caps.listen);
            target.connect.sort_by(|a, b| a.path.cmp(&b.path));
            target.connect.dedup_by(|a, b| a.path == b.path);
            target.listen.sort_by(|a, b| a.path.cmp(&b.path));
            target.listen.dedup_by(|a, b| a.path == b.path);
        }
    }

    #[allow(clippy::format_push_string)]
    pub(crate) fn render_summary(&self, peer: &str, source_label: &str) -> String {
        if self.is_empty() {
            return String::new();
        }
        let mut out = format!("Forwarding through {peer}\n");
        if !self.tcp.is_empty() {
            out.push_str("\nTCP ports:\n");
            let width = self
                .tcp
                .iter()
                .map(|spec| spec.local_addr().len())
                .max()
                .unwrap_or(0);
            for spec in &self.tcp {
                out.push_str(&format!(
                    "  -L  {local:<width$} -> {peer}:{}:{}\n",
                    spec.remote_host,
                    spec.remote_port,
                    local = spec.local_addr(),
                ));
            }
        }
        if !self.udp.is_empty() {
            out.push_str("\nUDP ports:\n");
            let width = self
                .udp
                .iter()
                .map(|spec| spec.local_addr().len())
                .max()
                .unwrap_or(0);
            for spec in &self.udp {
                out.push_str(&format!(
                    "  -L  {local:<width$} -> {peer}:{}:{}\n",
                    spec.remote_host,
                    spec.remote_port,
                    local = spec.local_addr(),
                ));
            }
        }
        if !self.unix.is_empty() {
            out.push_str("\nUnix sockets:\n");
            for (index, mode) in self.unix.iter().enumerate() {
                if index > 0 {
                    out.push('\n');
                }
                match mode {
                    socket::SocketMode::Connect {
                        local,
                        remote,
                        generated,
                        ..
                    } => {
                        let label = if *generated {
                            "generated local socket"
                        } else {
                            "explicit local socket"
                        };
                        out.push_str(&format!(
                            "  -L  {source_label}:{local}\n      -> {peer}:{remote}\n      {label}\n"
                        ));
                    }
                    socket::SocketMode::Listen {
                        remote,
                        local,
                        generated,
                        ..
                    } => {
                        let label = if *generated {
                            "generated remote socket"
                        } else {
                            "explicit remote socket"
                        };
                        out.push_str(&format!(
                            "  -R  {peer}:{remote}\n      -> {source_label}:{local}\n      {label}\n"
                        ));
                    }
                }
            }
        }
        out.push_str("\nWaiting for forwarded connections. Press Ctrl-C to stop.\n");
        out
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn start(&self, connected: &ConnectedPeer) -> Result<ForwardRuntime> {
        self.start_with_options(connected, ForwardStartOptions::default())
            .await
    }

    #[allow(clippy::too_many_lines)]
    pub(crate) async fn start_for_attach(
        &self,
        connected: &ConnectedPeer,
    ) -> Result<ForwardRuntime> {
        self.start_resilient(Some(connected), true).await
    }

    pub(crate) fn cleanup_attach_local_unix_sockets(&self) {
        for mode in &self.unix {
            if let socket::SocketMode::Connect { local, .. } = mode {
                cleanup_unix_socket_paths(&[PathBuf::from(local)]);
            }
        }
    }

    pub(crate) async fn start_persistent(&self) -> Result<ForwardRuntime> {
        self.start_resilient(None, false).await
    }

    #[allow(clippy::too_many_lines)]
    async fn start_resilient(
        &self,
        connected: Option<&ConnectedPeer>,
        cleanup_explicit: bool,
    ) -> Result<ForwardRuntime> {
        let (peer_tx, peer_rx) = watch::channel(connected.map(|peer| ForwardPeer::new(peer, 0)));
        let mut runtime = ForwardRuntime {
            tasks: Vec::new(),
            listen_controls: Vec::new(),
            peer_tx: Some(peer_tx),
            generation: 0,
            cleanup_unix_paths: Vec::new(),
        };
        let mut tcp_listeners = Vec::new();
        let mut udp_forwards = Vec::new();
        let mut unix_listeners = Vec::new();
        let mut unix_reverse = Vec::new();

        // Bind everything before spawning. A later bind failure drops all earlier
        // listeners immediately, rather than detaching their tasks.
        for spec in &self.tcp {
            let listener = bind_local_forward_listener(&spec.local_addr()).await?;
            tcp_listeners.push((spec.clone(), listener));
        }
        for spec in &self.udp {
            udp_forwards.push((
                spec.clone(),
                LocalUdpForwardHandle::bind(&spec.local_addr())?,
            ));
        }
        for mode in &self.unix {
            match mode {
                socket::SocketMode::Connect {
                    local,
                    remote,
                    cleanup,
                    generated,
                } => {
                    if *generated {
                        socket::ensure_generated_socket_parent(local, "portl-to-")?;
                    }
                    let cleanup = *cleanup || (cleanup_explicit && !*generated);
                    let listener = bind_local_unix_listener(local, cleanup)?;
                    if cleanup {
                        runtime.cleanup_unix_paths.push(PathBuf::from(local));
                    }
                    unix_listeners.push((local.clone(), remote.clone(), listener));
                }
                socket::SocketMode::Listen {
                    remote,
                    local,
                    cleanup,
                    generated,
                } => {
                    unix_reverse.push((
                        remote.clone(),
                        local.clone(),
                        *cleanup || (cleanup_explicit && !*generated),
                    ));
                }
            }
        }
        for (spec, listener) in tcp_listeners {
            runtime
                .tasks
                .push(tokio::spawn(run_resilient_tcp_forward_listener(
                    listener,
                    peer_rx.clone(),
                    spec.local_addr(),
                    spec.remote_host,
                    spec.remote_port,
                )));
        }
        for (spec, forward) in udp_forwards {
            runtime.tasks.push(tokio::spawn(run_resilient_udp_forward(
                forward,
                peer_rx.clone(),
                spec,
            )));
        }
        for (local, remote, listener) in unix_listeners {
            runtime
                .tasks
                .push(tokio::spawn(run_resilient_unix_forward_listener(
                    listener,
                    peer_rx.clone(),
                    local,
                    remote,
                )));
        }
        if !unix_reverse.is_empty() {
            runtime
                .tasks
                .push(tokio::spawn(run_resilient_unix_reverse_forward(
                    peer_rx,
                    unix_reverse,
                )));
        }
        Ok(runtime)
    }

    #[allow(clippy::too_many_lines)]
    async fn start_with_options(
        &self,
        connected: &ConnectedPeer,
        options: ForwardStartOptions,
    ) -> Result<ForwardRuntime> {
        let mut tcp_forwards = Vec::new();
        let mut udp_forwards = Vec::new();
        let mut unix_connects = Vec::new();
        let mut unix_listens = Vec::new();

        for spec in &self.tcp {
            let local_addr = spec.local_addr();
            let listener = bind_local_forward_listener(&local_addr).await?;
            tcp_forwards.push((
                listener,
                local_addr,
                spec.remote_host.clone(),
                spec.remote_port,
            ));
        }

        for spec in &self.udp {
            let forward = LocalUdpForwardHandle::bind(&spec.local_addr())?;
            udp_forwards.push((spec.clone(), forward));
        }

        for mode in &self.unix {
            match mode {
                socket::SocketMode::Connect {
                    local,
                    remote,
                    cleanup,
                    generated,
                } => {
                    if *generated {
                        socket::ensure_generated_socket_parent(local, "portl-to-")?;
                    }
                    let cleanup =
                        *cleanup || (options.cleanup_explicit_unix_sockets && !*generated);
                    let listener = bind_local_unix_listener(local, cleanup)?;
                    unix_connects.push((listener, local.clone(), remote.clone()));
                }
                socket::SocketMode::Listen {
                    remote,
                    local,
                    cleanup,
                    generated,
                } => {
                    let cleanup =
                        *cleanup || (options.cleanup_explicit_unix_sockets && !*generated);
                    unix_listens.push((remote.clone(), local.clone(), cleanup));
                }
            }
        }

        let mut udp_ready = Vec::new();
        for (spec, forward) in udp_forwards {
            let control = open_udp(
                &connected.connection,
                &connected.session,
                forward.session_id(),
                vec![UdpBind {
                    local_port_range: (spec.local_port, spec.local_port),
                    target_host: spec.remote_host.clone(),
                    target_port_range: (spec.remote_port, spec.remote_port),
                }],
            )
            .await?;
            udp_ready.push((spec, forward, control));
        }

        let mut listen_controls = Vec::new();
        let mut reverse_forwards = Vec::new();
        for (remote, local, cleanup) in unix_listens {
            let control =
                open_unix_listen(&connected.connection, &connected.session, &remote, cleanup)
                    .await?;
            listen_controls.push(control);
            reverse_forwards.push((remote, local));
        }

        let mut tasks = Vec::new();
        for (listener, local_addr, remote_host, remote_port) in tcp_forwards {
            let connection = connected.connection.clone();
            let session = connected.session.clone();
            tasks.push(tokio::spawn(async move {
                run_local_tcp_forward_with_listener_quiet(
                    listener,
                    connection,
                    session,
                    local_addr,
                    remote_host,
                    remote_port,
                )
                .await
            }));
        }

        for (spec, forward, control) in udp_ready {
            let connection = connected.connection.clone();
            let remote_port = spec.remote_port;
            tasks.push(tokio::spawn(async move {
                let opened_at = Instant::now();
                let start_stats = forward.stats_snapshot();
                tracing::info!(message = %udp::format_open_line(&spec), "udp forwarding event");
                let result = forward
                    .run_with_control(connection, control, remote_port)
                    .await;
                let stats = forward.stats_snapshot().delta_since(start_stats);
                match &result {
                    Ok(()) => tracing::info!(
                        message = %udp::format_close_line(&spec, opened_at.elapsed(), stats),
                        "udp forwarding event"
                    ),
                    Err(err) => tracing::info!(
                        message = %format!(
                            "[udp -L {}] closed after {}, error={err}",
                            spec.local_addr(),
                            udp::format_duration(opened_at.elapsed())
                        ),
                        "udp forwarding event"
                    ),
                }
                result
            }));
        }

        for (listener, local, remote) in unix_connects {
            tasks.push(tokio::spawn(run_local_unix_forward_with_listener_quiet(
                listener,
                connected.connection.clone(),
                connected.session.clone(),
                local,
                remote,
            )));
        }

        if !reverse_forwards.is_empty() {
            tasks.push(tokio::spawn(run_unix_reverse_forwards_quiet(
                connected.connection.clone(),
                connected.session.clone(),
                reverse_forwards,
            )));
        }

        Ok(ForwardRuntime {
            tasks,
            listen_controls,
            peer_tx: None,
            generation: 0,
            cleanup_unix_paths: Vec::new(),
        })
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ForwardStartOptions {
    cleanup_explicit_unix_sockets: bool,
}

#[derive(Clone)]
struct ForwardPeer {
    connection: Connection,
    session: PeerSession,
    generation: u64,
    udp_fanout: std::sync::Arc<std::sync::OnceLock<portl_core::net::udp_client::UdpDatagramFanout>>,
}

impl ForwardPeer {
    fn new(connected: &ConnectedPeer, generation: u64) -> Self {
        Self {
            connection: connected.connection.clone(),
            session: connected.session.clone(),
            generation,
            udp_fanout: std::sync::Arc::new(std::sync::OnceLock::new()),
        }
    }
}

async fn wait_for_forward_peer(
    rx: &mut watch::Receiver<Option<ForwardPeer>>,
) -> Result<ForwardPeer> {
    loop {
        if let Some(peer) = rx.borrow_and_update().clone()
            && peer.connection.close_reason().is_none()
        {
            tracing::debug!(
                generation = peer.generation,
                "forward using peer generation"
            );
            return Ok(peer);
        }
        // The owning command sets the reconnect budget. A worker must not
        // disappear just because a separate, shorter hold timer expired.
        rx.changed().await.context("forward peer owner stopped")?;
    }
}

async fn run_resilient_tcp_forward_listener(
    listener: TcpListener,
    peer_rx: watch::Receiver<Option<ForwardPeer>>,
    local_addr: String,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    let mut clients = tokio::task::JoinSet::new();
    loop {
        let (local, client_addr) = tokio::select! {
            accepted = listener.accept() => accepted.context("accept local tcp connection")?,
            result = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "TCP client task failed");
                }
                continue;
            }
        };
        let peer_rx = peer_rx.clone();
        let local_addr = local_addr.clone();
        let remote_host = remote_host.clone();
        clients.spawn(async move {
            let started = Instant::now();
            tracing::info!(
                message = %format!(
                    "[tcp -L {local_addr}] opened client={client_addr} -> remote {remote_host}:{remote_port}"
                ),
                "tcp forwarding event"
            );
            match forward_resilient_tcp_client(local, peer_rx, &remote_host, remote_port).await {
                Ok(stats) => tracing::info!(
                    message = %portl_core::net::tcp_client::format_close_line(&local_addr, client_addr, started.elapsed(), stats),
                    "tcp forwarding event"
                ),
                Err(err) => tracing::info!(
                    message = %format!(
                        "[tcp -L {local_addr}] closed client={client_addr} after {}, error={}",
                        udp::format_duration(started.elapsed()),
                        portl_core::diagnostics::redact_text(&format!("{err:#}"))
                    ),
                    "tcp forwarding event"
                ),
            }
        });
    }
}

async fn forward_resilient_tcp_client(
    local: TcpStream,
    peer_rx: watch::Receiver<Option<ForwardPeer>>,
    remote_host: &str,
    remote_port: u16,
) -> Result<portl_core::net::tcp_client::TcpForwardStats> {
    let peer = peer_rx
        .borrow()
        .clone()
        .context("forward unavailable while peer reconnects")?;
    let (send, recv) = network_lifecycle::setup(
        "TCP forward setup",
        open_tcp(&peer.connection, &peer.session, remote_host, remote_port),
    )
    .await?;
    let (upstream_bytes, downstream_bytes) = forward_stream(local, recv, send).await?;
    Ok(portl_core::net::tcp_client::TcpForwardStats {
        upstream_bytes,
        downstream_bytes,
    })
}

async fn run_resilient_unix_forward_listener(
    listener: LocalUnixForwardListener,
    peer_rx: watch::Receiver<Option<ForwardPeer>>,
    local_path: String,
    remote_path: String,
) -> Result<()> {
    let mut clients = tokio::task::JoinSet::new();
    loop {
        let (local, _) = tokio::select! {
            accepted = listener.accept() => accepted.context("accept local unix connection")?,
            result = clients.join_next(), if !clients.is_empty() => {
                if let Some(Err(error)) = result {
                    tracing::warn!(%error, "Unix client task failed");
                }
                continue;
            }
        };
        let peer_rx = peer_rx.clone();
        let local_path = local_path.clone();
        let remote_path = remote_path.clone();
        clients.spawn(async move {
            let started = Instant::now();
            tracing::info!(
                message = %format!("[unix -L {local_path}] opened -> remote {remote_path}"),
                "unix forwarding event"
            );
            match forward_resilient_unix_client(local, peer_rx, &remote_path).await {
                Ok(stats) => tracing::info!(
                    message = %portl_core::net::unix_client::format_close_line("-L", &local_path, started.elapsed(), stats),
                    "unix forwarding event"
                ),
                Err(err) => tracing::info!(
                    message = %format!(
                        "[unix -L {local_path}] closed after {}, error={}",
                        udp::format_duration(started.elapsed()),
                        portl_core::diagnostics::redact_text(&format!("{err:#}"))
                    ),
                    "unix forwarding event"
                ),
            }
        });
    }
}

async fn forward_resilient_unix_client(
    local: UnixStream,
    peer_rx: watch::Receiver<Option<ForwardPeer>>,
    remote_path: &str,
) -> Result<portl_core::net::unix_client::UnixForwardStats> {
    let peer = peer_rx
        .borrow()
        .clone()
        .context("forward unavailable while peer reconnects")?;
    let (send, recv) = network_lifecycle::setup(
        "Unix forward setup",
        open_unix(&peer.connection, &peer.session, remote_path),
    )
    .await?;
    let (upstream_bytes, downstream_bytes) = forward_stream(local, recv, send).await?;
    Ok(portl_core::net::unix_client::UnixForwardStats {
        upstream_bytes,
        downstream_bytes,
    })
}

async fn run_resilient_udp_forward(
    forward: LocalUdpForwardHandle,
    mut peer_rx: watch::Receiver<Option<ForwardPeer>>,
    spec: udp::LocalForwardSpec,
) -> Result<()> {
    let mut backoff = Backoff::default();
    loop {
        let peer = wait_for_forward_peer(&mut peer_rx).await?;
        let started = Instant::now();
        let operation = async {
            let control = network_lifecycle::setup(
                "UDP control setup",
                open_udp(
                    &peer.connection,
                    &peer.session,
                    forward.session_id(),
                    vec![UdpBind {
                        local_port_range: (spec.local_port, spec.local_port),
                        target_host: spec.remote_host.clone(),
                        target_port_range: (spec.remote_port, spec.remote_port),
                    }],
                ),
            )
            .await?;
            let start_stats = forward.stats_snapshot();
            tracing::info!(message = %udp::format_open_line(&spec), "udp forwarding event");
            let fanout = peer.udp_fanout.get_or_init(|| {
                portl_core::net::udp_client::UdpDatagramFanout::new(peer.connection.clone())
            });
            let result = forward
                .run_with_control_via_fanout(
                    peer.connection.clone(),
                    control,
                    spec.remote_port,
                    fanout,
                )
                .await;
            tracing::info!(message = %udp::format_close_line(&spec, started.elapsed(), forward.stats_snapshot().delta_since(start_stats)), "udp forwarding event");
            result
        };
        let result = tokio::select! {
            result = operation => result,
            _ = peer.connection.closed() => continue,
            changed = peer_rx.changed() => {
                changed.context("forward peer owner stopped")?;
                continue;
            }
        };
        if let Err(error) = result {
            if !network_lifecycle::retryable(&error) {
                return Err(error).context("UDP forward rejected");
            }
            tracing::warn!(error = %portl_core::diagnostics::redact_text(&format!("{error:#}")), local = %spec.local_addr(), "UDP control retry");
        }
        if started.elapsed() >= Duration::from_secs(30) {
            backoff.reset();
        }
        tokio::select! {
            () = tokio::time::sleep(backoff.next()) => {},
            _ = peer.connection.closed() => {},
            changed = peer_rx.changed() => { changed.context("forward peer owner stopped")?; }
        }
    }
}

async fn run_resilient_unix_reverse_forward(
    mut peer_rx: watch::Receiver<Option<ForwardPeer>>,
    forwards: Vec<(String, String, bool)>,
) -> Result<()> {
    loop {
        let peer = wait_for_forward_peer(&mut peer_rx).await?;
        let operation = async {
            let deadline = tokio::time::Instant::now() + network_lifecycle::SETUP_TIMEOUT;
            let mut controls = Vec::new();
            let mut routes = Vec::new();
            for (remote, local, cleanup) in &forwards {
                let control = network_lifecycle::before_deadline(
                    deadline,
                    "reverse Unix listener setup",
                    open_unix_listen(&peer.connection, &peer.session, remote, *cleanup),
                )
                .await?;
                controls.push(control);
                routes.push((remote.clone(), local.clone()));
            }
            let result = run_unix_reverse_forwards_quiet(
                peer.connection.clone(),
                peer.session.clone(),
                routes,
            )
            .await;
            for control in controls {
                let _ = control.close();
            }
            result
        };
        let result = tokio::select! {
            result = operation => result,
            _ = peer.connection.closed() => continue,
            changed = peer_rx.changed() => {
                changed.context("forward peer owner stopped")?;
                continue;
            }
        };
        if peer.connection.close_reason().is_some() {
            continue;
        }
        // A live peer may have applied a listen request before its reply was
        // lost. Do not blindly repeat that mutation on the same connection.
        result.context("reverse Unix forward stopped; setup was not replayed")?;
        bail!("reverse Unix forward ended while the peer was still connected");
    }
}

pub(crate) fn supervise_forwarding<'a, T: 'a>(
    runtime: &'a mut Option<ForwardRuntime>,
    operation: impl Future<Output = Result<T>> + 'a,
) -> impl Future<Output = Result<T>> + 'a {
    // Box before constructing the outer future so nested attach/reconnect
    // operations do not multiply its stack allocation.
    let operation = Box::pin(operation);
    async move {
        let Some(runtime) = runtime else {
            return operation.await;
        };
        tokio::select! {
            result = operation => result,
            error = runtime.failed() => Err(error.context(network_lifecycle::RetryClass::Permanent)),
        }
    }
}

pub(crate) struct ForwardRuntime {
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    listen_controls: Vec<UnixListenControl>,
    peer_tx: Option<watch::Sender<Option<ForwardPeer>>>,
    generation: u64,
    cleanup_unix_paths: Vec<PathBuf>,
}

impl ForwardRuntime {
    pub(crate) fn reconnect(&mut self, connected: &ConnectedPeer) {
        if let Some(peer_tx) = &self.peer_tx {
            if peer_tx
                .borrow()
                .as_ref()
                .is_some_and(|peer| peer.connection.stable_id() == connected.connection.stable_id())
            {
                return;
            }
            self.generation = self.generation.saturating_add(1);
            peer_tx.send_replace(Some(ForwardPeer::new(connected, self.generation)));
        }
    }

    pub(crate) fn disconnected(&mut self) {
        if let Some(peer_tx) = &self.peer_tx {
            peer_tx.send_replace(None);
        }
    }

    pub(crate) async fn failed(&mut self) -> anyhow::Error {
        std::future::poll_fn(|cx| {
            for index in 0..self.tasks.len() {
                if let std::task::Poll::Ready(result) =
                    std::pin::Pin::new(&mut self.tasks[index]).poll(cx)
                {
                    drop(self.tasks.swap_remove(index));
                    let error = match result {
                        Ok(Ok(())) => anyhow::anyhow!("forward worker ended unexpectedly"),
                        Ok(Err(error)) => error.context("forward worker failed"),
                        Err(error) => anyhow::Error::new(error)
                            .context("forward worker panicked or was cancelled"),
                    };
                    return std::task::Poll::Ready(error);
                }
            }
            std::task::Poll::Pending
        })
        .await
    }

    pub(crate) async fn shutdown(&mut self) {
        self.abort();
        if tokio::time::timeout(Duration::from_secs(2), async {
            for task in self.tasks.drain(..) {
                let _ = task.await;
            }
        })
        .await
        .is_err()
        {
            tracing::warn!("forward worker shutdown deadline exceeded");
        }
    }

    pub(crate) fn abort(&mut self) {
        for control in self.listen_controls.drain(..) {
            let _ = control.close();
        }
        for task in &self.tasks {
            task.abort();
        }
        cleanup_unix_socket_paths(&self.cleanup_unix_paths);
    }
}

#[cfg(unix)]
fn cleanup_unix_socket_paths(paths: &[PathBuf]) {
    for path in paths {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(not(unix))]
fn cleanup_unix_socket_paths(_paths: &[PathBuf]) {}

impl Drop for ForwardRuntime {
    fn drop(&mut self) {
        self.abort();
    }
}

fn sort_dedup_port_rules(rules: &mut Vec<PortRule>) {
    rules.sort_by(|a, b| {
        a.host_glob
            .cmp(&b.host_glob)
            .then(a.port_min.cmp(&b.port_min))
            .then(a.port_max.cmp(&b.port_max))
    });
    rules.dedup_by(|a, b| {
        a.host_glob == b.host_glob && a.port_min == b.port_min && a.port_max == b.port_max
    });
}

fn looks_like_unix_socket_spec(spec: &str) -> bool {
    spec.starts_with('/')
        || spec.starts_with(':')
        || spec
            .split_once(':')
            .is_some_and(|(left, right)| left.starts_with('/') || right.starts_with('/'))
}

pub(crate) fn source_label() -> Result<String> {
    socket::local_socket_source_label()
}

pub(crate) fn parse_for_target(peer: &str, args: &ForwardingArgs) -> Result<(String, ForwardPlan)> {
    let source_label = source_label().context("resolve local forwarding label")?;
    let plan = args.parse(peer, &source_label)?;
    Ok((source_label, plan))
}

#[cfg(test)]
mod tests {
    use std::os::unix::net::UnixListener;

    use super::ForwardingArgs;
    use crate::commands::peer_resolve::ConnectedPeer;
    use portl_core::net::PeerSession;
    use portl_core::test_util::pair;
    use portl_core::ticket::schema::{Capabilities, ShellCaps};

    const TEST_ALPN: &[u8] = b"portl/forwarding-plan-start-test/v1";

    #[tokio::test(start_paused = true)]
    async fn disconnected_worker_waits_for_owner_and_observes_owner_shutdown() {
        let (tx, mut rx) = tokio::sync::watch::channel(None);
        let worker = tokio::spawn(async move { super::wait_for_forward_peer(&mut rx).await });
        tokio::task::yield_now().await;
        tokio::time::advance(std::time::Duration::from_secs(121)).await;
        assert!(!worker.is_finished());
        drop(tx);
        assert!(worker.await.unwrap().is_err());
    }

    #[test]
    fn parses_mixed_local_and_remote_forwarding_flags() {
        let args = ForwardingArgs {
            local: vec![
                "8080:3000".to_owned(),
                "5353/udp".to_owned(),
                "/run/herdr.sock".to_owned(),
            ],
            remote: vec!["/tmp/local-agent.sock".to_owned()],
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        assert_eq!(plan.tcp.len(), 1);
        assert_eq!(plan.udp.len(), 1);
        assert_eq!(plan.unix.len(), 2);
    }

    #[test]
    fn rejects_remote_port_forwarding_until_protocol_exists() {
        let args = ForwardingArgs {
            local: Vec::new(),
            remote: vec!["9000:localhost:9000".to_owned()],
        };
        let err = args
            .parse("remote-dev", "local-dev")
            .expect_err("remote TCP -R should fail");
        assert!(
            err.to_string()
                .contains("TCP/UDP -R forwarding is not supported yet")
        );
    }

    #[test]
    fn renders_mixed_forwarding_summary_once() {
        let args = ForwardingArgs {
            local: vec!["8080:3000".to_owned(), "/run/herdr.sock".to_owned()],
            remote: Vec::new(),
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        let summary = plan.render_summary("remote-dev", "local-dev");
        assert_eq!(summary.matches("Forwarding through remote-dev").count(), 1);
        assert!(summary.contains("TCP ports:"));
        assert!(summary.contains("Unix sockets:"));
    }

    #[tokio::test]
    async fn forwarding_plan_start_fails_before_session_when_tcp_port_is_occupied() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = occupied.local_addr().unwrap();
        let (connected, accept_task) = connected_test_peer().await;
        let args = ForwardingArgs {
            local: vec![format!(
                "{}:{}",
                local_addr.port(),
                local_addr.port().saturating_add(1)
            )],
            remote: Vec::new(),
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();

        let Err(err) = plan.start(&connected).await else {
            panic!("occupied local TCP port should fail before attach/shell starts");
        };
        assert!(err.to_string().contains("bind local listener"), "{err}");
        finish_connected_test_peer(connected, accept_task).await;
    }

    #[tokio::test]
    async fn forwarding_plan_start_does_not_leave_partial_tcp_listener_when_later_bind_fails() {
        let first_port = unused_tcp_port().await;
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let occupied_port = occupied.local_addr().unwrap().port();
        let (connected, accept_task) = connected_test_peer().await;
        let args = ForwardingArgs {
            local: vec![
                format!("{}:{}", first_port, first_port.saturating_add(1)),
                format!("{}:{}", occupied_port, occupied_port.saturating_add(1)),
            ],
            remote: Vec::new(),
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();

        for resilient in [false, true] {
            let result = if resilient {
                plan.start_for_attach(&connected).await
            } else {
                plan.start(&connected).await
            };
            let Err(err) = result else {
                panic!("occupied second TCP port should fail plan startup");
            };
            assert!(err.to_string().contains("bind local listener"), "{err}");
            let _rebound = tokio::net::TcpListener::bind(format!("127.0.0.1:{first_port}"))
                .await
                .expect("failed startup must release the first listener immediately");
        }
        finish_connected_test_peer(connected, accept_task).await;
    }

    #[tokio::test]
    async fn attach_forwarding_reaps_stale_explicit_local_unix_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("cua-driver.sock");
        let stale_listener = UnixListener::bind(&path).unwrap();
        drop(stale_listener);

        let (connected, accept_task) = connected_test_peer().await;
        let args = ForwardingArgs {
            local: vec![format!("{}:/remote/cua-driver.sock", path.display())],
            remote: Vec::new(),
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();

        let Err(err) = plan.start(&connected).await else {
            panic!("default forwarding should refuse stale explicit sockets");
        };
        assert!(
            err.to_string().contains("bind local unix listener"),
            "{err}"
        );

        let runtime = plan.start_for_attach(&connected).await.unwrap();
        assert!(path.exists(), "attach runtime should own the socket path");
        drop(runtime);
        wait_for_socket_removal(&path).await;
        finish_connected_test_peer(connected, accept_task).await;
    }

    async fn unused_tcp_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        listener.local_addr().unwrap().port()
    }

    async fn wait_for_socket_removal(path: &std::path::Path) {
        for _ in 0..20 {
            if !path.exists() {
                return;
            }
            tokio::task::yield_now().await;
        }
        assert!(!path.exists(), "socket path was not removed: {path:?}");
    }

    #[tokio::test]
    async fn persistent_listener_starts_offline_and_recovers_on_the_same_port() {
        use std::time::Duration;
        use tokio::io::AsyncReadExt;

        let port = unused_tcp_port().await;
        let address = format!("127.0.0.1:{port}");
        let plan = super::ForwardPlan {
            tcp: vec![crate::commands::tcp::parse_local_spec(&format!("{port}:1234")).unwrap()],
            ..super::ForwardPlan::default()
        };
        let mut runtime = plan.start_persistent().await.unwrap();
        let mut offline = tokio::net::TcpStream::connect(&address).await.unwrap();
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), offline.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
        assert!(tokio::net::TcpListener::bind(&address).await.is_err());
        drop(offline);

        let (first, first_server) = echo_test_peer().await;
        let (second, second_server) = echo_test_peer().await;
        // Production keeps its endpoint alive across peer generations. Keep
        // these fixture endpoints alive too, so they can send QUIC close frames.
        let first_endpoint = first.endpoint.clone();
        let second_endpoint = second.endpoint.clone();
        let first_connection = first.connection.clone();
        let second_id = second.connection.stable_id();
        let mut state = runtime.peer_tx.as_ref().unwrap().subscribe();
        let mut attempts = std::collections::VecDeque::from([
            Err(anyhow::anyhow!("temporary transport failure")),
            Ok(first),
            Ok(second),
        ]);
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let owner = tokio::spawn(async move {
            let mut shutdown = Box::pin(async { stopped.await.map_err(anyhow::Error::from) });
            let result =
                crate::commands::persistent_forward::supervise(&mut runtime, &mut shutdown, || {
                    std::future::ready(
                        attempts
                            .pop_front()
                            .expect("unexpected extra connection attempt"),
                    )
                })
                .await;
            runtime.shutdown().await;
            assert!(attempts.is_empty());
            result
        });
        tokio::time::timeout(
            Duration::from_secs(5),
            super::wait_for_forward_peer(&mut state),
        )
        .await
        .unwrap()
        .unwrap();
        tcp_test_exchange(&address, b"before reconnect").await;
        first_connection.close(1u32.into(), b"test terminal peer failure");
        let recovered = tokio::time::timeout(
            Duration::from_secs(5),
            super::wait_for_forward_peer(&mut state),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(recovered.connection.stable_id(), second_id);
        tcp_test_exchange(&address, b"after reconnect").await;
        stop.send(()).unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), owner)
                .await
                .unwrap()
                .unwrap()
                .unwrap(),
            std::process::ExitCode::SUCCESS
        );
        tokio::time::timeout(Duration::from_secs(5), first_server)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(5), second_server)
            .await
            .unwrap()
            .unwrap();
        first_endpoint.close().await;
        second_endpoint.close().await;
        let _rebound = tokio::net::TcpListener::bind(&address).await.unwrap();
    }

    async fn tcp_test_exchange(address: &str, payload: &[u8]) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let mut client = tokio::net::TcpStream::connect(address).await.unwrap();
            client.write_all(payload).await.unwrap();
            client.shutdown().await.unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, payload);
        })
        .await
        .unwrap();
    }

    async fn echo_test_peer() -> (ConnectedPeer, tokio::task::JoinHandle<()>) {
        use tokio::io::AsyncReadExt;
        connected_test_peer_with_handler(|connection| async move {
            while let Ok((mut send, recv)) = connection.accept_bi().await {
                let mut recv = portl_core::io::BufferedRecv::new(recv, Vec::new());
                recv.read_frame::<portl_proto::tcp_v1::TcpReq>(4096)
                    .await
                    .unwrap()
                    .unwrap();
                send.write_all(
                    &postcard::to_stdvec(&portl_proto::tcp_v1::TcpAck {
                        ok: true,
                        error: None,
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
                let mut bytes = Vec::new();
                recv.read_to_end(&mut bytes).await.unwrap();
                send.write_all(&bytes).await.unwrap();
                send.finish().unwrap();
            }
        })
        .await
    }

    #[tokio::test]
    async fn dropping_peer_owner_closes_connection_even_when_workers_hold_clones() {
        let (connected, server) = connected_test_peer_with_handler(|connection| async move {
            connection.closed().await;
        })
        .await;
        let endpoint = connected.endpoint.clone();
        let worker_connection = connected.connection.clone();
        drop(connected);
        tokio::time::timeout(std::time::Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert!(worker_connection.close_reason().is_some());
        endpoint.close().await;
    }

    #[tokio::test]
    async fn worker_failure_is_observed_and_shutdown_can_reap_remaining_tasks() {
        let mut runtime = super::ForwardPlan::default()
            .start_persistent()
            .await
            .unwrap();
        runtime
            .tasks
            .push(tokio::spawn(async { anyhow::bail!("listener failed") }));
        let error = runtime.failed().await;
        assert!(format!("{error:#}").contains("listener failed"));
        runtime.shutdown().await;
        assert!(runtime.tasks.is_empty());
    }

    async fn connected_test_peer() -> (ConnectedPeer, tokio::task::JoinHandle<()>) {
        connected_test_peer_with_handler(|connection| async move {
            connection.close(0u32.into(), b"done");
        })
        .await
    }

    async fn connected_test_peer_with_handler<F, Fut>(
        handler: F,
    ) -> (ConnectedPeer, tokio::task::JoinHandle<()>)
    where
        F: FnOnce(iroh::endpoint::Connection) -> Fut + Send + 'static,
        Fut: Future<Output = ()> + Send + 'static,
    {
        let (client, server) = pair().await.expect("endpoint pair");
        server.inner().set_alpns(vec![TEST_ALPN.to_vec()]);
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.inner().accept().await.expect("incoming connection");
                let conn = incoming.await.expect("handshake");
                handler(conn).await;
            }
        });
        let connection = client
            .inner()
            .connect(server.addr(), TEST_ALPN)
            .await
            .expect("connect test endpoints");
        let connected = ConnectedPeer {
            endpoint: client.inner().clone(),
            connection,
            session: PeerSession {
                peer_token: [0; 16],
                effective_caps: Capabilities {
                    presence: 0,
                    shell: None,
                    tcp: None,
                    udp: None,
                    fs: None,
                    vpn: None,
                    meta: None,
                    unix: None,
                },
                server_time: 0,
                client_nonce_hash: [0; 16],
                supported_alpns: Vec::new(),
            },
            transport_observer: None,
        };
        (connected, accept_task)
    }

    #[tokio::test]
    async fn tcp_stream_reset_never_reopens_delivered_prefix() {
        reset_does_not_reopen(false).await;
    }

    #[tokio::test]
    async fn unix_stream_reset_never_reopens_delivered_prefix() {
        reset_does_not_reopen(true).await;
    }

    async fn reset_does_not_reopen(unix: bool) {
        use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};

        let (reset_tx, reset_rx) = tokio::sync::oneshot::channel();
        let (connected, accept_task) =
            connected_test_peer_with_handler(move |connection| async move {
                let (mut send, recv) = connection.accept_bi().await.unwrap();
                let mut recv = portl_core::io::BufferedRecv::new(recv, Vec::new());
                if unix {
                    recv.read_frame::<portl_proto::unix_v1::UnixReq>(4096)
                        .await
                        .unwrap()
                        .unwrap();
                } else {
                    recv.read_frame::<portl_proto::tcp_v1::TcpReq>(4096)
                        .await
                        .unwrap()
                        .unwrap();
                }
                // Both protocol versions encode this acknowledgement as (ok, error).
                send.write_all(
                    &postcard::to_stdvec(&portl_proto::tcp_v1::TcpAck {
                        ok: true,
                        error: None,
                    })
                    .unwrap(),
                )
                .await
                .unwrap();
                let mut prefix = [0; 6];
                recv.read_exact(&mut prefix).await.unwrap();
                assert_eq!(&prefix, b"prefix");
                send.reset(1u32.into()).unwrap();
                reset_tx.send(()).unwrap();
                assert!(
                    connection.accept_bi().await.is_err(),
                    "an established client reopened its destination"
                );
            })
            .await;
        let (peer_tx, peer_rx) =
            tokio::sync::watch::channel(Some(super::ForwardPeer::new(&connected, 0)));
        let (mut client, bridge): (
            Box<dyn AsyncWrite + Unpin + Send>,
            tokio::task::JoinHandle<anyhow::Result<()>>,
        ) = if unix {
            let (client, local) = tokio::net::UnixStream::pair().unwrap();
            (
                Box::new(client),
                tokio::spawn(async move {
                    super::forward_resilient_unix_client(local, peer_rx, "/tmp/test.sock")
                        .await
                        .map(|_| ())
                }),
            )
        } else {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (local, _) = listener.accept().await.unwrap();
            (
                Box::new(client),
                tokio::spawn(async move {
                    super::forward_resilient_tcp_client(local, peer_rx, "127.0.0.1", 1234)
                        .await
                        .map(|_| ())
                }),
            )
        };
        client.write_all(b"prefix").await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), reset_rx)
            .await
            .unwrap()
            .unwrap();
        // Publish a replacement generation while the original client remains open.
        peer_tx.send_replace(Some(super::ForwardPeer::new(&connected, 1)));
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(5), bridge)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        drop(client);
        finish_connected_test_peer(connected, accept_task).await;
    }

    async fn finish_connected_test_peer(
        connected: ConnectedPeer,
        accept_task: tokio::task::JoinHandle<()>,
    ) {
        connected.connection.close(0u32.into(), b"done");
        tokio::time::timeout(std::time::Duration::from_secs(5), accept_task)
            .await
            .expect("accept task timeout")
            .expect("accept task panic");
    }

    #[test]
    fn forwarding_plan_augments_existing_shell_caps() {
        let args = ForwardingArgs {
            local: vec!["8080".to_owned(), "5353/udp".to_owned()],
            remote: vec!["/tmp/local-agent.sock".to_owned()],
        };
        let plan = args.parse("remote-dev", "local-dev").unwrap();
        let mut caps = Capabilities {
            presence: 0b0000_0001,
            shell: Some(ShellCaps {
                user_allowlist: None,
                pty_allowed: true,
                exec_allowed: true,
                command_allowlist: None,
                env_policy: portl_core::ticket::schema::EnvPolicy::Merge { allow: None },
            }),
            tcp: None,
            udp: None,
            fs: None,
            vpn: None,
            meta: None,
            unix: None,
        };
        plan.augment_caps(&mut caps);
        assert_eq!(caps.presence & 0b0000_0001, 0b0000_0001);
        assert!(caps.tcp.is_some());
        assert!(caps.udp.is_some());
        assert!(
            caps.unix
                .as_ref()
                .is_some_and(|unix| !unix.listen.is_empty())
        );
    }
}
