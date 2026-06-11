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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::watch;

use crate::commands::peer_resolve::ConnectedPeer;
use crate::commands::{socket, tcp, udp};

const ATTACH_FORWARD_LISTENER_HOLD: Duration = Duration::from_mins(2);
const ATTACH_FORWARD_STREAM_HOLD: Duration = Duration::from_mins(1);
const ATTACH_FORWARD_UDP_HOLD: Duration = Duration::from_secs(30);

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ForwardPlan {
    tcp: Vec<tcp::LocalForwardSpec>,
    udp: Vec<udp::LocalForwardSpec>,
    unix: Vec<socket::SocketMode>,
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
        self.start_resilient_for_attach(connected).await
    }

    #[allow(clippy::too_many_lines)]
    async fn start_resilient_for_attach(
        &self,
        connected: &ConnectedPeer,
    ) -> Result<ForwardRuntime> {
        let mut tasks = Vec::new();
        let mut cleanup_unix_paths = Vec::new();
        let (peer_tx, peer_rx) = watch::channel(ForwardPeer::new(connected, 0));

        for spec in &self.tcp {
            let local_addr = spec.local_addr();
            let listener = bind_local_forward_listener(&local_addr).await?;
            tasks.push(tokio::spawn(run_resilient_tcp_forward_listener(
                listener,
                peer_rx.clone(),
                local_addr,
                spec.remote_host.clone(),
                spec.remote_port,
            )));
        }

        for spec in &self.udp {
            let forward = LocalUdpForwardHandle::bind(&spec.local_addr())?;
            tasks.push(tokio::spawn(run_resilient_udp_forward(
                forward,
                peer_rx.clone(),
                spec.clone(),
            )));
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
                    let cleanup = *cleanup || !*generated;
                    if cleanup {
                        cleanup_unix_paths.push(PathBuf::from(local));
                    }
                    let listener = bind_local_unix_listener(local, cleanup)?;
                    tasks.push(tokio::spawn(run_resilient_unix_forward_listener(
                        listener,
                        peer_rx.clone(),
                        local.clone(),
                        remote.clone(),
                    )));
                }
                socket::SocketMode::Listen {
                    remote,
                    local,
                    cleanup,
                    generated,
                } => {
                    let cleanup = *cleanup || !*generated;
                    tasks.push(tokio::spawn(run_resilient_unix_reverse_forward(
                        peer_rx.clone(),
                        remote.clone(),
                        local.clone(),
                        cleanup,
                    )));
                }
            }
        }

        Ok(ForwardRuntime {
            tasks,
            listen_controls: Vec::new(),
            peer_tx: Some(peer_tx),
            generation: 0,
            cleanup_unix_paths,
        })
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
}

impl ForwardPeer {
    fn new(connected: &ConnectedPeer, generation: u64) -> Self {
        Self {
            connection: connected.connection.clone(),
            session: connected.session.clone(),
            generation,
        }
    }
}

async fn wait_for_forward_peer_update(
    rx: &mut watch::Receiver<ForwardPeer>,
    seen_generation: u64,
    hold: Duration,
) -> Option<ForwardPeer> {
    if rx.borrow().generation != seen_generation {
        return Some(rx.borrow().clone());
    }
    match tokio::time::timeout(hold, rx.changed()).await {
        Ok(Ok(())) => Some(rx.borrow().clone()),
        Ok(Err(_)) | Err(_) => None,
    }
}

async fn run_resilient_tcp_forward_listener(
    listener: TcpListener,
    peer_rx: watch::Receiver<ForwardPeer>,
    local_addr: String,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    loop {
        let (local, client_addr) = listener
            .accept()
            .await
            .context("accept local tcp connection")?;
        let peer_rx = peer_rx.clone();
        let local_addr = local_addr.clone();
        let remote_host = remote_host.clone();
        tokio::spawn(async move {
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
                        "[tcp -L {local_addr}] closed client={client_addr} after {}, error={err}",
                        udp::format_duration(started.elapsed())
                    ),
                    "tcp forwarding event"
                ),
            }
        });
    }
}

async fn forward_resilient_tcp_client(
    local: TcpStream,
    mut peer_rx: watch::Receiver<ForwardPeer>,
    remote_host: &str,
    remote_port: u16,
) -> Result<portl_core::net::tcp_client::TcpForwardStats> {
    let (mut local_read, mut local_write) = local.into_split();
    let mut stats = portl_core::net::tcp_client::TcpForwardStats::default();
    let mut peer = peer_rx.borrow().clone();
    loop {
        let (mut send, mut recv) =
            open_tcp(&peer.connection, &peer.session, remote_host, remote_port).await?;
        let mut upstream_buf = vec![0_u8; 16 * 1024];
        let mut downstream_buf = vec![0_u8; 16 * 1024];
        let disconnected_generation = loop {
            tokio::select! {
                read = local_read.read(&mut upstream_buf) => {
                    let read = read.context("read local tcp")?;
                    if read == 0 {
                        let _ = send.finish();
                        return Ok(stats);
                    }
                    if let Err(err) = send.write_all(&upstream_buf[..read]).await {
                        tracing::debug!(%err, "tcp forward remote write failed; pausing local client");
                        break peer.generation;
                    }
                    stats.upstream_bytes = stats.upstream_bytes.saturating_add(read as u64);
                }
                read = recv.read(&mut downstream_buf) => {
                    let read = match read {
                        Ok(read) => read,
                        Err(err) => {
                            tracing::debug!(%err, "tcp forward remote read failed; pausing local client");
                            break peer.generation;
                        }
                    };
                    if read == 0 {
                        local_write.shutdown().await.context("shutdown local tcp")?;
                        return Ok(stats);
                    }
                    local_write.write_all(&downstream_buf[..read]).await.context("write local tcp")?;
                    stats.downstream_bytes = stats.downstream_bytes.saturating_add(read as u64);
                }
            }
        };
        peer = wait_for_forward_peer_update(
            &mut peer_rx,
            disconnected_generation,
            ATTACH_FORWARD_STREAM_HOLD,
        )
        .await
        .context("forwarded tcp client timed out waiting for reconnect")?;
    }
}

async fn run_resilient_unix_forward_listener(
    listener: LocalUnixForwardListener,
    peer_rx: watch::Receiver<ForwardPeer>,
    local_path: String,
    remote_path: String,
) -> Result<()> {
    loop {
        let (local, _) = listener
            .accept()
            .await
            .context("accept local unix connection")?;
        let peer_rx = peer_rx.clone();
        let local_path = local_path.clone();
        let remote_path = remote_path.clone();
        tokio::spawn(async move {
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
                        "[unix -L {local_path}] closed after {}, error={err}",
                        udp::format_duration(started.elapsed())
                    ),
                    "unix forwarding event"
                ),
            }
        });
    }
}

async fn forward_resilient_unix_client(
    local: UnixStream,
    mut peer_rx: watch::Receiver<ForwardPeer>,
    remote_path: &str,
) -> Result<portl_core::net::unix_client::UnixForwardStats> {
    let (mut local_read, mut local_write) = local.into_split();
    let mut stats = portl_core::net::unix_client::UnixForwardStats::default();
    let mut peer = peer_rx.borrow().clone();
    loop {
        let (mut send, mut recv) = open_unix(&peer.connection, &peer.session, remote_path).await?;
        let mut upstream_buf = vec![0_u8; 16 * 1024];
        let mut downstream_buf = vec![0_u8; 16 * 1024];
        let disconnected_generation = loop {
            tokio::select! {
                read = local_read.read(&mut upstream_buf) => {
                    let read = read.context("read local unix")?;
                    if read == 0 {
                        let _ = send.finish();
                        return Ok(stats);
                    }
                    if let Err(err) = send.write_all(&upstream_buf[..read]).await {
                        tracing::debug!(%err, "unix forward remote write failed; pausing local client");
                        break peer.generation;
                    }
                    stats.upstream_bytes = stats.upstream_bytes.saturating_add(read as u64);
                }
                read = recv.read(&mut downstream_buf) => {
                    let read = match read {
                        Ok(read) => read,
                        Err(err) => {
                            tracing::debug!(%err, "unix forward remote read failed; pausing local client");
                            break peer.generation;
                        }
                    };
                    if read == 0 {
                        local_write.shutdown().await.context("shutdown local unix")?;
                        return Ok(stats);
                    }
                    local_write.write_all(&downstream_buf[..read]).await.context("write local unix")?;
                    stats.downstream_bytes = stats.downstream_bytes.saturating_add(read as u64);
                }
            }
        };
        peer = wait_for_forward_peer_update(
            &mut peer_rx,
            disconnected_generation,
            ATTACH_FORWARD_STREAM_HOLD,
        )
        .await
        .context("forwarded unix client timed out waiting for reconnect")?;
    }
}

async fn run_resilient_udp_forward(
    forward: LocalUdpForwardHandle,
    mut peer_rx: watch::Receiver<ForwardPeer>,
    spec: udp::LocalForwardSpec,
) -> Result<()> {
    let mut peer = peer_rx.borrow().clone();
    loop {
        let control = open_udp(
            &peer.connection,
            &peer.session,
            forward.session_id(),
            vec![UdpBind {
                local_port_range: (spec.local_port, spec.local_port),
                target_host: spec.remote_host.clone(),
                target_port_range: (spec.remote_port, spec.remote_port),
            }],
        )
        .await?;
        let disconnected_generation = peer.generation;
        let result = forward
            .run_with_control(peer.connection.clone(), control, spec.remote_port)
            .await;
        if let Err(err) = result {
            tracing::debug!(%err, "udp forward paused waiting for reconnect");
        }
        peer = wait_for_forward_peer_update(
            &mut peer_rx,
            disconnected_generation,
            ATTACH_FORWARD_UDP_HOLD,
        )
        .await
        .context("udp forward timed out waiting for reconnect")?;
    }
}

async fn run_resilient_unix_reverse_forward(
    mut peer_rx: watch::Receiver<ForwardPeer>,
    remote_path: String,
    local_path: String,
    cleanup: bool,
) -> Result<()> {
    let mut peer = peer_rx.borrow().clone();
    loop {
        let control =
            open_unix_listen(&peer.connection, &peer.session, &remote_path, cleanup).await?;
        let disconnected_generation = peer.generation;
        let result = run_unix_reverse_forwards_quiet(
            peer.connection.clone(),
            peer.session.clone(),
            vec![(remote_path.clone(), local_path.clone())],
        )
        .await;
        let _ = control.close();
        if let Err(err) = result {
            tracing::debug!(%err, "reverse unix forward paused waiting for reconnect");
        }
        peer = wait_for_forward_peer_update(
            &mut peer_rx,
            disconnected_generation,
            ATTACH_FORWARD_LISTENER_HOLD,
        )
        .await
        .context("reverse unix forward timed out waiting for reconnect")?;
    }
}

pub(crate) struct ForwardRuntime {
    tasks: Vec<tokio::task::JoinHandle<Result<()>>>,
    listen_controls: Vec<UnixListenControl>,
    peer_tx: Option<watch::Sender<ForwardPeer>>,
    generation: u64,
    cleanup_unix_paths: Vec<PathBuf>,
}

impl ForwardRuntime {
    pub(crate) fn reconnect(&mut self, connected: &ConnectedPeer) {
        if let Some(peer_tx) = &self.peer_tx {
            self.generation = self.generation.saturating_add(1);
            let _ = peer_tx.send(ForwardPeer::new(connected, self.generation));
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
    use super::{
        ATTACH_FORWARD_LISTENER_HOLD, ATTACH_FORWARD_STREAM_HOLD, ATTACH_FORWARD_UDP_HOLD,
    };
    use crate::commands::peer_resolve::ConnectedPeer;
    use portl_core::net::PeerSession;
    use portl_core::test_util::pair;
    use portl_core::ticket::schema::{Capabilities, ShellCaps};

    const TEST_ALPN: &[u8] = b"portl/forwarding-plan-start-test/v1";

    #[test]
    fn attach_forwarding_hold_timeouts_match_interactive_defaults() {
        assert_eq!(
            ATTACH_FORWARD_LISTENER_HOLD,
            std::time::Duration::from_mins(2)
        );
        assert_eq!(
            ATTACH_FORWARD_STREAM_HOLD,
            std::time::Duration::from_mins(1)
        );
        assert_eq!(ATTACH_FORWARD_UDP_HOLD, std::time::Duration::from_secs(30));
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

        let Err(err) = plan.start(&connected).await else {
            panic!("occupied second TCP port should fail plan startup");
        };
        assert!(err.to_string().contains("bind local listener"), "{err}");

        let first_addr = format!("127.0.0.1:{first_port}");
        let leaked_listener = tokio::time::timeout(
            std::time::Duration::from_millis(100),
            tokio::net::TcpStream::connect(&first_addr),
        )
        .await;
        assert!(
            !matches!(leaked_listener, Ok(Ok(_))),
            "failed plan startup left {first_addr} listening"
        );
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

    async fn connected_test_peer() -> (ConnectedPeer, tokio::task::JoinHandle<()>) {
        let (client, server) = pair().await.expect("endpoint pair");
        server.inner().set_alpns(vec![TEST_ALPN.to_vec()]);
        let accept_task = tokio::spawn({
            let server = server.clone();
            async move {
                let incoming = server.inner().accept().await.expect("incoming connection");
                let conn = incoming.await.expect("handshake");
                conn.close(0u32.into(), b"done");
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
            },
            transport_observer: None,
        };
        (connected, accept_task)
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
