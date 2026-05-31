use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
use portl_core::io::BufferedRecv;
use portl_core::net::{
    PeerSession, ShellClient, UnixListenControl, UnixListenOptions,
    open_exec_with_env_and_controls, open_shell_with_env, open_tcp, open_unix_listen_with_options,
    run_unix_reverse_forward,
};
use portl_core::ticket::schema::{
    Capabilities, EnvPolicy, PortRule, ShellCaps, UnixCaps, UnixPathRule,
};
use portl_core::wire::shell::{EnvValue, PtyCfg, ResizeFrame, SignalFrame};
use rand_core::OsRng;
use russh::keys::{Algorithm, Certificate, PrivateKey, load_secret_key, ssh_key};
use russh::server::{self, Auth, Msg, Session as RusshSession};
use russh::{Channel, ChannelId, ChannelMsg, Sig};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
use tracing::debug;

use crate::commands::peer_resolve::{close_connected, connect_peer_quiet};

pub fn run(peer: &str, user: Option<&str>, forward_agent: bool) -> Result<ExitCode> {
    let runtime = tokio::runtime::Runtime::new()?;
    let result = runtime.block_on(run_stdio(peer, user.map(ToOwned::to_owned), forward_agent));
    runtime.shutdown_background();
    result
}

async fn run_stdio(peer: &str, user: Option<String>, forward_agent: bool) -> Result<ExitCode> {
    let remote_agent_path = remote_agent_socket_path(rand::random());
    let connected = connect_peer_quiet(peer, ssh_stdio_connect_caps(&remote_agent_path)).await?;
    let result =
        run_stdio_on_connected(peer, user, forward_agent, remote_agent_path, &connected).await;
    close_connected(connected, b"ssh stdio complete").await;
    result
}

async fn run_stdio_on_connected(
    peer: &str,
    user: Option<String>,
    forward_agent: bool,
    remote_agent_path: String,
    connected: &crate::commands::peer_resolve::ConnectedPeer,
) -> Result<ExitCode> {
    let host_key = load_or_generate_host_key(peer)?;
    let config = Arc::new(server::Config {
        auth_rejection_time: Duration::from_millis(0),
        auth_rejection_time_initial: Some(Duration::from_millis(0)),
        keys: vec![host_key],
        ..Default::default()
    });
    let initial_agent = if forward_agent {
        Some(AgentForwardRequest::from_env(remote_agent_path.clone())?)
    } else {
        None
    };
    let handler = PortlSshServer::new(
        Arc::new(PortlSshBackend {
            connection: connected.connection.clone(),
            session: connected.session.clone(),
            user,
            remote_agent_path,
        }),
        initial_agent,
    );
    let running = server::run_stream(config, StdioStream::new(), handler)
        .await
        .context("start stdio SSH server")?;
    running.await.context("run stdio SSH server")?;
    Ok(ExitCode::SUCCESS)
}

fn ssh_stdio_connect_caps(remote_agent_path: &str) -> Capabilities {
    // OpenSSH signals agent forwarding with a channel request after the
    // Portl ticket has already been resolved, so stdio mode must request
    // the exact future listen path up front. Stored tickets that do not
    // grant it still connect; `agent_request` checks the effective caps
    // before accepting forwarding and rejects cleanly when missing.
    ssh_stdio_caps_for_agent_path(Some(remote_agent_path))
}

#[cfg(test)]
fn ssh_stdio_caps(forward_agent: bool) -> Capabilities {
    let remote_agent_path = forward_agent.then(|| remote_agent_socket_path(rand::random()));
    ssh_stdio_caps_for_agent_path(remote_agent_path.as_deref())
}

fn ssh_stdio_caps_for_agent_path(remote_agent_path: Option<&str>) -> Capabilities {
    let unix = remote_agent_path.map(|path| UnixCaps {
        connect: Vec::new(),
        listen: vec![UnixPathRule {
            path: path.to_owned(),
        }],
    });
    Capabilities {
        presence: 0b0000_0011 | (u8::from(unix.is_some()) << 6),
        shell: Some(ShellCaps {
            user_allowlist: None,
            pty_allowed: true,
            exec_allowed: true,
            command_allowlist: None,
            env_policy: EnvPolicy::Merge { allow: None },
        }),
        tcp: Some(vec![PortRule {
            host_glob: "*".to_owned(),
            port_min: 1,
            port_max: u16::MAX,
        }]),
        udp: None,
        fs: None,
        vpn: None,
        meta: None,
        unix,
    }
}

fn remote_agent_socket_path(nonce: u64) -> String {
    format!("/tmp/portl-agent-{nonce:016x}/agent.sock")
}

fn sanitized_target_key_name(target: &str) -> String {
    let mut readable = target
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                ch
            } else {
                '_'
            }
        })
        .collect::<String>();
    while readable.contains("__") {
        readable = readable.replace("__", "_");
    }
    let readable = readable.trim_matches('_');
    let readable = if readable.is_empty() {
        "target".to_owned()
    } else {
        readable.chars().take(48).collect::<String>()
    };
    let digest = Sha256::digest(target.as_bytes());
    format!("{readable}-{}", &hex::encode(digest)[..16])
}

fn host_key_path_for_target(home: &Path, target: &str) -> PathBuf {
    home.join("data")
        .join("ssh")
        .join("hostkeys")
        .join(format!("{}.key", sanitized_target_key_name(target)))
}

fn load_or_generate_host_key(target: &str) -> Result<PrivateKey> {
    load_or_generate_host_key_at(&portl_core::paths::home_dir(), target)
}

fn load_or_generate_host_key_at(home: &Path, target: &str) -> Result<PrivateKey> {
    let path = host_key_path_for_target(home, target);
    if path.exists() {
        return load_secret_key(&path, None)
            .with_context(|| format!("load SSH facade host key {}", path.display()));
    }
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
    }
    let key = PrivateKey::random(&mut OsRng, Algorithm::Ed25519)
        .context("generate SSH facade host key")?;
    let encoded = key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("encode SSH facade host key")?;
    match install_private_file_no_overwrite(&path, encoded.as_bytes())? {
        InstallOutcome::Installed => Ok(key),
        InstallOutcome::AlreadyExists => load_secret_key(&path, None)
            .with_context(|| format!("load raced SSH facade host key {}", path.display())),
    }
}

enum InstallOutcome {
    Installed,
    AlreadyExists,
}

fn install_private_file_no_overwrite(path: &Path, bytes: &[u8]) -> Result<InstallOutcome> {
    let tmp_path = unique_tmp_path(path);
    write_private_file(&tmp_path, bytes)?;
    let link_result = fs::hard_link(&tmp_path, path);
    let remove_result = fs::remove_file(&tmp_path);
    if let Err(err) = remove_result
        && err.kind() != std::io::ErrorKind::NotFound
    {
        return Err(err).with_context(|| format!("remove {}", tmp_path.display()));
    }
    match link_result {
        Ok(()) => {
            #[cfg(unix)]
            set_mode_0600(path)?;
            Ok(InstallOutcome::Installed)
        }
        Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
            Ok(InstallOutcome::AlreadyExists)
        }
        Err(err) => {
            Err(err).with_context(|| format!("install SSH facade host key {}", path.display()))
        }
    }
}

fn unique_tmp_path(path: &Path) -> PathBuf {
    let nonce: u64 = rand::random();
    path.with_extension(format!("key.tmp.{}.{nonce:016x}", std::process::id()))
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut options = OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .with_context(|| format!("write {}", path.display()))?;
    file.write_all(bytes)
        .with_context(|| format!("write {}", path.display()))?;
    file.sync_all()
        .with_context(|| format!("sync {}", path.display()))?;
    Ok(())
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .with_context(|| format!("chmod 0600 {}", path.display()))
}

struct StdioStream {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
}

impl StdioStream {
    fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
        }
    }
}

impl AsyncRead for StdioStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StdioStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}

#[derive(Debug, Clone)]
struct PortlSshBackend {
    connection: Connection,
    session: PeerSession,
    user: Option<String>,
    remote_agent_path: String,
}

#[derive(Debug)]
struct PendingSessionChannel {
    channel: Channel<Msg>,
    pty: Option<PtyCfg>,
    env_patch: Vec<(String, EnvValue)>,
}

#[derive(Debug, Clone)]
struct AgentForwardRequest {
    local_agent_path: String,
    remote_agent_path: String,
}

impl AgentForwardRequest {
    fn from_env(remote_agent_path: String) -> Result<Self> {
        Ok(Self {
            local_agent_path: ssh_auth_sock_from_env(std::env::var_os("SSH_AUTH_SOCK"))?,
            remote_agent_path,
        })
    }
}

#[derive(Debug)]
struct AgentForwardGuard {
    control: UnixListenControl,
    task: tokio::task::JoinHandle<Result<()>>,
}

impl AgentForwardGuard {
    async fn close(self) -> Result<()> {
        let close_result = self.control.close();
        self.task.abort();
        let _ = self.task.await;
        close_result
    }
}

#[derive(Debug, Clone, Copy)]
enum ControlMessage {
    Resize { cols: u16, rows: u16 },
    Signal(u8),
}

#[derive(Debug)]
enum RemoteSessionRequest {
    Shell { pty: PtyCfg },
    Exec { argv: Vec<String> },
}

struct PortlSshServer {
    backend: Arc<PortlSshBackend>,
    channels: HashMap<ChannelId, PendingSessionChannel>,
    controls: HashMap<ChannelId, mpsc::Sender<ControlMessage>>,
    agent_forward: Option<AgentForwardRequest>,
    auth_user: Option<String>,
}

impl PortlSshServer {
    fn new(backend: Arc<PortlSshBackend>, agent_forward: Option<AgentForwardRequest>) -> Self {
        Self {
            backend,
            channels: HashMap::new(),
            controls: HashMap::new(),
            agent_forward,
            auth_user: None,
        }
    }

    fn remove_channel(&mut self, channel: ChannelId) -> Result<PendingSessionChannel> {
        self.channels
            .remove(&channel)
            .ok_or_else(|| anyhow!("SSH channel {channel:?} was not opened"))
    }
}

impl server::Handler for PortlSshServer {
    type Error = anyhow::Error;

    async fn auth_none(&mut self, user: &str) -> Result<Auth, Self::Error> {
        self.auth_user = Some(user.to_owned());
        Ok(Auth::Accept)
    }

    async fn auth_publickey_offered(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_user = Some(user.to_owned());
        Ok(Auth::Accept)
    }

    async fn auth_publickey(
        &mut self,
        user: &str,
        _public_key: &ssh_key::PublicKey,
    ) -> Result<Auth, Self::Error> {
        self.auth_user = Some(user.to_owned());
        Ok(Auth::Accept)
    }

    async fn auth_openssh_certificate(
        &mut self,
        user: &str,
        _certificate: &Certificate,
    ) -> Result<Auth, Self::Error> {
        self.auth_user = Some(user.to_owned());
        Ok(Auth::Accept)
    }

    async fn channel_open_session(
        &mut self,
        channel: Channel<Msg>,
        _session: &mut RusshSession,
    ) -> Result<bool, Self::Error> {
        self.channels.insert(
            channel.id(),
            PendingSessionChannel {
                channel,
                pty: None,
                env_patch: Vec::new(),
            },
        );
        Ok(true)
    }

    async fn channel_close(
        &mut self,
        channel: ChannelId,
        _session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        self.controls.remove(&channel);
        self.channels.remove(&channel);
        Ok(())
    }

    async fn pty_request(
        &mut self,
        channel: ChannelId,
        term: &str,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        _modes: &[(russh::Pty, u32)],
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        if let Some(pending) = self.channels.get_mut(&channel) {
            pending.pty = Some(PtyCfg {
                term: term.to_owned(),
                cols: ssh_dimension(col_width),
                rows: ssh_dimension(row_height),
            });
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn env_request(
        &mut self,
        channel: ChannelId,
        variable_name: &str,
        variable_value: &str,
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        if let Some(pending) = self.channels.get_mut(&channel)
            && ssh_env_request_allowed(&self.backend.session.effective_caps, variable_name)
        {
            pending.env_patch.push((
                variable_name.to_owned(),
                EnvValue::Set(variable_value.to_owned()),
            ));
            session.channel_success(channel)?;
        } else {
            session.channel_failure(channel)?;
        }
        Ok(())
    }

    async fn shell_request(
        &mut self,
        channel: ChannelId,
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        let pending = self.remove_channel(channel)?;
        let pty = pending.pty.unwrap_or_else(default_pty);
        let (control_tx, control_rx) = mpsc::channel(32);
        self.controls.insert(channel, control_tx);
        session.channel_success(channel)?;
        spawn_remote_session_bridge(
            pending.channel,
            Arc::clone(&self.backend),
            effective_portl_user(self.backend.user.as_ref(), self.auth_user.as_ref()),
            pending.env_patch,
            RemoteSessionRequest::Shell { pty },
            self.agent_forward.clone(),
            control_rx,
        );
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        let pending = self.remove_channel(channel)?;
        let command = String::from_utf8_lossy(data).into_owned();
        let argv = vec!["/bin/sh".to_owned(), "-lc".to_owned(), command];
        let (control_tx, control_rx) = mpsc::channel(32);
        self.controls.insert(channel, control_tx);
        session.channel_success(channel)?;
        spawn_remote_session_bridge(
            pending.channel,
            Arc::clone(&self.backend),
            effective_portl_user(self.backend.user.as_ref(), self.auth_user.as_ref()),
            pending.env_patch,
            RemoteSessionRequest::Exec { argv },
            self.agent_forward.clone(),
            control_rx,
        );
        Ok(())
    }

    async fn subsystem_request(
        &mut self,
        channel: ChannelId,
        name: &str,
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        let _ = self.channels.remove(&channel);
        let message = format!("portl-ssh --stdio does not implement subsystem {name}\n");
        session.extended_data(channel, 1, message.into_bytes().into())?;
        session.exit_status_request(channel, 1)?;
        session.channel_failure(channel)?;
        session.eof(channel)?;
        session.close(channel)?;
        Ok(())
    }

    async fn window_change_request(
        &mut self,
        channel: ChannelId,
        col_width: u32,
        row_height: u32,
        _pix_width: u32,
        _pix_height: u32,
        session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        if let Some(control) = self.controls.get(&channel) {
            let _ = control
                .send(ControlMessage::Resize {
                    cols: ssh_dimension(col_width),
                    rows: ssh_dimension(row_height),
                })
                .await;
        }
        session.channel_success(channel)?;
        Ok(())
    }

    async fn signal(
        &mut self,
        channel: ChannelId,
        signal: Sig,
        _session: &mut RusshSession,
    ) -> Result<(), Self::Error> {
        if let (Some(control), Some(sig)) = (self.controls.get(&channel), signal_number(&signal)) {
            let _ = control.send(ControlMessage::Signal(sig)).await;
        }
        Ok(())
    }

    async fn agent_request(
        &mut self,
        channel: ChannelId,
        session: &mut RusshSession,
    ) -> Result<bool, Self::Error> {
        match AgentForwardRequest::from_env(self.backend.remote_agent_path.clone()).and_then(
            |request| {
                ensure_agent_env_allowed(&self.backend.session.effective_caps)?;
                ensure_agent_unix_listen_allowed(
                    &self.backend.session.effective_caps,
                    &request.remote_agent_path,
                )?;
                Ok(request)
            },
        ) {
            Ok(request) => {
                self.agent_forward = Some(request);
                session.channel_success(channel)?;
                Ok(true)
            }
            Err(err) => {
                debug!(%err, "rejecting OpenSSH agent forwarding request");
                session.channel_failure(channel)?;
                Ok(false)
            }
        }
    }

    async fn channel_open_direct_tcpip(
        &mut self,
        channel: Channel<Msg>,
        host_to_connect: &str,
        port_to_connect: u32,
        _originator_address: &str,
        _originator_port: u32,
        _session: &mut RusshSession,
    ) -> Result<bool, Self::Error> {
        let Ok(port) = u16::try_from(port_to_connect) else {
            return Ok(false);
        };
        match open_tcp(
            &self.backend.connection,
            &self.backend.session,
            host_to_connect,
            port,
        )
        .await
        {
            Ok((send, recv)) => {
                spawn_direct_tcpip_bridge(channel, send, recv, host_to_connect.to_owned(), port);
                Ok(true)
            }
            Err(err) => {
                debug!(%err, host = host_to_connect, port, "rejecting direct-tcpip channel");
                Ok(false)
            }
        }
    }

    async fn tcpip_forward(
        &mut self,
        address: &str,
        port: &mut u32,
        _session: &mut RusshSession,
    ) -> Result<bool, Self::Error> {
        debug!(
            address,
            port = *port,
            "rejecting remote tcpip-forward request"
        );
        Ok(false)
    }

    async fn cancel_tcpip_forward(
        &mut self,
        address: &str,
        port: u32,
        _session: &mut RusshSession,
    ) -> Result<bool, Self::Error> {
        debug!(address, port, "rejecting cancel-tcpip-forward request");
        Ok(false)
    }
}

fn spawn_remote_session_bridge(
    channel: Channel<Msg>,
    backend: Arc<PortlSshBackend>,
    user: Option<String>,
    env_patch: Vec<(String, EnvValue)>,
    request: RemoteSessionRequest,
    agent_forward: Option<AgentForwardRequest>,
    control_rx: mpsc::Receiver<ControlMessage>,
) {
    tokio::spawn(async move {
        if let Err(err) = bridge_remote_session(
            channel,
            backend,
            user,
            env_patch,
            request,
            agent_forward,
            control_rx,
        )
        .await
        {
            debug!(%err, "SSH stdio session channel failed");
        }
    });
}

async fn bridge_remote_session(
    channel: Channel<Msg>,
    backend: Arc<PortlSshBackend>,
    user: Option<String>,
    mut env_patch: Vec<(String, EnvValue)>,
    request: RemoteSessionRequest,
    agent_forward: Option<AgentForwardRequest>,
    control_rx: mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    let channel_id = channel.id();
    let (agent_env_patch, agent_guard) =
        match start_agent_forward_if_requested(&backend, agent_forward).await {
            Ok(started) => started,
            Err(err) => return finish_channel_with_error(channel, err).await,
        };
    env_patch.extend(agent_env_patch);
    let shell = match match request {
        RemoteSessionRequest::Shell { pty } => open_shell_with_env(
            &backend.connection,
            &backend.session,
            user.clone(),
            None,
            pty,
            env_patch,
        )
        .await
        .context("open Portl shell for SSH channel"),
        RemoteSessionRequest::Exec { argv } => open_exec_with_env_and_controls(
            &backend.connection,
            &backend.session,
            user,
            None,
            argv,
            env_patch,
        )
        .await
        .context("open Portl exec for SSH channel"),
    } {
        Ok(shell) => shell,
        Err(err) => {
            if let Some(agent_guard) = agent_guard {
                agent_guard.close().await?;
            }
            return finish_channel_with_error(channel, err).await;
        }
    };

    let result = bridge_shell_client(channel, channel_id, shell, control_rx).await;
    if let Some(agent_guard) = agent_guard {
        agent_guard.close().await?;
    }
    result
}

fn effective_portl_user(cli_user: Option<&String>, auth_user: Option<&String>) -> Option<String> {
    cli_user.cloned().or_else(|| auth_user.cloned())
}

async fn finish_channel_with_error(channel: Channel<Msg>, err: anyhow::Error) -> Result<()> {
    let message = format!("portl-ssh --stdio failed to open Portl session: {err}\n");
    let mut stderr = channel.make_writer_ext(Some(1));
    stderr
        .write_all(message.as_bytes())
        .await
        .context("send SSH stdio open failure")?;
    stderr
        .flush()
        .await
        .context("flush SSH stdio open failure")?;
    channel
        .exit_status(1)
        .await
        .context("send SSH stdio open failure exit status")?;
    channel
        .eof()
        .await
        .context("send SSH stdio open failure EOF")?;
    channel
        .close()
        .await
        .context("close SSH stdio failed channel")?;
    Ok(())
}

async fn start_agent_forward_if_requested(
    backend: &PortlSshBackend,
    agent_forward: Option<AgentForwardRequest>,
) -> Result<(Vec<(String, EnvValue)>, Option<AgentForwardGuard>)> {
    let Some(agent_forward) = agent_forward else {
        return Ok((Vec::new(), None));
    };
    let control = open_unix_listen_with_options(
        &backend.connection,
        &backend.session,
        &agent_forward.remote_agent_path,
        UnixListenOptions {
            cleanup: true,
            ssh_agent: true,
        },
    )
    .await
    .context("open remote SSH agent socket")?;
    let task = tokio::spawn(run_unix_reverse_forward(
        backend.connection.clone(),
        backend.session.clone(),
        agent_forward.remote_agent_path.clone(),
        agent_forward.local_agent_path,
    ));
    Ok((
        vec![(
            "SSH_AUTH_SOCK".to_owned(),
            EnvValue::Set(agent_forward.remote_agent_path),
        )],
        Some(AgentForwardGuard { control, task }),
    ))
}

async fn bridge_shell_client(
    channel: Channel<Msg>,
    _channel_id: ChannelId,
    shell: ShellClient,
    control_rx: mpsc::Receiver<ControlMessage>,
) -> Result<()> {
    let (mut channel_read, channel_write) = channel.split();
    let mut stdout_writer = channel_write.make_writer();
    let mut stderr_writer = channel_write.make_writer_ext(Some(1));
    let ShellClient {
        control_send: _control_send,
        control_recv: _control_recv,
        mut stdin,
        mut stdout,
        mut stderr,
        mut exit,
        signal,
        resize,
    } = shell;

    let stdin_task = tokio::spawn(async move {
        while let Some(message) = channel_read.wait().await {
            match message {
                ChannelMsg::Data { data } => stdin.write_all(&data).await?,
                ChannelMsg::Eof | ChannelMsg::Close => break,
                _ => {}
            }
        }
        stdin.finish().context("finish Portl SSH stdin")?;
        Ok::<_, anyhow::Error>(())
    });
    let stdout_task = tokio::spawn(async move {
        tokio::io::copy(&mut stdout, &mut stdout_writer)
            .await
            .context("copy Portl stdout to SSH channel")?;
        stdout_writer.flush().await.context("flush SSH stdout")?;
        Ok::<_, anyhow::Error>(())
    });
    let stderr_task = tokio::spawn(async move {
        tokio::io::copy(&mut stderr, &mut stderr_writer)
            .await
            .context("copy Portl stderr to SSH channel")?;
        stderr_writer.flush().await.context("flush SSH stderr")?;
        Ok::<_, anyhow::Error>(())
    });
    let control_task = tokio::spawn(control_loop(control_rx, signal, resize));

    let code = read_remote_exit(&mut exit)
        .await
        .context("read Portl SSH exit")?;
    stdin_task.abort();
    control_task.abort();
    let _ = stdin_task.await;
    let _ = control_task.await;
    stdout_task.await.context("join SSH stdout bridge")??;
    stderr_task.await.context("join SSH stderr bridge")??;
    channel_write
        .exit_status(u32::try_from(code).unwrap_or(255))
        .await
        .context("send SSH exit status")?;
    channel_write.eof().await.context("send SSH EOF")?;
    channel_write.close().await.context("close SSH channel")?;
    Ok(())
}

async fn control_loop(
    mut control_rx: mpsc::Receiver<ControlMessage>,
    mut signal: Option<SendStream>,
    mut resize: Option<SendStream>,
) -> Result<()> {
    while let Some(message) = control_rx.recv().await {
        match message {
            ControlMessage::Resize { cols, rows } => {
                if let Some(resize) = resize.as_mut() {
                    let frame = ResizeFrame { cols, rows };
                    resize
                        .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
                        .await
                        .context("write resize frame")?;
                }
            }
            ControlMessage::Signal(sig) => {
                if let Some(signal) = signal.as_mut() {
                    let frame = SignalFrame { sig };
                    signal
                        .write_all(&postcard::to_stdvec(&frame).context("encode signal frame")?)
                        .await
                        .context("write signal frame")?;
                }
            }
        }
    }
    Ok(())
}

fn spawn_direct_tcpip_bridge(
    channel: Channel<Msg>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    host: String,
    port: u16,
) {
    tokio::spawn(async move {
        let mut stream = channel.into_stream();
        let (mut stream_read, mut stream_write) = tokio::io::split(&mut stream);
        let upstream = async {
            tokio::io::copy(&mut stream_read, &mut send)
                .await
                .context("copy SSH direct-tcpip to Portl tcp")?;
            send.finish().context("finish Portl tcp send")?;
            Ok::<_, anyhow::Error>(())
        };
        let downstream = async {
            tokio::io::copy(&mut recv, &mut stream_write)
                .await
                .context("copy Portl tcp to SSH direct-tcpip")?;
            stream_write
                .shutdown()
                .await
                .context("shutdown SSH direct-tcpip")?;
            Ok::<_, anyhow::Error>(())
        };
        if let Err(err) = tokio::try_join!(upstream, downstream) {
            debug!(%err, host, port, "SSH direct-tcpip bridge failed");
        }
    });
}

async fn read_remote_exit(recv: &mut BufferedRecv) -> Result<i32> {
    let frame = recv
        .read_frame::<portl_core::wire::shell::ExitFrame>(128)
        .await?
        .context("missing exit frame")?;
    Ok(frame.code)
}

fn ssh_auth_sock_from_env(value: Option<OsString>) -> Result<String> {
    let Some(value) = value else {
        bail!(
            "OpenSSH agent forwarding requires SSH_AUTH_SOCK to point at a local ssh-agent socket"
        );
    };
    if value.is_empty() {
        bail!("OpenSSH agent forwarding requires SSH_AUTH_SOCK to be non-empty");
    }
    let path = PathBuf::from(&value);
    let metadata = match fs::metadata(&path) {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => bail!(
            "OpenSSH agent forwarding requires SSH_AUTH_SOCK to point at an existing local ssh-agent socket: {}",
            path.display()
        ),
        Err(err) => {
            return Err(err).with_context(|| format!("stat SSH_AUTH_SOCK {}", path.display()));
        }
    };
    if !metadata.file_type().is_socket() {
        bail!("SSH_AUTH_SOCK is not a unix socket: {}", path.display());
    }
    value
        .into_string()
        .map_err(|_| anyhow!("SSH_AUTH_SOCK must be valid UTF-8 for Portl forwarding"))
}

fn ensure_agent_unix_listen_allowed(caps: &Capabilities, remote_agent_path: &str) -> Result<()> {
    let allowed = caps.unix.as_ref().is_some_and(|unix| {
        unix.listen
            .iter()
            .any(|rule| rule.matches_path(remote_agent_path))
    });
    if allowed {
        return Ok(());
    }
    bail!(
        "OpenSSH agent forwarding requires the ticket to allow Unix listen on {remote_agent_path}"
    )
}

fn ssh_env_request_allowed(caps: &Capabilities, variable_name: &str) -> bool {
    let Some(shell) = caps.shell.as_ref() else {
        return false;
    };
    match &shell.env_policy {
        EnvPolicy::Merge { allow: None } => true,
        EnvPolicy::Merge { allow: Some(allow) } => allow.iter().any(|key| key == variable_name),
        EnvPolicy::Deny | EnvPolicy::Replace { .. } => false,
    }
}

fn ensure_agent_env_allowed(caps: &Capabilities) -> Result<()> {
    let Some(shell) = caps.shell.as_ref() else {
        bail!("OpenSSH agent forwarding requires a ticket with shell capability");
    };
    match &shell.env_policy {
        EnvPolicy::Merge { allow: None } => Ok(()),
        EnvPolicy::Merge { allow: Some(allow) }
            if allow.iter().any(|key| key == "SSH_AUTH_SOCK") =>
        {
            Ok(())
        }
        _ => {
            bail!("OpenSSH agent forwarding requires the ticket env policy to allow SSH_AUTH_SOCK")
        }
    }
}

fn default_pty() -> PtyCfg {
    PtyCfg {
        term: "xterm-256color".to_owned(),
        cols: 80,
        rows: 24,
    }
}

fn ssh_dimension(value: u32) -> u16 {
    u16::try_from(value).unwrap_or(u16::MAX).max(1)
}

fn signal_number(signal: &Sig) -> Option<u8> {
    Some(match signal {
        Sig::HUP => 1,
        Sig::INT => 2,
        Sig::QUIT => 3,
        Sig::ILL => 4,
        Sig::ABRT => 6,
        Sig::FPE => 8,
        Sig::KILL => 9,
        Sig::USR1 => 10,
        Sig::SEGV => 11,
        Sig::PIPE => 13,
        Sig::ALRM => 14,
        Sig::TERM => 15,
        Sig::Custom(_) => return None,
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use russh::Sig;

    use super::{
        EnvPolicy, InstallOutcome, effective_portl_user, ensure_agent_unix_listen_allowed,
        host_key_path_for_target, install_private_file_no_overwrite, sanitized_target_key_name,
        signal_number, ssh_dimension, ssh_env_request_allowed, ssh_stdio_caps,
        ssh_stdio_connect_caps,
    };

    #[test]
    fn ssh_stdio_uses_cli_user_before_ssh_auth_user() {
        let cli = "cli-user".to_owned();
        let auth = "auth-user".to_owned();
        assert_eq!(effective_portl_user(Some(&cli), Some(&auth)), Some(cli));
        assert_eq!(effective_portl_user(None, Some(&auth)), Some(auth));
        assert_eq!(effective_portl_user(None, None), None);
    }

    #[test]
    fn ssh_stdio_caps_grant_shell_and_tcp_forwarding() {
        let caps = ssh_stdio_caps(false);
        assert_eq!(caps.presence & 0b0000_0001, 0b0000_0001);
        assert_eq!(caps.presence & 0b0000_0010, 0b0000_0010);
        assert!(caps.shell.expect("shell caps").pty_allowed);
        let tcp = caps.tcp.expect("tcp caps");
        assert_eq!(tcp.len(), 1);
        assert_eq!(tcp[0].host_glob, "*");
        assert_eq!(tcp[0].port_min, 1);
        assert_eq!(tcp[0].port_max, u16::MAX);
        assert!(caps.unix.is_none());
    }

    #[test]
    fn ssh_stdio_connect_caps_request_future_agent_socket_for_late_openssh_agent_req() {
        let path = "/tmp/portl-agent-0123456789abcdef/agent.sock";
        let caps = ssh_stdio_connect_caps(path);
        let unix = caps
            .unix
            .expect("stdio connect caps include future agent path");
        assert_eq!(unix.listen.len(), 1);
        assert_eq!(unix.listen[0].path, path);
    }

    #[test]
    fn ssh_stdio_caps_include_agent_socket_when_agent_forwarding_is_requested() {
        let caps = ssh_stdio_caps(true);
        let unix = caps.unix.expect("unix caps");
        assert!(unix.connect.is_empty());
        assert_eq!(unix.listen.len(), 1);
        assert!(unix.listen[0].path.starts_with("/tmp/portl-agent-"));
        assert!(unix.listen[0].path.ends_with("/agent.sock"));
    }

    #[test]
    fn ssh_compat_signal_and_dimension_mapping_matches_openssh_requests() {
        assert_eq!(ssh_dimension(0), 1);
        assert_eq!(ssh_dimension(u32::MAX), u16::MAX);
        assert_eq!(signal_number(&Sig::INT), Some(2));
        assert_eq!(signal_number(&Sig::TERM), Some(15));
        assert_eq!(signal_number(&Sig::Custom("INFO".to_owned())), None);
    }

    #[test]
    fn ssh_stdio_env_requests_follow_effective_ticket_policy() {
        let mut caps = ssh_stdio_caps(false);
        assert!(ssh_env_request_allowed(&caps, "LC_ALL"));

        caps.shell.as_mut().expect("shell caps").env_policy = EnvPolicy::Merge {
            allow: Some(vec!["TERM".to_owned()]),
        };
        assert!(ssh_env_request_allowed(&caps, "TERM"));
        assert!(!ssh_env_request_allowed(&caps, "LC_ALL"));

        caps.shell.as_mut().expect("shell caps").env_policy = EnvPolicy::Deny;
        assert!(!ssh_env_request_allowed(&caps, "TERM"));
    }

    #[test]
    fn ssh_stdio_agent_forward_requires_effective_unix_listen_cap() {
        let path = "/tmp/portl-agent-0123456789abcdef/agent.sock";
        let denied = ssh_stdio_caps(false);
        let err = ensure_agent_unix_listen_allowed(&denied, path)
            .expect_err("missing unix listen cap must fail");
        assert!(err.to_string().contains("Unix listen"));

        let allowed = super::ssh_stdio_caps_for_agent_path(Some(path));
        ensure_agent_unix_listen_allowed(&allowed, path).expect("exact unix listen cap passes");
    }

    #[test]
    fn host_key_names_are_stable_and_path_safe() {
        let name = sanitized_target_key_name("alice@example/vn3");
        assert!(name.starts_with("alice_example_vn3-"));
        assert!(!name.contains('/'));
        assert!(!name.contains('@'));

        let path = host_key_path_for_target(Path::new("/tmp/portl-home"), "alice@example/vn3");
        assert_eq!(
            path.parent().unwrap(),
            Path::new("/tmp/portl-home/data/ssh/hostkeys")
        );
        assert_eq!(path.extension().and_then(|ext| ext.to_str()), Some("key"));
    }

    #[test]
    fn host_key_install_does_not_overwrite_existing_key() {
        let home = tempfile::tempdir().expect("temp home");
        let path = home.path().join("data/ssh/hostkeys/vn3.key");
        std::fs::create_dir_all(path.parent().unwrap()).expect("hostkey dir");
        std::fs::write(&path, b"existing").expect("existing key placeholder");

        let outcome = install_private_file_no_overwrite(&path, b"new")
            .expect("already-existing destination is reported");

        assert!(matches!(outcome, InstallOutcome::AlreadyExists));
        assert_eq!(std::fs::read(&path).expect("read key"), b"existing");
    }

    #[test]
    fn host_key_generation_reuses_existing_target_key() {
        let home = tempfile::tempdir().expect("temp home");
        let _first = super::load_or_generate_host_key_at(home.path(), "vn3").expect("first key");
        let path = host_key_path_for_target(home.path(), "vn3");
        let first_bytes = std::fs::read(&path).expect("read first key");

        let _second = super::load_or_generate_host_key_at(home.path(), "vn3").expect("second key");
        let second_bytes = std::fs::read(&path).expect("read second key");

        assert_eq!(first_bytes, second_bytes);
    }
}
