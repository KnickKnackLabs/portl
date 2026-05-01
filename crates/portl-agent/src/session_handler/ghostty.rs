#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(unix)]
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
#[cfg(unix)]
use libghostty_vt::{Terminal, TerminalOptions};
#[cfg(unix)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::sync::{mpsc, oneshot, watch};

#[cfg(unix)]
use crate::shell_registry::{PtyCommand, ShellProcess, StdinMessage};

pub(crate) const GHOSTTY_PROTOCOL_VERSION: u16 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct GhosttySessionMetadata {
    pub(crate) name: String,
    pub(crate) provider: String,
    pub(crate) pid: u32,
    pub(crate) socket_path: PathBuf,
    pub(crate) created_at_ms: u64,
    pub(crate) last_seen_ms: u64,
    pub(crate) cwd: Option<String>,
    pub(crate) rows: u16,
    pub(crate) cols: u16,
    pub(crate) status: String,
    pub(crate) protocol_version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_field_names)]
pub(crate) struct GhosttySessionPaths {
    pub(crate) socket_path: PathBuf,
    pub(crate) metadata_path: PathBuf,
    pub(crate) history_path: PathBuf,
}

#[derive(Debug, Clone)]
pub(crate) struct GhosttyRegistry {
    runtime_root: PathBuf,
    state_root: PathBuf,
}

impl GhosttyRegistry {
    pub(crate) fn new() -> Self {
        let state_root = std::env::var_os("PORTL_GHOSTTY_STATE_DIR")
            .map_or_else(default_state_root, PathBuf::from);
        let runtime_root = std::env::var_os("PORTL_GHOSTTY_RUNTIME_DIR")
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var_os("XDG_RUNTIME_DIR")
                    .map(PathBuf::from)
                    .map(|dir| dir.join("portl/ghostty"))
            })
            .unwrap_or_else(|| state_root.join("runtime"));
        Self {
            runtime_root,
            state_root,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_roots(runtime_root: PathBuf, state_root: PathBuf) -> Self {
        Self {
            runtime_root,
            state_root,
        }
    }

    pub(crate) fn paths_for(&self, session: &str) -> GhosttySessionPaths {
        let encoded = encode_session_component(session);
        GhosttySessionPaths {
            socket_path: self
                .runtime_root
                .join("sockets")
                .join(format!("{encoded}.sock")),
            metadata_path: self
                .state_root
                .join("sessions")
                .join(format!("{encoded}.json")),
            history_path: self
                .state_root
                .join("sessions")
                .join(format!("{encoded}.history")),
        }
    }

    pub(crate) fn state_root(&self) -> &Path {
        &self.state_root
    }

    pub(crate) async fn list_metadata(&self) -> Result<Vec<GhosttySessionMetadata>> {
        let sessions_dir = self.state_root.join("sessions");
        let mut out = Vec::new();
        let mut entries = match tokio::fs::read_dir(&sessions_dir).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => return Ok(out),
            Err(err) => return Err(err).context("read ghostty sessions directory"),
        };
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|value| value.to_str()) != Some("json") {
                continue;
            }
            let Ok(bytes) = tokio::fs::read(&path).await else {
                continue;
            };
            let Ok(metadata) = serde_json::from_slice::<GhosttySessionMetadata>(&bytes) else {
                continue;
            };
            if metadata.protocol_version == GHOSTTY_PROTOCOL_VERSION {
                out.push(metadata);
            }
        }
        Ok(out)
    }
}

fn default_state_root() -> PathBuf {
    directories::ProjectDirs::from("computer", "KnickKnackLabs", "portl").map_or_else(
        || PathBuf::from(".portl/ghostty"),
        |dirs| dirs.data_dir().join("ghostty"),
    )
}

pub(crate) fn encode_session_component(input: &str) -> String {
    let mut encoded = String::new();
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-') {
            encoded.push(char::from(byte));
        } else {
            use std::fmt::Write as _;
            let _ = write!(encoded, "%{byte:02X}");
        }
    }
    encoded
}

#[cfg(unix)]
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
#[cfg(unix)]
const IO_CHUNK: usize = 16 * 1024;

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct GhosttyHelperConfig {
    name: String,
    paths: GhosttySessionPaths,
    cwd: Option<String>,
    rows: u16,
    cols: u16,
    argv: Vec<String>,
    env: Option<Vec<(String, String)>>,
}

#[cfg(unix)]
impl GhosttyHelperConfig {
    pub(crate) fn new(
        name: String,
        paths: GhosttySessionPaths,
        cwd: Option<String>,
        rows: u16,
        cols: u16,
        argv: Vec<String>,
        env: Option<Vec<(String, String)>>,
    ) -> Self {
        Self {
            name,
            paths,
            cwd,
            rows,
            cols,
            argv,
            env,
        }
    }

    #[cfg(test)]
    fn for_test(name: &str, paths: GhosttySessionPaths, argv: Vec<String>) -> Self {
        Self {
            name: name.to_owned(),
            paths,
            cwd: None,
            rows: 24,
            cols: 80,
            argv,
            env: None,
        }
    }
}

#[cfg(unix)]
#[derive(Debug, Clone)]
pub(crate) struct GhosttyProvider {
    registry: GhosttyRegistry,
    helper_exe: PathBuf,
}

#[cfg(unix)]
impl GhosttyProvider {
    pub(crate) fn new() -> Self {
        Self {
            registry: GhosttyRegistry::new(),
            helper_exe: std::env::current_exe().unwrap_or_else(|_| PathBuf::from("portl")),
        }
    }

    pub(crate) fn status(&self) -> portl_proto::session_v1::ProviderStatus {
        portl_proto::session_v1::ProviderStatus {
            name: "ghostty".to_owned(),
            available: true,
            path: Some(self.helper_exe.display().to_string()),
            notes: Some("built-in libghostty-vt provider".to_owned()),
            capabilities: portl_proto::session_v1::ProviderCapabilities::ghostty(),
            tier: Some("native".to_owned()),
            features: ghostty_features(),
        }
    }

    pub(crate) async fn list_detailed(&self) -> Result<Vec<portl_proto::session_v1::SessionInfo>> {
        let mut sessions = Vec::new();
        for metadata in self.registry.list_metadata().await? {
            let live = match GhosttyClient::connect(metadata.socket_path.clone()).await {
                Ok(client) => client.probe().await.is_ok(),
                Err(_) => false,
            };
            if !live {
                let paths = self.registry.paths_for(&metadata.name);
                cleanup_helper_files(&paths).await;
                continue;
            }
            sessions.push(session_info_from_metadata(metadata));
        }
        Ok(sessions)
    }

    pub(crate) async fn run(
        &self,
        session: &str,
        cwd: Option<&str>,
        argv: &[String],
        env: Option<Vec<(String, String)>>,
    ) -> Result<portl_proto::session_v1::SessionRunResult> {
        let paths = self.ensure_helper(session, cwd, None, None, env).await?;
        GhosttyClient::connect(paths.socket_path)
            .await?
            .run(cwd.map(ToOwned::to_owned), argv.to_vec())
            .await
    }

    pub(crate) async fn history(&self, session: &str) -> Result<String> {
        let paths = self.registry.paths_for(session);
        GhosttyClient::connect(paths.socket_path)
            .await?
            .history()
            .await
    }

    pub(crate) async fn kill(&self, session: &str) -> Result<()> {
        let paths = self.registry.paths_for(session);
        if let Ok(client) = GhosttyClient::connect(paths.socket_path.clone()).await {
            let _ = client.kill().await;
        }
        cleanup_helper_files(&paths).await;
        Ok(())
    }

    pub(crate) async fn attach_process(
        &self,
        session: &str,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        env: Option<Vec<(String, String)>>,
    ) -> Result<Arc<ShellProcess>> {
        let paths = self.ensure_helper(session, cwd, pty, argv, env).await?;
        let cols = pty.map_or(80, |pty| pty.cols);
        let rows = pty.map_or(24, |pty| pty.rows);
        let metadata = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .probe()
            .await?;
        let attach = GhosttyClient::connect(paths.socket_path)
            .await?
            .attach(cols, rows)
            .await?;
        Ok(ghostty_attach_process(metadata.pid, attach))
    }

    async fn ensure_helper(
        &self,
        session: &str,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        env: Option<Vec<(String, String)>>,
    ) -> Result<GhosttySessionPaths> {
        let paths = self.registry.paths_for(session);
        let live = match GhosttyClient::connect(paths.socket_path.clone()).await {
            Ok(client) => client.probe().await.is_ok(),
            Err(_) => false,
        };
        if live {
            return Ok(paths);
        }
        cleanup_helper_files(&paths).await;
        self.spawn_helper(session, &paths, cwd, pty, argv, env)
            .await?;
        Ok(paths)
    }

    async fn spawn_helper(
        &self,
        session: &str,
        paths: &GhosttySessionPaths,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        env: Option<Vec<(String, String)>>,
    ) -> Result<()> {
        let rows = pty.map_or(24, |pty| pty.rows);
        let cols = pty.map_or(80, |pty| pty.cols);
        if let Some(parent) = paths.socket_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        if let Some(parent) = paths.metadata_path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let helper_argv = helper_initial_argv(argv, env.as_ref());
        let mut command = std::process::Command::new(&self.helper_exe);
        command
            .arg("__ghostty-session")
            .arg("--name")
            .arg(session)
            .arg("--socket")
            .arg(&paths.socket_path)
            .arg("--state-dir")
            .arg(self.registry.state_root())
            .arg("--rows")
            .arg(rows.to_string())
            .arg("--cols")
            .arg(cols.to_string());
        if let Some(cwd) = cwd {
            command.arg("--cwd").arg(cwd);
        }
        command.arg("--").args(&helper_argv);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .env_clear();
        if let Some(env) = env {
            command.envs(env);
        } else {
            command.envs(minimal_helper_env());
        }
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt;
            // SAFETY(unsafe_code): setsid is async-signal-safe and runs in the child
            // after fork and before exec so helpers outlive the launching agent/CLI.
            #[allow(unsafe_code)]
            unsafe {
                command.pre_exec(|| {
                    if nix::libc::setsid() == -1 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        command.spawn().context("spawn ghostty helper")?;
        wait_for_socket(&paths.socket_path, Duration::from_secs(5)).await
    }
}

fn ghostty_features() -> Vec<String> {
    [
        "ghostty-vt.v1",
        "helper.v1",
        "viewport_snapshot.v1",
        "live_output.v1",
        "sidecar_run.v1",
    ]
    .into_iter()
    .map(ToOwned::to_owned)
    .collect()
}

#[cfg(unix)]
fn session_info_from_metadata(
    metadata: GhosttySessionMetadata,
) -> portl_proto::session_v1::SessionInfo {
    let mut map = std::collections::BTreeMap::new();
    map.insert("pid".to_owned(), metadata.pid.to_string());
    map.insert(
        "socket_path".to_owned(),
        metadata.socket_path.display().to_string(),
    );
    map.insert(
        "created_at_ms".to_owned(),
        metadata.created_at_ms.to_string(),
    );
    map.insert("last_seen_ms".to_owned(), metadata.last_seen_ms.to_string());
    map.insert("rows".to_owned(), metadata.rows.to_string());
    map.insert("cols".to_owned(), metadata.cols.to_string());
    map.insert("status".to_owned(), metadata.status);
    if let Some(cwd) = metadata.cwd {
        map.insert("cwd".to_owned(), cwd);
    }
    portl_proto::session_v1::SessionInfo {
        name: metadata.name,
        provider: "ghostty".to_owned(),
        metadata: map,
    }
}

#[cfg(unix)]
fn ghostty_attach_process(pid: u32, mut attach: GhosttyAttach) -> Arc<ShellProcess> {
    let initial_snapshot = std::mem::take(&mut attach.initial_snapshot);
    let (stdin_tx, mut stdin_rx) = mpsc::channel(32);
    let (pty_tx, mut pty_rx) = mpsc::unbounded_channel();
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (_stderr_tx, stderr_rx) = mpsc::channel(1);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);
    let exit_code_task = Arc::clone(&exit_code);
    let exit_tx_task = exit_tx.clone();

    tokio::spawn(async move {
        if !initial_snapshot.is_empty() && stdout_tx.send(initial_snapshot).await.is_err() {
            return;
        }
        loop {
            tokio::select! {
                Some(message) = stdin_rx.recv() => {
                    match message {
                        StdinMessage::Data(bytes) => {
                            if attach.input(bytes).await.is_err() {
                                break;
                            }
                        }
                        StdinMessage::Close => {
                            let _ = attach.detach().await;
                            break;
                        }
                    }
                }
                Some(command) = pty_rx.recv() => {
                    match command {
                        PtyCommand::Resize { rows, cols } => {
                            let _ = attach.resize(cols, rows).await;
                        }
                        PtyCommand::Close { .. } => {
                            let _ = attach.detach().await;
                            break;
                        }
                        PtyCommand::KickOthers => {}
                    }
                }
                response = attach.next_response() => {
                    match response {
                        Ok(Some(GhosttyResponse::Output { bytes })) => {
                            if stdout_tx.send(bytes).await.is_err() {
                                break;
                            }
                        }
                        Ok(Some(GhosttyResponse::Exit { code })) => {
                            if let Ok(mut guard) = exit_code_task.lock() {
                                *guard = Some(code);
                            }
                            let _ = exit_tx_task.send(Some(code));
                            break;
                        }
                        Ok(Some(GhosttyResponse::Error { .. }) | None) | Err(_) => {
                            if let Ok(mut guard) = exit_code_task.lock() {
                                *guard = Some(1);
                            }
                            let _ = exit_tx_task.send(Some(1));
                            break;
                        }
                        Ok(Some(_)) => {}
                    }
                }
            }
        }
    });

    let signal_target = i32::try_from(pid).ok().and_then(i32::checked_neg);
    Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target,
        pty_tx: Some(pty_tx),
        started_at: Arc::new(Mutex::new(Some(Instant::now()))),
    })
}

fn minimal_helper_env() -> Vec<(String, String)> {
    [
        "HOME", "LANG", "LC_ALL", "LOGNAME", "PATH", "SHELL", "TERM", "USER",
    ]
    .into_iter()
    .filter_map(|key| std::env::var(key).ok().map(|value| (key.to_owned(), value)))
    .collect()
}

#[cfg(unix)]
fn helper_initial_argv(
    argv: Option<&[String]>,
    env: Option<&Vec<(String, String)>>,
) -> Vec<String> {
    if let Some(argv) = argv.filter(|argv| !argv.is_empty()) {
        return argv.to_vec();
    }
    let shell = env
        .and_then(|env| {
            env.iter()
                .find(|(key, _)| key == "SHELL")
                .map(|(_, value)| value.clone())
        })
        .or_else(|| std::env::var("SHELL").ok())
        .unwrap_or_else(|| "/bin/sh".to_owned());
    vec![shell, "-l".to_owned()]
}

#[cfg(unix)]
pub(crate) async fn run_helper_command(
    name: String,
    socket_path: PathBuf,
    state_root: PathBuf,
    cwd: Option<String>,
    rows: u16,
    cols: u16,
    argv: Vec<String>,
) -> Result<()> {
    let encoded = encode_session_component(&name);
    let paths = GhosttySessionPaths {
        socket_path,
        metadata_path: state_root.join("sessions").join(format!("{encoded}.json")),
        history_path: state_root
            .join("sessions")
            .join(format!("{encoded}.history")),
    };
    let argv = if argv.is_empty() {
        helper_initial_argv(None, None)
    } else {
        argv
    };
    run_helper(GhosttyHelperConfig::new(
        name, paths, cwd, rows, cols, argv, None,
    ))
    .await
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum GhosttyRequest {
    Probe,
    Attach {
        cols: u16,
        rows: u16,
    },
    Input {
        bytes: Vec<u8>,
    },
    Resize {
        cols: u16,
        rows: u16,
    },
    Run {
        cwd: Option<String>,
        argv: Vec<String>,
    },
    History,
    Kill,
    Detach,
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum GhosttyResponse {
    Ack {
        metadata: GhosttySessionMetadata,
    },
    Attached {
        metadata: GhosttySessionMetadata,
        snapshot: Vec<u8>,
    },
    Output {
        bytes: Vec<u8>,
    },
    RunResult {
        result: portl_proto::session_v1::SessionRunResult,
    },
    History {
        output: String,
    },
    Exit {
        code: i32,
    },
    Error {
        message: String,
    },
}

#[cfg(unix)]
enum HelperCommand {
    Probe {
        reply: oneshot::Sender<GhosttySessionMetadata>,
    },
    Subscribe {
        cols: u16,
        rows: u16,
        reply: oneshot::Sender<(
            GhosttySessionMetadata,
            Vec<u8>,
            mpsc::UnboundedReceiver<Vec<u8>>,
        )>,
    },
    Input(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    Run {
        cwd: Option<String>,
        argv: Vec<String>,
        reply: oneshot::Sender<Result<portl_proto::session_v1::SessionRunResult, String>>,
    },
    History {
        reply: oneshot::Sender<String>,
    },
    Kill {
        reply: oneshot::Sender<()>,
    },
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_helper(config: GhosttyHelperConfig) -> Result<()> {
    if config.argv.is_empty() {
        bail!("ghostty helper argv cannot be empty");
    }
    if let Some(parent) = config.paths.socket_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    if let Some(parent) = config.paths.metadata_path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    match tokio::fs::remove_file(&config.paths.socket_path).await {
        Ok(()) => {}
        Err(err) if err.kind() == ErrorKind::NotFound => {}
        Err(err) => return Err(err).context("remove stale ghostty socket"),
    }

    let listener = UnixListener::bind(&config.paths.socket_path).context("bind ghostty socket")?;
    let winsize = nix::libc::winsize {
        ws_row: config.rows,
        ws_col: config.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let (program, args) = config
        .argv
        .split_first()
        .map(|(program, args)| (program.clone(), args.to_vec()))
        .expect("checked non-empty argv");
    let env = config.env.unwrap_or_else(|| std::env::vars().collect());
    let (master, mut child) = crate::shell_handler::spawn::spawn_pty_blocking(
        &program,
        &args,
        winsize,
        env,
        config.cwd.as_deref(),
    )
    .context("spawn ghostty helper pty")?;
    let pid = child.id().context("missing ghostty child pid")?;
    let now = now_ms();
    let metadata = GhosttySessionMetadata {
        name: config.name.clone(),
        provider: "ghostty".to_owned(),
        pid,
        socket_path: config.paths.socket_path.clone(),
        created_at_ms: now,
        last_seen_ms: now,
        cwd: config.cwd.clone(),
        rows: config.rows,
        cols: config.cols,
        status: "running".to_owned(),
        protocol_version: GHOSTTY_PROTOCOL_VERSION,
    };
    write_metadata(&config.paths.metadata_path, &metadata).await?;

    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel();
    let accept_tx = cmd_tx.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.context("accept ghostty client")?;
            let tx = accept_tx.clone();
            tokio::spawn(async move {
                if let Err(err) = handle_client(stream, tx).await {
                    tracing::debug!(%err, "ghostty client handler ended");
                }
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    });

    crate::shell_handler::pty_master::set_nonblocking(&master)?;
    let master = tokio::io::unix::AsyncFd::new(master).context("register ghostty pty")?;
    let mut terminal = Terminal::new(TerminalOptions {
        cols: config.cols,
        rows: config.rows,
        max_scrollback: 4096,
    })?;
    let mut metadata = metadata;
    let mut history = VecDeque::new();
    let mut subscribers: Vec<mpsc::UnboundedSender<Vec<u8>>> = Vec::new();
    let mut read_buf = vec![0_u8; IO_CHUNK];
    let mut child_wait = Box::pin(child.wait());

    loop {
        tokio::select! {
            status = &mut child_wait => {
                let _ = status;
                broadcast(&mut subscribers, &[]);
                cleanup_helper_files(&config.paths).await;
                accept_task.abort();
                return Ok(());
            }
            chunk = crate::shell_handler::pty_master::read_pty_chunk(&master, &mut read_buf) => {
                if let Some(bytes) = chunk.context("read ghostty pty")? {
                    process_output(&mut terminal, &mut history, &mut subscribers, &bytes);
                } else {
                    cleanup_helper_files(&config.paths).await;
                    accept_task.abort();
                    return Ok(());
                }
            }
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    HelperCommand::Probe { reply } => {
                        metadata.last_seen_ms = now_ms();
                        let _ = reply.send(metadata.clone());
                    }
                    HelperCommand::Subscribe { cols, rows, reply } => {
                        let _ = resize_helper(&master, &mut terminal, &mut metadata, rows, cols);
                        metadata.last_seen_ms = now_ms();
                        let (tx, rx) = mpsc::unbounded_channel();
                        subscribers.push(tx);
                        let snapshot = history.iter().copied().collect::<Vec<_>>();
                        let _ = reply.send((metadata.clone(), snapshot, rx));
                    }
                    HelperCommand::Input(bytes) => {
                        crate::shell_handler::pty_master::write_pty_all(&master, &bytes).await.context("write ghostty pty input")?;
                    }
                    HelperCommand::Resize { cols, rows } => {
                        let _ = resize_helper(&master, &mut terminal, &mut metadata, rows, cols);
                    }
                    HelperCommand::Run { cwd, argv, reply } => {
                        let result = run_sidecar(cwd.as_deref().or(config.cwd.as_deref()), &argv).await;
                        if let Ok(run) = &result {
                            let mirrored = mirror_run_output(&argv, run);
                            process_output(&mut terminal, &mut history, &mut subscribers, &mirrored);
                            metadata.last_seen_ms = now_ms();
                        }
                        let _ = reply.send(result.map_err(|err| err.to_string()));
                    }
                    HelperCommand::History { reply } => {
                        let output = String::from_utf8_lossy(history.make_contiguous()).into_owned();
                        let _ = reply.send(output);
                    }
                    HelperCommand::Kill { reply } => {
                        let _ = reply.send(());
                        if let Ok(raw) = i32::try_from(pid) {
                            let _ = nix::sys::signal::killpg(
                                nix::unistd::Pid::from_raw(raw),
                                nix::sys::signal::Signal::SIGHUP,
                            );
                        }
                    }
                }
            }
        }
    }
}

#[cfg(unix)]
fn resize_helper(
    master: &tokio::io::unix::AsyncFd<std::os::fd::OwnedFd>,
    terminal: &mut Terminal<'_, '_>,
    metadata: &mut GhosttySessionMetadata,
    rows: u16,
    cols: u16,
) -> Result<()> {
    crate::shell_handler::pumps::resize_pty(master.get_ref(), rows, cols).context("resize pty")?;
    terminal
        .resize(cols, rows, 0, 0)
        .context("resize ghostty terminal")?;
    metadata.rows = rows;
    metadata.cols = cols;
    metadata.last_seen_ms = now_ms();
    Ok(())
}

#[cfg(unix)]
fn process_output(
    terminal: &mut Terminal<'_, '_>,
    history: &mut VecDeque<u8>,
    subscribers: &mut Vec<mpsc::UnboundedSender<Vec<u8>>>,
    bytes: &[u8],
) {
    terminal.vt_write(bytes);
    append_bounded(history, bytes);
    broadcast(subscribers, bytes);
}

#[cfg(unix)]
fn append_bounded(history: &mut VecDeque<u8>, bytes: &[u8]) {
    history.extend(bytes.iter().copied());
    while history.len() > MAX_HISTORY_BYTES {
        let _ = history.pop_front();
    }
}

#[cfg(unix)]
fn broadcast(subscribers: &mut Vec<mpsc::UnboundedSender<Vec<u8>>>, bytes: &[u8]) {
    subscribers.retain(|subscriber| subscriber.send(bytes.to_vec()).is_ok());
}

#[cfg(unix)]
async fn run_sidecar(
    cwd: Option<&str>,
    argv: &[String],
) -> Result<portl_proto::session_v1::SessionRunResult> {
    let Some((program, command_args)) = argv.split_first() else {
        bail!("run argv cannot be empty");
    };
    let mut command = tokio::process::Command::new(program);
    command.args(command_args);
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    let output = command
        .output()
        .await
        .with_context(|| format!("run {}", argv.join(" ")))?;
    Ok(portl_proto::session_v1::SessionRunResult {
        code: output.status.code().unwrap_or(1),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

#[cfg(unix)]
fn mirror_run_output(argv: &[String], run: &portl_proto::session_v1::SessionRunResult) -> Vec<u8> {
    let mut out = format!("\r\n[portl run] {}\r\n", argv.join(" ")).into_bytes();
    out.extend_from_slice(run.stdout.as_bytes());
    out.extend_from_slice(run.stderr.as_bytes());
    if !out.ends_with(b"\n") {
        out.extend_from_slice(b"\r\n");
    }
    out
}

#[cfg(unix)]
async fn handle_client(
    mut stream: UnixStream,
    tx: mpsc::UnboundedSender<HelperCommand>,
) -> Result<()> {
    let Some(first) = read_frame::<GhosttyRequest>(&mut stream).await? else {
        return Ok(());
    };
    match first {
        GhosttyRequest::Probe => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Probe { reply: reply_tx })
                .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let metadata = reply_rx.await.context("ghostty probe reply")?;
            write_frame(&mut stream, &GhosttyResponse::Ack { metadata }).await
        }
        GhosttyRequest::Run { cwd, argv } => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Run {
                cwd,
                argv,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("ghostty helper stopped"))?;
            match reply_rx.await.context("ghostty run reply")? {
                Ok(result) => {
                    write_frame(&mut stream, &GhosttyResponse::RunResult { result }).await
                }
                Err(message) => write_frame(&mut stream, &GhosttyResponse::Error { message }).await,
            }
        }
        GhosttyRequest::History => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::History { reply: reply_tx })
                .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let output = reply_rx.await.context("ghostty history reply")?;
            write_frame(&mut stream, &GhosttyResponse::History { output }).await
        }
        GhosttyRequest::Kill => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Kill { reply: reply_tx })
                .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let _ = reply_rx.await;
            write_frame(&mut stream, &GhosttyResponse::Exit { code: 0 }).await
        }
        GhosttyRequest::Attach { cols, rows } => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Subscribe {
                cols,
                rows,
                reply: reply_tx,
            })
            .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let (metadata, snapshot, mut output_rx) =
                reply_rx.await.context("ghostty attach reply")?;
            write_frame(
                &mut stream,
                &GhosttyResponse::Attached { metadata, snapshot },
            )
            .await?;
            loop {
                tokio::select! {
                    Some(bytes) = output_rx.recv() => {
                        if bytes.is_empty() {
                            write_frame(&mut stream, &GhosttyResponse::Exit { code: 0 }).await?;
                            return Ok(());
                        }
                        write_frame(&mut stream, &GhosttyResponse::Output { bytes }).await?;
                    }
                    request = read_frame::<GhosttyRequest>(&mut stream) => {
                        match request? {
                            Some(GhosttyRequest::Input { bytes }) => tx.send(HelperCommand::Input(bytes)).map_err(|_| anyhow!("ghostty helper stopped"))?,
                            Some(GhosttyRequest::Resize { cols, rows }) => tx.send(HelperCommand::Resize { cols, rows }).map_err(|_| anyhow!("ghostty helper stopped"))?,
                            Some(GhosttyRequest::Detach) | None => return Ok(()),
                            Some(GhosttyRequest::Kill) => {
                                let (reply_tx, reply_rx) = oneshot::channel();
                                tx.send(HelperCommand::Kill { reply: reply_tx }).map_err(|_| anyhow!("ghostty helper stopped"))?;
                                let _ = reply_rx.await;
                                return Ok(());
                            }
                            Some(other) => tracing::debug!(?other, "ignoring non-attach ghostty request on attach stream"),
                        }
                    }
                }
            }
        }
        other => bail!("unexpected first ghostty request: {other:?}"),
    }
}

#[cfg(unix)]
pub(crate) struct GhosttyClient {
    stream: UnixStream,
}

#[cfg(unix)]
impl GhosttyClient {
    pub(crate) async fn connect(path: PathBuf) -> Result<Self> {
        Ok(Self {
            stream: UnixStream::connect(path)
                .await
                .context("connect ghostty helper")?,
        })
    }

    pub(crate) async fn probe(mut self) -> Result<GhosttySessionMetadata> {
        write_frame(&mut self.stream, &GhosttyRequest::Probe).await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::Ack { metadata }) => Ok(metadata),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty probe response: {other:?}"),
        }
    }

    pub(crate) async fn run(
        mut self,
        cwd: Option<String>,
        argv: Vec<String>,
    ) -> Result<portl_proto::session_v1::SessionRunResult> {
        write_frame(&mut self.stream, &GhosttyRequest::Run { cwd, argv }).await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::RunResult { result }) => Ok(result),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty run response: {other:?}"),
        }
    }

    pub(crate) async fn history(mut self) -> Result<String> {
        write_frame(&mut self.stream, &GhosttyRequest::History).await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::History { output }) => Ok(output),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty history response: {other:?}"),
        }
    }

    pub(crate) async fn kill(mut self) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Kill).await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::Exit { .. } | GhosttyResponse::Ack { .. }) | None => Ok(()),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty kill response: {other:?}"),
        }
    }

    pub(crate) async fn attach(mut self, cols: u16, rows: u16) -> Result<GhosttyAttach> {
        write_frame(&mut self.stream, &GhosttyRequest::Attach { cols, rows }).await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::Attached { snapshot, .. }) => Ok(GhosttyAttach {
                stream: self.stream,
                #[cfg(test)]
                buffered: String::from_utf8_lossy(&snapshot).into_owned(),
                initial_snapshot: snapshot,
            }),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty attach response: {other:?}"),
        }
    }
}

#[cfg(unix)]
pub(crate) struct GhosttyAttach {
    stream: UnixStream,
    initial_snapshot: Vec<u8>,
    #[cfg(test)]
    buffered: String,
}

#[cfg(unix)]
impl GhosttyAttach {
    pub(crate) async fn input(&mut self, bytes: Vec<u8>) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Input { bytes }).await
    }

    pub(crate) async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Resize { cols, rows }).await
    }

    pub(crate) async fn detach(&mut self) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Detach).await
    }

    async fn next_response(&mut self) -> Result<Option<GhosttyResponse>> {
        read_frame::<GhosttyResponse>(&mut self.stream).await
    }

    #[cfg(test)]
    async fn read_until_contains(&mut self, needle: &str, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            if self.buffered.contains(needle) {
                return Ok(self.buffered.clone());
            }
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                bail!("timed out waiting for ghostty attach output containing {needle:?}");
            };
            let response =
                tokio::time::timeout(remaining, read_frame::<GhosttyResponse>(&mut self.stream))
                    .await
                    .context("wait for ghostty output")??;
            match response {
                Some(GhosttyResponse::Output { bytes }) => {
                    self.buffered.push_str(&String::from_utf8_lossy(&bytes));
                }
                Some(GhosttyResponse::Exit { code }) => bail!("ghostty helper exited with {code}"),
                Some(GhosttyResponse::Error { message }) => bail!(message),
                Some(_) => {}
                None => bail!("ghostty attach stream closed"),
            }
        }
    }
}

#[cfg(unix)]
async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let bytes = postcard::to_stdvec(value).context("encode ghostty frame")?;
    if bytes.len() > MAX_FRAME_BYTES {
        bail!("ghostty frame too large: {} bytes", bytes.len());
    }
    let len = u32::try_from(bytes.len()).context("ghostty frame length overflow")?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(&bytes).await?;
    Ok(())
}

#[cfg(unix)]
async fn read_frame<T: DeserializeOwned>(stream: &mut UnixStream) -> Result<Option<T>> {
    let mut len_buf = [0_u8; 4];
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(err) if err.kind() == ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err).context("read ghostty frame length"),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_BYTES {
        bail!("ghostty frame too large: {len} bytes");
    }
    let mut bytes = vec![0_u8; len];
    stream
        .read_exact(&mut bytes)
        .await
        .context("read ghostty frame")?;
    Ok(Some(
        postcard::from_bytes(&bytes).context("decode ghostty frame")?,
    ))
}

#[cfg(unix)]
async fn write_metadata(path: &Path, metadata: &GhosttySessionMetadata) -> Result<()> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let bytes = serde_json::to_vec_pretty(metadata)?;
    tokio::fs::write(path, bytes).await?;
    Ok(())
}

#[cfg(unix)]
async fn cleanup_helper_files(paths: &GhosttySessionPaths) {
    let _ = tokio::fs::remove_file(&paths.socket_path).await;
    let _ = tokio::fs::remove_file(&paths.metadata_path).await;
}

#[cfg(unix)]
async fn wait_for_socket(path: &Path, timeout: Duration) -> Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if path.exists() && UnixStream::connect(path).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            bail!("timed out waiting for socket {}", path.display());
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(unix)]
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

#[cfg(all(test, unix))]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use anyhow::{Context, Result};

    use super::*;

    #[test]
    fn session_names_are_encoded_for_single_path_component() {
        assert_eq!(encode_session_component("dev"), "dev");
        assert_eq!(encode_session_component("dev/main"), "dev%2Fmain");
        assert_eq!(encode_session_component("weird name"), "weird%20name");
        assert_eq!(encode_session_component("%already"), "%25already");
    }

    #[test]
    fn metadata_round_trips_as_json() -> Result<()> {
        let metadata = GhosttySessionMetadata {
            name: "dev".to_owned(),
            provider: "ghostty".to_owned(),
            pid: 42,
            socket_path: PathBuf::from("/tmp/portl-ghostty/dev.sock"),
            created_at_ms: 1_700_000_000_000,
            last_seen_ms: 1_700_000_001_000,
            cwd: Some("/work".to_owned()),
            rows: 24,
            cols: 80,
            status: "running".to_owned(),
            protocol_version: GHOSTTY_PROTOCOL_VERSION,
        };

        let encoded = serde_json::to_vec(&metadata)?;
        let decoded: GhosttySessionMetadata = serde_json::from_slice(&encoded)?;

        assert_eq!(decoded, metadata);
        Ok(())
    }

    #[tokio::test]
    async fn helper_run_history_and_kill_round_trip() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("dev");
        let helper = GhosttyHelperConfig::for_test(
            "dev",
            paths.clone(),
            vec!["/bin/sh".to_owned(), "-l".to_owned()],
        );
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let run = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .run(
                None,
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "printf run-ok".to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);
        assert_eq!(run.stdout, "run-ok");

        let history = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .history()
            .await?;
        assert!(history.contains("run-ok"), "history was: {history:?}");

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        assert!(!paths.metadata_path.exists());
        Ok(())
    }

    #[tokio::test]
    async fn helper_attach_forwards_input_and_output() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("cat");
        let helper =
            GhosttyHelperConfig::for_test("cat", paths.clone(), vec!["/bin/cat".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach(80, 24)
            .await?;
        attach.input(b"hello from attach\n".to_vec()).await?;
        let output = attach
            .read_until_contains("hello from attach", Duration::from_secs(2))
            .await?;
        assert!(
            output.contains("hello from attach"),
            "output was: {output:?}"
        );

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    fn spawn_helper_thread(
        config: GhosttyHelperConfig,
    ) -> std::thread::JoinHandle<anyhow::Result<()>> {
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .context("build helper runtime")?;
            runtime.block_on(run_helper(config))
        })
    }

    #[test]
    fn registry_paths_are_stable_and_separated_by_purpose() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = temp.path().join("runtime");
        let state = temp.path().join("state");
        let registry = GhosttyRegistry::with_roots(runtime.clone(), state.clone());

        let paths = registry.paths_for("dev/main");

        assert_eq!(
            paths.socket_path,
            runtime.join("sockets").join("dev%2Fmain.sock")
        );
        assert_eq!(
            paths.metadata_path,
            state.join("sessions").join("dev%2Fmain.json")
        );
        assert_eq!(
            paths.history_path,
            state.join("sessions").join("dev%2Fmain.history")
        );
    }
}
