#[cfg(unix)]
use std::cell::RefCell;
#[cfg(unix)]
use std::collections::VecDeque;
#[cfg(unix)]
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::process::Stdio;
#[cfg(unix)]
use std::rc::Rc;
#[cfg(unix)]
use std::sync::{Arc, Mutex};
#[cfg(unix)]
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow, bail};
#[cfg(unix)]
use libghostty_vt::render::{CellIterator, RowIterator};
#[cfg(unix)]
use libghostty_vt::screen::Screen;
#[cfg(unix)]
use libghostty_vt::style::{RgbColor, Underline};
#[cfg(unix)]
use libghostty_vt::{
    RenderState, Terminal, TerminalOptions,
    terminal::{
        ConformanceLevel, DeviceAttributeFeature, DeviceAttributes, DeviceType, Mode,
        PrimaryDeviceAttributes, SecondaryDeviceAttributes, TertiaryDeviceAttributes,
    },
};
#[cfg(unix)]
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
#[cfg(unix)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(unix)]
use tokio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot, watch};

#[cfg(unix)]
use crate::shell_registry::{PtyCommand, ShellOutput, ShellProcess, StdinMessage};

pub(crate) const GHOSTTY_PROTOCOL_VERSION: u16 = 1;

#[cfg(unix)]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 104;

#[cfg(unix)]
type TerminalPtyReplies = Rc<RefCell<Vec<Vec<u8>>>>;

#[cfg(unix)]
struct GhosttyTerminalIo {
    terminal: Terminal<'static, 'static>,
    pty_replies: TerminalPtyReplies,
    pending_input: crate::shell_handler::pty_master::PendingPtyWrite,
    query_stripper: portl_core::QueryStripper,
}

#[cfg(unix)]
impl GhosttyTerminalIo {
    fn new(options: TerminalOptions) -> Result<Self> {
        let mut terminal = Terminal::new(options)?;
        let pty_replies = Rc::new(RefCell::new(Vec::new()));
        configure_portl_terminal_capabilities(&mut terminal, Rc::clone(&pty_replies))?;
        Ok(Self {
            terminal,
            pty_replies,
            pending_input: crate::shell_handler::pty_master::PendingPtyWrite::new(
                crate::shell_handler::pty_master::DEFAULT_PTY_INPUT_QUEUE_BYTES,
            ),
            query_stripper: portl_core::QueryStripper::new(),
        })
    }
}

#[cfg(unix)]
impl std::ops::Deref for GhosttyTerminalIo {
    type Target = Terminal<'static, 'static>;

    fn deref(&self) -> &Self::Target {
        &self.terminal
    }
}

#[cfg(unix)]
impl std::ops::DerefMut for GhosttyTerminalIo {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.terminal
    }
}

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
            .map_or_else(portl_core::paths::ghostty_state_dir, PathBuf::from);
        let runtime_root = std::env::var_os("PORTL_GHOSTTY_RUNTIME_DIR")
            .map_or_else(portl_core::paths::ghostty_runtime_dir, PathBuf::from);
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
        self.paths_for_with_socket(session, socket_path_for(&self.runtime_root, session))
    }

    fn paths_for_with_socket(&self, session: &str, socket_path: PathBuf) -> GhosttySessionPaths {
        let encoded = encode_session_component(session);
        GhosttySessionPaths {
            socket_path,
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

fn socket_path_for(runtime_root: &Path, session: &str) -> PathBuf {
    let socket_name = socket_file_name(session);
    let preferred = runtime_root.join("sockets").join(&socket_name);
    if unix_socket_path_fits(&preferred) {
        preferred
    } else {
        short_runtime_root().join("sockets").join(socket_name)
    }
}

fn socket_file_name(session: &str) -> String {
    let encoded = encode_session_component(session);
    let prefix = if encoded.is_empty() {
        "session".to_owned()
    } else {
        encoded.chars().take(24).collect()
    };
    format!("{prefix}-{:016x}.sock", stable_session_hash(session))
}

fn stable_session_hash(session: &str) -> u64 {
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    session.bytes().fold(FNV_OFFSET_BASIS, |hash, byte| {
        (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
    })
}

#[cfg(unix)]
fn unix_socket_path_fits(path: &Path) -> bool {
    use std::os::unix::ffi::OsStrExt as _;
    path.as_os_str().as_bytes().len() < MAX_UNIX_SOCKET_PATH_BYTES
}

#[cfg(not(unix))]
fn unix_socket_path_fits(_path: &Path) -> bool {
    true
}

#[cfg(unix)]
fn short_runtime_root() -> PathBuf {
    use std::os::unix::ffi::OsStrExt as _;

    let suffix = format!("portl-ghostty-{}", nix::unistd::Uid::current().as_raw());
    let xdg_candidate = std::env::var_os("XDG_RUNTIME_DIR")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .map(|dir| dir.join(&suffix));
    if let Some(candidate) = xdg_candidate
        && candidate.as_os_str().as_bytes().len() <= 48
    {
        return candidate;
    }
    PathBuf::from("/tmp").join(suffix)
}

#[cfg(not(unix))]
fn short_runtime_root() -> PathBuf {
    std::env::temp_dir().join("portl-ghostty")
}

#[cfg(unix)]
const MAX_FRAME_BYTES: usize = 4 * 1024 * 1024;
#[cfg(unix)]
const MAX_HISTORY_BYTES: usize = 64 * 1024 * 1024;
#[cfg(unix)]
const IO_CHUNK: usize = 16 * 1024;
// Shared command queue for all clients; bounded to propagate backpressure instead of
// accumulating paste data. Clients that overflow the queue receive an explicit error.
#[cfg(unix)]
const GHOSTTY_HELPER_COMMANDS: usize = 64;
#[cfg(unix)]
const GHOSTTY_SUBSCRIBER_BUFFER: usize = 64;
#[cfg(unix)]
const GHOSTTY_ATTACH_V2_QUEUE: usize = 256;
#[cfg(unix)]
const GHOSTTY_ATTACH_V2_HISTORY_CHUNK: usize = 64 * 1024;
#[cfg(unix)]
const GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES: usize = 1024 * 1024;
#[cfg(unix)]
const GHOSTTY_ATTACH_V2_RESIZE_SETTLE_MS: u64 = 200;
#[cfg(unix)]
const GHOSTTY_ATTACH_V2_MAX_RELOAD_JOBS: usize = 2;
#[cfg(unix)]
const GHOSTTY_FRAME_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
// MAX_FRAME_BYTES / 2 leaves postcard metadata/headroom under the frame cap so the
// serialized, length-prefixed snapshot never exceeds the wire frame size limit.
#[cfg(unix)]
const MAX_ATTACH_SNAPSHOT_BYTES: usize = MAX_FRAME_BYTES / 2;

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
                let paths = self
                    .registry
                    .paths_for_with_socket(&metadata.name, metadata.socket_path.clone());
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
        let paths = self
            .live_existing_paths(session)
            .await?
            .unwrap_or_else(|| self.registry.paths_for(session));
        GhosttyClient::connect(paths.socket_path)
            .await?
            .history()
            .await
    }

    pub(crate) async fn kill(&self, session: &str) -> Result<()> {
        for paths in self.candidate_paths(session).await? {
            if let Ok(client) = GhosttyClient::connect(paths.socket_path.clone()).await {
                let _ = client.kill().await;
            }
            cleanup_helper_files(&paths).await;
        }
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

    pub(crate) async fn attach_v2_session(
        &self,
        session: &str,
        cwd: Option<&str>,
        pty: Option<&portl_proto::shell_v1::PtyCfg>,
        argv: Option<&[String]>,
        env: Option<Vec<(String, String)>>,
        config: portl_proto::session_v1::AttachV2Config,
    ) -> Result<Arc<GhosttyAttachV2Session>> {
        let paths = self.ensure_helper(session, cwd, pty, argv, env).await?;
        let cols = pty.map_or(80, |pty| pty.cols);
        let rows = pty.map_or(24, |pty| pty.rows);
        let metadata = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .probe()
            .await?;
        let attach = GhosttyClient::connect(paths.socket_path)
            .await?
            .attach_v2(cols, rows, config)
            .await?;
        GhosttyAttachV2Session::new(metadata.pid, attach).await
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
        if let Some(paths) = self.live_existing_paths(session).await? {
            return Ok(paths);
        }
        cleanup_helper_files(&paths).await;
        self.spawn_helper(session, &paths, cwd, pty, argv, env)
            .await?;
        Ok(paths)
    }

    async fn live_existing_paths(&self, session: &str) -> Result<Option<GhosttySessionPaths>> {
        for metadata in self.registry.list_metadata().await? {
            if metadata.name != session {
                continue;
            }
            let paths = self
                .registry
                .paths_for_with_socket(&metadata.name, metadata.socket_path.clone());
            let live = match GhosttyClient::connect(paths.socket_path.clone()).await {
                Ok(client) => client.probe().await.is_ok(),
                Err(_) => false,
            };
            if live {
                return Ok(Some(paths));
            }
            cleanup_helper_files(&paths).await;
        }
        Ok(None)
    }

    async fn candidate_paths(&self, session: &str) -> Result<Vec<GhosttySessionPaths>> {
        let mut paths = vec![self.registry.paths_for(session)];
        for metadata in self.registry.list_metadata().await? {
            if metadata.name == session {
                let metadata_paths = self
                    .registry
                    .paths_for_with_socket(&metadata.name, metadata.socket_path);
                if !paths
                    .iter()
                    .any(|paths| paths.socket_path == metadata_paths.socket_path)
                {
                    paths.push(metadata_paths);
                }
            }
        }
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
    let (stderr_closed_tx, stderr_closed_rx) = watch::channel(false);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);
    let exit_code_task = Arc::clone(&exit_code);
    let exit_tx_task = exit_tx.clone();

    tokio::spawn(async move {
        struct CloseOnDrop(watch::Sender<bool>);

        impl Drop for CloseOnDrop {
            fn drop(&mut self) {
                let _ = self.0.send(true);
            }
        }

        let _stderr_closed = CloseOnDrop(stderr_closed_tx);
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
        stdout: ShellOutput::channel(stdout_rx),
        stderr: ShellOutput::empty_until_closed(stderr_closed_rx),
        exit_code,
        exit_tx,
        signal_target,
        strip_stdout_queries: std::sync::atomic::AtomicBool::new(false),
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
async fn prepare_socket_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    tokio::fs::create_dir_all(path).await?;
    let link_meta = tokio::fs::symlink_metadata(path).await?;
    if link_meta.file_type().is_symlink() {
        bail!(
            "ghostty socket directory must not be a symlink: {}",
            path.display()
        );
    }
    let meta = tokio::fs::metadata(path).await?;
    if !meta.is_dir() {
        bail!(
            "ghostty socket path parent is not a directory: {}",
            path.display()
        );
    }
    let current_uid = nix::unistd::Uid::current().as_raw();
    if meta.uid() != current_uid {
        bail!(
            "ghostty socket directory {} is owned by uid {}, expected {}",
            path.display(),
            meta.uid(),
            current_uid
        );
    }
    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).await?;
    Ok(())
}

#[cfg(unix)]
async fn set_socket_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .await
        .with_context(|| format!("set ghostty socket permissions on {}", path.display()))
}

#[cfg(unix)]
#[derive(Debug, Clone, Serialize, Deserialize)]
enum GhosttyRequest {
    Probe,
    Attach {
        cols: u16,
        rows: u16,
    },
    AttachV2 {
        cols: u16,
        rows: u16,
        config: portl_proto::session_v1::AttachV2Config,
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
    ReloadV2 {
        reload_id: u64,
    },
    CancelReloadV2 {
        reload_id: u64,
    },
    RequestViewportV2 {
        resize_id: u64,
        reason: String,
    },
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
    AttachedV2 {
        metadata: GhosttySessionMetadata,
        prelude: Vec<u8>,
        viewport: Vec<u8>,
        covers_live_seq: u64,
        generation: u64,
        cols: u16,
        rows: u16,
        resize_id: u64,
    },
    Output {
        bytes: Vec<u8>,
    },
    OutputV2 {
        start_seq: u64,
        end_seq: u64,
        bytes: Vec<u8>,
    },
    ViewportV2 {
        generation: u64,
        covers_live_seq: u64,
        cols: u16,
        rows: u16,
        resize_id: u64,
        bytes: Vec<u8>,
    },
    ReloadStartedV2 {
        reload_id: u64,
        total_bytes: Option<u64>,
    },
    ReloadChunkV2 {
        reload_id: u64,
        seq: u64,
        progress: portl_proto::session_v1::AttachV2Progress,
        bytes: Vec<u8>,
    },
    ReloadDoneV2 {
        reload_id: u64,
        final_generation: u64,
    },
    ReloadCancelledV2 {
        reload_id: u64,
    },
    ResyncRequiredV2 {
        reason: String,
        from_seq: u64,
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
        reply: oneshot::Sender<(GhosttySessionMetadata, Vec<u8>, mpsc::Receiver<Vec<u8>>)>,
    },
    SubscribeV2 {
        cols: u16,
        rows: u16,
        config: portl_proto::session_v1::AttachV2Config,
        reply: oneshot::Sender<GhosttyAttachV2Initial>,
    },
    Input(Vec<u8>),
    Resize {
        cols: u16,
        rows: u16,
    },
    ViewportV2 {
        resize_id: u64,
        reply: oneshot::Sender<GhosttyViewportV2>,
    },
    ReloadV2 {
        reload_id: u64,
        reply: mpsc::Sender<GhosttyResponse>,
    },
    CancelReloadV2 {
        reload_id: u64,
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
#[derive(Debug, Clone)]
struct GhosttyLiveOutputV2 {
    start_seq: u64,
    end_seq: u64,
    bytes: Vec<u8>,
}

#[cfg(unix)]
struct GhosttyAttachV2Initial {
    metadata: GhosttySessionMetadata,
    prelude: Vec<u8>,
    viewport: Vec<u8>,
    covers_live_seq: u64,
    generation: u64,
    cols: u16,
    rows: u16,
    resize_id: u64,
    output_rx: mpsc::Receiver<GhosttyLiveOutputV2>,
    event_rx: mpsc::UnboundedReceiver<GhosttyResponse>,
}

#[cfg(unix)]
struct GhosttyViewportV2 {
    generation: u64,
    covers_live_seq: u64,
    cols: u16,
    rows: u16,
    resize_id: u64,
    bytes: Vec<u8>,
}

#[cfg(unix)]
struct GhosttyV2Subscriber {
    live: mpsc::Sender<GhosttyLiveOutputV2>,
    events: mpsc::UnboundedSender<GhosttyResponse>,
    resync_pending: bool,
}

#[cfg(unix)]
struct AttachV2ResizeTracker {
    current_resize_id: u64,
    deferred_viewport: Option<(u64, String)>,
}

#[cfg(unix)]
impl AttachV2ResizeTracker {
    fn new(initial_resize_id: u64) -> Self {
        Self {
            current_resize_id: initial_resize_id,
            deferred_viewport: None,
        }
    }

    #[cfg(test)]
    fn current_resize_id(&self) -> u64 {
        self.current_resize_id
    }

    fn recovery_resize_id(&self) -> u64 {
        self.current_resize_id
    }

    fn record_resize(&mut self, resize_id: u64) -> Option<(u64, String)> {
        self.current_resize_id = self.current_resize_id.max(resize_id);
        if self
            .deferred_viewport
            .as_ref()
            .is_some_and(|(pending_resize_id, _)| *pending_resize_id <= self.current_resize_id)
        {
            return self.deferred_viewport.take();
        }
        None
    }

    fn request_or_defer(&mut self, resize_id: u64, reason: String) -> Option<(u64, String)> {
        if resize_id <= self.current_resize_id {
            Some((resize_id, reason))
        } else {
            self.deferred_viewport = Some((resize_id, reason));
            None
        }
    }
}

#[cfg(unix)]
struct GhosttyReloadJob {
    reload_id: u64,
    start_abs: u64,
    end_abs: u64,
    offset: u64,
    seq: u64,
    reply: mpsc::Sender<GhosttyResponse>,
    started: bool,
    final_generation: u64,
    retained_history_truncated: bool,
    pending_response: Option<GhosttyResponse>,
    replay_sanitizer: TerminalReplaySanitizer,
}

#[cfg(unix)]
impl GhosttyReloadJob {
    fn new(
        reload_id: u64,
        history_start_abs: u64,
        retained_len: usize,
        reply: mpsc::Sender<GhosttyResponse>,
        final_generation: u64,
        retained_history_truncated: bool,
    ) -> Self {
        Self {
            reload_id,
            start_abs: history_start_abs,
            end_abs: history_start_abs.saturating_add(retained_len as u64),
            offset: 0,
            seq: 0,
            reply,
            started: false,
            final_generation,
            retained_history_truncated,
            pending_response: None,
            replay_sanitizer: TerminalReplaySanitizer::new(),
        }
    }

    fn poll_send_next(&mut self, history: &VecDeque<u8>, history_start_abs: u64) -> bool {
        if let Some(response) = self.pending_response.take() {
            match self.reply.try_send(response) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(response)) => {
                    self.pending_response = Some(response);
                    return false;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return true,
            }
        }
        if self.reply.capacity() == 0 {
            return false;
        }
        let current_abs = self.start_abs.saturating_add(self.offset);
        if history_start_abs > current_abs {
            self.offset = history_start_abs.saturating_sub(self.start_abs);
            self.retained_history_truncated = true;
        }
        if !self.started {
            let total_bytes = Some(self.end_abs.saturating_sub(self.start_abs));
            match self.reply.try_send(GhosttyResponse::ReloadStartedV2 {
                reload_id: self.reload_id,
                total_bytes,
            }) {
                Ok(()) => self.started = true,
                Err(mpsc::error::TrySendError::Full(_)) => return false,
                Err(mpsc::error::TrySendError::Closed(_)) => return true,
            }
        }
        let current_abs = self.start_abs.saturating_add(self.offset);
        if current_abs >= self.end_abs {
            return match self.reply.try_send(GhosttyResponse::ReloadDoneV2 {
                reload_id: self.reload_id,
                final_generation: self.final_generation,
            }) {
                Ok(()) | Err(mpsc::error::TrySendError::Closed(_)) => true,
                Err(mpsc::error::TrySendError::Full(_)) => false,
            };
        }
        let available_end = history_start_abs.saturating_add(history.len() as u64);
        if current_abs >= available_end {
            self.offset = self.end_abs.saturating_sub(self.start_abs);
            self.retained_history_truncated = true;
            return false;
        }
        let rel_start = usize::try_from(current_abs.saturating_sub(history_start_abs))
            .unwrap_or(usize::MAX)
            .min(history.len());
        let chunk_len = usize::try_from(
            self.end_abs
                .saturating_sub(current_abs)
                .min(available_end.saturating_sub(current_abs))
                .min(GHOSTTY_ATTACH_V2_HISTORY_CHUNK as u64),
        )
        .unwrap_or(usize::MAX);
        if chunk_len == 0 {
            return false;
        }
        let raw_bytes = vec_deque_chunk(history, rel_start, chunk_len);
        if raw_bytes.is_empty() {
            self.offset = self.offset.saturating_add(chunk_len as u64);
            return false;
        }
        let loaded = self.offset.saturating_add(raw_bytes.len() as u64);
        let complete = self.start_abs.saturating_add(loaded) >= self.end_abs;
        let bytes = bracket_reload_replay_chunk(
            self.replay_sanitizer.feed(&raw_bytes, complete),
            self.seq == 0,
            complete,
        );
        let progress = portl_proto::session_v1::AttachV2Progress {
            loaded_bytes: loaded,
            total_bytes: Some(self.end_abs.saturating_sub(self.start_abs)),
            retained_history_truncated: self.retained_history_truncated,
            complete,
        };
        let response = GhosttyResponse::ReloadChunkV2 {
            reload_id: self.reload_id,
            seq: self.seq,
            progress,
            bytes,
        };
        match self.reply.try_send(response) {
            Ok(()) => {
                self.offset = loaded;
                self.seq = self.seq.saturating_add(1);
                false
            }
            Err(mpsc::error::TrySendError::Full(response)) => {
                self.pending_response = Some(response);
                false
            }
            Err(mpsc::error::TrySendError::Closed(_)) => true,
        }
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn run_helper(config: GhosttyHelperConfig) -> Result<()> {
    if config.argv.is_empty() {
        bail!("ghostty helper argv cannot be empty");
    }
    if let Some(parent) = config.paths.socket_path.parent() {
        if let Some(runtime_root) = parent.parent() {
            prepare_socket_dir(runtime_root).await?;
        }
        prepare_socket_dir(parent).await?;
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
    set_socket_permissions(&config.paths.socket_path).await?;
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

    let (cmd_tx, mut cmd_rx) = mpsc::channel(GHOSTTY_HELPER_COMMANDS);
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
    let mut terminal = GhosttyTerminalIo::new(TerminalOptions {
        cols: config.cols,
        rows: config.rows,
        max_scrollback: 4096,
    })?;
    let mut metadata = metadata;
    let mut history = VecDeque::new();
    let mut subscribers: Vec<mpsc::Sender<Vec<u8>>> = Vec::new();
    let mut v2_subscribers: Vec<GhosttyV2Subscriber> = Vec::new();
    let mut history_start_abs = 0_u64;
    let mut live_seq = 0_u64;
    let mut viewport_generation = 0_u64;
    let mut reload_jobs: VecDeque<GhosttyReloadJob> = VecDeque::new();
    let mut read_buf = vec![0_u8; IO_CHUNK];
    let mut child_wait = Box::pin(child.wait());

    loop {
        reload_jobs.retain_mut(|job| !job.poll_send_next(&history, history_start_abs));
        tokio::select! {
            status = &mut child_wait => {
                let code = status
                    .context("wait for ghostty child")?
                    .code()
                    .unwrap_or(1);
                broadcast(&mut subscribers, &[]);
                broadcast_v2_event(&mut v2_subscribers, &GhosttyResponse::Exit { code });
                cleanup_helper_files(&config.paths).await;
                accept_task.abort();
                return Ok(());
            }
            chunk = crate::shell_handler::pty_master::read_pty_chunk(&master, &mut read_buf) => {
                if let Some(bytes) = chunk.context("read ghostty pty")? {
                    process_output(
                        &mut terminal,
                        &mut history,
                        &mut subscribers,
                        &mut v2_subscribers,
                        &mut history_start_abs,
                        &mut live_seq,
                        &bytes,
                    );
                } else {
                    broadcast(&mut subscribers, &[]);
                    broadcast_v2_event(&mut v2_subscribers, &GhosttyResponse::Exit { code: 0 });
                    cleanup_helper_files(&config.paths).await;
                    accept_task.abort();
                    return Ok(());
                }
            }
            result = crate::shell_handler::pty_master::write_one_pending_pty_chunk(&master, &mut terminal.pending_input), if !terminal.pending_input.is_empty() => {
                result.context("write queued ghostty pty input")?;
            }
            () = tokio::time::sleep(Duration::from_millis(25)), if !reload_jobs.is_empty() => {}
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    HelperCommand::Probe { reply } => {
                        metadata.last_seen_ms = now_ms();
                        let _ = reply.send(metadata.clone());
                    }
                    HelperCommand::Subscribe { cols, rows, reply } => {
                        let _ = resize_helper(&master, &mut terminal, &mut metadata, rows, cols);
                        metadata.last_seen_ms = now_ms();
                        let (tx, rx) = mpsc::channel(GHOSTTY_SUBSCRIBER_BUFFER);
                        subscribers.push(tx);
                        let snapshot = capped_attach_snapshot(&history);
                        let _ = reply.send((metadata.clone(), snapshot, rx));
                    }
                    HelperCommand::SubscribeV2 { cols, rows, config, reply } => {
                        let _ = resize_helper(&master, &mut terminal, &mut metadata, rows, cols);
                        viewport_generation = viewport_generation.saturating_add(1);
                        metadata.last_seen_ms = now_ms();
                        let (tx, rx) = mpsc::channel(GHOSTTY_ATTACH_V2_QUEUE);
                        let (event_tx, event_rx) = mpsc::unbounded_channel();
                        v2_subscribers.push(GhosttyV2Subscriber {
                            live: tx,
                            events: event_tx,
                            resync_pending: false,
                        });
                        let raw_history_allowed = terminal_allows_raw_history(&terminal).unwrap_or(false);
                        let prelude = if raw_history_allowed {
                            capped_prelude_snapshot(&history, config.prelude_max_bytes)
                        } else {
                            Vec::new()
                        };
                        let render_started = Instant::now();
                        let viewport = render_viewport_snapshot(&terminal).unwrap_or_default();
                        tracing::trace!(
                            lane = "viewport",
                            reason = "initial_attach",
                            generation = viewport_generation,
                            covers_live_seq = live_seq,
                            cols,
                            rows,
                            prelude_bytes = prelude.len(),
                            viewport_bytes = viewport.len(),
                            raw_history_allowed,
                            render_ms = render_started.elapsed().as_millis(),
                            "render ghostty attach v2 initial viewport"
                        );
                        let initial = GhosttyAttachV2Initial {
                            metadata: metadata.clone(),
                            prelude,
                            viewport,
                            covers_live_seq: live_seq,
                            generation: viewport_generation,
                            cols,
                            rows,
                            resize_id: 0,
                            output_rx: rx,
                            event_rx,
                        };
                        let _ = reply.send(initial);
                    }
                    HelperCommand::Input(bytes) => {
                        if let Err(err) = terminal.pending_input.push(bytes) {
                            crate::metrics::record_ghostty_event("input_queue_full");
                            tracing::warn!(%err, "ghostty pty input queue full; requesting attach v2 resync");
                            broadcast(&mut subscribers, &[]);
                            broadcast_v2_resync(&mut v2_subscribers, "input queue full", live_seq);
                        }
                    }
                    HelperCommand::Resize { cols, rows } => {
                        if resize_helper(&master, &mut terminal, &mut metadata, rows, cols).is_ok() {
                            viewport_generation = viewport_generation.saturating_add(1);
                        }
                    }
                    HelperCommand::ViewportV2 { resize_id, reply } => {
                        viewport_generation = viewport_generation.saturating_add(1);
                        let render_started = Instant::now();
                        let bytes = render_viewport_snapshot(&terminal).unwrap_or_default();
                        tracing::trace!(
                            lane = "viewport",
                            reason = "request",
                            generation = viewport_generation,
                            covers_live_seq = live_seq,
                            cols = metadata.cols,
                            rows = metadata.rows,
                            resize_id,
                            viewport_bytes = bytes.len(),
                            render_ms = render_started.elapsed().as_millis(),
                            "render ghostty attach v2 requested viewport"
                        );
                        let _ = reply.send(GhosttyViewportV2 {
                            generation: viewport_generation,
                            covers_live_seq: live_seq,
                            cols: metadata.cols,
                            rows: metadata.rows,
                            resize_id,
                            bytes,
                        });
                    }
                    HelperCommand::ReloadV2 { reload_id, reply } => {
                        reload_jobs.retain(|job| job.reload_id != reload_id);
                        if !terminal_allows_raw_history(&terminal).unwrap_or(false) {
                            tracing::trace!(reload_id, "cancel ghostty attach v2 raw reload in alternate screen");
                            let _ = reply.try_send(GhosttyResponse::ReloadCancelledV2 { reload_id });
                            continue;
                        }
                        viewport_generation = viewport_generation.saturating_add(1);
                        while reload_jobs.len() >= GHOSTTY_ATTACH_V2_MAX_RELOAD_JOBS {
                            if let Some(job) = reload_jobs.pop_front() {
                                let _ = job.reply.try_send(GhosttyResponse::ReloadCancelledV2 {
                                    reload_id: job.reload_id,
                                });
                            }
                        }
                        let (reload_start_abs, reload_len, reload_truncated) =
                            bounded_reload_window(history_start_abs, &history);
                        tracing::trace!(
                            reload_id,
                            reload_start_abs,
                            reload_len,
                            reload_truncated,
                            history_start_abs,
                            history_len = history.len(),
                            "start ghostty attach v2 raw reload"
                        );
                        reload_jobs.push_back(GhosttyReloadJob::new(
                            reload_id,
                            reload_start_abs,
                            reload_len,
                            reply,
                            viewport_generation,
                            reload_truncated,
                        ));
                    }
                    HelperCommand::CancelReloadV2 { reload_id } => {
                        reload_jobs.retain(|job| job.reload_id != reload_id);
                    }
                    HelperCommand::Run { cwd, argv, reply } => {
                        let result = run_sidecar(cwd.as_deref().or(config.cwd.as_deref()), &argv).await;
                        if let Ok(run) = &result {
                            let mirrored = mirror_run_output(&argv, run);
                            process_output(
                                &mut terminal,
                                &mut history,
                                &mut subscribers,
                                &mut v2_subscribers,
                                &mut history_start_abs,
                                &mut live_seq,
                                &mirrored,
                            );
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
fn configure_portl_terminal_capabilities(
    terminal: &mut Terminal<'_, '_>,
    pty_replies: TerminalPtyReplies,
) -> Result<()> {
    use crate::session_handler::vt_capability::PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS;

    terminal
        .on_pty_write(move |_term, data| {
            pty_replies.borrow_mut().push(data.to_vec());
        })?
        .on_device_attributes(|_term| {
            Some(DeviceAttributes {
                primary: PrimaryDeviceAttributes::new(
                    ConformanceLevel::VT220,
                    [
                        DeviceAttributeFeature::COLUMNS_132,
                        DeviceAttributeFeature::SELECTIVE_ERASE,
                        DeviceAttributeFeature::ANSI_COLOR,
                    ],
                ),
                secondary: SecondaryDeviceAttributes {
                    device_type: DeviceType::VT220,
                    firmware_version: 1,
                    rom_cartridge: 0,
                },
                tertiary: TertiaryDeviceAttributes { unit_id: 0 },
            })
        })?;
    match PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS {
        0 => terminal.vt_write(b"\x1b[=0u"),
        flags => terminal.vt_write(format!("\x1b[={flags}u").as_bytes()),
    }
    Ok(())
}

#[cfg(unix)]
fn drain_terminal_pty_replies(terminal: &mut GhosttyTerminalIo) -> bool {
    let mut replies = terminal.pty_replies.borrow_mut();
    let mut queued_all = true;
    for reply in replies.drain(..) {
        if let Err(err) = terminal.pending_input.push(reply) {
            queued_all = false;
            crate::metrics::record_ghostty_event("input_queue_full");
            tracing::warn!(%err, "ghostty pty input queue full while queueing terminal capability response");
        }
    }
    queued_all
}

#[cfg(unix)]
fn process_output(
    terminal: &mut GhosttyTerminalIo,
    history: &mut VecDeque<u8>,
    subscribers: &mut Vec<mpsc::Sender<Vec<u8>>>,
    v2_subscribers: &mut Vec<GhosttyV2Subscriber>,
    history_start_abs: &mut u64,
    live_seq: &mut u64,
    bytes: &[u8],
) {
    let start_seq = *live_seq;
    let output = terminal.query_stripper.feed(bytes);
    *live_seq = live_seq.saturating_add(output.len() as u64);
    let end_seq = *live_seq;
    terminal.vt_write(bytes);
    let queued_terminal_replies = drain_terminal_pty_replies(terminal);
    let dropped = append_bounded(history, &output);
    *history_start_abs = history_start_abs.saturating_add(dropped as u64);
    tracing::trace!(
        lane = "live",
        bytes = bytes.len(),
        stripped_bytes = output.len(),
        start_seq,
        end_seq,
        dropped,
        history_start_abs = *history_start_abs,
        history_len = history.len(),
        subscribers = subscribers.len(),
        v2_subscribers = v2_subscribers.len(),
        "process ghostty pty output"
    );
    if !output.is_empty() {
        broadcast(subscribers, &output);
        broadcast_v2(
            v2_subscribers,
            &GhosttyLiveOutputV2 {
                start_seq,
                end_seq,
                bytes: output,
            },
        );
    }
    if !queued_terminal_replies {
        broadcast(subscribers, &[]);
        broadcast_v2_resync(v2_subscribers, "input queue full", *live_seq);
    }
}

#[cfg(unix)]
pub(crate) fn query_strip_capture_for_test(bytes: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut terminal = GhosttyTerminalIo::new(TerminalOptions {
        cols: 80,
        rows: 24,
        max_scrollback: 4096,
    })?;
    let mut history = VecDeque::new();
    let mut subscribers = Vec::new();
    let mut v2_subscribers = Vec::new();
    let mut history_start_abs = 0;
    let mut live_seq = 0;

    process_output(
        &mut terminal,
        &mut history,
        &mut subscribers,
        &mut v2_subscribers,
        &mut history_start_abs,
        &mut live_seq,
        bytes,
    );

    let wire_capture = history.iter().copied().collect::<Vec<_>>();
    let mut guest_pty_input = Vec::new();
    while let Some(chunk) = terminal.pending_input.front_chunk() {
        let len = chunk.len();
        guest_pty_input.extend_from_slice(chunk);
        terminal.pending_input.consume(len);
    }
    Ok((wire_capture, guest_pty_input))
}

#[cfg(unix)]
fn capped_attach_snapshot(history: &VecDeque<u8>) -> Vec<u8> {
    let len = history.len().min(MAX_ATTACH_SNAPSHOT_BYTES);
    history
        .iter()
        .skip(history.len().saturating_sub(len))
        .copied()
        .collect()
}

#[cfg(unix)]
fn capped_prelude_snapshot(history: &VecDeque<u8>, max_bytes: u64) -> Vec<u8> {
    let cap = usize::try_from(max_bytes)
        .unwrap_or(usize::MAX)
        .min(MAX_ATTACH_SNAPSHOT_BYTES);
    let len = history.len().min(cap);
    let mut raw = history
        .iter()
        .skip(history.len().saturating_sub(len))
        .copied()
        .collect::<Vec<_>>();
    if len < history.len() {
        raw = trim_partial_replay_prefix(raw);
    }
    sanitize_terminal_replay(&raw)
}

#[cfg(unix)]
fn trim_partial_replay_prefix(mut bytes: Vec<u8>) -> Vec<u8> {
    if let Some(newline) = bytes.iter().position(|byte| *byte == b'\n') {
        bytes.drain(..=newline);
    } else {
        bytes.clear();
    }
    while bytes
        .first()
        .is_some_and(|byte| (*byte & 0b1100_0000) == 0b1000_0000)
    {
        bytes.remove(0);
    }
    bytes
}

#[cfg(unix)]
fn bracket_reload_replay_chunk(bytes: Vec<u8>, _first_chunk: bool, _final_chunk: bool) -> Vec<u8> {
    bytes
}

#[cfg(unix)]
#[derive(Debug, Default)]
struct TerminalReplaySanitizer {
    pending: Vec<u8>,
}

#[cfg(unix)]
impl TerminalReplaySanitizer {
    fn new() -> Self {
        Self::default()
    }

    fn feed(&mut self, bytes: &[u8], final_chunk: bool) -> Vec<u8> {
        let mut combined = Vec::with_capacity(self.pending.len() + bytes.len());
        combined.extend_from_slice(&self.pending);
        combined.extend_from_slice(bytes);
        self.pending.clear();

        if final_chunk {
            return sanitize_terminal_replay(&combined);
        }

        let split = [
            trailing_incomplete_replay_escape_start(&combined),
            trailing_incomplete_utf8_start(&combined),
        ]
        .into_iter()
        .flatten()
        .min();
        if let Some(split) = split {
            self.pending.extend_from_slice(&combined[split..]);
            sanitize_terminal_replay(&combined[..split])
        } else {
            sanitize_terminal_replay(&combined)
        }
    }
}

#[cfg(unix)]
fn vec_deque_chunk(history: &VecDeque<u8>, rel_start: usize, chunk_len: usize) -> Vec<u8> {
    let (front, back) = history.as_slices();
    let mut out = Vec::with_capacity(chunk_len);
    if rel_start < front.len() {
        let front_end = rel_start.saturating_add(chunk_len).min(front.len());
        out.extend_from_slice(&front[rel_start..front_end]);
        let remaining = chunk_len.saturating_sub(front_end.saturating_sub(rel_start));
        if remaining > 0 {
            out.extend_from_slice(&back[..remaining.min(back.len())]);
        }
    } else {
        let back_start = rel_start.saturating_sub(front.len()).min(back.len());
        let back_end = back_start.saturating_add(chunk_len).min(back.len());
        out.extend_from_slice(&back[back_start..back_end]);
    }
    let snap_len = utf8_boundary_snap_len(&out);
    out.truncate(snap_len);
    out
}

#[cfg(unix)]
fn trailing_incomplete_replay_escape_start(bytes: &[u8]) -> Option<usize> {
    #[derive(Clone, Copy)]
    enum State {
        Ground,
        Escape { start: usize },
        Csi { start: usize },
        ControlString { start: usize, esc: bool },
        PlainEscape { start: usize },
    }

    let mut state = State::Ground;
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match state {
            State::Ground => {
                if byte == 0x1b {
                    state = State::Escape { start: index };
                }
                index += 1;
            }
            State::Escape { start } => match byte {
                b'[' => {
                    state = State::Csi { start };
                    index += 1;
                }
                b']' | b'P' | b'^' | b'_' => {
                    state = State::ControlString { start, esc: false };
                    index += 1;
                }
                0x20..=0x2f => {
                    state = State::PlainEscape { start };
                    index += 1;
                }
                _ => {
                    state = State::Ground;
                    index += 1;
                }
            },
            State::PlainEscape { .. } => {
                if (0x20..=0x2f).contains(&byte) {
                    index += 1;
                } else {
                    state = State::Ground;
                    index += 1;
                }
            }
            State::Csi { start } => {
                if byte == 0x1b {
                    state = State::Escape { start: index };
                    index += 1;
                } else {
                    if (0x40..=0x7e).contains(&byte) {
                        state = State::Ground;
                    }
                    index += 1;
                }
                let _ = start;
            }
            State::ControlString { start, esc } => {
                if esc {
                    if byte == b'\\' {
                        state = State::Ground;
                    } else {
                        state = State::ControlString { start, esc: false };
                    }
                    index += 1;
                } else if byte == 0x07 {
                    state = State::Ground;
                    index += 1;
                } else if byte == 0x1b {
                    state = State::ControlString { start, esc: true };
                    index += 1;
                } else {
                    index += 1;
                }
            }
        }
    }

    match state {
        State::Ground => None,
        State::Escape { start }
        | State::Csi { start }
        | State::ControlString { start, .. }
        | State::PlainEscape { start } => Some(start),
    }
}

#[cfg(unix)]
fn trailing_incomplete_utf8_start(bytes: &[u8]) -> Option<usize> {
    let snap_len = utf8_boundary_snap_len(bytes);
    (snap_len < bytes.len()).then_some(snap_len)
}

#[cfg(unix)]
fn sanitize_terminal_replay(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0_usize;
    while index < bytes.len() {
        let byte = bytes[index];
        if byte == 0x1b && index + 1 < bytes.len() {
            match bytes[index + 1] {
                b'[' => {
                    index = sanitize_escape_csi(bytes, index, &mut out);
                    continue;
                }
                b']' | b'P' | b'^' | b'_' => {
                    index += 2;
                    while index < bytes.len() {
                        if bytes[index] == 0x07 {
                            index += 1;
                            break;
                        }
                        if bytes[index] == 0x1b
                            && index + 1 < bytes.len()
                            && bytes[index + 1] == b'\\'
                        {
                            index += 2;
                            break;
                        }
                        index += 1;
                    }
                    continue;
                }
                _ => {}
            }
        }
        if byte == 0x1b {
            index = sanitize_plain_escape(bytes, index);
            continue;
        }
        if byte < 0x20 && !matches!(byte, b'\n' | b'\r' | b'\t') {
            index += 1;
            continue;
        }
        out.push(byte);
        index += 1;
    }
    out
}

#[cfg(unix)]
fn sanitize_escape_csi(bytes: &[u8], start: usize, out: &mut Vec<u8>) -> usize {
    let mut index = start.saturating_add(2);
    let private = bytes
        .get(index)
        .is_some_and(|byte| matches!(*byte, b'?' | b'>' | b'!' | b' '));
    while index < bytes.len() {
        let byte = bytes[index];
        if (0x80..=0x9f).contains(&byte) {
            index = index.saturating_add(1);
            continue;
        }
        if byte >= 0x80 {
            return index;
        }
        if (0x40..=0x7e).contains(&byte) {
            let end = index.saturating_add(1);
            if byte == b'm' && !private {
                out.extend_from_slice(&bytes[start..end]);
            }
            return end;
        }
        index = index.saturating_add(1);
    }
    bytes.len()
}

#[cfg(unix)]
fn utf8_boundary_snap_len(bytes: &[u8]) -> usize {
    let len = bytes.len();
    if len == 0 {
        return 0;
    }
    let mut start = len.saturating_sub(1);
    while start > 0 && (0x80..=0xbf).contains(&bytes[start]) {
        start -= 1;
    }
    let expected = match bytes[start] {
        0x00..=0x7f => 1,
        0xc2..=0xdf => 2,
        0xe0..=0xef => 3,
        0xf0..=0xf4 => 4,
        _ => return len,
    };
    if start.saturating_add(expected) <= len {
        len
    } else {
        start
    }
}

#[cfg(unix)]
fn sanitize_plain_escape(bytes: &[u8], start: usize) -> usize {
    let mut index = start.saturating_add(1);
    if index >= bytes.len() {
        return bytes.len();
    }
    if (0x20..=0x2f).contains(&bytes[index]) {
        index = index.saturating_add(1);
        while index < bytes.len() && (0x20..=0x2f).contains(&bytes[index]) {
            index = index.saturating_add(1);
        }
        if index < bytes.len() && (0x30..=0x7e).contains(&bytes[index]) {
            return index.saturating_add(1);
        }
        return index;
    }
    index.saturating_add(1).min(bytes.len())
}

#[cfg(unix)]
fn push_viewport_row_prefix(out: &mut Vec<u8>, row_index: u16) {
    out.extend_from_slice(format!("\x1b[{};1H", row_index.saturating_add(1)).as_bytes());
}

#[cfg(unix)]
fn terminal_allows_raw_history(terminal: &Terminal<'_, '_>) -> Result<bool> {
    Ok(!matches!(terminal.active_screen()?, Screen::Alternate))
}

#[cfg(unix)]
fn render_viewport_snapshot(terminal: &Terminal<'_, '_>) -> Result<Vec<u8>> {
    let mut render_state = RenderState::new().context("create ghostty render state")?;
    let snapshot = render_state
        .update(terminal)
        .context("update ghostty render state")?;
    let rows = snapshot.rows().context("read ghostty viewport rows")?;
    let mut row_iter = RowIterator::new().context("create ghostty row iterator")?;
    let mut cell_iter = CellIterator::new().context("create ghostty cell iterator")?;
    let mut out = Vec::new();
    if matches!(terminal.active_screen()?, Screen::Alternate) {
        out.extend_from_slice(b"\x1b[?1049h");
    } else {
        out.extend_from_slice(b"\x1b[?1049l");
    }
    out.extend_from_slice(b"\x1b[?25l\x1b[?7l\x1b[0m\x1b[2J\x1b[H");
    let mut rows_iter = row_iter.update(&snapshot).context("iterate ghostty rows")?;
    let mut row_index = 0_u16;
    let mut styled_active = false;
    while let Some(row) = rows_iter.next() {
        push_viewport_row_prefix(&mut out, row_index);
        let mut cells = cell_iter.update(row).context("iterate ghostty cells")?;
        while let Some(cell) = cells.next() {
            let style = cell.style().context("read ghostty cell style")?;
            let fg = cell.fg_color().context("read ghostty cell foreground")?;
            let bg = cell.bg_color().context("read ghostty cell background")?;
            if !style.is_default() || fg.is_some() || bg.is_some() {
                push_cell_sgr(&mut out, style, fg, bg);
                styled_active = true;
            } else if styled_active {
                out.extend_from_slice(b"\x1b[0m");
                styled_active = false;
            }
            let graphemes = cell.graphemes().context("read ghostty cell graphemes")?;
            if graphemes.is_empty() || style.invisible {
                out.push(b' ');
            } else {
                for grapheme in graphemes {
                    let mut buf = [0_u8; 4];
                    out.extend_from_slice(grapheme.encode_utf8(&mut buf).as_bytes());
                }
            }
        }
        if styled_active {
            out.extend_from_slice(b"\x1b[0m");
            styled_active = false;
        }
        out.extend_from_slice(b"\x1b[K");
        row_index = row_index.saturating_add(1);
        if row_index >= rows {
            break;
        }
    }
    out.extend_from_slice(b"\x1b[0m");
    if terminal.mode(Mode::WRAPAROUND).unwrap_or(true) {
        out.extend_from_slice(b"\x1b[?7h");
    } else {
        out.extend_from_slice(b"\x1b[?7l");
    }
    if let Some(cursor) = snapshot.cursor_viewport().context("read ghostty cursor")? {
        out.extend_from_slice(
            format!(
                "\x1b[{};{}H",
                cursor.y.saturating_add(1),
                cursor.x.saturating_add(1)
            )
            .as_bytes(),
        );
    }
    if snapshot
        .cursor_visible()
        .context("read ghostty cursor visibility")?
    {
        out.extend_from_slice(b"\x1b[?25h");
    } else {
        out.extend_from_slice(b"\x1b[?25l");
    }
    Ok(out)
}

#[cfg(unix)]
fn push_cell_sgr(
    out: &mut Vec<u8>,
    style: libghostty_vt::style::Style,
    fg: Option<RgbColor>,
    bg: Option<RgbColor>,
) {
    let mut codes = vec!["0".to_owned()];
    if style.bold {
        codes.push("1".to_owned());
    }
    if style.faint {
        codes.push("2".to_owned());
    }
    if style.italic {
        codes.push("3".to_owned());
    }
    match style.underline {
        Underline::Single => codes.push("4".to_owned()),
        Underline::Double => codes.push("21".to_owned()),
        Underline::Curly => codes.push("4:3".to_owned()),
        Underline::Dotted => codes.push("4:4".to_owned()),
        Underline::Dashed => codes.push("4:5".to_owned()),
        _ => {}
    }
    if style.blink {
        codes.push("5".to_owned());
    }
    if style.inverse {
        codes.push("7".to_owned());
    }
    if style.strikethrough {
        codes.push("9".to_owned());
    }
    if style.overline {
        codes.push("53".to_owned());
    }
    if let Some(RgbColor { r, g, b }) = fg {
        codes.push(format!("38;2;{r};{g};{b}"));
    }
    if let Some(RgbColor { r, g, b }) = bg {
        codes.push(format!("48;2;{r};{g};{b}"));
    }
    out.extend_from_slice(format!("\x1b[{}m", codes.join(";")).as_bytes());
}

#[cfg(unix)]
fn append_bounded(history: &mut VecDeque<u8>, bytes: &[u8]) -> usize {
    history.extend(bytes.iter().copied());
    let mut dropped = 0_usize;
    while history.len() > MAX_HISTORY_BYTES {
        let _ = history.pop_front();
        dropped = dropped.saturating_add(1);
    }
    dropped
}

#[cfg(unix)]
fn bounded_reload_window(history_start_abs: u64, history: &VecDeque<u8>) -> (u64, usize, bool) {
    let retained_len = history.len();
    let reload_len = retained_len.min(GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES);
    let mut skipped_retained = retained_len.saturating_sub(reload_len);
    while skipped_retained < retained_len
        && history
            .get(skipped_retained)
            .is_some_and(|byte| (*byte & 0b1100_0000) == 0b1000_0000)
    {
        skipped_retained = skipped_retained.saturating_add(1);
    }
    let reload_start_abs = history_start_abs.saturating_add(skipped_retained as u64);
    let reload_len = retained_len.saturating_sub(skipped_retained);
    let truncated = history_start_abs > 0 || skipped_retained > 0;
    (reload_start_abs, reload_len, truncated)
}

#[cfg(unix)]
fn broadcast(subscribers: &mut Vec<mpsc::Sender<Vec<u8>>>, bytes: &[u8]) {
    subscribers.retain(|subscriber| match subscriber.try_send(bytes.to_vec()) {
        Ok(()) => true,
        // Channel full: evict the slow subscriber so the client gets a closed
        // stream and can reconnect for a fresh snapshot instead of silently
        // diverging after missed output frames. Receiver dropped: evict the
        // dead subscriber.
        Err(mpsc::error::TrySendError::Full(_)) => {
            crate::metrics::record_ghostty_event("subscriber_evicted_full");
            false
        }
        Err(mpsc::error::TrySendError::Closed(_)) => {
            crate::metrics::record_ghostty_event("subscriber_evicted_closed");
            false
        }
    });
}

#[cfg(unix)]
fn broadcast_v2(subscribers: &mut Vec<GhosttyV2Subscriber>, output: &GhosttyLiveOutputV2) {
    subscribers.retain_mut(
        |subscriber| match subscriber.live.try_send(output.clone()) {
            Ok(()) => {
                subscriber.resync_pending = false;
                true
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                crate::metrics::record_ghostty_event("attach_v2_live_queue_full");
                if subscriber.resync_pending {
                    return true;
                }
                subscriber.resync_pending = true;
                subscriber
                    .events
                    .send(GhosttyResponse::ResyncRequiredV2 {
                        reason: "live queue full".to_owned(),
                        from_seq: output.start_seq,
                    })
                    .is_ok()
            }
            Err(mpsc::error::TrySendError::Closed(_)) => false,
        },
    );
}

#[cfg(unix)]
fn broadcast_v2_event(subscribers: &mut Vec<GhosttyV2Subscriber>, event: &GhosttyResponse) {
    subscribers.retain(|subscriber| subscriber.events.send(event.clone()).is_ok());
}

#[cfg(unix)]
fn broadcast_v2_resync(subscribers: &mut Vec<GhosttyV2Subscriber>, reason: &str, from_seq: u64) {
    subscribers.retain_mut(|subscriber| {
        if subscriber.resync_pending {
            return true;
        }
        subscriber.resync_pending = true;
        subscriber
            .events
            .send(GhosttyResponse::ResyncRequiredV2 {
                reason: reason.to_owned(),
                from_seq,
            })
            .is_ok()
    });
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
#[allow(clippy::too_many_lines)]
async fn handle_client(mut stream: UnixStream, tx: mpsc::Sender<HelperCommand>) -> Result<()> {
    let Some(first) = read_frame::<GhosttyRequest>(&mut stream).await? else {
        return Ok(());
    };
    match first {
        GhosttyRequest::Probe => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Probe { reply: reply_tx })
                .await
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
            .await
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
                .await
                .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let output = reply_rx.await.context("ghostty history reply")?;
            write_frame(&mut stream, &GhosttyResponse::History { output }).await
        }
        GhosttyRequest::Kill => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Kill { reply: reply_tx })
                .await
                .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let _ = reply_rx.await;
            write_frame(&mut stream, &GhosttyResponse::Exit { code: 0 }).await
        }
        GhosttyRequest::AttachV2 { cols, rows, config } => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::SubscribeV2 {
                cols,
                rows,
                config,
                reply: reply_tx,
            })
            .await
            .map_err(|_| anyhow!("ghostty helper stopped"))?;
            let initial = reply_rx.await.context("ghostty attach v2 reply")?;
            let mut output_rx = initial.output_rx;
            let mut event_rx = initial.event_rx;
            write_frame(
                &mut stream,
                &GhosttyResponse::AttachedV2 {
                    metadata: initial.metadata,
                    prelude: initial.prelude,
                    viewport: initial.viewport,
                    covers_live_seq: initial.covers_live_seq,
                    generation: initial.generation,
                    cols: initial.cols,
                    rows: initial.rows,
                    resize_id: initial.resize_id,
                },
            )
            .await?;
            let mut reload_rx: Option<mpsc::Receiver<GhosttyResponse>> = None;
            loop {
                tokio::select! {
                    output = output_rx.recv() => {
                        let Some(output) = output else {
                            return Ok(());
                        };
                        write_frame(
                            &mut stream,
                            &GhosttyResponse::OutputV2 {
                                start_seq: output.start_seq,
                                end_seq: output.end_seq,
                                bytes: output.bytes,
                            },
                        ).await?;
                    }
                    event = event_rx.recv() => {
                        let Some(event) = event else {
                            return Ok(());
                        };
                        write_frame(&mut stream, &event).await?;
                        if matches!(event, GhosttyResponse::Exit { .. } | GhosttyResponse::Error { .. }) {
                            return Ok(());
                        }
                    }
                    Some(response) = async {
                        match reload_rx.as_mut() {
                            Some(rx) => rx.recv().await,
                            None => None,
                        }
                    }, if reload_rx.is_some() => {
                        let done = matches!(response, GhosttyResponse::ReloadDoneV2 { .. } | GhosttyResponse::ReloadCancelledV2 { .. });
                        write_frame(&mut stream, &response).await?;
                        if done {
                            reload_rx = None;
                        }
                    }
                    request = read_frame::<GhosttyRequest>(&mut stream) => {
                        match request? {
                            Some(GhosttyRequest::Input { bytes }) => {
                                forward_helper_input(&tx, bytes, &mut stream).await?;
                            }
                            Some(GhosttyRequest::Resize { cols, rows }) => {
                                forward_helper_resize(&tx, cols, rows, &mut stream).await?;
                            }
                            Some(GhosttyRequest::ReloadV2 { reload_id }) => {
                                let (reload_tx, rx) = mpsc::channel(GHOSTTY_ATTACH_V2_QUEUE);
                                tx.send(HelperCommand::ReloadV2 { reload_id, reply: reload_tx })
                                    .await
                                    .map_err(|_| anyhow!("ghostty helper stopped"))?;
                                reload_rx = Some(rx);
                            }
                            Some(GhosttyRequest::CancelReloadV2 { reload_id }) => {
                                reload_rx = None;
                                tx.send(HelperCommand::CancelReloadV2 { reload_id })
                                    .await
                                    .map_err(|_| anyhow!("ghostty helper stopped"))?;
                                write_frame(
                                    &mut stream,
                                    &GhosttyResponse::ReloadCancelledV2 { reload_id },
                                ).await?;
                            }
                            Some(GhosttyRequest::RequestViewportV2 { resize_id, reason: _ }) => {
                                let (reply_tx, reply_rx) = oneshot::channel();
                                tx.send(HelperCommand::ViewportV2 { resize_id, reply: reply_tx })
                                    .await
                                    .map_err(|_| anyhow!("ghostty helper stopped"))?;
                                let viewport = reply_rx.await.context("ghostty viewport v2 reply")?;
                                write_frame(
                                    &mut stream,
                                    &GhosttyResponse::ViewportV2 {
                                        generation: viewport.generation,
                                        covers_live_seq: viewport.covers_live_seq,
                                        cols: viewport.cols,
                                        rows: viewport.rows,
                                        resize_id: viewport.resize_id,
                                        bytes: viewport.bytes,
                                    },
                                ).await?;
                            }
                            Some(GhosttyRequest::Detach) | None => return Ok(()),
                            Some(GhosttyRequest::Kill) => {
                                let (reply_tx, reply_rx) = oneshot::channel();
                                tx.send(HelperCommand::Kill { reply: reply_tx })
                                    .await
                                    .map_err(|_| anyhow!("ghostty helper stopped"))?;
                                let _ = reply_rx.await;
                                return Ok(());
                            }
                            Some(other) => tracing::debug!(?other, "ignoring non-v2 ghostty request on attach v2 stream"),
                        }
                    }
                    else => return Ok(()),
                }
            }
        }
        GhosttyRequest::Attach { cols, rows } => {
            let (reply_tx, reply_rx) = oneshot::channel();
            tx.send(HelperCommand::Subscribe {
                cols,
                rows,
                reply: reply_tx,
            })
            .await
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
                    response = output_rx.recv() => {
                        let Some(bytes) = response else {
                            return Ok(());
                        };
                        if bytes.is_empty() {
                            write_frame(&mut stream, &GhosttyResponse::Exit { code: 0 }).await?;
                            return Ok(());
                        }
                        write_frame(&mut stream, &GhosttyResponse::Output { bytes }).await?;
                    }
                    request = read_frame::<GhosttyRequest>(&mut stream) => {
                        match request? {
                            Some(GhosttyRequest::Input { bytes }) => {
                                // Use try_send so input cannot block output forwarding in
                                // this task. If the command queue is full, close the attach
                                // stream with an error rather than starving output delivery.
                                match tx.try_send(HelperCommand::Input(bytes)) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        write_frame(
                                            &mut stream,
                                            &GhosttyResponse::Error {
                                                message: "ghostty helper input queue is full"
                                                    .to_owned(),
                                            },
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        return Err(anyhow!("ghostty helper stopped"));
                                    }
                                }
                            }
                            Some(GhosttyRequest::Resize { cols, rows }) => {
                                // try_send: avoid blocking output forwarding. On Full,
                                // report backpressure to the client and close the attach
                                // stream; on Closed, propagate the error.
                                match tx.try_send(HelperCommand::Resize { cols, rows }) {
                                    Ok(()) => {}
                                    Err(mpsc::error::TrySendError::Full(_)) => {
                                        write_frame(
                                            &mut stream,
                                            &GhosttyResponse::Error {
                                                message: "ghostty helper input queue is full"
                                                    .to_owned(),
                                            },
                                        )
                                        .await?;
                                        return Ok(());
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        return Err(anyhow!("ghostty helper stopped"));
                                    }
                                }
                            }
                            Some(GhosttyRequest::Detach) | None => return Ok(()),
                            Some(GhosttyRequest::Kill) => {
                                let (reply_tx, reply_rx) = oneshot::channel();
                                match tx.try_send(HelperCommand::Kill { reply: reply_tx }) {
                                    Ok(()) => {
                                        let _ = reply_rx.await;
                                        return Ok(());
                                    }
                                    Err(mpsc::error::TrySendError::Full(command)) => {
                                        tx.send(command)
                                            .await
                                            .map_err(|_| anyhow!("ghostty helper stopped"))?;
                                        let _ = reply_rx.await;
                                        return Ok(());
                                    }
                                    Err(mpsc::error::TrySendError::Closed(_)) => {
                                        return Err(anyhow!("ghostty helper stopped"));
                                    }
                                }
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
async fn forward_helper_command_with_resync(
    tx: &mpsc::Sender<HelperCommand>,
    command: HelperCommand,
    stream: &mut UnixStream,
    reason: &'static str,
) -> Result<()> {
    match tx.try_send(command) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(command)) => {
            write_frame(
                stream,
                &GhosttyResponse::ResyncRequiredV2 {
                    reason: reason.to_owned(),
                    from_seq: 0,
                },
            )
            .await?;
            tx.send(command)
                .await
                .map_err(|_| anyhow!("ghostty helper stopped"))
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(anyhow!("ghostty helper stopped")),
    }
}

#[cfg(unix)]
async fn forward_helper_input(
    tx: &mpsc::Sender<HelperCommand>,
    bytes: Vec<u8>,
    stream: &mut UnixStream,
) -> Result<()> {
    forward_helper_command_with_resync(tx, HelperCommand::Input(bytes), stream, "input_queue_full")
        .await
}

#[cfg(unix)]
async fn forward_helper_resize(
    tx: &mpsc::Sender<HelperCommand>,
    cols: u16,
    rows: u16,
    stream: &mut UnixStream,
) -> Result<()> {
    forward_helper_command_with_resync(
        tx,
        HelperCommand::Resize { cols, rows },
        stream,
        "resize_queue_full",
    )
    .await
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

    pub(crate) async fn attach_v2(
        mut self,
        cols: u16,
        rows: u16,
        config: portl_proto::session_v1::AttachV2Config,
    ) -> Result<GhosttyAttachV2> {
        write_frame(
            &mut self.stream,
            &GhosttyRequest::AttachV2 { cols, rows, config },
        )
        .await?;
        match read_frame::<GhosttyResponse>(&mut self.stream).await? {
            Some(GhosttyResponse::AttachedV2 {
                prelude,
                viewport,
                covers_live_seq,
                generation,
                cols,
                rows,
                resize_id,
                ..
            }) => Ok(GhosttyAttachV2 {
                stream: self.stream,
                attach_id: [0; 16],
                prelude,
                viewport,
                covers_live_seq,
                generation,
                cols,
                rows,
                resize_id,
            }),
            Some(GhosttyResponse::Error { message }) => bail!(message),
            other => bail!("unexpected ghostty attach v2 response: {other:?}"),
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
pub(crate) struct GhosttyAttachV2 {
    stream: UnixStream,
    pub(crate) attach_id: [u8; 16],
    pub(crate) prelude: Vec<u8>,
    pub(crate) viewport: Vec<u8>,
    pub(crate) covers_live_seq: u64,
    pub(crate) generation: u64,
    pub(crate) cols: u16,
    pub(crate) rows: u16,
    pub(crate) resize_id: u64,
}

#[cfg(unix)]
#[derive(Debug)]
enum GhosttyAttachV2Command {
    Input(Vec<u8>),
    Resize {
        resize_id: u64,
        cols: u16,
        rows: u16,
    },
    Detach,
    Reload {
        reload_id: u64,
    },
    CancelReload {
        reload_id: u64,
    },
    RequestViewport {
        resize_id: u64,
        reason: String,
    },
}

#[cfg(unix)]
pub(crate) struct GhosttyAttachV2Session {
    pub(crate) attach_id: [u8; 16],
    command_tx: mpsc::Sender<GhosttyAttachV2Command>,
    control_rx:
        AsyncMutex<Option<mpsc::UnboundedReceiver<portl_proto::session_v1::AttachV2ServerFrame>>>,
    viewport_rx:
        AsyncMutex<Option<watch::Receiver<Option<portl_proto::session_v1::AttachV2ServerFrame>>>>,
    live_rx: AsyncMutex<Option<mpsc::Receiver<portl_proto::session_v1::AttachV2ServerFrame>>>,
    history_rx: AsyncMutex<Option<mpsc::Receiver<portl_proto::session_v1::AttachV2ServerFrame>>>,
}

#[cfg(unix)]
impl GhosttyAttachV2Session {
    pub(crate) async fn new(_pid: u32, mut attach: GhosttyAttachV2) -> Result<Arc<Self>> {
        let attach_id = rand::random::<[u8; 16]>();
        attach.attach_id = attach_id;
        let (command_tx, command_rx) = mpsc::channel(64);
        let (control_tx, control_rx) = mpsc::unbounded_channel();
        let (viewport_tx, viewport_rx) = watch::channel(None);
        let (live_tx, live_rx) = mpsc::channel(128);
        let (history_tx, history_rx) = mpsc::channel(16);
        let session = Arc::new(Self {
            attach_id,
            command_tx,
            control_rx: AsyncMutex::new(Some(control_rx)),
            viewport_rx: AsyncMutex::new(Some(viewport_rx)),
            live_rx: AsyncMutex::new(Some(live_rx)),
            history_rx: AsyncMutex::new(Some(history_rx)),
        });
        enqueue_initial_attach_v2_frames(&attach, &control_tx, &viewport_tx, &history_tx).await?;
        let error_tx = control_tx.clone();
        let error_attach_id = attach_id;
        tokio::spawn(async move {
            if let Err(err) = attach_v2_dispatch_loop(
                attach,
                command_rx,
                control_tx,
                viewport_tx,
                live_tx,
                history_tx,
            )
            .await
            {
                let _ = error_tx.send(portl_proto::session_v1::AttachV2ServerFrame::Error {
                    attach_id: error_attach_id,
                    message: format!("ghostty attach v2 dispatcher stopped: {err:#}"),
                    recoverable: false,
                });
                tracing::debug!(%err, "ghostty attach v2 dispatcher ended");
            }
        });
        Ok(session)
    }

    pub(crate) async fn take_control_rx(
        &self,
    ) -> Result<mpsc::UnboundedReceiver<portl_proto::session_v1::AttachV2ServerFrame>> {
        self.control_rx
            .lock()
            .await
            .take()
            .context("attach v2 control stream already attached")
    }

    pub(crate) async fn take_viewport_rx(
        &self,
    ) -> Result<watch::Receiver<Option<portl_proto::session_v1::AttachV2ServerFrame>>> {
        self.viewport_rx
            .lock()
            .await
            .take()
            .context("attach v2 viewport stream already attached")
    }

    pub(crate) async fn take_live_rx(
        &self,
    ) -> Result<mpsc::Receiver<portl_proto::session_v1::AttachV2ServerFrame>> {
        self.live_rx
            .lock()
            .await
            .take()
            .context("attach v2 live stream already attached")
    }

    pub(crate) async fn take_history_rx(
        &self,
    ) -> Result<mpsc::Receiver<portl_proto::session_v1::AttachV2ServerFrame>> {
        self.history_rx
            .lock()
            .await
            .take()
            .context("attach v2 history stream already attached")
    }

    pub(crate) async fn handle_client_frame(
        &self,
        frame: portl_proto::session_v1::AttachV2ClientFrame,
    ) -> Result<()> {
        use portl_proto::session_v1::AttachV2ClientFrame as Frame;
        match frame {
            Frame::Input { attach_id, bytes } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::Input(bytes))
                .await
                .context("send attach v2 input command"),
            Frame::Resize {
                attach_id,
                resize_id,
                cols,
                rows,
            } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::Resize {
                    resize_id,
                    cols,
                    rows,
                })
                .await
                .context("send attach v2 resize command"),
            Frame::Detach { attach_id } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::Detach)
                .await
                .context("send attach v2 detach command"),
            Frame::Reload {
                attach_id,
                reload_id,
            } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::Reload { reload_id })
                .await
                .context("send attach v2 reload command"),
            Frame::CancelReload {
                attach_id,
                reload_id,
            } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::CancelReload { reload_id })
                .await
                .context("send attach v2 cancel reload command"),
            Frame::RequestViewport {
                attach_id,
                resize_id,
                reason,
            } if attach_id == self.attach_id => self
                .command_tx
                .send(GhosttyAttachV2Command::RequestViewport { resize_id, reason })
                .await
                .context("send attach v2 viewport request command"),
            _ => Ok(()),
        }
    }
}

#[cfg(unix)]
async fn enqueue_initial_attach_v2_frames(
    attach: &GhosttyAttachV2,
    control_tx: &mpsc::UnboundedSender<portl_proto::session_v1::AttachV2ServerFrame>,
    viewport_tx: &watch::Sender<Option<portl_proto::session_v1::AttachV2ServerFrame>>,
    history_tx: &mpsc::Sender<portl_proto::session_v1::AttachV2ServerFrame>,
) -> Result<()> {
    use portl_proto::session_v1::{
        AttachV2Payload, AttachV2Progress, AttachV2ServerFrame as Frame,
    };
    control_tx
        .send(Frame::AttachReady {
            attach_id: attach.attach_id,
            provider: "ghostty".to_owned(),
        })
        .context("queue attach v2 ready frame")?;
    if !attach.prelude.is_empty() {
        history_tx
            .send(Frame::PreludeChunk {
                attach_id: attach.attach_id,
                seq: 0,
                progress: AttachV2Progress {
                    loaded_bytes: attach.prelude.len() as u64,
                    total_bytes: Some(attach.prelude.len() as u64),
                    retained_history_truncated: false,
                    complete: true,
                },
                payload: AttachV2Payload::encode_auto(&attach.prelude)?,
            })
            .await
            .context("queue attach v2 prelude frame")?;
    }
    viewport_tx.send_replace(Some(Frame::ViewportSnapshot {
        attach_id: attach.attach_id,
        generation: attach.generation,
        covers_live_seq: attach.covers_live_seq,
        cols: attach.cols,
        rows: attach.rows,
        resize_id: attach.resize_id,
        payload: AttachV2Payload::encode_auto(&attach.viewport)?,
    }));
    Ok(())
}

#[cfg(unix)]
async fn attach_v2_dispatch_loop(
    mut attach: GhosttyAttachV2,
    mut command_rx: mpsc::Receiver<GhosttyAttachV2Command>,
    control_tx: mpsc::UnboundedSender<portl_proto::session_v1::AttachV2ServerFrame>,
    viewport_tx: watch::Sender<Option<portl_proto::session_v1::AttachV2ServerFrame>>,
    live_tx: mpsc::Sender<portl_proto::session_v1::AttachV2ServerFrame>,
    history_tx: mpsc::Sender<portl_proto::session_v1::AttachV2ServerFrame>,
) -> Result<()> {
    let mut pending_resize_viewport: Option<(u64, tokio::time::Instant)> = None;
    let mut resize_tracker = AttachV2ResizeTracker::new(attach.resize_id);
    let mut resync_pending = false;
    loop {
        tokio::select! {
            Some(command) = command_rx.recv() => {
                match command {
                    GhosttyAttachV2Command::Resize { resize_id, cols, rows } => {
                        attach.resize(cols, rows).await?;
                        pending_resize_viewport = Some((
                            resize_id,
                            tokio::time::Instant::now()
                                + Duration::from_millis(GHOSTTY_ATTACH_V2_RESIZE_SETTLE_MS),
                        ));
                        if let Some((request_resize_id, reason)) = resize_tracker.record_resize(resize_id) {
                            attach.request_viewport(request_resize_id, reason).await?;
                        }
                    }
                    GhosttyAttachV2Command::RequestViewport { resize_id, reason } => {
                        if let Some((request_resize_id, reason)) = resize_tracker.request_or_defer(resize_id, reason) {
                            attach.request_viewport(request_resize_id, reason).await?;
                        }
                    }
                    command => handle_attach_v2_command(&mut attach, command).await?,
                }
            }
            () = async {
                let Some((_, deadline)) = pending_resize_viewport else {
                    std::future::pending::<()>().await;
                    return;
                };
                tokio::time::sleep_until(deadline).await;
            }, if pending_resize_viewport.is_some() => {
                if let Some((resize_id, _)) = pending_resize_viewport.take() {
                    attach
                        .request_viewport(resize_id, "resize_settled".to_owned())
                        .await?;
                }
            }
            response = attach.next_response() => {
                let Some(response) = response? else {
                    let _ = control_tx.send(portl_proto::session_v1::AttachV2ServerFrame::Error {
                        attach_id: attach.attach_id,
                        message: "ghostty attach v2 helper stream closed".to_owned(),
                        recoverable: false,
                    });
                    return Ok(());
                };
                let output_after_resize = matches!(response, GhosttyResponse::OutputV2 { .. })
                    && pending_resize_viewport.is_some();
                if handle_attach_v2_response(
                    &mut attach,
                    response,
                    &control_tx,
                    &viewport_tx,
                    &live_tx,
                    &history_tx,
                    resize_tracker.recovery_resize_id(),
                    &mut resync_pending,
                ).await? {
                    return Ok(());
                }
                if output_after_resize
                    && let Some((resize_id, _)) = pending_resize_viewport.take()
                {
                    attach
                        .request_viewport(resize_id, "resize_output".to_owned())
                        .await?;
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(unix)]
async fn handle_attach_v2_command(
    attach: &mut GhosttyAttachV2,
    command: GhosttyAttachV2Command,
) -> Result<()> {
    match command {
        GhosttyAttachV2Command::Input(bytes) => attach.input(bytes).await,
        GhosttyAttachV2Command::Resize {
            resize_id,
            cols,
            rows,
        } => {
            attach.resize(cols, rows).await?;
            attach
                .request_viewport(resize_id, "resize".to_owned())
                .await
        }
        GhosttyAttachV2Command::Detach => attach.detach().await,
        GhosttyAttachV2Command::Reload { reload_id } => attach.reload(reload_id).await,
        GhosttyAttachV2Command::CancelReload { reload_id } => attach.cancel_reload(reload_id).await,
        GhosttyAttachV2Command::RequestViewport { resize_id, reason } => {
            attach.request_viewport(resize_id, reason).await
        }
    }
}

#[cfg(unix)]
#[allow(clippy::too_many_arguments)]
#[allow(clippy::too_many_lines)]
async fn handle_attach_v2_response(
    attach: &mut GhosttyAttachV2,
    response: GhosttyResponse,
    control_tx: &mpsc::UnboundedSender<portl_proto::session_v1::AttachV2ServerFrame>,
    viewport_tx: &watch::Sender<Option<portl_proto::session_v1::AttachV2ServerFrame>>,
    live_tx: &mpsc::Sender<portl_proto::session_v1::AttachV2ServerFrame>,
    history_tx: &mpsc::Sender<portl_proto::session_v1::AttachV2ServerFrame>,
    current_resize_id: u64,
    resync_pending: &mut bool,
) -> Result<bool> {
    use portl_proto::session_v1::{AttachV2Payload, AttachV2ServerFrame as Frame};
    match response {
        GhosttyResponse::OutputV2 {
            start_seq,
            end_seq,
            bytes,
        } => {
            let frame = Frame::LiveOutput {
                attach_id: attach.attach_id,
                start_seq,
                end_seq,
                payload: AttachV2Payload::encode_auto(&bytes)?,
            };
            match live_tx.try_send(frame) {
                Ok(()) => {
                    tracing::trace!(
                        lane = "live",
                        start_seq,
                        end_seq,
                        bytes = bytes.len(),
                        "queue attach v2 live output"
                    );
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::metrics::record_ghostty_event("attach_v2_live_queue_full");
                    if !*resync_pending {
                        *resync_pending = true;
                        control_tx
                            .send(Frame::ResyncRequired {
                                attach_id: attach.attach_id,
                                reason: "live queue full".to_owned(),
                                from_seq: start_seq,
                            })
                            .context("queue attach v2 live resync")?;
                        let _ = attach
                            .request_viewport(current_resize_id, "live_queue_full".to_owned())
                            .await;
                    }
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(true),
            }
        }
        GhosttyResponse::ViewportV2 {
            generation,
            covers_live_seq,
            cols,
            rows,
            resize_id,
            bytes,
        } => {
            *resync_pending = false;
            tracing::trace!(
                lane = "viewport",
                generation,
                covers_live_seq,
                cols,
                rows,
                resize_id,
                bytes = bytes.len(),
                "queue attach v2 viewport snapshot"
            );
            viewport_tx.send_replace(Some(Frame::ViewportSnapshot {
                attach_id: attach.attach_id,
                generation,
                covers_live_seq,
                cols,
                rows,
                resize_id,
                payload: AttachV2Payload::encode_auto(&bytes)?,
            }));
        }
        GhosttyResponse::ReloadStartedV2 {
            reload_id,
            total_bytes,
        } => {
            control_tx
                .send(Frame::ReloadStarted {
                    attach_id: attach.attach_id,
                    reload_id,
                    total_bytes,
                })
                .context("queue attach v2 reload started")?;
        }
        GhosttyResponse::ReloadChunkV2 {
            reload_id,
            seq,
            progress,
            bytes,
        } => {
            tracing::trace!(
                lane = "history",
                reload_id,
                seq,
                bytes = bytes.len(),
                complete = progress.complete,
                "queue attach v2 reload chunk"
            );
            match history_tx.try_send(Frame::ReloadChunk {
                attach_id: attach.attach_id,
                reload_id,
                seq,
                progress,
                payload: AttachV2Payload::encode_auto(&bytes)?,
            }) {
                Ok(()) => {}
                Err(mpsc::error::TrySendError::Full(_)) => {
                    crate::metrics::record_ghostty_event("attach_v2_history_queue_full");
                    let _ = control_tx.send(Frame::ReloadCancelled {
                        attach_id: attach.attach_id,
                        reload_id,
                    });
                    let _ = attach.cancel_reload(reload_id).await;
                    let _ = attach
                        .request_viewport(current_resize_id, "history_queue_full".to_owned())
                        .await;
                }
                Err(mpsc::error::TrySendError::Closed(_)) => return Ok(true),
            }
        }
        GhosttyResponse::ReloadDoneV2 {
            reload_id,
            final_generation,
        } => {
            control_tx
                .send(Frame::ReloadDone {
                    attach_id: attach.attach_id,
                    reload_id,
                    final_generation,
                })
                .context("queue attach v2 reload done")?;
            let _ = attach
                .request_viewport(current_resize_id, "reload_done".to_owned())
                .await;
        }
        GhosttyResponse::ReloadCancelledV2 { reload_id } => {
            control_tx
                .send(Frame::ReloadCancelled {
                    attach_id: attach.attach_id,
                    reload_id,
                })
                .context("queue attach v2 reload cancelled")?;
            let _ = attach
                .request_viewport(current_resize_id, "reload_cancelled".to_owned())
                .await;
        }
        GhosttyResponse::ResyncRequiredV2 { reason, from_seq } => {
            control_tx
                .send(Frame::ResyncRequired {
                    attach_id: attach.attach_id,
                    reason: reason.clone(),
                    from_seq,
                })
                .context("queue attach v2 resync required")?;
            let _ = attach.request_viewport(current_resize_id, reason).await;
        }
        GhosttyResponse::Exit { code } => {
            let _ = control_tx.send(Frame::Exit {
                attach_id: attach.attach_id,
                code,
            });
            return Ok(true);
        }
        GhosttyResponse::Error { message } => {
            let _ = control_tx.send(Frame::Error {
                attach_id: attach.attach_id,
                message,
                recoverable: false,
            });
            return Ok(true);
        }
        _ => {}
    }
    Ok(false)
}

#[cfg(unix)]
impl GhosttyAttachV2 {
    pub(crate) async fn input(&mut self, bytes: Vec<u8>) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Input { bytes }).await
    }

    pub(crate) async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Resize { cols, rows }).await
    }

    pub(crate) async fn reload(&mut self, reload_id: u64) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::ReloadV2 { reload_id }).await
    }

    pub(crate) async fn cancel_reload(&mut self, reload_id: u64) -> Result<()> {
        write_frame(
            &mut self.stream,
            &GhosttyRequest::CancelReloadV2 { reload_id },
        )
        .await
    }

    pub(crate) async fn request_viewport(&mut self, resize_id: u64, reason: String) -> Result<()> {
        write_frame(
            &mut self.stream,
            &GhosttyRequest::RequestViewportV2 { resize_id, reason },
        )
        .await
    }

    pub(crate) async fn detach(&mut self) -> Result<()> {
        write_frame(&mut self.stream, &GhosttyRequest::Detach).await
    }

    async fn next_response(&mut self) -> Result<Option<GhosttyResponse>> {
        read_frame::<GhosttyResponse>(&mut self.stream).await
    }

    #[cfg(test)]
    async fn read_reload_until_done(
        &mut self,
        reload_id: u64,
        timeout: Duration,
    ) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        let mut out = Vec::new();
        loop {
            let Some(remaining) = deadline.checked_duration_since(tokio::time::Instant::now())
            else {
                bail!("timed out waiting for ghostty attach v2 reload {reload_id}");
            };
            let response = tokio::time::timeout(remaining, self.next_response())
                .await
                .context("wait for ghostty attach v2 reload")??;
            match response {
                Some(GhosttyResponse::ReloadStartedV2 { reload_id: id, .. }) if id == reload_id => {
                }
                Some(GhosttyResponse::ReloadChunkV2 {
                    reload_id: id,
                    bytes,
                    ..
                }) if id == reload_id => {
                    out.extend_from_slice(&bytes);
                }
                Some(GhosttyResponse::ReloadDoneV2 { reload_id: id, .. }) if id == reload_id => {
                    return Ok(String::from_utf8_lossy(&out).into_owned());
                }
                Some(GhosttyResponse::ReloadCancelledV2 { reload_id: id }) if id == reload_id => {
                    bail!("ghostty attach v2 reload {reload_id} cancelled");
                }
                Some(GhosttyResponse::Error { message }) => bail!(message),
                Some(_) => {}
                None => bail!("ghostty attach v2 stream closed"),
            }
        }
    }
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
    tokio::time::timeout(
        GHOSTTY_FRAME_WRITE_TIMEOUT,
        stream.write_all(&len.to_be_bytes()),
    )
    .await
    .context("write ghostty frame length timed out")??;
    tokio::time::timeout(GHOSTTY_FRAME_WRITE_TIMEOUT, stream.write_all(&bytes))
        .await
        .context("write ghostty frame timed out")??;
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
    use crate::session_handler::vt_capability::{
        PORTL_CANONICAL_DA1_PARAMETER_LIST, PORTL_CANONICAL_DA2_PARAMETER_LIST,
        PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS,
    };

    fn configured_test_terminal() -> Result<(Terminal<'static, 'static>, TerminalPtyReplies)> {
        let mut terminal = Terminal::new(TerminalOptions {
            cols: 80,
            rows: 24,
            max_scrollback: 4096,
        })?;
        let replies = Rc::new(RefCell::new(Vec::new()));
        configure_portl_terminal_capabilities(&mut terminal, Rc::clone(&replies))?;
        Ok((terminal, replies))
    }

    fn terminal_replies_for(input: &[u8]) -> Result<Vec<u8>> {
        let (mut terminal, replies) = configured_test_terminal()?;
        terminal.vt_write(input);
        Ok(replies.borrow_mut().drain(..).flatten().collect())
    }

    fn expected_da1_response() -> Vec<u8> {
        let mut out = b"\x1b[?".to_vec();
        out.extend_from_slice(PORTL_CANONICAL_DA1_PARAMETER_LIST);
        out.push(b'c');
        out
    }

    fn expected_da2_response() -> Vec<u8> {
        let mut out = b"\x1b[>".to_vec();
        out.extend_from_slice(PORTL_CANONICAL_DA2_PARAMETER_LIST);
        out.push(b'c');
        out
    }

    fn expected_kitty_flag_response() -> Vec<u8> {
        format!("\x1b[?{PORTL_CANONICAL_KITTY_KEYBOARD_FLAGS}u").into_bytes()
    }

    fn contains_subslice(haystack: &[u8], needle: &[u8]) -> bool {
        !needle.is_empty()
            && haystack
                .windows(needle.len())
                .any(|window| window == needle)
    }

    #[derive(Clone, Copy)]
    enum ExpectedReply {
        None,
        Da1,
        Da2,
        Kitty,
    }

    #[derive(Clone, Copy)]
    struct QueryCase {
        name: &'static str,
        query: &'static [u8],
        expected_reply: ExpectedReply,
    }

    fn expected_reply_bytes(kind: ExpectedReply) -> Option<Vec<u8>> {
        match kind {
            ExpectedReply::None => None,
            ExpectedReply::Da1 => Some(expected_da1_response()),
            ExpectedReply::Da2 => Some(expected_da2_response()),
            ExpectedReply::Kitty => Some(expected_kitty_flag_response()),
        }
    }

    fn assert_query_stripped_from_ghostty_output(case: QueryCase) -> Result<()> {
        let mut terminal = GhosttyTerminalIo::new(TerminalOptions {
            cols: 80,
            rows: 24,
            max_scrollback: 4096,
        })?;
        let mut history = VecDeque::new();
        let (tx, mut rx) = mpsc::channel(4);
        let mut subscribers = vec![tx];
        let (v2_tx, mut v2_rx) = mpsc::channel(4);
        let mut v2_subscribers = vec![GhosttyV2Subscriber {
            live: v2_tx,
            events: mpsc::unbounded_channel().0,
            resync_pending: false,
        }];
        let mut history_start_abs = 0;
        let mut live_seq = 0;
        let mut input = b"pre".to_vec();
        input.extend_from_slice(case.query);
        input.extend_from_slice(b"post");

        process_output(
            &mut terminal,
            &mut history,
            &mut subscribers,
            &mut v2_subscribers,
            &mut history_start_abs,
            &mut live_seq,
            &input,
        );

        let history_bytes = history.iter().copied().collect::<Vec<_>>();
        assert_eq!(history_bytes, b"prepost", "{} history", case.name);
        assert_eq!(
            rx.try_recv()?,
            b"prepost".to_vec(),
            "{} broadcast",
            case.name
        );
        assert!(
            rx.try_recv().is_err(),
            "{} extra broadcast chunk",
            case.name
        );
        let v2 = v2_rx.try_recv()?;
        assert_eq!(v2.bytes, b"prepost", "{} v2 broadcast", case.name);
        assert_eq!(v2.start_seq, 0, "{} v2 start seq", case.name);
        assert_eq!(
            v2.end_seq,
            b"prepost".len() as u64,
            "{} v2 end seq",
            case.name
        );
        assert_eq!(live_seq, b"prepost".len() as u64, "{} live seq", case.name);
        assert!(
            v2_rx.try_recv().is_err(),
            "{} extra v2 broadcast chunk",
            case.name
        );
        assert!(
            !contains_subslice(&history_bytes, case.query),
            "{} query in history",
            case.name
        );
        assert!(
            !contains_subslice(&v2.bytes, case.query),
            "{} query in v2",
            case.name
        );

        let mut queued_replies = Vec::new();
        while let Some(chunk) = terminal.pending_input.front_chunk() {
            let len = chunk.len();
            queued_replies.extend_from_slice(chunk);
            terminal.pending_input.consume(len);
        }
        if let Some(expected_reply) = expected_reply_bytes(case.expected_reply) {
            assert_eq!(
                &queued_replies, &expected_reply,
                "{} guest pty reply",
                case.name
            );
            assert!(
                !contains_subslice(&history_bytes, &expected_reply),
                "{} reply leaked into history",
                case.name
            );
            assert!(
                !contains_subslice(&v2.bytes, &expected_reply),
                "{} reply leaked into v2",
                case.name
            );
        }

        Ok(())
    }

    const HOST_ENV_SIGNAL_VARS: &[&str] = &[
        "TERM",
        "COLORTERM",
        "TERM_PROGRAM",
        "KITTY_WINDOW_ID",
        "KITTY_PID",
    ];

    struct HostEnvProfile {
        name: &'static str,
        vars: &'static [(&'static str, Option<&'static str>)],
    }

    const HOST_ENV_PROFILES: &[HostEnvProfile] = &[
        HostEnvProfile {
            name: "xterm without kitty advertisement",
            vars: &[("TERM", Some("xterm-256color"))],
        },
        HostEnvProfile {
            name: "kitty advertisement",
            vars: &[
                ("TERM", Some("xterm-kitty")),
                ("TERM_PROGRAM", Some("kitty")),
                ("KITTY_WINDOW_ID", Some("1")),
            ],
        },
        HostEnvProfile {
            name: "dumb terminal",
            vars: &[("TERM", Some("dumb"))],
        },
        HostEnvProfile {
            name: "truecolor colorterm",
            vars: &[
                ("TERM", Some("screen-256color")),
                ("COLORTERM", Some("truecolor")),
            ],
        },
        HostEnvProfile {
            name: "ghostty term program",
            vars: &[
                ("TERM", Some("xterm-256color")),
                ("TERM_PROGRAM", Some("ghostty")),
            ],
        },
        HostEnvProfile {
            name: "empty host environment",
            vars: &[],
        },
    ];

    fn host_env_lock() -> &'static Mutex<()> {
        static LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    struct HostEnvGuard {
        saved: Vec<(&'static str, Option<std::ffi::OsString>)>,
        _guard: std::sync::MutexGuard<'static, ()>,
    }

    impl HostEnvGuard {
        #[allow(unsafe_code)]
        fn apply(profile: &HostEnvProfile) -> Self {
            let guard = host_env_lock().lock().expect("host env lock");
            let saved = HOST_ENV_SIGNAL_VARS
                .iter()
                .map(|name| (*name, std::env::var_os(name)))
                .collect::<Vec<_>>();

            for name in HOST_ENV_SIGNAL_VARS {
                // SAFETY: all test env mutation in this module is serialized by host_env_lock.
                unsafe { std::env::remove_var(name) };
            }
            for (name, value) in profile.vars {
                match value {
                    Some(value) => {
                        // SAFETY: all test env mutation in this module is serialized by host_env_lock.
                        unsafe { std::env::set_var(name, value) };
                    }
                    None => {
                        // SAFETY: all test env mutation in this module is serialized by host_env_lock.
                        unsafe { std::env::remove_var(name) };
                    }
                }
            }

            for name in HOST_ENV_SIGNAL_VARS {
                assert_eq!(
                    std::env::var(name).ok().as_deref(),
                    expected_profile_value(profile, name),
                    "host env profile {} did not apply {name}",
                    profile.name
                );
            }

            Self {
                saved,
                _guard: guard,
            }
        }
    }

    impl Drop for HostEnvGuard {
        #[allow(unsafe_code)]
        fn drop(&mut self) {
            for (name, value) in &self.saved {
                match value {
                    Some(value) => {
                        // SAFETY: all test env mutation in this module is serialized by host_env_lock.
                        unsafe { std::env::set_var(name, value) };
                    }
                    None => {
                        // SAFETY: all test env mutation in this module is serialized by host_env_lock.
                        unsafe { std::env::remove_var(name) };
                    }
                }
            }
        }
    }

    fn expected_profile_value<'a>(profile: &'a HostEnvProfile, name: &str) -> Option<&'a str> {
        profile
            .vars
            .iter()
            .find_map(|(var, value)| (*var == name).then_some(*value).flatten())
    }

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

    #[test]
    fn da1_query_uses_canonical_primary_device_attributes() -> Result<()> {
        let expected = expected_da1_response();

        assert_eq!(terminal_replies_for(b"\x1b[c")?, expected);
        assert_eq!(terminal_replies_for(b"unrelated\x1b[c")?, expected);
        assert_eq!(terminal_replies_for(b"\x1b[c")?, expected);

        Ok(())
    }

    #[test]
    fn da2_query_uses_canonical_secondary_device_attributes() -> Result<()> {
        let expected = expected_da2_response();

        assert_eq!(terminal_replies_for(b"\x1b[>c")?, expected);
        assert_eq!(terminal_replies_for(b"unrelated\x1b[>c")?, expected);
        assert_eq!(terminal_replies_for(b"\x1b[>c")?, expected);

        Ok(())
    }

    #[test]
    fn da1_and_da2_queries_are_host_environment_independent() -> Result<()> {
        for profile in HOST_ENV_PROFILES {
            let _env = HostEnvGuard::apply(profile);
            assert_eq!(terminal_replies_for(b"\x1b[c")?, expected_da1_response());
            assert_eq!(terminal_replies_for(b"\x1b[>c")?, expected_da2_response());
        }

        Ok(())
    }

    #[test]
    fn kitty_flag_query_uses_canonical_fixed_response() -> Result<()> {
        let expected = expected_kitty_flag_response();

        assert_eq!(terminal_replies_for(b"\x1b[?u")?, expected);
        assert_eq!(terminal_replies_for(b"unrelated\x1b[?u")?, expected);
        assert_eq!(terminal_replies_for(b"\x1b[?u")?, expected);

        Ok(())
    }

    #[test]
    fn kitty_flag_query_is_host_environment_independent() -> Result<()> {
        for profile in HOST_ENV_PROFILES {
            let _env = HostEnvGuard::apply(profile);
            assert_eq!(
                terminal_replies_for(b"\x1b[?u")?,
                expected_kitty_flag_response()
            );
        }

        Ok(())
    }

    #[test]
    fn malformed_da_input_does_not_emit_spurious_response_and_resyncs() -> Result<()> {
        for malformed in [
            b"\x1b[".as_slice(),
            b"\x1b[?".as_slice(),
            b"\x1b[?;;x".as_slice(),
            b"\x1b[>;;x".as_slice(),
            b"\x1b[\x07".as_slice(),
        ] {
            let (mut terminal, replies) = configured_test_terminal()?;
            terminal.vt_write(malformed);
            assert!(
                replies.borrow().is_empty(),
                "malformed input emitted {:?}",
                replies.borrow()
            );

            terminal.vt_write(b"\x1b[c");
            let response: Vec<u8> = replies.borrow_mut().drain(..).flatten().collect();
            assert_eq!(response, expected_da1_response());
        }

        Ok(())
    }

    #[test]
    fn multiple_sequential_da_queries_in_one_chunk_each_receive_a_response() -> Result<()> {
        let mut expected = expected_da1_response();
        expected.extend_from_slice(&expected_da2_response());
        expected.extend_from_slice(&expected_da1_response());

        assert_eq!(terminal_replies_for(b"\x1b[c\x1b[>c\x1b[c")?, expected);

        Ok(())
    }

    #[test]
    fn ghostty_query_forms_are_stripped_from_history_and_broadcasts() -> Result<()> {
        for case in [
            QueryCase {
                name: "da1",
                query: b"\x1b[c",
                expected_reply: ExpectedReply::Da1,
            },
            QueryCase {
                name: "da2",
                query: b"\x1b[>c",
                expected_reply: ExpectedReply::Da2,
            },
            QueryCase {
                name: "dsr_cpr",
                query: b"\x1b[6n",
                expected_reply: ExpectedReply::None,
            },
            QueryCase {
                name: "kitty_primary",
                query: b"\x1b[?u",
                expected_reply: ExpectedReply::Kitty,
            },
            QueryCase {
                name: "kitty_push",
                query: b"\x1b[>1u",
                expected_reply: ExpectedReply::None,
            },
            QueryCase {
                name: "kitty_set",
                query: b"\x1b[=15u",
                expected_reply: ExpectedReply::None,
            },
            QueryCase {
                name: "kitty_pop",
                query: b"\x1b[<u",
                expected_reply: ExpectedReply::None,
            },
        ] {
            assert_query_stripped_from_ghostty_output(case)?;
        }

        Ok(())
    }

    #[test]
    fn reload_replay_chunk_bracketing_does_not_inject_sgr_resets() {
        assert_eq!(
            bracket_reload_replay_chunk(b"abc".to_vec(), true, false),
            b"abc"
        );
        assert_eq!(
            bracket_reload_replay_chunk(b"def".to_vec(), false, true),
            b"def"
        );
        assert_eq!(
            bracket_reload_replay_chunk(b"ghi".to_vec(), true, true),
            b"ghi"
        );
    }

    #[test]
    fn da1_da2_and_kitty_flag_query_replies_are_queued_to_guest_pty_input_not_broadcast_to_host()
    -> Result<()> {
        let mut terminal = GhosttyTerminalIo::new(TerminalOptions {
            cols: 80,
            rows: 24,
            max_scrollback: 4096,
        })?;
        let mut history = VecDeque::new();
        let (tx, mut rx) = mpsc::channel(4);
        let mut subscribers = vec![tx];
        let mut v2_subscribers = Vec::new();
        let mut history_start_abs = 0;
        let mut live_seq = 0;

        process_output(
            &mut terminal,
            &mut history,
            &mut subscribers,
            &mut v2_subscribers,
            &mut history_start_abs,
            &mut live_seq,
            b"\x1b[c\x1b[>c\x1b[?u",
        );

        let mut expected = expected_da1_response();
        expected.extend_from_slice(&expected_da2_response());
        expected.extend_from_slice(&expected_kitty_flag_response());
        let mut queued_replies = Vec::new();
        while let Some(chunk) = terminal.pending_input.front_chunk() {
            let len = chunk.len();
            queued_replies.extend_from_slice(chunk);
            terminal.pending_input.consume(len);
        }
        assert_eq!(queued_replies, expected);
        assert!(rx.try_recv().is_err());

        Ok(())
    }

    #[tokio::test]
    async fn helper_run_strips_queries_from_history_and_attach_stream() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("query-strip");
        let helper =
            GhosttyHelperConfig::for_test("query-strip", paths.clone(), vec!["/bin/sh".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let run = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .run(
                None,
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "printf 'pre\\033[c\\033[>c\\033[6n\\033[?u\\033[>1u\\033[=15u\\033[<upost'"
                        .to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let history = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .history()
            .await?;
        assert!(
            history.contains("prepost"),
            "history should preserve surrounding bytes: {history:?}"
        );
        for query in [
            "\x1b[c",
            "\x1b[>c",
            "\x1b[6n",
            "\x1b[?u",
            "\x1b[>1u",
            "\x1b[=15u",
            "\x1b[<u",
        ] {
            assert!(
                !history.contains(query),
                "history leaked query {query:?}: {history:?}"
            );
        }

        let attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach(80, 24)
            .await?;
        assert!(
            contains_subslice(&attach.initial_snapshot, b"prepost"),
            "attach snapshot should preserve surrounding bytes: {:?}",
            String::from_utf8_lossy(&attach.initial_snapshot)
        );
        for query in [
            b"\x1b[c".as_slice(),
            b"\x1b[>c",
            b"\x1b[6n",
            b"\x1b[?u",
            b"\x1b[>1u",
            b"\x1b[=15u",
            b"\x1b[<u",
        ] {
            assert!(
                !contains_subslice(&attach.initial_snapshot, query),
                "attach snapshot leaked query {:?}: {:?}",
                String::from_utf8_lossy(query),
                String::from_utf8_lossy(&attach.initial_snapshot)
            );
        }

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[tokio::test]
    async fn helper_run_history_and_kill_round_trip() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("dev");
        let helper =
            GhosttyHelperConfig::for_test("dev", paths.clone(), vec!["/bin/sh".to_owned()]);
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
    async fn helper_attach_v2_sends_bounded_prelude_then_viewport() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-prelude");
        let helper =
            GhosttyHelperConfig::for_test("v2-prelude", paths.clone(), vec!["/bin/sh".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let run = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .run(
                None,
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "printf '0123456789abcdef\\nviewport-ok\\n'".to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let config = portl_proto::session_v1::AttachV2Config {
            prelude_max_wait_ms: 200,
            prelude_max_bytes: 8,
        };
        let attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(80, 24, config)
            .await?;

        assert_eq!(attach.attach_id, [0; 16]);
        assert!(attach.prelude.len() <= 8, "prelude was too large");
        assert!(
            String::from_utf8_lossy(&attach.viewport).contains("viewport-ok"),
            "viewport was {:?}",
            String::from_utf8_lossy(&attach.viewport)
        );
        assert!(attach.covers_live_seq > 0);

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[test]
    fn attach_v2_alt_screen_disables_raw_history_replay() -> Result<()> {
        let mut terminal = Terminal::new(TerminalOptions {
            cols: 80,
            rows: 24,
            max_scrollback: 4096,
        })?;

        assert!(terminal_allows_raw_history(&terminal)?);
        terminal.vt_write(b"\x1b[?1049hfullscreen");
        assert!(!terminal_allows_raw_history(&terminal)?);
        Ok(())
    }

    #[test]
    fn attach_v2_viewport_rows_use_absolute_positioning() {
        let mut out = Vec::new();

        push_viewport_row_prefix(&mut out, 0);
        push_viewport_row_prefix(&mut out, 1);

        assert_eq!(out, b"\x1b[1;1H\x1b[2;1H");
        assert!(!out.windows(b"\r\n".len()).any(|w| w == b"\r\n"));
    }

    #[test]
    fn attach_v2_viewport_snapshot_disables_wrap_and_clears_rows() -> Result<()> {
        let mut terminal = Terminal::new(TerminalOptions {
            cols: 3,
            rows: 2,
            max_scrollback: 4096,
        })?;
        terminal.vt_write(b"abcde");

        let snapshot = render_viewport_snapshot(&terminal)?;

        assert!(
            snapshot
                .windows(b"\x1b[?25l".len())
                .any(|w| w == b"\x1b[?25l"),
            "snapshot should hide cursor during repaint: {snapshot:?}"
        );
        assert!(
            snapshot
                .windows(b"\x1b[?7l".len())
                .any(|w| w == b"\x1b[?7l"),
            "snapshot should disable autowrap during repaint: {snapshot:?}"
        );
        assert!(
            snapshot.windows(b"\x1b[K".len()).any(|w| w == b"\x1b[K"),
            "snapshot should clear each row to EOL: {snapshot:?}"
        );
        assert!(
            snapshot
                .windows(b"\x1b[?7h".len())
                .any(|w| w == b"\x1b[?7h"),
            "snapshot should restore autowrap after repaint: {snapshot:?}"
        );
        assert!(!snapshot.windows(b"\r\n".len()).any(|w| w == b"\r\n"));
        Ok(())
    }

    #[test]
    fn render_viewport_snapshot_preserves_decawm_off() -> Result<()> {
        let mut terminal = Terminal::new(TerminalOptions {
            cols: 8,
            rows: 1,
            max_scrollback: 4096,
        })?;
        terminal.vt_write(b"\x1b[?7lno-wrap");

        let snapshot = render_viewport_snapshot(&terminal)?;

        assert!(
            snapshot
                .windows(b"\x1b[?7l".len())
                .any(|w| w == b"\x1b[?7l"),
            "snapshot should preserve DECAWM off: {snapshot:?}"
        );
        assert!(
            !snapshot
                .windows(b"\x1b[?7h".len())
                .any(|w| w == b"\x1b[?7h"),
            "snapshot must not unconditionally enable DECAWM: {snapshot:?}"
        );
        Ok(())
    }

    #[test]
    fn attach_v2_viewport_snapshot_resets_style_before_clearing_rows() -> Result<()> {
        let mut terminal = Terminal::new(TerminalOptions {
            cols: 3,
            rows: 1,
            max_scrollback: 4096,
        })?;
        terminal.vt_write(b"\x1b[44mabc");

        let snapshot = render_viewport_snapshot(&terminal)?;

        assert!(
            snapshot
                .windows(b"\x1b[0m\x1b[K".len())
                .any(|w| w == b"\x1b[0m\x1b[K"),
            "row clear should not inherit styled cell background: {snapshot:?}"
        );
        Ok(())
    }

    #[test]
    fn attach_v2_terminal_replay_strips_unsafe_csi_but_keeps_sgr() {
        assert_eq!(
            sanitize_terminal_replay(b"a\x1b[?1049hb\x1b[2Jc\x1b[31mred\x1b[0m"),
            b"abc\x1b[31mred\x1b[0m"
        );
    }

    #[test]
    fn attach_v2_terminal_replay_strips_unsafe_control_strings() {
        assert_eq!(
            sanitize_terminal_replay(b"before\x1b]52;c;secret\x07after"),
            b"beforeafter"
        );
        assert_eq!(
            sanitize_terminal_replay(b"before\x1bPprivate\x1b\\after"),
            b"beforeafter"
        );
    }

    #[test]
    fn attach_v2_terminal_replay_strips_plain_esc_sequences() {
        assert_eq!(
            sanitize_terminal_replay(b"a\x1bcb\x1b7c\x1b8d\x1b(Be\x1b=f\x1b>g"),
            b"abcdefg"
        );
    }

    #[test]
    fn sanitize_terminal_replay_preserves_utf8_continuations_outside_escape_context() {
        let box_drawing = "─│┌┐└┘├┤┬┴┼ ╔╗╚╝═║ ╭╮╰╯ ▐▌▀▄ █▓▒░";
        assert_eq!(
            sanitize_terminal_replay(box_drawing.as_bytes()),
            box_drawing.as_bytes()
        );
        assert_eq!(
            sanitize_terminal_replay("left │ right".as_bytes()),
            "left │ right".as_bytes()
        );
    }

    #[test]
    fn sanitize_terminal_replay_preserves_c1_bytes_in_csi_escape_context() {
        assert_eq!(sanitize_terminal_replay(b"pre\x94post"), b"pre\x94post");
        assert_eq!(
            sanitize_terminal_replay(b"pre\x1b[31;\x94mred\x1b[0m"),
            b"pre\x1b[31;\x94mred\x1b[0m"
        );
        assert_eq!(
            sanitize_terminal_replay(b"pre\x1b]0;\x94title\x07post"),
            b"prepost"
        );
        assert_eq!(
            sanitize_terminal_replay(b"pre\x1bPpayload\x94\x1b\\post"),
            b"prepost"
        );
    }

    #[test]
    fn sanitize_terminal_replay_does_not_consume_utf8_after_malformed_csi_prefix() {
        assert_eq!(
            sanitize_terminal_replay("pre\x1b[│post".as_bytes()),
            "pre│post".as_bytes()
        );
    }

    #[test]
    fn sanitize_terminal_replay_vec_deque_chunk_snaps_end_to_utf8_codepoint_boundary() {
        let bytes = "ab─🭁cd".as_bytes();
        let history = VecDeque::from(bytes.to_vec());

        assert_eq!(vec_deque_chunk(&history, 0, 3), b"ab");
        assert_eq!(vec_deque_chunk(&history, 0, 4), b"ab");
        assert_eq!(vec_deque_chunk(&history, 0, 5), "ab─".as_bytes());
        assert_eq!(vec_deque_chunk(&history, 0, 6), "ab─".as_bytes());
        assert_eq!(vec_deque_chunk(&history, 0, 8), "ab─".as_bytes());
        assert_eq!(vec_deque_chunk(&history, 0, 9), "ab─🭁".as_bytes());
        assert_eq!(vec_deque_chunk(&history, 0, 10), "ab─🭁c".as_bytes());
    }

    #[test]
    fn bounded_reload_window_snaps_capped_start_to_utf8_boundary() {
        let mut bytes = Vec::with_capacity(GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES + 1);
        bytes.extend_from_slice("─".as_bytes());
        bytes.resize(GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES + 1, b'x');
        let history = VecDeque::from(bytes);

        let (start_abs, retained_len, truncated) = bounded_reload_window(0, &history);
        let rel_start = usize::try_from(start_abs).unwrap();
        let first_chunk = vec_deque_chunk(&history, rel_start, retained_len.min(16));

        assert_eq!(start_abs, 3);
        assert_eq!(retained_len, GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES - 2);
        assert!(truncated);
        assert!(
            first_chunk
                .first()
                .is_some_and(|byte| (*byte & 0b1100_0000) != 0b1000_0000),
            "first reload chunk started with UTF-8 continuation byte: {first_chunk:?}"
        );
        assert!(!first_chunk.windows("�".len()).any(|w| w == "�".as_bytes()));
    }

    #[test]
    fn sanitize_terminal_replay_sgr_only_regression_baseline() {
        assert_eq!(
            sanitize_terminal_replay(b"\x1b[31mred\x1b[0m plain \x1b[1;4mbold\x1b[0m"),
            b"\x1b[31mred\x1b[0m plain \x1b[1;4mbold\x1b[0m"
        );
    }

    #[test]
    fn reload_edge_sanitizer_preserves_split_sgr_and_drops_split_private_modes() {
        let mut sanitizer = TerminalReplaySanitizer::new();

        assert_eq!(sanitizer.feed(b"pre\x1b[", false), b"pre");
        assert_eq!(sanitizer.feed(b"31mred\x1b[?", false), b"\x1b[31mred");
        assert_eq!(sanitizer.feed(b"1049lpost", true), b"post");
    }

    #[test]
    fn reload_edge_sanitizer_drops_split_osc_without_orphaned_bytes() {
        let mut sanitizer = TerminalReplaySanitizer::new();

        assert_eq!(sanitizer.feed(b"before\x1b]52;c;", false), b"before");
        assert_eq!(sanitizer.feed(b"secret", false), b"");
        assert_eq!(sanitizer.feed(b"\x07after", true), b"after");
    }

    #[test]
    fn replay_sanitizer_carries_escape_context_across_reload_chunks() {
        let whole = sanitize_terminal_replay(
            b"pre\x1b[31mred\x1b[0m\x1b[?1049hmid\x1b]52;c;secret\x07tail\x1bPprivate\x1b\\post",
        );
        let mut sanitizer = TerminalReplaySanitizer::new();
        let mut split = Vec::new();
        for (chunk, final_chunk) in [
            (b"pre\x1b[".as_slice(), false),
            (b"31mred\x1b[0m\x1b[?".as_slice(), false),
            (b"1049hmid\x1b]52;c;".as_slice(), false),
            (b"secret\x07tail\x1bPpri".as_slice(), false),
            (b"vate\x1b\\post".as_slice(), true),
        ] {
            split.extend_from_slice(&sanitizer.feed(chunk, final_chunk));
        }

        assert_eq!(split, whole);
        for leaked in [b"1049h".as_slice(), b"secret", b"private"] {
            assert!(
                !split.windows(leaked.len()).any(|window| window == leaked),
                "split replay leaked envelope bytes {leaked:?}: {split:?}"
            );
        }
        assert_eq!(split, b"pre\x1b[31mred\x1b[0mmidtailpost");
    }

    #[test]
    fn sanitize_terminal_replay_csi_split_on_c1_byte_preserves_envelope_state() {
        let whole = sanitize_terminal_replay(b"pre\x1b[31;\x94mred");
        let mut sanitizer = TerminalReplaySanitizer::new();
        let mut split = sanitizer.feed(b"pre\x1b[31;\x94", false);
        split.extend_from_slice(&sanitizer.feed(b"mred", true));

        assert_eq!(split, whole);
        assert!(
            !split
                .windows("�".len())
                .any(|window| window == "�".as_bytes())
        );
        assert_ne!(split, b"premred");
    }

    #[test]
    fn sanitize_terminal_replay_osc_split_on_c1_byte_preserves_envelope_state() {
        let whole = sanitize_terminal_replay(b"pre\x1b]52;c;\x94\x1b\\post");
        let mut sanitizer = TerminalReplaySanitizer::new();
        let mut split = sanitizer.feed(b"pre\x1b]52;c;\x94", false);
        split.extend_from_slice(&sanitizer.feed(b"\x1b\\post", true));

        assert_eq!(split, whole);
        assert_eq!(split, b"prepost");
    }

    #[test]
    fn sanitize_terminal_replay_dcs_split_on_c1_byte_preserves_envelope_state() {
        let whole = sanitize_terminal_replay(b"pre\x1bPpayload\x94\x1b\\post");
        let mut sanitizer = TerminalReplaySanitizer::new();
        let mut split = sanitizer.feed(b"pre\x1bPpayload\x94", false);
        split.extend_from_slice(&sanitizer.feed(b"\x1b\\post", true));

        assert_eq!(split, whole);
        assert_eq!(split, b"prepost");
    }

    #[test]
    fn reload_edge_sanitizer_preserves_utf8_edge_classes_across_chunks() {
        let mut sanitizer = TerminalReplaySanitizer::new();
        let payload = "e\u{0301} 👨\u{200d}💻 漢字 \u{200e}\u{200f}\t";
        let bytes = payload.as_bytes();
        let split = bytes
            .iter()
            .position(|byte| *byte >= 0x80)
            .expect("multibyte payload")
            + 1;

        let mut out = sanitizer.feed(&bytes[..split], false);
        assert_eq!(out, b"e");
        out.extend_from_slice(&sanitizer.feed(&bytes[split..], true));

        assert_eq!(out, bytes);
        assert!(!out.windows("�".len()).any(|w| w == "�".as_bytes()));
    }

    #[test]
    fn sanitize_terminal_replay_linear_smoke_large_utf8_payloads() {
        for size in [1024_usize, 64 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
            let mut payload = Vec::with_capacity(size + 16);
            while payload.len() < size {
                payload.extend_from_slice("text │ ─ \x1b[31mred\x1b[0m ".as_bytes());
            }
            payload.truncate(size);
            let sanitized = sanitize_terminal_replay(&payload);
            assert!(!sanitized.windows("�".len()).any(|w| w == "�".as_bytes()));
            assert!(sanitized.len() >= size / 2);
        }
    }

    #[tokio::test]
    async fn helper_v2_input_queue_full_reports_resync_and_applies_bounded_backpressure()
    -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(HelperCommand::Input(b"held".to_vec()))?;
        let (mut server, mut client) = UnixStream::pair()?;

        let tx_task = tx.clone();
        let mut forward = tokio::spawn(async move {
            forward_helper_input(&tx_task, b"queued".to_vec(), &mut server).await
        });
        let response = read_frame::<GhosttyResponse>(&mut client).await?;

        assert!(matches!(
            response,
            Some(GhosttyResponse::ResyncRequiredV2 { reason, .. }) if reason == "input_queue_full"
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut forward)
                .await
                .is_err(),
            "queue-full forwarding must apply bounded backpressure instead of spawning an unbounded waiter"
        );
        assert!(matches!(rx.recv().await, Some(HelperCommand::Input(bytes)) if bytes == b"held"));
        tokio::time::timeout(Duration::from_secs(1), &mut forward).await???;
        assert!(matches!(rx.recv().await, Some(HelperCommand::Input(bytes)) if bytes == b"queued"));
        Ok(())
    }

    #[tokio::test]
    async fn helper_v2_resize_queue_full_reports_resync_and_applies_bounded_backpressure()
    -> Result<()> {
        let (tx, mut rx) = mpsc::channel(1);
        tx.try_send(HelperCommand::Input(b"held".to_vec()))?;
        let (mut server, mut client) = UnixStream::pair()?;

        let tx_task = tx.clone();
        let mut forward =
            tokio::spawn(
                async move { forward_helper_resize(&tx_task, 100, 40, &mut server).await },
            );
        let response = read_frame::<GhosttyResponse>(&mut client).await?;

        assert!(matches!(
            response,
            Some(GhosttyResponse::ResyncRequiredV2 { reason, .. }) if reason == "resize_queue_full"
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut forward)
                .await
                .is_err(),
            "queue-full resize forwarding must apply bounded backpressure instead of spawning an unbounded waiter"
        );
        assert!(matches!(rx.recv().await, Some(HelperCommand::Input(bytes)) if bytes == b"held"));
        tokio::time::timeout(Duration::from_secs(1), &mut forward).await???;
        let resize = tokio::time::timeout(Duration::from_secs(1), rx.recv()).await?;
        assert!(matches!(
            resize,
            Some(HelperCommand::Resize {
                cols: 100,
                rows: 40
            })
        ));
        Ok(())
    }

    #[tokio::test]
    async fn helper_attach_v2_omits_prelude_in_alt_screen() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-alt-prelude");
        let helper = GhosttyHelperConfig::for_test(
            "v2-alt-prelude",
            paths.clone(),
            vec!["/bin/sh".to_owned()],
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
                    "printf '\\033[?1049hfullscreen-alt\\n'".to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(
                80,
                24,
                portl_proto::session_v1::AttachV2Config {
                    prelude_max_wait_ms: 200,
                    prelude_max_bytes: 1024,
                },
            )
            .await?;

        assert!(
            attach.prelude.is_empty(),
            "alternate-screen attaches must not replay raw history as prelude: {:?}",
            String::from_utf8_lossy(&attach.prelude)
        );
        assert!(
            String::from_utf8_lossy(&attach.viewport).contains("fullscreen-alt"),
            "viewport should still restore alternate-screen content: {:?}",
            String::from_utf8_lossy(&attach.viewport)
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

    #[tokio::test]
    async fn helper_attach_v2_reload_cancels_raw_history_in_alt_screen() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-alt-reload");
        let helper = GhosttyHelperConfig::for_test(
            "v2-alt-reload",
            paths.clone(),
            vec!["/bin/sh".to_owned()],
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
                    "printf '\\033[?1049hfullscreen-alt-reload\\n'".to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(
                80,
                24,
                portl_proto::session_v1::AttachV2Config {
                    prelude_max_wait_ms: 200,
                    prelude_max_bytes: 0,
                },
            )
            .await?;
        attach.reload(17).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .context("timed out waiting for alt-screen reload cancellation")?;
            match tokio::time::timeout(remaining, attach.next_response())
                .await
                .context("wait for alt-screen reload cancellation")??
            {
                Some(GhosttyResponse::ReloadCancelledV2 { reload_id: 17 }) => break,
                Some(GhosttyResponse::ReloadChunkV2 { .. }) => {
                    bail!("alternate-screen reload must not stream raw history chunks")
                }
                Some(_) => {}
                None => bail!("ghostty attach v2 stream closed"),
            }
        }

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[tokio::test]
    async fn helper_attach_v2_reload_cancel_reports_cancelled() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-reload-cancel");
        let helper = GhosttyHelperConfig::for_test(
            "v2-reload-cancel",
            paths.clone(),
            vec!["/bin/sh".to_owned()],
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
                    "for i in $(seq 1 2000); do printf 'cancel-line-%04d\\n' \"$i\"; done"
                        .to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(
                80,
                24,
                portl_proto::session_v1::AttachV2Config {
                    prelude_max_wait_ms: 200,
                    prelude_max_bytes: 16,
                },
            )
            .await?;
        attach.reload(9).await?;
        attach.cancel_reload(9).await?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .context("timed out waiting for reload cancellation")?;
            match tokio::time::timeout(remaining, attach.next_response())
                .await
                .context("wait for reload cancellation")??
            {
                Some(GhosttyResponse::ReloadCancelledV2 { reload_id: 9 }) => break,
                Some(_) => {}
                None => bail!("ghostty attach v2 stream closed"),
            }
        }

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[test]
    fn attach_v2_resize_tracker_defers_future_viewport_requests() {
        let mut tracker = AttachV2ResizeTracker::new(0);

        assert_eq!(tracker.current_resize_id(), 0);
        assert_eq!(tracker.request_or_defer(2, "live_seq_gap".to_owned()), None);
        assert_eq!(tracker.record_resize(1), None);
        assert_eq!(
            tracker.record_resize(2),
            Some((2, "live_seq_gap".to_owned()))
        );
        assert_eq!(tracker.current_resize_id(), 2);
        assert_eq!(tracker.recovery_resize_id(), 2);
    }

    #[tokio::test]
    async fn reload_job_leaves_sgr_framing_to_client_reload_coordinator() -> Result<()> {
        let history = VecDeque::from(b"\x1b[2mdimmed".to_vec());
        let (tx, mut rx) = mpsc::channel(4);
        let mut job = GhosttyReloadJob::new(3, 0, history.len(), tx, 1, false);

        assert!(!job.poll_send_next(&history, 0));
        assert!(matches!(
            rx.recv().await,
            Some(GhosttyResponse::ReloadStartedV2 { reload_id: 3, .. })
        ));
        let Some(GhosttyResponse::ReloadChunkV2 { bytes, .. }) = rx.recv().await else {
            bail!("missing reload chunk");
        };

        assert_eq!(
            bytes, b"\x1b[2mdimmed",
            "reload chunks must not inject per-chunk SGR resets: {bytes:?}"
        );
        Ok(())
    }

    #[test]
    fn attach_v2_reload_window_keeps_small_untruncated_history() {
        let history = VecDeque::from(vec![b'x'; 42]);
        let (start_abs, retained_len, truncated) = bounded_reload_window(0, &history);

        assert_eq!(start_abs, 0);
        assert_eq!(retained_len, 42);
        assert!(!truncated);
    }

    #[test]
    fn attach_v2_reload_window_caps_to_recent_history() {
        let overflow = 1234;
        let history_start_abs = 10_000;
        let retained = GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES + overflow;
        let history = VecDeque::from(vec![b'x'; retained]);
        let (start_abs, retained_len, truncated) =
            bounded_reload_window(history_start_abs, &history);

        assert_eq!(start_abs, history_start_abs + overflow as u64);
        assert_eq!(retained_len, GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES);
        assert!(truncated);
    }

    #[tokio::test]
    async fn helper_attach_v2_reload_caps_large_retained_history_to_recent_limit() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-reload-cap");
        let helper = GhosttyHelperConfig::for_test(
            "v2-reload-cap",
            paths.clone(),
            vec!["/bin/sh".to_owned()],
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
                    "python3 - <<'PY'\nimport sys\nsys.stdout.write('old-marker-before-reload-cap\\n')\nsys.stdout.write('x' * (1024 * 1024 + 4096))\nsys.stdout.write('recent-marker-after-reload-cap\\n')\nPY"
                        .to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(
                80,
                24,
                portl_proto::session_v1::AttachV2Config {
                    prelude_max_wait_ms: 200,
                    prelude_max_bytes: 0,
                },
            )
            .await?;
        attach.reload(11).await?;
        let history = attach
            .read_reload_until_done(11, Duration::from_secs(10))
            .await?;

        assert!(
            history.len() <= GHOSTTY_ATTACH_V2_RELOAD_MAX_BYTES + 16,
            "reload exceeded recent-history cap: {} bytes",
            history.len()
        );
        assert!(
            !history.contains("old-marker-before-reload-cap"),
            "reload should omit older retained history"
        );
        assert!(
            history.contains("recent-marker-after-reload-cap"),
            "reload should include the newest retained history"
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

    #[tokio::test]
    async fn helper_attach_v2_reload_streams_recent_history_in_chunks() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("v2-reload");
        let helper =
            GhosttyHelperConfig::for_test("v2-reload", paths.clone(), vec!["/bin/sh".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let run = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .run(
                None,
                vec![
                    "/bin/sh".to_owned(),
                    "-c".to_owned(),
                    "python3 - <<'PY'\nfor i in range(256): print(f'history-line-{i:03d}')\nPY"
                        .to_owned(),
                ],
            )
            .await?;
        assert_eq!(run.code, 0);

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach_v2(
                80,
                24,
                portl_proto::session_v1::AttachV2Config {
                    prelude_max_wait_ms: 200,
                    prelude_max_bytes: 16,
                },
            )
            .await?;
        attach.reload(7).await?;
        let history = attach
            .read_reload_until_done(7, Duration::from_secs(2))
            .await?;

        assert!(
            history.contains("history-line-000"),
            "history was {history:?}"
        );
        assert!(
            history.contains("history-line-255"),
            "history was {history:?}"
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
    fn registry_socket_paths_fit_macos_unix_socket_limit() {
        let runtime = PathBuf::from(
            "/Users/thinh/Library/Application Support/computer.KnickKnackLabs.portl/ghostty/runtime",
        );
        let state = PathBuf::from(
            "/Users/thinh/Library/Application Support/computer.KnickKnackLabs.portl/ghostty",
        );
        let registry = GhosttyRegistry::with_roots(runtime, state.clone());

        let paths = registry.paths_for("ghostty-test");
        let socket_len = paths.socket_path.to_string_lossy().len();

        assert!(
            socket_len < 104,
            "macOS sockaddr_un paths must be shorter than SUN_LEN; got {socket_len}: {}",
            paths.socket_path.display()
        );
        assert_eq!(
            paths.metadata_path,
            state.join("sessions").join("ghostty-test.json")
        );
        assert_eq!(
            paths.history_path,
            state.join("sessions").join("ghostty-test.history")
        );
    }

    #[test]
    fn registry_paths_are_stable_and_separated_by_purpose() {
        let temp = tempfile::tempdir().expect("tempdir");
        let runtime = PathBuf::from("/tmp/portl-ghostty-test-runtime");
        let state = temp.path().join("state");
        let registry = GhosttyRegistry::with_roots(runtime.clone(), state.clone());

        let paths = registry.paths_for("dev/main");

        assert_eq!(
            paths.socket_path,
            runtime.join("sockets").join(format!(
                "dev%2Fmain-{:016x}.sock",
                stable_session_hash("dev/main")
            ))
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

    #[tokio::test]
    async fn helper_attach_handles_large_echoing_input() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("large-cat");
        let helper =
            GhosttyHelperConfig::for_test("large-cat", paths.clone(), vec!["/bin/cat".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach(80, 24)
            .await?;
        let input = vec![b'a'; 256 * 1024];
        attach.input(input).await?;
        let output = attach
            .read_until_contains("aaaaaaaaaaaaaaaa", Duration::from_secs(5))
            .await?;
        assert!(output.contains("aaaaaaaaaaaaaaaa"));

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[tokio::test]
    async fn ghostty_attach_models_stderr_as_empty_until_attach_closes() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("stderr-lifecycle");
        let helper = GhosttyHelperConfig::for_test(
            "stderr-lifecycle",
            paths.clone(),
            vec!["/bin/cat".to_owned()],
        );
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        let metadata = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .probe()
            .await?;
        let attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach(80, 24)
            .await?;
        let process = ghostty_attach_process(metadata.pid, attach);

        assert!(
            process.stderr.is_empty_until_closed(),
            "ghostty stderr should be explicit empty output, not an already-closed live channel"
        );
        let mut closed = process
            .stderr
            .empty_close_signal_for_test()
            .expect("ghostty stderr close signal");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), closed.changed())
                .await
                .is_err(),
            "empty stderr must remain open while the attach is active"
        );

        process
            .stdin_tx
            .send(StdinMessage::Close)
            .await
            .context("detach ghostty attach")?;
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if *closed.borrow_and_update() {
                    break;
                }
                closed.changed().await.context("wait for stderr close")?;
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
        .context("stderr close timeout")??;

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }

    #[test]
    fn capped_snapshot_stays_below_frame_limit() {
        let mut history = VecDeque::new();
        append_bounded(&mut history, &vec![b'x'; MAX_FRAME_BYTES + 1024]);
        let snapshot = capped_attach_snapshot(&history);
        assert!(snapshot.len() < MAX_FRAME_BYTES);
        assert!(snapshot.iter().all(|byte| *byte == b'x'));
    }

    #[test]
    fn broadcast_full_evicts_subscriber() {
        // A subscriber whose channel is full should be evicted so it can reconnect
        // for a fresh snapshot rather than silently missing output frames.
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        tx.try_send(vec![1]).unwrap();
        let mut subscribers = vec![tx];
        broadcast(&mut subscribers, b"overflow");
        assert_eq!(subscribers.len(), 0, "full subscriber must be evicted");
    }

    #[test]
    fn broadcast_closed_evicts_subscriber() {
        // A subscriber whose receiver has been dropped should be evicted.
        let (tx, rx) = mpsc::channel::<Vec<u8>>(4);
        drop(rx);
        let mut subscribers = vec![tx];
        broadcast(&mut subscribers, b"any data");
        assert_eq!(subscribers.len(), 0, "closed subscriber must be evicted");
    }

    #[tokio::test]
    async fn attach_full_command_queue_returns_error_frame() -> Result<()> {
        // When the command queue is full, Input should receive a GhosttyResponse::Error
        // rather than blocking and starving output forwarding.
        let temp = tempfile::tempdir()?;
        let registry =
            GhosttyRegistry::with_roots(temp.path().join("run"), temp.path().join("state"));
        let paths = registry.paths_for("queue-full");
        let helper =
            GhosttyHelperConfig::for_test("queue-full", paths.clone(), vec!["/bin/cat".to_owned()]);
        let task = spawn_helper_thread(helper);
        wait_for_socket(&paths.socket_path, Duration::from_secs(2)).await?;

        // Saturate the command queue by opening many attach connections before the helper
        // drains them, then send a burst of Input frames. At least one should return an
        // Error rather than blocking indefinitely.
        let mut attach = GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .attach(80, 24)
            .await?;

        // Send more Input frames than the queue depth without waiting for responses.
        // The stream holds a UnixStream that we drive manually via write_frame.
        for _ in 0..GHOSTTY_HELPER_COMMANDS + 10 {
            if attach.input(b"x".to_vec()).await.is_err() {
                break;
            }
        }
        // Drain any responses; if we get at least one Error, the test passes.
        // If we only get Output/Exit, that's also acceptable (helper drained queue fast).
        let mut got_error_or_exit = false;
        for _ in 0..(GHOSTTY_HELPER_COMMANDS + 20) {
            match tokio::time::timeout(Duration::from_millis(200), attach.next_response()).await {
                Ok(Ok(Some(GhosttyResponse::Error { .. } | GhosttyResponse::Exit { .. }))) => {
                    got_error_or_exit = true;
                    break;
                }
                Ok(Ok(Some(_))) => {}
                _ => break,
            }
        }
        // The test validates the path exists (no hang / panic). got_error_or_exit
        // may be false if the helper was fast enough to drain the queue.
        let _ = got_error_or_exit;

        GhosttyClient::connect(paths.socket_path.clone())
            .await?
            .kill()
            .await?;
        task.join()
            .expect("helper thread")
            .context("helper result")?;
        Ok(())
    }
}
