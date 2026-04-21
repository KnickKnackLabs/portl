use std::collections::BTreeMap;
use std::process::{Command as StdCommand, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
#[cfg(unix)]
use nix::sys::signal::{Signal, kill, killpg};
#[cfg(unix)]
use nix::unistd::{Gid, Pid, Uid, User, geteuid};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt, unix::AsyncFd};
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::{shell_caps, shell_permits};
use crate::session::Session;
use crate::shell_registry::{PtyCommand, ShellProcess, ShellRegistry, StdinMessage};
use crate::stream_io::BufferedRecv;

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_SIGNAL_BYTES: usize = 1024;
const MAX_RESIZE_BYTES: usize = 1024;
const IO_CHUNK: usize = 16 * 1024;
const SESSION_REAPER_GRACE: Duration = Duration::from_secs(5);
const PTY_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let first = recv
        .read_frame::<portl_proto::shell_v1::ShellFirstFrame>(MAX_CONTROL_BYTES)
        .await?
        .context("missing shell first frame")?;

    match first {
        portl_proto::shell_v1::ShellFirstFrame::Control(req_body) => {
            let req = portl_proto::shell_v1::ShellReq {
                preamble: preamble.clone(),
                mode: req_body.mode,
                argv: req_body.argv,
                env_patch: req_body.env_patch,
                cwd: req_body.cwd,
                pty: req_body.pty,
                user: req_body.user,
            };
            serve_control_stream(connection, session, state, send, recv, req).await
        }
        portl_proto::shell_v1::ShellFirstFrame::Sub(tail) => {
            serve_substream(connection, session, state, send, recv, preamble, tail).await
        }
    }
}

struct ShellSessionGuard<'a> {
    registry: &'a ShellRegistry,
    revocations: &'a std::sync::RwLock<crate::revocations::RevocationSet>,
    session_id: [u8; 16],
    ticket_chain_ids: Vec<[u8; 16]>,
}

impl Drop for ShellSessionGuard<'_> {
    fn drop(&mut self) {
        if let Ok(mut revocations) = self.revocations.write() {
            revocations.deregister_live_session(self.session_id, &self.ticket_chain_ids);
        }
        if let Some((_, process)) = self.registry.remove(&self.session_id) {
            begin_session_shutdown(process.as_ref(), false).spawn();
        }
    }
}

#[cfg(unix)]
#[derive(Debug)]
pub(crate) struct SessionReaper {
    pgid: Option<Pid>,
    exit_rx: watch::Receiver<Option<i32>>,
    grace: Duration,
}

#[cfg(unix)]
impl SessionReaper {
    pub(crate) fn from_process(process: &ShellProcess) -> Self {
        Self {
            pgid: process
                .signal_target
                .and_then(i32::checked_abs)
                .map(Pid::from_raw),
            exit_rx: process.exit_rx(),
            grace: SESSION_REAPER_GRACE,
        }
    }

    #[cfg(test)]
    fn new_for_test(pgid: Pid, exit_rx: watch::Receiver<Option<i32>>, grace: Duration) -> Self {
        Self {
            pgid: Some(pgid),
            exit_rx,
            grace,
        }
    }

    pub(crate) fn spawn(self) {
        tokio::spawn(async move {
            let _ = self.reap().await;
        });
    }

    pub(crate) async fn reap(mut self) -> bool {
        let Some(pgid) = self.pgid else {
            return true;
        };
        if self.is_reaped() {
            return true;
        }

        for signal in [Signal::SIGHUP, Signal::SIGTERM] {
            match killpg(pgid, signal) {
                Ok(()) => {}
                Err(nix::errno::Errno::ESRCH) => return true,
                Err(err) => {
                    warn!(
                        ?err,
                        pgid = pgid.as_raw(),
                        ?signal,
                        "session reaper failed to signal process group"
                    );
                    return false;
                }
            }
            if self.wait_for_reap().await {
                return true;
            }
        }

        match killpg(pgid, Signal::SIGKILL) {
            Ok(()) => {}
            Err(nix::errno::Errno::ESRCH) => return true,
            Err(err) => {
                warn!(?err, pgid = pgid.as_raw(), signal = ?Signal::SIGKILL, "session reaper failed to signal process group");
                return false;
            }
        }

        if std::env::var_os("PORTL_TEST_REAPER_SKIP_OBSERVATION").is_some() {
            return false;
        }

        self.wait_for_reap_with_timeout(Duration::from_millis(100))
            .await
    }

    fn is_reaped(&self) -> bool {
        self.exit_rx.borrow().is_some()
    }

    async fn wait_for_reap(&mut self) -> bool {
        self.wait_for_reap_with_timeout(self.grace).await
    }

    async fn wait_for_reap_with_timeout(&mut self, timeout: Duration) -> bool {
        if self.is_reaped() {
            return true;
        }
        tokio::select! {
            changed = self.exit_rx.changed() => changed.is_ok() && self.is_reaped(),
            () = tokio::time::sleep(timeout) => self.is_reaped(),
        }
    }
}

#[cfg(not(unix))]
#[derive(Debug)]
pub(crate) struct SessionReaper;

#[cfg(not(unix))]
impl SessionReaper {
    pub(crate) fn from_process(_process: &ShellProcess) -> Self {
        Self
    }

    pub(crate) fn spawn(self) {
        let _ = self;
    }
}

#[allow(clippy::too_many_lines)]
async fn serve_control_stream(
    _connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    req: portl_proto::shell_v1::ShellReq,
) -> Result<()> {
    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1)
    {
        bail!("invalid shell preamble")
    }

    if let Err(reason) = shell_permits(&session.caps, &req) {
        audit::shell_reject(&session, "caps_denied");
        let ack = portl_proto::shell_v1::ShellAck {
            ok: false,
            reason: Some(reason),
            pid: None,
            session_id: None,
        };
        send.write_all(&postcard::to_stdvec(&ack)?).await?;
        send.finish().context("finish rejected shell ack")?;
        return Ok(());
    }

    let requested_user = match resolve_requested_user(req.user.as_deref()) {
        Ok(user) => user,
        Err(reject) => {
            audit::shell_reject(&session, reject.kind.reason_str());
            let ack = portl_proto::shell_v1::ShellAck {
                ok: false,
                reason: Some(reject.wire),
                pid: None,
                session_id: None,
            };
            send.write_all(&postcard::to_stdvec(&ack)?).await?;
            send.finish().context("finish rejected shell ack")?;
            return Ok(());
        }
    };
    let audit_session_id = uuid::Uuid::new_v4().to_string();
    let process = match spawn_process(&session, &req, requested_user.as_ref(), &audit_session_id) {
        Ok(process) => process,
        Err(reject) => {
            audit::shell_reject(&session, reject.kind.reason_str());
            let ack = portl_proto::shell_v1::ShellAck {
                ok: false,
                reason: Some(reject.wire),
                pid: None,
                session_id: None,
            };
            send.write_all(&postcard::to_stdvec(&ack)?).await?;
            send.finish().context("finish rejected shell ack")?;
            return Ok(());
        }
    };

    let session_id = fresh_session_id();
    let cancel = CancellationToken::new();
    state
        .shell_registry
        .insert(session_id, Arc::clone(&process));
    if let Ok(mut revocations) = state.revocations.write() {
        revocations.register_live_session(session_id, &session.ticket_chain_ids, &cancel);
    } else {
        warn!(session_id = %hex::encode(session_id), "revocations lock poisoned; live shell session will not be revocation-cancellable");
    }
    let _session_guard = ShellSessionGuard {
        registry: &state.shell_registry,
        revocations: &state.revocations,
        session_id,
        ticket_chain_ids: session.ticket_chain_ids.clone(),
    };
    let mode_str: &'static str = match req.mode {
        portl_proto::shell_v1::ShellMode::Exec => "exec",
        portl_proto::shell_v1::ShellMode::Shell => "pty",
    };
    process.set_started_at(Instant::now());
    audit::shell_start(
        &session,
        &audit_session_id,
        mode_str,
        process.pid,
        req.user.as_deref(),
        req.argv.as_ref(),
    );

    // Keep the shell session registered until the control stream drops.
    // Short-lived exec commands can exit before the client finishes opening
    // the exit/stdout/stderr substreams; removing the registry immediately on
    // process exit races those attachments and can produce missing exit frames.

    let ack = portl_proto::shell_v1::ShellAck {
        ok: true,
        reason: None,
        pid: Some(process.pid),
        session_id: Some(session_id),
    };
    send.write_all(&postcard::to_stdvec(&ack)?).await?;

    let mut control_buffer = [0_u8; 1024];
    loop {
        tokio::select! {
            () = cancel.cancelled() => {
                let _ = send.finish();
                return Ok(());
            }
            read = recv.read(&mut control_buffer) => {
                let read = read.context("read control stream")?;
                if read == 0 {
                    let _ = send.finish();
                    return Ok(());
                }
            }
        }
    }
}

async fn serve_substream(
    _connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    send: SendStream,
    recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
    tail: portl_proto::shell_v1::ShellSubTail,
) -> Result<()> {
    if preamble.peer_token != session.peer_token
        || preamble.alpn != String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1)
    {
        bail!("invalid shell sub-stream preamble")
    }

    let process = state
        .shell_registry
        .get(&tail.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| anyhow!("shell session not found"))?;

    match tail.kind {
        portl_proto::shell_v1::ShellStreamKind::Stdin => pump_stdin(recv, process).await,
        portl_proto::shell_v1::ShellStreamKind::Stdout => {
            pump_output(send, &process.stdout_rx).await
        }
        portl_proto::shell_v1::ShellStreamKind::Stderr => {
            pump_output(send, &process.stderr_rx).await
        }
        portl_proto::shell_v1::ShellStreamKind::Signal => pump_signals(recv, &process).await,
        portl_proto::shell_v1::ShellStreamKind::Resize => pump_resizes(recv, &process).await,
        portl_proto::shell_v1::ShellStreamKind::Exit => pump_exit(send, &process).await,
    }
}

async fn pump_stdin(mut recv: BufferedRecv, process: Arc<ShellProcess>) -> Result<()> {
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        let read = recv.read(&mut buf).await.context("read shell stdin")?;
        if read == 0 {
            let _ = process.stdin_tx.send(StdinMessage::Close).await;
            return Ok(());
        }
        process
            .stdin_tx
            .send(StdinMessage::Data(buf[..read].to_vec()))
            .await
            .context("forward shell stdin")?;
    }
}

async fn pump_output(
    mut send: SendStream,
    rx: &tokio::sync::Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
) -> Result<()> {
    let mut rx = rx.lock().await.take().context("stream already attached")?;
    while let Some(chunk) = rx.recv().await {
        send.write_all(&chunk).await.context("write shell output")?;
    }
    send.finish().context("finish shell output")?;
    Ok(())
}

async fn pump_signals(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::SignalFrame>(MAX_SIGNAL_BYTES)
        .await?
    {
        send_signal(process.signal_target, frame.sig);
    }
    Ok(())
}

async fn pump_resizes(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::shell_v1::ResizeFrame>(MAX_RESIZE_BYTES)
        .await?
    {
        #[cfg(unix)]
        if let Some(pty_tx) = process.pty_tx.as_ref() {
            pty_tx
                .send(PtyCommand::Resize {
                    rows: frame.rows,
                    cols: frame.cols,
                })
                .map_err(|_| anyhow!("pty resize channel closed"))
                .context("forward pty resize")?;
        }
        #[cfg(not(unix))]
        let _ = frame;
    }
    Ok(())
}

#[cfg(unix)]
fn resize_pty(master: &impl std::os::fd::AsRawFd, rows: u16, cols: u16) -> std::io::Result<()> {
    let ws = nix::libc::winsize {
        ws_row: rows,
        ws_col: cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    // SAFETY(unsafe_code): TIOCSWINSZ on a valid pty master fd is a
    // well-defined ioctl; we borrow the fd via AsRawFd for the duration
    // of the call only.
    #[allow(unsafe_code)]
    let rc = unsafe { nix::libc::ioctl(master.as_raw_fd(), nix::libc::TIOCSWINSZ, &ws) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

async fn pump_exit(mut send: SendStream, process: &ShellProcess) -> Result<()> {
    let initial = *process
        .exit_code
        .lock()
        .map_err(|_| anyhow!("exit code mutex poisoned"))?;
    let code = if let Some(code) = initial {
        code
    } else {
        let mut rx = process.exit_rx();
        let current = *rx.borrow();
        match current {
            Some(code) => code,
            None => loop {
                rx.changed().await.context("wait for shell exit")?;
                if let Some(code) = *rx.borrow() {
                    break code;
                }
            },
        }
    };

    let frame = portl_proto::shell_v1::ExitFrame { code };
    send.write_all(&postcard::to_stdvec(&frame)?).await?;
    send.finish().context("finish shell exit stream")?;
    Ok(())
}

/// Enumerated reject reasons from spec docs/specs/150-v0.1.1-safety-net.md §3.2.
///
/// The wire-visible `ShellReason` is a free-form enum for client-facing
/// error messages; the audit reject reasons are a closed set. This
/// local enum carries the spec reason alongside every pre-spawn
/// failure so audit dispatch can match on the variant rather than
/// inferring from the request shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RejectKind {
    ArgvEmpty,
    PathProbeFailed,
    PtyAllocationFailed,
    UidLookupFailed,
    UserSwitchRefused,
}

impl RejectKind {
    pub(crate) fn reason_str(self) -> &'static str {
        match self {
            Self::ArgvEmpty => "argv_empty",
            Self::PathProbeFailed => "path_probe_failed",
            Self::PtyAllocationFailed => "pty_allocation_failed",
            Self::UidLookupFailed => "uid_lookup_failed",
            Self::UserSwitchRefused => "user_switch_refused",
        }
    }
}

/// Paired audit kind + wire reason returned from `spawn_process`
/// and `resolve_requested_user` so the control-stream handler can
/// emit both the spec-enumerated audit string and the client-visible
/// `ShellAck.reason` without re-deriving one from the other.
#[derive(Debug)]
pub(crate) struct SpawnReject {
    pub(crate) kind: RejectKind,
    pub(crate) wire: portl_proto::shell_v1::ShellReason,
}

impl SpawnReject {
    fn new(kind: RejectKind, wire: portl_proto::shell_v1::ShellReason) -> Self {
        Self { kind, wire }
    }

    fn argv_empty() -> Self {
        Self::new(
            RejectKind::ArgvEmpty,
            portl_proto::shell_v1::ShellReason::SpawnFailed("missing argv".to_owned()),
        )
    }

    fn path_probe_failed(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::PathProbeFailed,
            portl_proto::shell_v1::ShellReason::SpawnFailed(msg.into()),
        )
    }

    fn pty_allocation_failed(wire: portl_proto::shell_v1::ShellReason) -> Self {
        Self::new(RejectKind::PtyAllocationFailed, wire)
    }

    fn uid_lookup_failed(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::UidLookupFailed,
            portl_proto::shell_v1::ShellReason::BadUser(msg.into()),
        )
    }

    fn user_switch_refused(msg: impl Into<String>) -> Self {
        Self::new(
            RejectKind::UserSwitchRefused,
            portl_proto::shell_v1::ShellReason::BadUser(msg.into()),
        )
    }
}

fn spawn_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, SpawnReject> {
    match req.mode {
        portl_proto::shell_v1::ShellMode::Exec => {
            spawn_exec_process(session, req, requested_user, audit_session_id)
        }
        portl_proto::shell_v1::ShellMode::Shell => {
            spawn_pty_process(session, req, requested_user, audit_session_id)
        }
    }
}

#[allow(clippy::too_many_lines)]
fn spawn_exec_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, SpawnReject> {
    let argv = req
        .argv
        .as_ref()
        .filter(|argv| !argv.is_empty())
        .ok_or_else(SpawnReject::argv_empty)?;
    let mut command = StdCommand::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if let Some(cwd) = req.cwd.as_deref() {
        command.current_dir(cwd);
    }
    apply_env_to_command(
        &mut command,
        effective_env(session.caps.shell.as_ref(), req, requested_user),
    );
    #[cfg(unix)]
    install_exec_session_pre_exec(&mut command);
    #[cfg(unix)]
    if let Some(user) = requested_user {
        install_exec_user_switch(&mut command, user);
    }

    let mut child = TokioCommand::from(command)
        .spawn()
        .map_err(|err| SpawnReject::path_probe_failed(err.to_string()))?;
    let pid = child
        .id()
        .ok_or_else(|| SpawnReject::path_probe_failed("missing child pid"))?;

    let stdin = child
        .stdin
        .take()
        .ok_or_else(|| SpawnReject::path_probe_failed("missing child stdin"))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| SpawnReject::path_probe_failed("missing child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| SpawnReject::path_probe_failed("missing child stderr"))?;

    let (stdin_tx, stdin_rx) = mpsc::channel(32);
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (stderr_tx, stderr_rx) = mpsc::channel(32);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);

    tokio::spawn(async move {
        if let Err(err) = exec_stdin_task(stdin, stdin_rx).await {
            debug!(%err, "exec stdin task ended with error");
        }
    });
    tokio::spawn(async move {
        if let Err(err) = output_reader_task(stdout, stdout_tx).await {
            debug!(%err, "exec stdout task ended with error");
        }
    });
    tokio::spawn(async move {
        if let Err(err) = output_reader_task(stderr, stderr_tx).await {
            debug!(%err, "exec stderr task ended with error");
        }
    });

    let exit_code_wait = Arc::clone(&exit_code);
    let exit_tx_wait = exit_tx.clone();
    let ticket_id = session.ticket_id;
    let caller_endpoint_id = session.caller_endpoint_id;
    let audit_session_id = audit_session_id.to_owned();
    let started_at = Arc::new(Mutex::new(None::<Instant>));
    let started_at_wait = Arc::clone(&started_at);
    tokio::spawn(async move {
        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(1),
            Err(err) => {
                warn!(?err, "wait on exec child failed");
                1
            }
        };
        if let Ok(mut guard) = exit_code_wait.lock() {
            *guard = Some(code);
        }
        let _ = exit_tx_wait.send(Some(code));
        let duration_ms = started_at_wait
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map_or(0, |instant| {
                u64::try_from(instant.elapsed().as_millis()).unwrap_or(u64::MAX)
            });
        audit::shell_exit_raw(
            ticket_id,
            caller_endpoint_id,
            &audit_session_id,
            pid,
            code,
            duration_ms,
        );
    });

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target: Some(process_group_signal_target_from_pid(pid)?),
        pty_tx: None,
        started_at,
    }))
}

#[cfg(unix)]
#[allow(clippy::too_many_lines)]
fn spawn_pty_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, SpawnReject> {
    if let Some(user) = requested_user
        && user.switch_required
    {
        return Err(SpawnReject::user_switch_refused(
            "pty mode does not support --user in v0.1; use `portl exec --user <name>` or run the agent as the target user",
        ));
    }

    let pty = req.pty.as_ref().ok_or_else(|| {
        SpawnReject::pty_allocation_failed(portl_proto::shell_v1::ShellReason::InvalidPty)
    })?;
    let winsize = nix::libc::winsize {
        ws_row: pty.rows,
        ws_col: pty.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let shell_program = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let env = effective_env(shell_caps(&session.caps), req, requested_user);
    let argv: Vec<String> = vec!["-l".to_owned()];

    let (master, mut child) =
        spawn_pty_blocking(&shell_program, &argv, winsize, env, req.cwd.as_deref()).map_err(
            |err| {
                SpawnReject::pty_allocation_failed(portl_proto::shell_v1::ShellReason::SpawnFailed(
                    err.to_string(),
                ))
            },
        )?;

    let pid = child.id().ok_or_else(|| {
        SpawnReject::pty_allocation_failed(portl_proto::shell_v1::ShellReason::SpawnFailed(
            "missing child pid".to_owned(),
        ))
    })?;

    let (stdin_tx, stdin_rx) = mpsc::channel(32);
    let (pty_tx, pty_rx) = mpsc::unbounded_channel();
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (_stderr_tx, stderr_rx) = mpsc::channel(1);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);

    tokio::spawn(async move {
        if let Err(err) =
            pty_master_task(master, stdout_tx, stdin_rx, pty_rx, PTY_DRAIN_TIMEOUT).await
        {
            debug!(%err, "pty master task ended with error");
        }
    });

    let exit_code_wait = Arc::clone(&exit_code);
    let exit_tx_wait = exit_tx.clone();
    let ticket_id = session.ticket_id;
    let caller_endpoint_id = session.caller_endpoint_id;
    let audit_session_id = audit_session_id.to_owned();
    let started_at = Arc::new(Mutex::new(None::<Instant>));
    let started_at_wait = Arc::clone(&started_at);
    tokio::spawn(async move {
        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(1),
            Err(err) => {
                warn!(?err, "wait on pty child failed");
                1
            }
        };
        if let Ok(mut guard) = exit_code_wait.lock() {
            *guard = Some(code);
        }
        let _ = exit_tx_wait.send(Some(code));
        let duration_ms = started_at_wait
            .lock()
            .ok()
            .and_then(|guard| *guard)
            .map_or(0, |instant| {
                u64::try_from(instant.elapsed().as_millis()).unwrap_or(u64::MAX)
            });
        audit::shell_exit_raw(
            ticket_id,
            caller_endpoint_id,
            &audit_session_id,
            pid,
            code,
            duration_ms,
        );
    });

    // The child called setsid() in pre_exec, so its pid is also the
    // session/process-group leader. Deliver signals to the whole group
    // via a negative pid.
    let signal_target = i32::try_from(pid).map(|raw| Some(-raw)).map_err(|_| {
        SpawnReject::pty_allocation_failed(portl_proto::shell_v1::ShellReason::SpawnFailed(
            "child pid out of range".to_owned(),
        ))
    })?;

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target,
        pty_tx: Some(pty_tx),
        started_at,
    }))
}

#[cfg(not(unix))]
fn spawn_pty_process(
    _session: &Session,
    _req: &portl_proto::shell_v1::ShellReq,
    _requested_user: Option<&RequestedUser>,
    _audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, SpawnReject> {
    Err(SpawnReject::pty_allocation_failed(
        portl_proto::shell_v1::ShellReason::SpawnFailed(
            "pty mode requires a unix platform".to_owned(),
        ),
    ))
}

/// Open a pty and spawn `program` as the session leader on its slave.
///
/// The returned fd is the master side of the pair. The child has stdin,
/// stdout, and stderr wired to the slave, has called `setsid()` and
/// `ioctl(TIOCSCTTY)`, and inherits the supplied environment exactly
/// (the current process's env is cleared first).
#[cfg(unix)]
fn spawn_pty_blocking(
    program: &str,
    argv: &[String],
    size: nix::libc::winsize,
    env: Vec<(String, String)>,
    cwd: Option<&str>,
) -> std::io::Result<(OwnedFd, tokio::process::Child)> {
    use std::os::fd::AsRawFd;

    let nix::pty::OpenptyResult { master, slave } =
        nix::pty::openpty(Some(&size), None).map_err(std::io::Error::from)?;
    // Set FD_CLOEXEC on the master so it is not inherited by the forked
    // child. Without this the child retains a copy of the master fd
    // which (a) breaks PTY hangup semantics because the master's
    // refcount stays > 0 after the parent closes it, and (b) leaks a
    // read/write handle to the controlling tty into the process tree.
    // The slave intentionally does NOT get CLOEXEC because it is
    // dup2'd to 0/1/2 in pre_exec and dup2 clears CLOEXEC on the
    // destination fds.
    nix::fcntl::fcntl(
        &master,
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
    )
    .map_err(std::io::Error::from)?;
    let slave_fd = slave.as_raw_fd();

    let mut command = TokioCommand::new(program);
    command.args(argv);
    command.env_clear();
    for (k, v) in env {
        command.env(k, v);
    }
    if let Some(dir) = cwd {
        command.current_dir(dir);
    }

    // SAFETY(unsafe_code): pre_exec runs in the forked child between
    // fork(2) and execve(2). The closure only invokes async-signal-safe
    // syscalls (setsid, ioctl TIOCSCTTY, dup2, close) and returns an
    // io::Result, matching the documented contract.
    //
    // SAFETY(signal): every libc call below is on POSIX.1-2017's
    // async-signal-safe (AS-safe) list: setrlimit (via
    // `apply_rlimits`), setsid, ioctl, dup2, close. The only Rust
    // stdlib call is `std::io::Error::last_os_error()`, which in
    // practice just wraps a pre-initialised errno read and does not
    // allocate on the error path (Err(io::Error::from_raw_os_error)),
    // making it AS-safe enough for the narrow post-fork window.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(move || {
            // Apply v0.1.1 resource limits before any fd wiring so a
            // broken pty setup can't escape the caps.
            apply_rlimits()?;
            // Become a new session and process-group leader so the pty
            // slave can be claimed as the controlling terminal.
            if nix::libc::setsid() == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Make the slave the controlling tty for this session.
            // The `ioctl` request argument type varies by target:
            // `c_ulong` on glibc and darwin, `c_int` on musl, which
            // means a direct `as c_ulong` breaks the musl release
            // build. `try_into().expect(...)` adapts across all
            // three because `TIOCSCTTY` (0x540E on Linux, 0x2000_7461
            // on darwin) fits comfortably in every integer type
            // `ioctl`'s second parameter might be on a supported
            // platform.
            // Clippy sees this as `useless_conversion` on glibc-linux
            // and `unnecessary_fallible_conversions` on darwin
            // because on both platforms `libc::TIOCSCTTY` and the
            // `ioctl` request parameter are `c_ulong`. On musl the
            // request parameter is `c_int`, so `.into()` won't
            // compile; `.try_into()` is the only form that works
            // everywhere. Both allows are needed because clippy
            // picks a different lint on each host.
            #[allow(clippy::useless_conversion, clippy::unnecessary_fallible_conversions)]
            let req = nix::libc::TIOCSCTTY
                .try_into()
                .expect("TIOCSCTTY fits in ioctl request type");
            if nix::libc::ioctl(slave_fd, req, 0) == -1 {
                return Err(std::io::Error::last_os_error());
            }
            // Wire stdio to the slave.
            for target in [0, 1, 2] {
                if nix::libc::dup2(slave_fd, target) == -1 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            // The inherited slave fd is no longer needed once it's
            // aliased at 0/1/2.
            if slave_fd > 2 {
                let _ = nix::libc::close(slave_fd);
            }
            Ok(())
        });
    }

    let child = command.spawn()?;
    drop(slave); // close the parent's copy of the slave
    Ok((master, child))
}

/// Test-only wrapper exposing `spawn_pty_blocking` with a minimal
/// signature and a sensible default window size.
#[cfg(unix)]
pub fn spawn_pty_for_test(
    program: &str,
    argv: &[&str],
) -> std::io::Result<(OwnedFd, tokio::process::Child)> {
    let size = nix::libc::winsize {
        ws_row: 24,
        ws_col: 80,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
    spawn_pty_blocking(program, &argv, size, Vec::new(), None)
}

/// Apply the v0.1.1 resource limits to the calling process.
///
/// Called from inside `pre_exec` closures (async-signal-safe path) on
/// both the exec and PTY spawn paths. Values:
/// - `RLIMIT_NOFILE` = 4096
/// - `RLIMIT_CORE`   = 0       (no core dumps)
/// - `RLIMIT_CPU`    = 86400 s
/// - `RLIMIT_FSIZE`  = 10 GiB
/// - `RLIMIT_NPROC`  = 512     (Linux only; Darwin `RLIMIT_NPROC`
///   is per-process and cannot contain a fork bomb at the uid level)
#[cfg(unix)]
fn apply_rlimits() -> std::io::Result<()> {
    // Use nix::sys::resource::setrlimit so nix's Resource enum handles
    // the platform-specific resource-id integer type. On Linux glibc,
    // libc::RLIMIT_* are `u32` and setrlimit takes `__rlimit_resource_t`;
    // on Darwin/BSD they're `i32` / `c_int`. A hand-rolled libc wrapper
    // using `c_int` compiles on macOS but fails on linux-musl/glibc
    // (E0308: expected i32, found u32). The `nix` shim abstracts that
    // away and is still async-signal-safe (thin wrapper over libc::
    // setrlimit, which POSIX lists as AS-safe).
    use nix::sys::resource::{Resource, setrlimit};

    fn set(resource: Resource, value: u64) -> std::io::Result<()> {
        setrlimit(resource, value, value).map_err(std::io::Error::from)
    }

    set(Resource::RLIMIT_NOFILE, 4096)?;
    set(Resource::RLIMIT_CORE, 0)?;
    set(Resource::RLIMIT_CPU, 86_400)?;
    set(Resource::RLIMIT_FSIZE, 10 * 1024 * 1024 * 1024)?;
    #[cfg(target_os = "linux")]
    set(Resource::RLIMIT_NPROC, 512)?;
    Ok(())
}

/// Install a `pre_exec` hook that applies the v0.1.1 rlimits and moves
/// the child into its own process group so teardown can signal the
/// session tree without touching the agent's process group.
#[cfg(unix)]
fn install_exec_session_pre_exec(command: &mut StdCommand) {
    use std::os::unix::process::CommandExt;
    // SAFETY(unsafe_code): pre_exec runs post-fork, pre-exec. The
    // closure calls `apply_rlimits()` and `setpgid(0, 0)`, both of
    // which are async-signal-safe syscalls, and returns an io::Result.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(|| {
            apply_rlimits()?;
            nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0)).map_err(std::io::Error::from)
        });
    }
}

/// Captured output of a single exec-path spawn. Used by the
/// `tests/rlimits.rs` integration test suite to observe
/// `apply_rlimits()` effects from outside the crate.
#[derive(Debug)]
pub struct ExecCapture {
    pub status: std::process::ExitStatus,
    pub stdout: String,
    pub stderr: String,
}

/// Test helper that runs `program argv` through the same rlimits hook
/// the production exec path uses, then collects stdout/stderr.
#[cfg(unix)]
pub async fn run_exec_capture(
    program: &str,
    argv: &[&str],
    env: Vec<(String, String)>,
) -> std::io::Result<ExecCapture> {
    let mut command = StdCommand::new(program);
    command.args(argv);
    command.stdin(Stdio::null());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    command.env_clear();
    for (k, v) in env {
        command.env(k, v);
    }
    // Inherit a minimal PATH so `/bin/sh` can resolve builtins.
    command.env("PATH", "/usr/local/bin:/usr/bin:/bin");
    install_exec_session_pre_exec(&mut command);
    let output = TokioCommand::from(command).output().await?;
    Ok(ExecCapture {
        status: output.status,
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

async fn exec_stdin_task(
    mut stdin: tokio::process::ChildStdin,
    mut rx: mpsc::Receiver<StdinMessage>,
) -> Result<()> {
    while let Some(message) = rx.recv().await {
        match message {
            StdinMessage::Data(bytes) => {
                stdin.write_all(&bytes).await.context("write exec stdin")?;
            }
            StdinMessage::Close => break,
        }
    }
    Ok(())
}

async fn output_reader_task<R>(mut reader: R, tx: mpsc::Sender<Vec<u8>>) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        let read = reader.read(&mut buf).await.context("read child output")?;
        if read == 0 {
            return Ok(());
        }
        if tx.send(buf[..read].to_vec()).await.is_err() {
            return Ok(());
        }
    }
}

#[cfg(unix)]
async fn pty_master_task(
    master: OwnedFd,
    stdout_tx: mpsc::Sender<Vec<u8>>,
    mut stdin_rx: mpsc::Receiver<StdinMessage>,
    mut pty_rx: mpsc::UnboundedReceiver<PtyCommand>,
    drain_timeout: Duration,
) -> Result<()> {
    set_nonblocking(&master)?;
    let master = AsyncFd::new(master).context("register pty master fd")?;
    let mut stdin_open = true;
    let mut drain_deadline = None;
    let mut read_buf = vec![0_u8; IO_CHUNK];

    loop {
        let drain_sleep = async {
            if let Some(deadline) = drain_deadline {
                tokio::time::sleep_until(deadline).await;
            } else {
                std::future::pending::<()>().await;
            }
        };

        tokio::select! {
            biased;
            Some(cmd) = pty_rx.recv() => {
                match cmd {
                    PtyCommand::Resize { rows, cols } => {
                        if drain_deadline.is_none() {
                            resize_pty(master.get_ref(), rows, cols).context("resize pty")?;
                        }
                    }
                    PtyCommand::Close { force } => {
                        if force {
                            return Ok(());
                        }
                        drain_deadline
                            .get_or_insert_with(|| tokio::time::Instant::now() + drain_timeout);
                    }
                }
            }
            Some(message) = stdin_rx.recv(), if stdin_open && drain_deadline.is_none() => {
                match message {
                    StdinMessage::Data(bytes) => write_pty_all(&master, &bytes).await.context("write pty stdin")?,
                    StdinMessage::Close => stdin_open = false,
                }
            }
            () = drain_sleep => {
                return Ok(());
            }
            chunk = read_pty_chunk(&master, &mut read_buf) => {
                match chunk.context("read pty output")? {
                    Some(chunk) => {
                        if stdout_tx.send(chunk).await.is_err() {
                            return Ok(());
                        }
                    }
                    None => return Ok(()),
                }
            }
            else => return Ok(()),
        }
    }
}

#[cfg(unix)]
async fn read_pty_chunk(
    master: &AsyncFd<OwnedFd>,
    buf: &mut [u8],
) -> std::io::Result<Option<Vec<u8>>> {
    loop {
        let mut guard = master.readable().await?;
        match nix::unistd::read(master.get_ref(), buf) {
            Ok(0) | Err(nix::errno::Errno::EIO) => return Ok(None),
            Ok(read) => return Ok(Some(buf[..read].to_vec())),
            Err(nix::errno::Errno::EAGAIN) => {
                guard.clear_ready();
            }
            Err(err) => return Err(std::io::Error::from(err)),
        }
    }
}

#[cfg(unix)]
async fn write_pty_all(master: &AsyncFd<OwnedFd>, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let mut guard = master.writable().await?;
        match nix::unistd::write(master.get_ref(), bytes) {
            Ok(0) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "pty write returned zero bytes",
                ));
            }
            Ok(written) => {
                bytes = &bytes[written..];
            }
            Err(nix::errno::Errno::EAGAIN) => {
                guard.clear_ready();
            }
            Err(err) => return Err(std::io::Error::from(err)),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn set_nonblocking(fd: &OwnedFd) -> std::io::Result<()> {
    let flags =
        nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_GETFL).map_err(std::io::Error::from)?;
    let flags = nix::fcntl::OFlag::from_bits_truncate(flags) | nix::fcntl::OFlag::O_NONBLOCK;
    nix::fcntl::fcntl(fd, nix::fcntl::FcntlArg::F_SETFL(flags)).map_err(std::io::Error::from)?;
    Ok(())
}

fn apply_env_to_command(command: &mut StdCommand, envs: Vec<(String, String)>) {
    command.env_clear();
    command.envs(envs);
}

fn effective_env(
    shell_caps: Option<&portl_core::ticket::schema::ShellCaps>,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> Vec<(String, String)> {
    // v0.1 uses a minimal sanitized env; v0.2 may add PAM login-env
    // synthesis for Merge policy.
    let deny_base = sanitized_env_base(requested_user, req);

    let env = match shell_caps.map(|caps| &caps.env_policy) {
        Some(portl_core::ticket::schema::EnvPolicy::Deny) | None => deny_base,
        Some(portl_core::ticket::schema::EnvPolicy::Merge { allow: Some(keys) }) => {
            let mut env = deny_base;
            merge_env_patch(&mut env, &req.env_patch, Some(keys));
            env
        }
        Some(portl_core::ticket::schema::EnvPolicy::Merge { allow: None }) => {
            let mut env = deny_base;
            merge_env_patch(&mut env, &req.env_patch, None);
            env
        }
        Some(portl_core::ticket::schema::EnvPolicy::Replace { base }) => {
            base.iter().cloned().collect::<BTreeMap<_, _>>()
        }
    };

    env.into_iter().collect()
}

fn merge_env_patch(
    env: &mut BTreeMap<String, String>,
    env_patch: &[(String, portl_proto::shell_v1::EnvValue)],
    allow: Option<&Vec<String>>,
) {
    for (key, value) in env_patch {
        if allow
            .as_ref()
            .is_some_and(|allow| !allow.iter().any(|candidate| candidate == key))
        {
            continue;
        }
        match value {
            portl_proto::shell_v1::EnvValue::Set(value) => {
                env.insert(key.clone(), value.clone());
            }
            portl_proto::shell_v1::EnvValue::Unset => {
                env.remove(key);
            }
        }
    }
}

fn sanitized_env_base(
    requested_user: Option<&RequestedUser>,
    req: &portl_proto::shell_v1::ShellReq,
) -> BTreeMap<String, String> {
    let mut env = BTreeMap::new();

    #[cfg(unix)]
    if let Some(user) = requested_user {
        env.insert("HOME".to_owned(), user.home_dir.clone());
        env.insert("USER".to_owned(), user.name.clone());
        env.insert("LOGNAME".to_owned(), user.name.clone());
        env.insert("SHELL".to_owned(), user.shell.clone());
    }

    #[cfg(not(unix))]
    {
        let _ = requested_user;
    }

    env.insert("PATH".to_owned(), "/usr/local/bin:/usr/bin:/bin".to_owned());

    if let Some(pty) = req.pty.as_ref() {
        env.insert("TERM".to_owned(), pty.term.clone());
    }

    env
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct RequestedUser {
    uid: Uid,
    gid: Gid,
    name: String,
    home_dir: String,
    shell: String,
    switch_required: bool,
}

#[cfg(not(unix))]
#[derive(Debug, Clone)]
struct RequestedUser;

fn resolve_requested_user(
    user: Option<&str>,
) -> std::result::Result<Option<RequestedUser>, SpawnReject> {
    #[cfg(unix)]
    {
        let current = geteuid();
        let current_user = User::from_uid(current)
            .map_err(|err| SpawnReject::uid_lookup_failed(err.to_string()))?
            .ok_or_else(|| {
                SpawnReject::uid_lookup_failed(format!(
                    "unknown current user: {}",
                    current.as_raw()
                ))
            })?;
        let requested = match user {
            Some(user) => User::from_name(user)
                .map_err(|err| SpawnReject::user_switch_refused(err.to_string()))?
                .ok_or_else(|| SpawnReject::user_switch_refused(format!("unknown user: {user}")))?,
            None => current_user,
        };
        if !current.is_root() && requested.uid != current {
            return Err(SpawnReject::user_switch_refused(
                "cannot drop uid as non-root",
            ));
        }
        let shell = requested.shell.to_string_lossy().into_owned();
        Ok(Some(RequestedUser {
            uid: requested.uid,
            gid: requested.gid,
            name: requested.name,
            home_dir: requested.dir.to_string_lossy().into_owned(),
            shell: if shell.is_empty() {
                "/bin/sh".to_owned()
            } else {
                shell
            },
            switch_required: current.is_root() && requested.uid != current,
        }))
    }

    #[cfg(not(unix))]
    {
        match user {
            Some(_) => Err(SpawnReject::user_switch_refused(
                "user switching is unsupported on this platform",
            )),
            None => Ok(None),
        }
    }
}

#[cfg(unix)]
fn send_signal(target: Option<i32>, sig: u8) {
    let Some(target) = target else {
        return;
    };
    if let Ok(signal) = Signal::try_from(i32::from(sig)) {
        let _ = kill(Pid::from_raw(target), signal);
    }
}

#[cfg(not(unix))]
fn send_signal(_target: Option<i32>, _sig: u8) {}

fn request_pty_close(pty_tx: Option<&mpsc::UnboundedSender<PtyCommand>>, force: bool) {
    if let Some(pty_tx) = pty_tx {
        let _ = pty_tx.send(PtyCommand::Close { force });
    }
}

pub(crate) fn begin_session_shutdown(process: &ShellProcess, force_close: bool) -> SessionReaper {
    request_pty_close(process.pty_tx.as_ref(), force_close);
    SessionReaper::from_process(process)
}

fn process_group_signal_target_from_pid(pid: u32) -> std::result::Result<i32, SpawnReject> {
    let pid =
        i32::try_from(pid).map_err(|_| SpawnReject::path_probe_failed("child pid out of range"))?;
    pid.checked_neg()
        .ok_or_else(|| SpawnReject::path_probe_failed("child pid out of range"))
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
#[allow(unsafe_code)]
fn install_exec_user_switch(command: &mut StdCommand, user: &RequestedUser) -> bool {
    use std::os::unix::process::CommandExt;
    if !user.switch_required {
        return false;
    }

    let gid_raw = user.gid.as_raw();
    let uid_raw = user.uid.as_raw();
    // SAFETY: pre_exec runs in the child process between fork(2) and
    // execve(2). The closure only calls async-signal-safe syscalls
    // (setgroups/setgid/setuid) and returns an io::Result, which is
    // the documented contract.
    unsafe {
        command.pre_exec(move || {
            // Drop supplementary groups BEFORE setgid/setuid. Order matters:
            // setgroups requires uid 0.
            nix::unistd::setgroups(&[]).map_err(nix_to_io_error)?;
            // Set the primary gid before uid.
            nix::unistd::setgid(Gid::from_raw(gid_raw)).map_err(nix_to_io_error)?;
            nix::unistd::setuid(Uid::from_raw(uid_raw)).map_err(nix_to_io_error)?;
            Ok(())
        });
    }

    true
}

#[cfg(all(
    unix,
    not(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    ))
))]
fn nix_to_io_error(err: nix::errno::Errno) -> std::io::Error {
    std::io::Error::from_raw_os_error(err as i32)
}

#[cfg(all(
    unix,
    any(
        target_os = "macos",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos",
        target_os = "visionos"
    )
))]
fn install_exec_user_switch(command: &mut StdCommand, user: &RequestedUser) -> bool {
    use std::os::unix::process::CommandExt;

    if !user.switch_required {
        return false;
    }

    command.uid(user.uid.as_raw());
    command.gid(user.gid.as_raw());
    true
}

fn fresh_session_id() -> [u8; 16] {
    loop {
        let mut id = rand::random::<[u8; 16]>();
        id[0] |= 0b1000_0000;
        if id[0] >= 2 {
            return id;
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use super::{RequestedUser, SessionReaper, install_exec_user_switch};
    use super::{ShellProcess, ShellSessionGuard};
    use crate::shell_registry::PtyCommand;
    use crate::shell_registry::ShellRegistry;
    #[cfg(unix)]
    use nix::errno::Errno;
    #[cfg(unix)]
    use nix::sys::signal::{Signal, kill};
    #[cfg(unix)]
    use nix::unistd::{Gid, Pid, Uid};
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::fd::AsRawFd;
    #[cfg(unix)]
    use std::os::unix::process::ExitStatusExt as _;
    #[cfg(unix)]
    use std::path::PathBuf;
    #[cfg(unix)]
    use std::process::Command as StdCommand;
    #[cfg(unix)]
    use std::time::Duration;
    use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

    #[tokio::test]
    async fn shell_registry_is_empty_after_control_stream_error() {
        let registry = ShellRegistry::default();
        let session_id = [9; 16];
        let (stdin_tx, _stdin_rx) = mpsc::channel(1);
        let (_stdout_tx, stdout_rx) = mpsc::channel(1);
        let (_stderr_tx, stderr_rx) = mpsc::channel(1);
        let exit_code = std::sync::Arc::new(std::sync::Mutex::new(None));
        let (exit_tx, _) = watch::channel(None);

        registry.insert(
            session_id,
            std::sync::Arc::new(ShellProcess {
                pid: 42,
                stdin_tx,
                stdout_rx: AsyncMutex::new(Some(stdout_rx)),
                stderr_rx: AsyncMutex::new(Some(stderr_rx)),
                exit_code,
                exit_tx,
                signal_target: None,
                pty_tx: None,
                started_at: std::sync::Arc::new(std::sync::Mutex::new(None)),
            }),
        );
        let revocations = std::sync::RwLock::new(
            crate::revocations::RevocationSet::load(std::env::temp_dir().join(format!(
                "portl-shell-guard-revocations-{}.jsonl",
                uuid::Uuid::new_v4()
            )))
            .expect("load revocations set"),
        );

        {
            let _guard = ShellSessionGuard {
                registry: &registry,
                revocations: &revocations,
                session_id,
                ticket_chain_ids: vec![[0x11; 16]],
            };
        }

        assert!(registry.is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn exec_user_switch_hook_only_installs_when_switch_is_required() {
        let base_user = RequestedUser {
            uid: Uid::from_raw(1000),
            gid: Gid::from_raw(1000),
            name: "demo".to_owned(),
            home_dir: "/home/demo".to_owned(),
            shell: "/bin/sh".to_owned(),
            switch_required: false,
        };

        let mut unchanged = StdCommand::new("/bin/echo");
        assert!(!install_exec_user_switch(&mut unchanged, &base_user));

        let mut switched = StdCommand::new("/bin/echo");
        let mut target_user = base_user;
        target_user.switch_required = true;
        assert!(install_exec_user_switch(&mut switched, &target_user));
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        ))
    ))]
    #[tokio::test]
    async fn session_reaper_kills_interactive_shell_on_hup() {
        let (_master, pid, exit_rx, wait_task) = spawn_pty_reaper_target(&["-i"]);

        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(status.signal(), Some(Signal::SIGHUP as i32));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reaper_escalates_to_term_on_hup_ignored() {
        let (pid, exit_rx, wait_task) = spawn_exec_reaper_target("trap '' HUP; exec sleep 1000");

        tokio::time::sleep(Duration::from_millis(50)).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(status.signal(), Some(Signal::SIGTERM as i32));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn session_reaper_escalates_to_kill_on_term_ignored() {
        let (pid, exit_rx, wait_task) =
            spawn_exec_reaper_target("trap '' HUP TERM; exec sleep 1000");

        tokio::time::sleep(Duration::from_millis(50)).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;

        let status = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");
        assert_eq!(status.signal(), Some(Signal::SIGKILL as i32));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn background_jobs_in_pgroup_are_terminated() {
        let pid_file = temp_pid_file("session-reaper-background");
        let script = format!("sleep 1000 & echo $! > {}; wait", pid_file.display());
        let (pid, exit_rx, wait_task) = spawn_exec_reaper_target(&script);

        let background_pid = wait_for_pid_file(&pid_file).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;
        let _ = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");

        tokio::time::sleep(Duration::from_millis(100)).await;
        assert_process_gone(background_pid);
        let _ = fs::remove_file(pid_file);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn double_forked_daemons_survive_teardown() {
        let pid_file = temp_pid_file("session-reaper-daemon");
        let (pid, exit_rx, wait_task) = spawn_helper_reaper_target("double-fork-daemon", &pid_file);

        let daemon_pid = wait_for_pid_file(&pid_file).await;
        SessionReaper::new_for_test(pid, exit_rx, Duration::from_millis(100))
            .reap()
            .await;
        let _ = wait_task
            .await
            .expect("wait task join")
            .expect("wait status");

        assert!(
            process_exists(daemon_pid),
            "double-forked daemon should survive session teardown"
        );
        let _ = kill(Pid::from_raw(daemon_pid), Signal::SIGKILL);
        let _ = fs::remove_file(pid_file);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pty_drain_completes_on_normal_exit() {
        let mut harness = spawn_pty_task_harness(
            &["-c", "printf 'pty-drain-ok'; exit 0"],
            Duration::from_millis(200),
        );

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        let output = collect_output(&mut harness.stdout_rx).await;
        assert!(output.contains("pty-drain-ok"), "output was: {output:?}");
        harness
            .task
            .await
            .expect("pty task join")
            .expect("pty task result");
        let status = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");
        assert!(status.success(), "child status was {status:?}");
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn pty_drain_force_closes_at_30s() {
        let harness = spawn_pty_task_harness(
            &["-c", "printf 'held-open'; while :; do sleep 1; done"],
            Duration::from_millis(100),
        );

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        tokio::time::timeout(Duration::from_secs(1), harness.task)
            .await
            .expect("pty task timeout")
            .expect("pty task join")
            .expect("pty task result");

        let _ = kill(Pid::from_raw(harness.child_pid), Signal::SIGKILL);
        let _ = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[tokio::test]
    async fn pty_master_fd_closed_after_session_end() {
        let mut harness = spawn_pty_task_harness(
            &["-c", "printf 'fd-close'; exit 0"],
            Duration::from_millis(200),
        );
        let fd = harness.master_fd;

        harness
            .pty_tx
            .send(PtyCommand::Close { force: false })
            .expect("queue pty close");

        let _ = collect_output(&mut harness.stdout_rx).await;
        harness
            .task
            .await
            .expect("pty task join")
            .expect("pty task result");
        let _ = harness
            .child_wait
            .await
            .expect("child wait join")
            .expect("child wait status");

        assert!(!fd_path_exists(fd), "pty master fd {fd} should be closed");
    }

    #[cfg(unix)]
    #[test]
    fn session_reaper_helper_entrypoint() {
        let Ok(mode) = std::env::var("PORTL_SESSION_REAPER_HELPER") else {
            return;
        };
        let pid_file =
            PathBuf::from(std::env::var("PORTL_SESSION_REAPER_PID_FILE").expect("pid file"));
        match mode.as_str() {
            "double-fork-daemon" => run_double_fork_daemon_helper(&pid_file),
            other => panic!("unknown session reaper helper mode {other}"),
        }
    }

    #[cfg(unix)]
    fn spawn_exec_reaper_target(
        script: &str,
    ) -> (
        Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let mut command = tokio::process::Command::new("/bin/sh");
        command.arg("-c").arg(script);
        spawn_reaper_target(command)
    }

    #[cfg(all(
        unix,
        not(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "tvos",
            target_os = "watchos",
            target_os = "visionos"
        ))
    ))]
    fn spawn_pty_reaper_target(
        argv: &[&str],
    ) -> (
        std::os::fd::OwnedFd,
        Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let (master, mut child) =
            super::spawn_pty_for_test("/bin/sh", argv).expect("spawn pty reaper target");
        let pid =
            Pid::from_raw(i32::try_from(child.id().expect("child pid")).expect("pid fits in i32"));
        let (exit_tx, exit_rx) = watch::channel(None);
        let wait_task = tokio::spawn(async move {
            let status = child.wait().await?;
            let _ = exit_tx.send(Some(exit_marker(status)));
            Ok(status)
        });
        (master, pid, exit_rx, wait_task)
    }

    #[cfg(unix)]
    fn spawn_helper_reaper_target(
        mode: &str,
        pid_file: &PathBuf,
    ) -> (
        Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        let helper_name = "shell_handler::tests::session_reaper_helper_entrypoint";
        let mut command =
            tokio::process::Command::new(std::env::current_exe().expect("current exe"));
        command
            .env("PORTL_SESSION_REAPER_HELPER", mode)
            .env("PORTL_SESSION_REAPER_PID_FILE", pid_file)
            .arg("--exact")
            .arg(helper_name)
            .arg("--nocapture")
            .arg("--test-threads=1");
        spawn_reaper_target(command)
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn spawn_reaper_target(
        mut command: tokio::process::Command,
    ) -> (
        Pid,
        watch::Receiver<Option<i32>>,
        tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    ) {
        // SAFETY: post-fork hook only calls setpgid, which is async-signal-safe.
        unsafe {
            command.pre_exec(|| {
                nix::unistd::setpgid(Pid::from_raw(0), Pid::from_raw(0))
                    .map_err(std::io::Error::from)
            });
        }
        let mut child = command.spawn().expect("spawn reaper target");
        let pid =
            Pid::from_raw(i32::try_from(child.id().expect("child pid")).expect("pid fits in i32"));
        let (exit_tx, exit_rx) = watch::channel(None);
        let wait_task = tokio::spawn(async move {
            let status = child.wait().await?;
            let _ = exit_tx.send(Some(exit_marker(status)));
            Ok(status)
        });
        (pid, exit_rx, wait_task)
    }

    #[cfg(unix)]
    struct PtyTaskHarness {
        child_pid: i32,
        master_fd: i32,
        pty_tx: mpsc::UnboundedSender<PtyCommand>,
        stdout_rx: mpsc::Receiver<Vec<u8>>,
        task: tokio::task::JoinHandle<anyhow::Result<()>>,
        child_wait: tokio::task::JoinHandle<std::io::Result<std::process::ExitStatus>>,
    }

    #[cfg(unix)]
    fn spawn_pty_task_harness(argv: &[&str], drain_timeout: Duration) -> PtyTaskHarness {
        let (master, mut child) =
            super::spawn_pty_for_test("/bin/sh", argv).expect("spawn pty task harness");
        let master_fd = master.as_raw_fd();
        let child_pid = i32::try_from(child.id().expect("child pid")).expect("pid fits in i32");
        let (stdin_tx, stdin_rx) = mpsc::channel(32);
        let (pty_tx, pty_rx) = mpsc::unbounded_channel();
        let (stdout_tx, stdout_rx) = mpsc::channel(32);
        let task = tokio::spawn(super::pty_master_task(
            master,
            stdout_tx,
            stdin_rx,
            pty_rx,
            drain_timeout,
        ));
        let child_wait = tokio::spawn(async move { child.wait().await });
        let _ = stdin_tx;
        PtyTaskHarness {
            child_pid,
            master_fd,
            pty_tx,
            stdout_rx,
            task,
            child_wait,
        }
    }

    #[cfg(unix)]
    async fn collect_output(stdout_rx: &mut mpsc::Receiver<Vec<u8>>) -> String {
        let mut output = Vec::new();
        while let Some(chunk) = stdout_rx.recv().await {
            output.extend_from_slice(&chunk);
        }
        String::from_utf8_lossy(&output).into_owned()
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    fn fd_path_exists(fd: i32) -> bool {
        #[cfg(target_os = "linux")]
        let fd_dir = "/proc/self/fd";
        #[cfg(target_os = "macos")]
        let fd_dir = "/dev/fd";

        std::path::Path::new(fd_dir).join(fd.to_string()).exists()
    }

    #[cfg(unix)]
    #[allow(unsafe_code)]
    fn run_double_fork_daemon_helper(pid_file: &PathBuf) {
        use nix::sys::wait::{WaitPidFlag, waitpid};
        use nix::unistd::{ForkResult, fork, setsid};
        use std::thread;

        // SAFETY: test-only helper process; each fork path either exits quickly
        // or enters a simple sleep loop, and no shared Rust state is touched
        // after the fork beyond process exit.
        match unsafe { fork() }.expect("first fork") {
            ForkResult::Parent { child } => {
                let _ = waitpid(child, Some(WaitPidFlag::empty()));
                loop {
                    thread::sleep(Duration::from_secs(60));
                }
            }
            ForkResult::Child => {
                setsid().expect("setsid");
                match unsafe { fork() }.expect("second fork") {
                    ForkResult::Parent { .. } => std::process::exit(0),
                    ForkResult::Child => {
                        fs::write(pid_file, std::process::id().to_string())
                            .expect("write daemon pid file");
                        loop {
                            thread::sleep(Duration::from_secs(60));
                        }
                    }
                }
            }
        }
    }

    #[cfg(unix)]
    fn temp_pid_file(label: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "{label}-{}-{}.pid",
            std::process::id(),
            uuid::Uuid::new_v4()
        ))
    }

    #[cfg(unix)]
    async fn wait_for_pid_file(path: &PathBuf) -> i32 {
        for _ in 0..100 {
            if let Ok(raw) = fs::read_to_string(path)
                && let Ok(pid) = raw.trim().parse::<i32>()
            {
                return pid;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("timed out waiting for pid file {}", path.display());
    }

    #[cfg(unix)]
    fn process_exists(pid: i32) -> bool {
        match kill(Pid::from_raw(pid), None) {
            Ok(()) | Err(Errno::EPERM) => true,
            Err(Errno::ESRCH) => false,
            Err(err) => panic!("unexpected kill(0) error for pid {pid}: {err}"),
        }
    }

    #[cfg(unix)]
    fn assert_process_gone(pid: i32) {
        assert!(!process_exists(pid), "pid {pid} should not be alive");
    }

    #[cfg(unix)]
    fn exit_marker(status: std::process::ExitStatus) -> i32 {
        status
            .code()
            .unwrap_or_else(|| status.signal().unwrap_or(1))
    }
}
