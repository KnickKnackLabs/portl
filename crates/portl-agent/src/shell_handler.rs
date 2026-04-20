use std::collections::BTreeMap;
use std::process::{Command as StdCommand, Stdio};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::{Gid, Pid, Uid, User, geteuid};
#[cfg(unix)]
use std::os::fd::OwnedFd;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::{shell_caps, shell_permits};
use crate::session::Session;
use crate::shell_registry::{ShellProcess, ShellRegistry, StdinMessage};
use crate::stream_io::BufferedRecv;

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_SIGNAL_BYTES: usize = 1024;
const MAX_RESIZE_BYTES: usize = 1024;
const IO_CHUNK: usize = 16 * 1024;

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
    session_id: [u8; 16],
}

impl Drop for ShellSessionGuard<'_> {
    fn drop(&mut self) {
        if let Some((_, process)) = self.registry.remove(&self.session_id) {
            terminate_process(process.signal_target);
        }
    }
}

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
        Err(reason) => {
            audit::shell_reject(&session, classify_user_reject(req.user.as_deref()));
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
    };
    let audit_session_id = uuid::Uuid::new_v4().to_string();
    let process = match spawn_process(&session, &req, requested_user.as_ref(), &audit_session_id) {
        Ok(process) => process,
        Err(reason) => {
            audit::shell_reject(&session, classify_spawn_reject(&req, &reason));
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
    };

    let session_id = fresh_session_id();
    state
        .shell_registry
        .insert(session_id, Arc::clone(&process));
    let _session_guard = ShellSessionGuard {
        registry: &state.shell_registry,
        session_id,
    };
    audit::shell_start(
        &session,
        &audit_session_id,
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
        let read = recv
            .read(&mut control_buffer)
            .await
            .context("read control stream")?;
        if read == 0 {
            let _ = send.finish();
            return Ok(());
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
        if let Some(master) = process.pty_master.as_ref() {
            resize_pty(master, frame.rows, frame.cols).context("resize pty")?;
        }
        #[cfg(not(unix))]
        let _ = frame;
    }
    Ok(())
}

#[cfg(unix)]
fn resize_pty(master: &OwnedFd, rows: u16, cols: u16) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
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

fn spawn_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
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
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    let argv = req
        .argv
        .as_ref()
        .filter(|argv| !argv.is_empty())
        .ok_or_else(|| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("missing argv".to_owned())
        })?;
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
    install_exec_rlimits_pre_exec(&mut command);
    #[cfg(unix)]
    if let Some(user) = requested_user {
        install_exec_user_switch(&mut command, user);
    }

    let mut child = TokioCommand::from(command)
        .spawn()
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;
    let pid = child.id().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child pid".to_owned())
    })?;

    let stdin = child.stdin.take().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child stdin".to_owned())
    })?;
    let stdout = child.stdout.take().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child stdout".to_owned())
    })?;
    let stderr = child.stderr.take().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child stderr".to_owned())
    })?;

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
        audit::shell_exit_raw(ticket_id, caller_endpoint_id, &audit_session_id, pid, code);
    });

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target: Some(signal_target_from_pid(pid)?),
        pty_master: None,
    }))
}

#[cfg(unix)]
fn spawn_pty_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    if let Some(user) = requested_user
        && user.switch_required
    {
        return Err(portl_proto::shell_v1::ShellReason::BadUser(
            "pty mode does not support --user in v0.1; use `portl exec --user <name>` or run the agent as the target user"
                .to_owned(),
        ));
    }

    let pty = req
        .pty
        .as_ref()
        .ok_or(portl_proto::shell_v1::ShellReason::InvalidPty)?;
    let winsize = nix::libc::winsize {
        ws_row: pty.rows,
        ws_col: pty.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };

    let shell_program = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let env = effective_env(shell_caps(&session.caps), req, requested_user);
    let argv: Vec<String> = vec!["-l".to_owned()];

    let (master, mut child) = spawn_pty_blocking(
        &shell_program,
        &argv,
        winsize,
        env,
        req.cwd.as_deref(),
    )
    .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;

    let pid = child.id().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child pid".to_owned())
    })?;

    let reader_fd = master
        .try_clone()
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;
    let writer_fd = master
        .try_clone()
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;
    let master = Arc::new(master);

    let (stdin_tx, stdin_rx) = mpsc::channel(32);
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (_stderr_tx, stderr_rx) = mpsc::channel(1);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);

    std::thread::spawn(move || pty_stdin_thread(Box::new(std::fs::File::from(writer_fd)), stdin_rx));
    std::thread::spawn(move || pty_stdout_thread(Box::new(std::fs::File::from(reader_fd)), &stdout_tx));

    let exit_code_wait = Arc::clone(&exit_code);
    let exit_tx_wait = exit_tx.clone();
    let ticket_id = session.ticket_id;
    let caller_endpoint_id = session.caller_endpoint_id;
    let audit_session_id = audit_session_id.to_owned();
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
        audit::shell_exit_raw(ticket_id, caller_endpoint_id, &audit_session_id, pid, code);
    });

    // The child called setsid() in pre_exec, so its pid is also the
    // session/process-group leader. Deliver signals to the whole group
    // via a negative pid.
    let signal_target = i32::try_from(pid)
        .map(|raw| Some(-raw))
        .map_err(|_| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("child pid out of range".to_owned())
        })?;

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target,
        pty_master: Some(master),
    }))
}

#[cfg(not(unix))]
fn spawn_pty_process(
    _session: &Session,
    _req: &portl_proto::shell_v1::ShellReq,
    _requested_user: Option<&RequestedUser>,
    _audit_session_id: &str,
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    Err(portl_proto::shell_v1::ShellReason::SpawnFailed(
        "pty mode requires a unix platform".to_owned(),
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
            #[allow(clippy::cast_lossless)]
            let req = nix::libc::TIOCSCTTY as nix::libc::c_ulong;
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
    fn set(resource: nix::libc::c_int, value: u64) -> std::io::Result<()> {
        let rl = nix::libc::rlimit {
            rlim_cur: value as nix::libc::rlim_t,
            rlim_max: value as nix::libc::rlim_t,
        };
        // SAFETY(unsafe_code): setrlimit with a valid &rlimit is a
        // standard libc call; it cannot escape memory or aliasing rules.
        #[allow(unsafe_code)]
        let rc = unsafe { nix::libc::setrlimit(resource, &raw const rl) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }

    set(nix::libc::RLIMIT_NOFILE, 4096)?;
    set(nix::libc::RLIMIT_CORE, 0)?;
    set(nix::libc::RLIMIT_CPU, 86_400)?;
    set(nix::libc::RLIMIT_FSIZE, 10 * 1024 * 1024 * 1024)?;
    #[cfg(target_os = "linux")]
    set(nix::libc::RLIMIT_NPROC, 512)?;
    Ok(())
}

/// Install a `pre_exec` hook that applies the v0.1.1 rlimits. This
/// is the first closure registered on the exec path so it runs
/// before the optional user-switch hook.
#[cfg(unix)]
fn install_exec_rlimits_pre_exec(command: &mut StdCommand) {
    use std::os::unix::process::CommandExt;
    // SAFETY(unsafe_code): pre_exec runs post-fork, pre-exec. The
    // closure calls `apply_rlimits()` which only invokes
    // async-signal-safe syscalls (setrlimit) and returns an io::Result.
    #[allow(unsafe_code)]
    unsafe {
        command.pre_exec(apply_rlimits);
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
    install_exec_rlimits_pre_exec(&mut command);
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

fn pty_stdin_thread(
    mut writer: Box<dyn std::io::Write + Send>,
    mut rx: mpsc::Receiver<StdinMessage>,
) {
    while let Some(message) = rx.blocking_recv() {
        match message {
            StdinMessage::Data(bytes) => {
                if writer.write_all(&bytes).is_err() {
                    return;
                }
                let _ = writer.flush();
            }
            StdinMessage::Close => return,
        }
    }
}

fn pty_stdout_thread(mut reader: Box<dyn std::io::Read + Send>, tx: &mpsc::Sender<Vec<u8>>) {
    let mut buf = vec![0_u8; IO_CHUNK];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => return,
            Ok(read) => {
                if tx.blocking_send(buf[..read].to_vec()).is_err() {
                    return;
                }
            }
            Err(err) => {
                warn!(?err, "pty stdout thread read failed");
                return;
            }
        }
    }
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
) -> std::result::Result<Option<RequestedUser>, portl_proto::shell_v1::ShellReason> {
    #[cfg(unix)]
    {
        let current = geteuid();
        let current_user = User::from_uid(current)
            .map_err(|err| portl_proto::shell_v1::ShellReason::BadUser(err.to_string()))?
            .ok_or_else(|| {
                portl_proto::shell_v1::ShellReason::BadUser(format!(
                    "unknown current user: {}",
                    current.as_raw()
                ))
            })?;
        let requested = match user {
            Some(user) => User::from_name(user)
                .map_err(|err| portl_proto::shell_v1::ShellReason::BadUser(err.to_string()))?
                .ok_or_else(|| {
                    portl_proto::shell_v1::ShellReason::BadUser(format!("unknown user: {user}"))
                })?,
            None => current_user,
        };
        if !current.is_root() && requested.uid != current {
            return Err(portl_proto::shell_v1::ShellReason::BadUser(
                "cannot drop uid as non-root".to_owned(),
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
            Some(_) => Err(portl_proto::shell_v1::ShellReason::BadUser(
                "user switching is unsupported on this platform".to_owned(),
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

fn terminate_process(target: Option<i32>) {
    #[cfg(unix)]
    {
        if let Some(target) = target {
            let _ = kill(Pid::from_raw(target), Signal::SIGHUP);
        }
    }

    #[cfg(not(unix))]
    {
        let _ = target;
    }
}

fn signal_target_from_pid(
    pid: u32,
) -> std::result::Result<i32, portl_proto::shell_v1::ShellReason> {
    i32::try_from(pid).map_err(|_| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("child pid out of range".to_owned())
    })
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

    let target_gid = user.gid.as_raw();
    let target_uid = user.uid.as_raw();
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
            nix::unistd::setgid(Gid::from_raw(target_gid)).map_err(nix_to_io_error)?;
            nix::unistd::setuid(Uid::from_raw(target_uid)).map_err(nix_to_io_error)?;
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

/// Classify a `resolve_requested_user` failure into one of the
/// enumerated `audit.shell_reject` reason strings.
///
/// A rejection with no requested user means the failure originated in
/// the agent's own euid lookup (`uid_lookup_failed`); a rejection with
/// a requested user is always a refusal to switch to that target
/// (`user_switch_refused`), whether because the name is unknown, the
/// agent is non-root, or the user-allowlist denies the switch.
fn classify_user_reject(requested: Option<&str>) -> &'static str {
    if requested.is_some() {
        "user_switch_refused"
    } else {
        "uid_lookup_failed"
    }
}

/// Classify a `spawn_process` failure into one of the enumerated
/// `audit.shell_reject` reason strings based on the request shape and
/// the returned `ShellReason`.
fn classify_spawn_reject(
    req: &portl_proto::shell_v1::ShellReq,
    reason: &portl_proto::shell_v1::ShellReason,
) -> &'static str {
    match req.mode {
        portl_proto::shell_v1::ShellMode::Exec => {
            if req.argv.as_ref().is_none_or(Vec::is_empty) {
                "argv_empty"
            } else {
                "path_probe_failed"
            }
        }
        portl_proto::shell_v1::ShellMode::Shell => match reason {
            portl_proto::shell_v1::ShellReason::BadUser(_) => "user_switch_refused",
            _ => "pty_allocation_failed",
        },
    }
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
    use super::{RequestedUser, install_exec_user_switch};
    use super::{ShellProcess, ShellSessionGuard};
    use crate::shell_registry::ShellRegistry;
    #[cfg(unix)]
    use nix::unistd::{Gid, Uid};
    #[cfg(unix)]
    use std::process::Command as StdCommand;
    use tokio::sync::{Mutex as AsyncMutex, mpsc, watch};

    #[test]
    fn shell_registry_is_empty_after_control_stream_error() {
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
                pty_master: None,
            }),
        );

        {
            let _guard = ShellSessionGuard {
                registry: &registry,
                session_id,
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
}
