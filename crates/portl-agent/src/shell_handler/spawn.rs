use std::process::{Command as StdCommand, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[cfg(unix)]
use nix::unistd::Pid;
#[cfg(unix)]
use std::os::fd::OwnedFd;
use tokio::process::Command as TokioCommand;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::audit;
use crate::caps_enforce::shell_caps;
use crate::session::Session;
use crate::shell_registry::ShellProcess;

use super::PTY_DRAIN_TIMEOUT;
use super::env::{apply_env_to_command, effective_env};
use super::exec_capture::{exec_stdin_task, output_reader_task};
#[cfg(unix)]
use super::pty_master::pty_master_task;
use super::reject::SpawnReject;
use super::shutdown::process_group_signal_target_from_pid;
use super::user::{RequestedUser, install_exec_user_switch};

pub(crate) fn spawn_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
    audit_session_id: &str,
) -> Result<Arc<ShellProcess>, SpawnReject> {
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
) -> Result<Arc<ShellProcess>, SpawnReject> {
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
        let _ = exit_tx_wait.send(Some(code));
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
) -> Result<Arc<ShellProcess>, SpawnReject> {
    if let Some(user) = requested_user
        && user.switch_required
    {
        return Err(SpawnReject::user_switch_refused(
            "pty mode does not support --user; use `portl exec --user <name>` or run the agent as the target user",
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

    let (program, argv): (String, Vec<String>) = req.argv.as_ref().map_or_else(
        || {
            (
                std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned()),
                vec!["-l".to_owned()],
            )
        },
        |requested| {
            let mut args = requested.clone();
            let program = args.remove(0);
            (program, args)
        },
    );
    let env = effective_env(shell_caps(&session.caps), req, requested_user);

    let (master, mut child) = spawn_pty_blocking(&program, &argv, winsize, env, req.cwd.as_deref())
        .map_err(|err| {
            SpawnReject::pty_allocation_failed(portl_proto::shell_v1::ShellReason::SpawnFailed(
                err.to_string(),
            ))
        })?;

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
        let _ = exit_tx_wait.send(Some(code));
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
) -> Result<Arc<ShellProcess>, SpawnReject> {
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
pub(super) fn apply_rlimits() -> std::io::Result<()> {
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
pub(super) fn install_exec_session_pre_exec(command: &mut StdCommand) {
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
