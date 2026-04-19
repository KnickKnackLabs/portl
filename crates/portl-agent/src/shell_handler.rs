use std::collections::BTreeMap;
use std::process::Stdio;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
#[cfg(unix)]
use nix::sys::signal::{Signal, kill};
#[cfg(unix)]
use nix::unistd::{Gid, Pid, Uid, User, geteuid};
use portable_pty::{CommandBuilder, PtySize, native_pty_system};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tracing::{debug, warn};

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::{shell_caps, shell_permits};
use crate::session::Session;
use crate::shell_registry::{ShellProcess, StdinMessage};
use crate::stream_io::BufferedRecv;

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_SIGNAL_BYTES: usize = 1024;
const MAX_RESIZE_BYTES: usize = 1024;
const IO_CHUNK: usize = 16 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShellReqBody {
    mode: portl_proto::shell_v1::ShellMode,
    argv: Option<Vec<String>>,
    env_patch: Vec<(String, portl_proto::shell_v1::EnvValue)>,
    cwd: Option<String>,
    pty: Option<portl_proto::shell_v1::PtyCfg>,
    user: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShellSubTail {
    session_id: [u8; 16],
    kind: portl_proto::shell_v1::ShellStreamKind,
}

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    if recv.prefix().is_empty() {
        let mut hint = [0_u8; 1];
        let read = recv
            .read(&mut hint)
            .await
            .context("read shell stream hint")?;
        if read == 0 {
            bail!("empty shell stream")
        }
        recv.push_front(&hint[..read]);
    }

    if recv.prefix()[0] < 2 {
        let req_body = recv
            .read_frame::<ShellReqBody>(MAX_CONTROL_BYTES)
            .await?
            .context("missing shell control request")?;
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
    } else {
        let tail = postcard_tail(&mut recv, MAX_CONTROL_BYTES).await?;
        serve_substream(connection, session, state, send, recv, preamble, tail).await
    }
}

async fn postcard_tail(recv: &mut BufferedRecv, max_bytes: usize) -> Result<ShellSubTail> {
    recv.read_frame::<ShellSubTail>(max_bytes)
        .await?
        .context("missing shell sub-stream preamble")
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
    let process = match spawn_process(&session, &req, requested_user.as_ref()) {
        Ok(process) => process,
        Err(reason) => {
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
    audit::shell_spawn(&session, req.user.as_deref(), req.argv.as_ref());

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
            terminate_process(process.signal_target);
            state.shell_registry.remove(&session_id);
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
    tail: ShellSubTail,
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
        if let Some(master) = process.pty_master.as_ref() {
            master
                .lock()
                .map_err(|_| anyhow!("pty master poisoned"))?
                .resize(PtySize {
                    rows: frame.rows,
                    cols: frame.cols,
                    pixel_width: 0,
                    pixel_height: 0,
                })
                .context("resize pty")?;
        }
    }
    Ok(())
}

async fn pump_exit(mut send: SendStream, process: &ShellProcess) -> Result<()> {
    let mut rx = process.exit_rx();
    let initial = *rx.borrow();
    let code = match initial {
        Some(code) => code,
        None => loop {
            rx.changed().await.context("wait for shell exit")?;
            if let Some(code) = *rx.borrow() {
                break code;
            }
        },
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
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    match req.mode {
        portl_proto::shell_v1::ShellMode::Exec => spawn_exec_process(session, req, requested_user),
        portl_proto::shell_v1::ShellMode::Shell => spawn_pty_process(session, req, requested_user),
    }
}

fn spawn_exec_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    let argv = req
        .argv
        .as_ref()
        .filter(|argv| !argv.is_empty())
        .ok_or_else(|| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("missing argv".to_owned())
        })?;
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command.stdin(Stdio::piped());
    command.stdout(Stdio::piped());
    command.stderr(Stdio::piped());
    if let Some(cwd) = req.cwd.as_deref() {
        command.current_dir(cwd);
    }
    apply_env_to_command(
        &mut command,
        effective_env(session.caps.shell.as_ref(), req),
    );
    #[cfg(unix)]
    if let Some(user) = requested_user
        && user.switch_required
    {
        command.uid(user.uid.as_raw());
        command.gid(user.gid.as_raw());
    }

    let mut child = command
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

    let exit_tx_wait = exit_tx.clone();
    let ticket_id = session.ticket_id;
    let caller_endpoint_id = session.caller_endpoint_id;
    tokio::spawn(async move {
        let code = match child.wait().await {
            Ok(status) => status.code().unwrap_or(1),
            Err(err) => {
                warn!(?err, "wait on exec child failed");
                1
            }
        };
        let _ = exit_tx_wait.send(Some(code));
        audit::shell_exit_raw(ticket_id, caller_endpoint_id, pid, code);
    });

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_tx,
        signal_target: Some(signal_target_from_pid(pid)?),
        pty_master: None,
    }))
}

fn spawn_pty_process(
    session: &Session,
    req: &portl_proto::shell_v1::ShellReq,
    requested_user: Option<&RequestedUser>,
) -> std::result::Result<Arc<ShellProcess>, portl_proto::shell_v1::ShellReason> {
    if let Some(user) = requested_user
        && user.switch_required
    {
        return Err(portl_proto::shell_v1::ShellReason::BadUser(
            "portable-pty uid switching is not implemented".to_owned(),
        ));
    }

    let pty = req
        .pty
        .as_ref()
        .ok_or(portl_proto::shell_v1::ShellReason::InvalidPty)?;
    let pty_pair = native_pty_system()
        .openpty(PtySize {
            rows: pty.rows,
            cols: pty.cols,
            pixel_width: 0,
            pixel_height: 0,
        })
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;

    let master = Arc::new(Mutex::new(pty_pair.master));
    let shell_program = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_owned());
    let mut cmd = CommandBuilder::new(shell_program);
    cmd.arg("-l");
    if let Some(cwd) = req.cwd.as_deref() {
        cmd.cwd(cwd);
    }
    apply_env_to_pty_command(&mut cmd, effective_env(shell_caps(&session.caps), req));
    cmd.env("TERM", &pty.term);

    let mut child = pty_pair
        .slave
        .spawn_command(cmd)
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;
    let pid = child.process_id().ok_or_else(|| {
        portl_proto::shell_v1::ShellReason::SpawnFailed("missing child pid".to_owned())
    })?;

    let reader = master
        .lock()
        .map_err(|_| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("pty master poisoned".to_owned())
        })?
        .try_clone_reader()
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;
    let writer = master
        .lock()
        .map_err(|_| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("pty master poisoned".to_owned())
        })?
        .take_writer()
        .map_err(|err| portl_proto::shell_v1::ShellReason::SpawnFailed(err.to_string()))?;

    let (stdin_tx, stdin_rx) = mpsc::channel(32);
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (_stderr_tx, stderr_rx) = mpsc::channel(1);
    let (exit_tx, _) = watch::channel(None);

    std::thread::spawn(move || pty_stdin_thread(writer, stdin_rx));
    std::thread::spawn(move || pty_stdout_thread(reader, &stdout_tx));

    let exit_tx_wait = exit_tx.clone();
    let ticket_id = session.ticket_id;
    let caller_endpoint_id = session.caller_endpoint_id;
    tokio::task::spawn_blocking(move || {
        let code = match child.wait() {
            Ok(status) => i32::try_from(status.exit_code()).unwrap_or(1),
            Err(err) => {
                warn!(?err, "wait on pty child failed");
                1
            }
        };
        let _ = exit_tx_wait.send(Some(code));
        audit::shell_exit_raw(ticket_id, caller_endpoint_id, pid, code);
    });

    #[cfg(unix)]
    let signal_target = master
        .lock()
        .map_err(|_| {
            portl_proto::shell_v1::ShellReason::SpawnFailed("pty master poisoned".to_owned())
        })?
        .process_group_leader()
        .map_or_else(
            || Ok(Some(signal_target_from_pid(pid)?)),
            |pgid| Ok(Some(-pgid)),
        )?;
    #[cfg(not(unix))]
    let signal_target = Some(pid as i32);

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_tx,
        signal_target,
        pty_master: Some(master),
    }))
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

fn apply_env_to_command(command: &mut Command, envs: Vec<(String, String)>) {
    command.env_clear();
    command.envs(envs);
}

fn apply_env_to_pty_command(command: &mut CommandBuilder, envs: Vec<(String, String)>) {
    command.env_clear();
    for (key, value) in envs {
        command.env(key, value);
    }
}

fn effective_env(
    shell_caps: Option<&portl_core::ticket::schema::ShellCaps>,
    req: &portl_proto::shell_v1::ShellReq,
) -> Vec<(String, String)> {
    let mut env = match shell_caps.map(|caps| &caps.env_policy) {
        Some(portl_core::ticket::schema::EnvPolicy::Replace { base }) => {
            base.iter().cloned().collect::<BTreeMap<_, _>>()
        }
        _ => std::env::vars().collect::<BTreeMap<_, _>>(),
    };

    match shell_caps.map(|caps| &caps.env_policy) {
        Some(portl_core::ticket::schema::EnvPolicy::Deny) | None => {}
        Some(portl_core::ticket::schema::EnvPolicy::Merge { allow }) => {
            for (key, value) in &req.env_patch {
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
        Some(portl_core::ticket::schema::EnvPolicy::Replace { .. }) => {
            for (key, value) in &req.env_patch {
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
    }

    env.into_iter().collect()
}

#[cfg(unix)]
#[derive(Debug, Clone)]
struct RequestedUser {
    uid: Uid,
    gid: Gid,
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
        let Some(user) = user else {
            return Ok(None);
        };
        let requested = User::from_name(user)
            .map_err(|err| portl_proto::shell_v1::ShellReason::BadUser(err.to_string()))?
            .ok_or_else(|| {
                portl_proto::shell_v1::ShellReason::BadUser(format!("unknown user: {user}"))
            })?;
        let current = geteuid();
        if current.is_root() {
            return Ok(Some(RequestedUser {
                uid: requested.uid,
                gid: requested.gid,
                switch_required: requested.uid != current,
            }));
        }
        if requested.uid != current {
            return Err(portl_proto::shell_v1::ShellReason::BadUser(
                "cannot drop uid as non-root".to_owned(),
            ));
        }
        Ok(Some(RequestedUser {
            uid: requested.uid,
            gid: requested.gid,
            switch_required: false,
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

fn fresh_session_id() -> [u8; 16] {
    loop {
        let mut id = rand::random::<[u8; 16]>();
        id[0] |= 0b1000_0000;
        if id[0] >= 2 {
            return id;
        }
    }
}
