use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
use portl_proto::session_v1::{
    ALPN_SESSION_V1, SessionAck, SessionEntry, SessionFirstFrame, SessionOp,
    SessionProviderSessions, SessionReason, SessionReq, SessionStreamKind, SessionSubTail,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Child;
use tokio::sync::{mpsc, watch};

use crate::caps_enforce::shell_permits;
use crate::session::Session;
use crate::shell_handler::pumps::{pump_exit, pump_output, pump_resizes, pump_signals, pump_stdin};
use crate::shell_handler::spawn::spawn_process;
use crate::shell_handler::user::{RequestedUser, resolve_requested_user};
use crate::shell_registry::{PtyCommand, ShellProcess, StdinMessage};
use crate::stream_io::BufferedRecv;
use crate::target_context::TargetProcessContext;
use crate::{AgentState, audit};

pub(crate) mod provider;
mod tmux_control;

const MAX_CONTROL_BYTES: usize = 256 * 1024;
const ZMX_CONTROL_HEADER_BYTES: usize = 5;
const MAX_ZMX_CONTROL_FRAME_BYTES: usize = 16 * 1024 * 1024;
const ZMX_TAG_OUTPUT: u8 = 1;
const ZMX_TAG_VIEWPORT_SNAPSHOT: u8 = 14;
const ZMX_TAG_LIVE_OUTPUT: u8 = 15;

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let first = recv
        .read_frame::<SessionFirstFrame>(MAX_CONTROL_BYTES)
        .await?
        .context("missing session first frame")?;
    match first {
        SessionFirstFrame::Control(req_body) => {
            let req = SessionReq {
                preamble: preamble.clone(),
                op: req_body.op,
                provider: req_body.provider,
                session_name: req_body.session_name,
                user: req_body.user,
                cwd: req_body.cwd,
                argv: req_body.argv,
                pty: req_body.pty,
            };
            serve_control_stream(connection, session, state, send, recv, req).await
        }
        SessionFirstFrame::Sub(tail) => {
            serve_substream(session, state, send, recv, preamble, tail).await
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn serve_control_stream(
    _connection: Connection,
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    recv: BufferedRecv,
    req: SessionReq,
) -> Result<()> {
    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(ALPN_SESSION_V1)
    {
        bail!("invalid session preamble")
    }
    if let Err(reason) = session_permits(&session, &req) {
        audit::session_reject(&session, op_name(req.op), "caps_denied");
        write_ack(&mut send, reject(reason)).await?;
        let _ = send.finish();
        return Ok(());
    }
    let zmx = provider::ZmxProvider::new(state.session_provider_path.clone());
    let tmux_path = state.session_provider_path.clone().filter(|path| {
        path.file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name == "tmux")
    });
    let tmux = provider::TmuxProvider::new(tmux_path);
    match req.op {
        SessionOp::Providers => {
            audit::session_event(
                &session,
                "audit.session_providers",
                None,
                None,
                "providers",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let providers = provider::provider_report(&zmx, &tmux).await?;
            write_ack(
                &mut send,
                SessionAck {
                    ok: true,
                    reason: None,
                    session_id: None,
                    provider: providers.default_provider.clone(),
                    providers: Some(providers),
                    sessions: None,
                    session_entries: None,
                    session_groups: None,
                    run: None,
                    output: None,
                },
            )
            .await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::List => {
            let groups = match list_session_groups(&zmx, &tmux, req.provider.as_deref()).await {
                Ok(groups) => groups,
                Err(err) => {
                    audit::session_reject(&session, "list", "provider_command_failed");
                    write_ack(&mut send, reject(err)).await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            let provider_name = groups
                .iter()
                .find(|group| group.default)
                .or_else(|| groups.first())
                .map_or_else(|| "zmx".to_owned(), |group| group.provider.clone());
            audit::session_event(
                &session,
                "audit.session_list",
                Some(provider_name.as_str()),
                None,
                "list",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let sessions = groups
                .iter()
                .flat_map(|group| group.sessions.iter().map(|session| session.name.clone()))
                .collect();
            write_ack(
                &mut send,
                ok_with_session_groups(&provider_name, sessions, groups),
            )
            .await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Run => {
            let selected = match select_provider(&zmx, &tmux, req.provider.as_deref(), req.op).await
            {
                Ok(selected) => selected,
                Err(reason) => {
                    write_ack(&mut send, reject(reason)).await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            let Some(name) = req.session_name.as_deref() else {
                write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
                let _ = send.finish();
                return Ok(());
            };
            let Some(argv) = req.argv.as_ref().filter(|argv| !argv.is_empty()) else {
                write_ack(&mut send, reject(SessionReason::MissingArgv)).await?;
                let _ = send.finish();
                return Ok(());
            };
            audit::session_event(
                &session,
                "audit.session_run",
                Some(selected.name()),
                Some(name),
                "run",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let run = match selected.run(&zmx, name, argv).await {
                Ok(run) => run,
                Err(err) => {
                    audit::session_reject(&session, "run", "provider_command_failed");
                    write_ack(
                        &mut send,
                        reject(SessionReason::SpawnFailed(err.to_string())),
                    )
                    .await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            write_ack(&mut send, ok_with_run(selected.name(), run)).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::History => {
            let Some(name) = req.session_name.as_deref() else {
                write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
                let _ = send.finish();
                return Ok(());
            };
            let selected = match resolve_provider_for_session(
                &zmx,
                &tmux,
                req.provider.as_deref(),
                name,
                req.op,
                false,
            )
            .await
            {
                Ok(selected) => selected,
                Err(reason) => {
                    write_ack(&mut send, reject(reason)).await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            audit::session_event(
                &session,
                "audit.session_history",
                Some(selected.name()),
                Some(name),
                "history",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let output = match selected.history(&zmx, &tmux, name).await {
                Ok(output) => output,
                Err(err) => {
                    audit::session_reject(&session, "history", "provider_command_failed");
                    write_ack(
                        &mut send,
                        reject(SessionReason::SpawnFailed(err.to_string())),
                    )
                    .await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            write_ack(&mut send, ok_with_output(selected.name(), output)).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Kill => {
            let Some(name) = req.session_name.as_deref() else {
                write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
                let _ = send.finish();
                return Ok(());
            };
            let selected = match resolve_provider_for_session(
                &zmx,
                &tmux,
                req.provider.as_deref(),
                name,
                req.op,
                false,
            )
            .await
            {
                Ok(selected) => selected,
                Err(reason) => {
                    write_ack(&mut send, reject(reason)).await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            audit::session_event(
                &session,
                "audit.session_kill",
                Some(selected.name()),
                Some(name),
                "kill",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            if let Err(err) = selected.kill(&zmx, &tmux, name).await {
                audit::session_reject(&session, "kill", "provider_command_failed");
                write_ack(
                    &mut send,
                    reject(SessionReason::SpawnFailed(err.to_string())),
                )
                .await?;
                let _ = send.finish();
                return Ok(());
            }
            write_ack(&mut send, ok_empty(selected.name())).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Attach => serve_attach(session, state, send, recv, req, zmx, tmux).await,
    }
}

struct TmuxAttachPlan {
    session: String,
    target: String,
    notice: Option<Vec<u8>>,
}

async fn plan_tmux_attach(tmux: &provider::TmuxProvider, requested: &str) -> TmuxAttachPlan {
    let parsed = provider::parse_tmux_target(requested);
    if parsed.has_selector {
        return TmuxAttachPlan {
            session: parsed.session,
            target: parsed.target,
            notice: None,
        };
    }

    let panes = tmux.list_panes(&parsed.session).await.unwrap_or_default();
    let target = panes
        .iter()
        .find(|pane| pane.active)
        .or_else(|| panes.first())
        .map_or_else(|| parsed.target.clone(), |pane| pane.target.clone());
    let notice = if panes.len() > 1 {
        let mut text = format!("portl: available tmux panes for {}:\n", parsed.session);
        for pane in &panes {
            let active = if pane.active { " active" } else { "" };
            let _ = writeln!(
                text,
                "  {}  window={}({}) pane={}{}",
                pane.target, pane.window_index, pane.window_name, pane.pane_index, active
            );
        }
        let _ = writeln!(text, "portl: attaching to {target}");
        Some(text.into_bytes())
    } else if target != parsed.target {
        Some(format!("portl: attaching to {target}\n").into_bytes())
    } else {
        None
    };

    TmuxAttachPlan {
        session: parsed.session,
        target,
        notice,
    }
}

#[allow(clippy::too_many_lines)]
async fn serve_attach(
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    req: SessionReq,
    zmx: provider::ZmxProvider,
    tmux: provider::TmuxProvider,
) -> Result<()> {
    let Some(name) = req.session_name.as_deref() else {
        write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
        let _ = send.finish();
        return Ok(());
    };
    let selected = match resolve_provider_for_session(
        &zmx,
        &tmux,
        req.provider.as_deref(),
        name,
        req.op,
        true,
    )
    .await
    {
        Ok(selected) => selected,
        Err(reason) => {
            write_ack(&mut send, reject(reason)).await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    let requested_user = match resolve_requested_user(req.user.as_deref()) {
        Ok(user) => user,
        Err(reject_reason) => {
            write_ack(
                &mut send,
                reject(SessionReason::SpawnFailed(format!(
                    "{:?}",
                    reject_reason.wire
                ))),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    let target_home = requested_user
        .as_ref()
        .map(|user| std::path::PathBuf::from(&user.home_dir));
    let zmx = zmx.with_target_home(target_home.clone());
    let tmux = tmux.with_target_home(target_home);
    let workload_context = session_workload_context(&session, &req, requested_user.as_ref());
    audit::session_event(
        &session,
        "audit.session_attach",
        Some(selected.name()),
        Some(name),
        "attach",
        req.user.as_deref(),
        workload_context.cwd.as_deref(),
        req.argv.as_ref(),
    );
    if selected == SelectedProvider::Tmux {
        if req.user.is_some() {
            write_ack(
                &mut send,
                reject(SessionReason::CapabilityUnsupported {
                    provider: "tmux".to_owned(),
                    capability: "user".to_owned(),
                }),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
        let attach_plan = plan_tmux_attach(&tmux, name).await;
        let initial_snapshot = tmux.viewport_snapshot(&attach_plan.target).await.ok();
        return serve_tmux_control_attach(
            session,
            state,
            send,
            recv,
            req,
            tmux,
            &attach_plan.session,
            Some(&attach_plan.target),
            attach_plan.notice,
            &workload_context,
            initial_snapshot,
        )
        .await;
    }

    if req.user.is_none() && zmx.control_available().await? {
        let name = name.to_owned();
        return serve_control_attach(
            session,
            state,
            send,
            recv,
            req,
            zmx,
            &name,
            &workload_context,
        )
        .await;
    }

    let provider_argv = zmx.attach_argv(name, req.argv.as_deref())?;
    let shell_req = portl_proto::shell_v1::ShellReq {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into_owned(),
        },
        mode: portl_proto::shell_v1::ShellMode::Shell,
        argv: Some(provider_argv),
        env_patch: Vec::new(),
        cwd: workload_context.cwd,
        pty: req.pty,
        user: req.user,
    };
    let session_id = rand::random::<[u8; 16]>();
    let audit_session_id = hex::encode(session_id);
    let process = match spawn_process(
        &session,
        &shell_req,
        requested_user.as_ref(),
        &audit_session_id,
    ) {
        Ok(process) => process,
        Err(err) => {
            write_ack(
                &mut send,
                reject(SessionReason::SpawnFailed(format!("{:?}", err.wire))),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    process.set_started_at(Instant::now());
    state
        .shell_registry
        .insert(session_id, Arc::clone(&process));
    let _guard = SessionRegistryGuard {
        state: Arc::clone(&state),
        session_id,
    };
    write_ack(
        &mut send,
        SessionAck {
            ok: true,
            reason: None,
            session_id: Some(session_id),
            provider: Some("zmx".to_owned()),
            providers: None,
            sessions: None,
            session_entries: None,
            session_groups: None,
            run: None,
            output: None,
        },
    )
    .await?;
    let mut control_buffer = [0_u8; 1024];
    loop {
        let read = recv
            .read(&mut control_buffer)
            .await
            .context("read session control")?;
        if read == 0 {
            let _ = send.finish();
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_control_attach(
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    req: SessionReq,
    zmx: provider::ZmxProvider,
    name: &str,
    context: &TargetProcessContext,
) -> Result<()> {
    let session_id = rand::random::<[u8; 16]>();
    let audit_session_id = hex::encode(session_id);
    let process = match spawn_zmx_control_process(
        &session,
        &zmx,
        name,
        context.cwd.as_deref(),
        req.pty.as_ref(),
        req.argv.as_deref(),
        &context.env,
        &audit_session_id,
    ) {
        Ok(process) => process,
        Err(err) => {
            write_ack(
                &mut send,
                reject(SessionReason::SpawnFailed(err.to_string())),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    process.set_started_at(Instant::now());
    state
        .shell_registry
        .insert(session_id, Arc::clone(&process));
    let _guard = SessionRegistryGuard {
        state: Arc::clone(&state),
        session_id,
    };
    write_ack(
        &mut send,
        SessionAck {
            ok: true,
            reason: None,
            session_id: Some(session_id),
            provider: Some("zmx".to_owned()),
            providers: None,
            sessions: None,
            session_entries: None,
            session_groups: None,
            run: None,
            output: None,
        },
    )
    .await?;
    let mut control_buffer = [0_u8; 1024];
    loop {
        let read = recv
            .read(&mut control_buffer)
            .await
            .context("read session control")?;
        if read == 0 {
            let _ = send.finish();
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
async fn serve_tmux_control_attach(
    session: Session,
    state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    req: SessionReq,
    tmux: provider::TmuxProvider,
    name: &str,
    tmux_target: Option<&str>,
    initial_stderr: Option<Vec<u8>>,
    context: &TargetProcessContext,
    initial_snapshot: Option<Vec<u8>>,
) -> Result<()> {
    let session_id = rand::random::<[u8; 16]>();
    let audit_session_id = hex::encode(session_id);
    let process = match spawn_tmux_control_process(
        &session,
        &tmux,
        name,
        tmux_target,
        context.cwd.as_deref(),
        req.pty.as_ref(),
        req.argv.as_deref(),
        &context.env,
        &audit_session_id,
        initial_snapshot,
        initial_stderr,
    ) {
        Ok(process) => process,
        Err(err) => {
            write_ack(
                &mut send,
                reject(SessionReason::SpawnFailed(err.to_string())),
            )
            .await?;
            let _ = send.finish();
            return Ok(());
        }
    };
    process.set_started_at(Instant::now());
    state
        .shell_registry
        .insert(session_id, Arc::clone(&process));
    let _guard = SessionRegistryGuard {
        state: Arc::clone(&state),
        session_id,
    };
    write_ack(
        &mut send,
        SessionAck {
            ok: true,
            reason: None,
            session_id: Some(session_id),
            provider: Some("tmux".to_owned()),
            providers: None,
            sessions: None,
            session_entries: None,
            session_groups: None,
            run: None,
            output: None,
        },
    )
    .await?;
    let mut control_buffer = [0_u8; 1024];
    loop {
        let read = recv
            .read(&mut control_buffer)
            .await
            .context("read session control")?;
        if read == 0 {
            let _ = send.finish();
            return Ok(());
        }
    }
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn spawn_tmux_control_process(
    session: &Session,
    tmux: &provider::TmuxProvider,
    name: &str,
    tmux_target: Option<&str>,
    cwd: Option<&str>,
    pty: Option<&portl_proto::shell_v1::PtyCfg>,
    argv: Option<&[String]>,
    workload_env: &[(String, String)],
    audit_session_id: &str,
    initial_snapshot: Option<Vec<u8>>,
    initial_stderr: Option<Vec<u8>>,
) -> Result<Arc<ShellProcess>> {
    use std::sync::Mutex;

    let spawn =
        tmux.control_spawn_config_with_env(name, tmux_target, cwd, pty, argv, Some(workload_env))?;
    let pty_cfg = pty.ok_or_else(|| anyhow!("tmux -CC attach requires pty dimensions"))?;
    let winsize = nix::libc::winsize {
        ws_row: pty_cfg.rows,
        ws_col: pty_cfg.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    };
    let program = spawn
        .program
        .to_str()
        .ok_or_else(|| anyhow!("tmux path is not valid UTF-8"))?;
    let (master, child) = crate::shell_handler::spawn::spawn_pty_blocking(
        program,
        &spawn.args,
        winsize,
        spawn.env,
        None,
    )
    .context("spawn tmux -CC control pty")?;
    let pid = child.id().ok_or_else(|| anyhow!("missing child pid"))?;

    let (stdin_tx, stdin_rx) = mpsc::channel(32);
    let (pty_tx, pty_rx) = mpsc::unbounded_channel();
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (stderr_tx, stderr_rx) = mpsc::channel(32);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);

    if let Some(snapshot) = initial_snapshot.filter(|snapshot| !snapshot.is_empty()) {
        let _ = stdout_tx.try_send(snapshot);
    }
    if let Some(stderr) = initial_stderr.filter(|stderr| !stderr.is_empty()) {
        let _ = stderr_tx.try_send(stderr);
    }

    tokio::spawn(async move {
        if let Err(err) = tmux_control::pump_tmux_cc_pty(
            master,
            stdout_tx,
            stderr_tx,
            stdin_rx,
            pty_rx,
            spawn.initial_commands,
        )
        .await
        {
            tracing::debug!(%err, "tmux -CC pty task ended with error");
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
        wait_zmx_control_child(
            child,
            pid,
            ticket_id,
            caller_endpoint_id,
            audit_session_id,
            exit_code_wait,
            exit_tx_wait,
            started_at_wait,
        )
        .await;
    });

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target: None,
        pty_tx: Some(pty_tx),
        started_at,
    }))
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
fn spawn_zmx_control_process(
    session: &Session,
    zmx: &provider::ZmxProvider,
    name: &str,
    cwd: Option<&str>,
    pty: Option<&portl_proto::shell_v1::PtyCfg>,
    argv: Option<&[String]>,
    workload_env: &[(String, String)],
    audit_session_id: &str,
) -> Result<Arc<ShellProcess>> {
    use std::sync::Mutex;

    let mut command = zmx.control_command(name, cwd, pty, argv, Some(workload_env))?;
    command
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = command.spawn().context("spawn zmx control")?;
    let pid = child.id().ok_or_else(|| anyhow!("missing child pid"))?;
    let mut stdin = child.stdin.take().context("missing zmx-control stdin")?;
    let mut stdout = child.stdout.take().context("missing zmx-control stdout")?;
    let mut stderr = child.stderr.take().context("missing zmx-control stderr")?;

    let (stdin_tx, mut stdin_rx) = mpsc::channel(32);
    let (pty_tx, mut pty_rx) = mpsc::unbounded_channel();
    let (stdout_tx, stdout_rx) = mpsc::channel(32);
    let (stderr_tx, stderr_rx) = mpsc::channel(32);
    let exit_code = Arc::new(Mutex::new(None));
    let (exit_tx, _) = watch::channel(None);

    #[allow(clippy::unused_async)]
    tokio::spawn(async move {
        loop {
            tokio::select! {
                Some(message) = stdin_rx.recv() => {
                    let close = matches!(message, StdinMessage::Close);
                    let write = match message {
                        StdinMessage::Data(data) => write_control_frame(&mut stdin, 0, &data).await,
                        StdinMessage::Close => write_control_frame(&mut stdin, 3, &[]).await,
                    };
                    if write.is_err() {
                        break;
                    }
                    if close {
                        let _ = stdin.shutdown().await;
                        break;
                    }
                }
                Some(command) = pty_rx.recv() => {
                    match command {
                        PtyCommand::Resize { rows, cols } => {
                            let mut payload = [0_u8; 4];
                            payload[..2].copy_from_slice(&rows.to_le_bytes());
                            payload[2..].copy_from_slice(&cols.to_le_bytes());
                            if write_control_frame(&mut stdin, 2, &payload).await.is_err() {
                                break;
                            }
                        }
                        PtyCommand::Close { .. } => {
                            let _ = write_control_frame(&mut stdin, 3, &[]).await;
                            let _ = stdin.shutdown().await;
                            break;
                        }
                        PtyCommand::KickOthers => {}
                    }
                }
                else => {
                    let _ = write_control_frame(&mut stdin, 3, &[]).await;
                    let _ = stdin.shutdown().await;
                    break;
                }
            }
        }
    });

    tokio::spawn(async move {
        while let Ok(Some((tag, payload))) = read_control_frame(&mut stdout).await {
            if matches!(
                tag,
                ZMX_TAG_OUTPUT | ZMX_TAG_VIEWPORT_SNAPSHOT | ZMX_TAG_LIVE_OUTPUT
            ) && stdout_tx.send(payload).await.is_err()
            {
                break;
            }
        }
    });

    tokio::spawn(async move {
        let mut buf = vec![0_u8; 16 * 1024];
        loop {
            match stderr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(read) => {
                    if stderr_tx.send(buf[..read].to_vec()).await.is_err() {
                        break;
                    }
                }
            }
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
        wait_zmx_control_child(
            child,
            pid,
            ticket_id,
            caller_endpoint_id,
            audit_session_id,
            exit_code_wait,
            exit_tx_wait,
            started_at_wait,
        )
        .await;
    });

    Ok(Arc::new(ShellProcess {
        pid,
        stdin_tx,
        stdout_rx: tokio::sync::Mutex::new(Some(stdout_rx)),
        stderr_rx: tokio::sync::Mutex::new(Some(stderr_rx)),
        exit_code,
        exit_tx,
        signal_target: None,
        pty_tx: Some(pty_tx),
        started_at,
    }))
}

async fn write_control_frame(
    writer: &mut tokio::process::ChildStdin,
    tag: u8,
    payload: &[u8],
) -> std::io::Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "zmx-control payload exceeds u32 frame length",
        )
    })?;
    writer.write_all(&[tag]).await?;
    writer.write_all(&len.to_le_bytes()).await?;
    writer.write_all(payload).await
}

async fn read_control_frame(
    reader: &mut tokio::process::ChildStdout,
) -> std::io::Result<Option<(u8, Vec<u8>)>> {
    let mut header = [0_u8; ZMX_CONTROL_HEADER_BYTES];
    match reader.read_exact(&mut header).await {
        Ok(_) => {}
        Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(err) => return Err(err),
    }
    let len = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
    if len > MAX_ZMX_CONTROL_FRAME_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "zmx-control frame exceeds maximum payload size",
        ));
    }
    let mut payload = vec![0_u8; len];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[0], payload)))
}

#[allow(clippy::too_many_arguments)]
async fn wait_zmx_control_child(
    mut child: Child,
    pid: u32,
    ticket_id: [u8; 16],
    caller_endpoint_id: [u8; 32],
    audit_session_id: String,
    exit_code: Arc<std::sync::Mutex<Option<i32>>>,
    exit_tx: watch::Sender<Option<i32>>,
    started_at: Arc<std::sync::Mutex<Option<Instant>>>,
) {
    let code = match child.wait().await {
        Ok(status) => status.code().unwrap_or(1),
        Err(_) => 1,
    };
    if let Ok(mut guard) = exit_code.lock() {
        *guard = Some(code);
    }
    let duration_ms = started_at
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
    let _ = exit_tx.send(Some(code));
}

async fn serve_substream(
    session: Session,
    state: Arc<AgentState>,
    send: SendStream,
    recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
    tail: SessionSubTail,
) -> Result<()> {
    if preamble.peer_token != session.peer_token
        || preamble.alpn != String::from_utf8_lossy(ALPN_SESSION_V1)
    {
        bail!("invalid session sub-stream preamble")
    }
    let process = state
        .shell_registry
        .get(&tail.session_id)
        .map(|entry| Arc::clone(entry.value()))
        .ok_or_else(|| anyhow!("session attach process not found"))?;
    match tail.kind {
        SessionStreamKind::Stdin => pump_stdin(recv, process).await,
        SessionStreamKind::Stdout => pump_output(send, &process.stdout_rx).await,
        SessionStreamKind::Stderr => pump_output(send, &process.stderr_rx).await,
        SessionStreamKind::Signal => pump_signals(recv, &process).await,
        SessionStreamKind::Resize => pump_resizes(recv, &process).await,
        SessionStreamKind::Exit => pump_exit(send, &process).await,
        SessionStreamKind::Control => pump_session_controls(recv, &process).await,
    }
}

async fn pump_session_controls(mut recv: BufferedRecv, process: &ShellProcess) -> Result<()> {
    while let Some(frame) = recv
        .read_frame::<portl_proto::session_v1::SessionControlFrame>(MAX_CONTROL_BYTES)
        .await?
    {
        match frame.action {
            portl_proto::session_v1::SessionControlAction::KickOthers => {
                if let Some(pty_tx) = process.pty_tx.as_ref() {
                    pty_tx
                        .send(PtyCommand::KickOthers)
                        .map_err(|_| anyhow!("pty control channel closed"))
                        .context("forward kick-others control")?;
                }
            }
        }
    }
    Ok(())
}

fn session_workload_context(
    session: &Session,
    req: &SessionReq,
    requested_user: Option<&RequestedUser>,
) -> TargetProcessContext {
    let shell_req = portl_proto::shell_v1::ShellReq {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into_owned(),
        },
        mode: portl_proto::shell_v1::ShellMode::Shell,
        argv: None,
        env_patch: Vec::new(),
        cwd: req.cwd.clone(),
        pty: req.pty.clone(),
        user: req.user.clone(),
    };
    TargetProcessContext::new(session.caps.shell.as_ref(), &shell_req, requested_user)
}

fn session_permits(session: &Session, req: &SessionReq) -> Result<(), SessionReason> {
    let shell_req = portl_proto::shell_v1::ShellReq {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into_owned(),
        },
        mode: portl_proto::shell_v1::ShellMode::Shell,
        argv: None,
        env_patch: Vec::new(),
        cwd: req.cwd.clone(),
        pty: Some(portl_proto::shell_v1::PtyCfg {
            term: "xterm-256color".to_owned(),
            cols: 80,
            rows: 24,
        }),
        user: req.user.clone(),
    };
    shell_permits(&session.caps, &shell_req).map_err(|_| SessionReason::CapDenied)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SelectedProvider {
    Zmx,
    Tmux,
}

impl SelectedProvider {
    const fn name(self) -> &'static str {
        match self {
            Self::Zmx => "zmx",
            Self::Tmux => "tmux",
        }
    }

    async fn list_detailed(
        self,
        zmx: &provider::ZmxProvider,
        tmux: &provider::TmuxProvider,
    ) -> Result<Vec<portl_proto::session_v1::SessionInfo>> {
        match self {
            Self::Zmx => zmx.list_detailed().await,
            Self::Tmux => tmux.list_detailed().await,
        }
    }

    async fn run(
        self,
        zmx: &provider::ZmxProvider,
        session: &str,
        argv: &[String],
    ) -> Result<portl_proto::session_v1::SessionRunResult> {
        match self {
            Self::Zmx => zmx.run(session, argv).await,
            Self::Tmux => bail!("tmux provider does not support run"),
        }
    }

    async fn history(
        self,
        zmx: &provider::ZmxProvider,
        tmux: &provider::TmuxProvider,
        session: &str,
    ) -> Result<String> {
        match self {
            Self::Zmx => zmx.history(session).await,
            Self::Tmux => tmux.history(session).await,
        }
    }

    async fn kill(
        self,
        zmx: &provider::ZmxProvider,
        tmux: &provider::TmuxProvider,
        session: &str,
    ) -> Result<()> {
        match self {
            Self::Zmx => zmx.kill(session).await,
            Self::Tmux => tmux.kill(session).await,
        }
    }
}

async fn aggregate_session_entries(
    zmx: &provider::ZmxProvider,
    tmux: &provider::TmuxProvider,
) -> Result<Vec<SessionEntry>> {
    let mut entries = Vec::new();
    for provider in [SelectedProvider::Zmx, SelectedProvider::Tmux] {
        let status = match provider {
            SelectedProvider::Zmx => zmx.probe().await?,
            SelectedProvider::Tmux => tmux.probe().await?,
        };
        if !status.available {
            continue;
        }
        for session in provider.list_detailed(zmx, tmux).await? {
            entries.push(SessionEntry {
                provider: provider.name().to_owned(),
                name: session.name,
            });
        }
    }
    Ok(entries)
}

async fn resolve_provider_for_session(
    zmx: &provider::ZmxProvider,
    tmux: &provider::TmuxProvider,
    requested: Option<&str>,
    session_name: &str,
    op: SessionOp,
    create_if_missing: bool,
) -> Result<SelectedProvider, SessionReason> {
    if requested.is_some() {
        return select_provider(zmx, tmux, requested, op).await;
    }

    let entries = aggregate_session_entries(zmx, tmux)
        .await
        .map_err(|err| SessionReason::SpawnFailed(err.to_string()))?;
    let tmux_lookup = provider::tmux_lookup_session(session_name);
    let mut providers = Vec::new();
    for entry in entries.iter().filter(|entry| {
        if entry.provider == "tmux" {
            entry.name == tmux_lookup
        } else {
            entry.name == session_name
        }
    }) {
        match entry.provider.as_str() {
            "zmx" if !providers.contains(&SelectedProvider::Zmx) => {
                providers.push(SelectedProvider::Zmx);
            }
            "tmux" if !providers.contains(&SelectedProvider::Tmux) => {
                providers.push(SelectedProvider::Tmux);
            }
            _ => {}
        }
    }

    match providers.as_slice() {
        [provider] => Ok(*provider),
        [] if create_if_missing => select_provider(zmx, tmux, None, op).await,
        [] => Err(SessionReason::SessionNotFound(session_name.to_owned())),
        _ => Err(SessionReason::SessionAmbiguous {
            name: session_name.to_owned(),
            providers: providers
                .iter()
                .map(|provider| provider.name().to_owned())
                .collect(),
        }),
    }
}

async fn select_provider(
    zmx: &provider::ZmxProvider,
    tmux: &provider::TmuxProvider,
    requested: Option<&str>,
    op: SessionOp,
) -> Result<SelectedProvider, SessionReason> {
    if let Some(provider) = requested {
        return match provider {
            "zmx" => ensure_available(zmx.probe().await, "zmx", SelectedProvider::Zmx),
            "tmux" => {
                if op == SessionOp::Run {
                    Err(SessionReason::CapabilityUnsupported {
                        provider: provider.to_owned(),
                        capability: op_name(op).to_owned(),
                    })
                } else {
                    ensure_available(tmux.probe().await, "tmux", SelectedProvider::Tmux)
                }
            }
            "raw" => Err(SessionReason::CapabilityUnsupported {
                provider: provider.to_owned(),
                capability: op_name(op).to_owned(),
            }),
            other => Err(SessionReason::ProviderNotFound(other.to_owned())),
        };
    }

    let zmx_status = zmx
        .probe()
        .await
        .map_err(|err| SessionReason::InternalError(err.to_string()))?;
    if zmx_status.available {
        return Ok(SelectedProvider::Zmx);
    }
    if op == SessionOp::Run {
        return Err(SessionReason::ProviderUnavailable("zmx".to_owned()));
    }
    let tmux_status = tmux
        .probe()
        .await
        .map_err(|err| SessionReason::InternalError(err.to_string()))?;
    if tmux_status.available {
        Ok(SelectedProvider::Tmux)
    } else {
        Err(SessionReason::ProviderUnavailable("zmx".to_owned()))
    }
}

async fn list_session_groups(
    zmx: &provider::ZmxProvider,
    tmux: &provider::TmuxProvider,
    requested: Option<&str>,
) -> Result<Vec<SessionProviderSessions>, SessionReason> {
    if let Some(provider) = requested {
        let selected = select_provider(zmx, tmux, Some(provider), SessionOp::List).await?;
        let zmx_available = if selected == SelectedProvider::Zmx {
            true
        } else {
            zmx.probe()
                .await
                .map_err(|err| SessionReason::InternalError(err.to_string()))?
                .available
        };
        let sessions = selected
            .list_detailed(zmx, tmux)
            .await
            .map_err(|err| SessionReason::SpawnFailed(err.to_string()))?;
        return Ok(vec![SessionProviderSessions {
            provider: provider.to_owned(),
            available: true,
            default: selected == SelectedProvider::Zmx || !zmx_available,
            sessions,
        }]);
    }

    let zmx_status = zmx
        .probe()
        .await
        .map_err(|err| SessionReason::InternalError(err.to_string()))?;
    let tmux_status = tmux
        .probe()
        .await
        .map_err(|err| SessionReason::InternalError(err.to_string()))?;
    let default_provider = if zmx_status.available {
        Some("zmx")
    } else if tmux_status.available {
        Some("tmux")
    } else {
        None
    };
    let mut groups = Vec::new();
    if zmx_status.available {
        groups.push(SessionProviderSessions {
            provider: "zmx".to_owned(),
            available: true,
            default: default_provider == Some("zmx"),
            sessions: zmx
                .list_detailed()
                .await
                .map_err(|err| SessionReason::SpawnFailed(err.to_string()))?,
        });
    }
    if tmux_status.available {
        groups.push(SessionProviderSessions {
            provider: "tmux".to_owned(),
            available: true,
            default: default_provider == Some("tmux"),
            sessions: tmux
                .list_detailed()
                .await
                .map_err(|err| SessionReason::SpawnFailed(err.to_string()))?,
        });
    }
    if groups.is_empty() {
        Err(SessionReason::ProviderUnavailable("zmx".to_owned()))
    } else {
        Ok(groups)
    }
}

fn ensure_available(
    status: Result<portl_proto::session_v1::ProviderStatus>,
    name: &str,
    selected: SelectedProvider,
) -> Result<SelectedProvider, SessionReason> {
    let status = status.map_err(|err| SessionReason::InternalError(err.to_string()))?;
    if status.available {
        Ok(selected)
    } else {
        Err(SessionReason::ProviderUnavailable(name.to_owned()))
    }
}

fn op_name(op: SessionOp) -> &'static str {
    match op {
        SessionOp::Providers => "providers",
        SessionOp::List => "list",
        SessionOp::Attach => "attach",
        SessionOp::Run => "run",
        SessionOp::History => "history",
        SessionOp::Kill => "kill",
    }
}

async fn write_ack(send: &mut SendStream, ack: SessionAck) -> Result<()> {
    send.write_all(&postcard::to_stdvec(&ack).context("encode session ack")?)
        .await
        .context("write session ack")
}

fn reject(reason: SessionReason) -> SessionAck {
    SessionAck {
        ok: false,
        reason: Some(reason),
        session_id: None,
        provider: None,
        providers: None,
        sessions: None,
        session_entries: None,
        session_groups: None,
        run: None,
        output: None,
    }
}

fn ok_empty(provider: &str) -> SessionAck {
    SessionAck {
        ok: true,
        reason: None,
        session_id: None,
        provider: Some(provider.to_owned()),
        providers: None,
        sessions: None,
        session_entries: None,
        session_groups: None,
        run: None,
        output: None,
    }
}

fn ok_with_session_groups(
    provider: &str,
    sessions: Vec<String>,
    groups: Vec<SessionProviderSessions>,
) -> SessionAck {
    let entries = session_groups_to_entries(&groups);
    SessionAck {
        sessions: Some(sessions),
        session_entries: Some(entries),
        session_groups: Some(groups),
        ..ok_empty(provider)
    }
}

fn session_groups_to_entries(groups: &[SessionProviderSessions]) -> Vec<SessionEntry> {
    groups
        .iter()
        .flat_map(|group| {
            group.sessions.iter().map(|session| SessionEntry {
                provider: group.provider.clone(),
                name: session.name.clone(),
            })
        })
        .collect()
}
fn ok_with_run(provider: &str, run: portl_proto::session_v1::SessionRunResult) -> SessionAck {
    SessionAck {
        run: Some(run),
        ..ok_empty(provider)
    }
}
fn ok_with_output(provider: &str, output: String) -> SessionAck {
    SessionAck {
        output: Some(output),
        ..ok_empty(provider)
    }
}

struct SessionRegistryGuard {
    state: Arc<AgentState>,
    session_id: [u8; 16],
}

impl Drop for SessionRegistryGuard {
    fn drop(&mut self) {
        self.state.shell_registry.remove(&self.session_id);
    }
}
