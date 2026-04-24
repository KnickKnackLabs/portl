use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
use portl_proto::session_v1::{
    ALPN_SESSION_V1, SessionAck, SessionFirstFrame, SessionOp, SessionReason, SessionReq,
    SessionStreamKind, SessionSubTail,
};
use tokio::io::AsyncReadExt;

use crate::caps_enforce::shell_permits;
use crate::session::Session;
use crate::shell_handler::pumps::{pump_exit, pump_output, pump_resizes, pump_signals, pump_stdin};
use crate::shell_handler::spawn::spawn_process;
use crate::shell_handler::user::resolve_requested_user;
use crate::stream_io::BufferedRecv;
use crate::{AgentState, audit};

mod provider;

const MAX_CONTROL_BYTES: usize = 256 * 1024;

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
            let providers = provider::provider_report(&zmx).await?;
            write_ack(
                &mut send,
                SessionAck {
                    ok: true,
                    reason: None,
                    session_id: None,
                    provider: providers.default_provider.clone(),
                    providers: Some(providers),
                    sessions: None,
                    run: None,
                    output: None,
                },
            )
            .await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::List => {
            if let Err(reason) = ensure_zmx_selected(&zmx, req.provider.as_deref(), req.op).await {
                write_ack(&mut send, reject(reason)).await?;
                let _ = send.finish();
                return Ok(());
            }
            audit::session_event(
                &session,
                "audit.session_providers",
                Some("zmx"),
                None,
                "list",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let sessions = match zmx.list().await {
                Ok(sessions) => sessions,
                Err(err) => {
                    audit::session_reject(&session, "list", "provider_command_failed");
                    write_ack(
                        &mut send,
                        reject(SessionReason::SpawnFailed(err.to_string())),
                    )
                    .await?;
                    let _ = send.finish();
                    return Ok(());
                }
            };
            write_ack(&mut send, ok_with_sessions(sessions)).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Run => {
            if let Err(reason) = ensure_zmx_selected(&zmx, req.provider.as_deref(), req.op).await {
                write_ack(&mut send, reject(reason)).await?;
                let _ = send.finish();
                return Ok(());
            }
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
                Some("zmx"),
                Some(name),
                "run",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let run = match zmx.run(name, argv).await {
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
            write_ack(&mut send, ok_with_run(run)).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::History => {
            if let Err(reason) = ensure_zmx_selected(&zmx, req.provider.as_deref(), req.op).await {
                write_ack(&mut send, reject(reason)).await?;
                let _ = send.finish();
                return Ok(());
            }
            let Some(name) = req.session_name.as_deref() else {
                write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
                let _ = send.finish();
                return Ok(());
            };
            audit::session_event(
                &session,
                "audit.session_history",
                Some("zmx"),
                Some(name),
                "history",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            let output = match zmx.history(name).await {
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
            write_ack(&mut send, ok_with_output(output)).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Kill => {
            if let Err(reason) = ensure_zmx_selected(&zmx, req.provider.as_deref(), req.op).await {
                write_ack(&mut send, reject(reason)).await?;
                let _ = send.finish();
                return Ok(());
            }
            let Some(name) = req.session_name.as_deref() else {
                write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
                let _ = send.finish();
                return Ok(());
            };
            audit::session_event(
                &session,
                "audit.session_kill",
                Some("zmx"),
                Some(name),
                "kill",
                req.user.as_deref(),
                req.cwd.as_deref(),
                req.argv.as_ref(),
            );
            if let Err(err) = zmx.kill(name).await {
                audit::session_reject(&session, "kill", "provider_command_failed");
                write_ack(
                    &mut send,
                    reject(SessionReason::SpawnFailed(err.to_string())),
                )
                .await?;
                let _ = send.finish();
                return Ok(());
            }
            write_ack(&mut send, ok_empty()).await?;
            let _ = send.finish();
            Ok(())
        }
        SessionOp::Attach => serve_attach(session, state, send, recv, req, zmx).await,
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
) -> Result<()> {
    if let Err(reason) = ensure_zmx_selected(&zmx, req.provider.as_deref(), req.op).await {
        write_ack(&mut send, reject(reason)).await?;
        let _ = send.finish();
        return Ok(());
    }
    let Some(name) = req.session_name.as_deref() else {
        write_ack(&mut send, reject(SessionReason::MissingSessionName)).await?;
        let _ = send.finish();
        return Ok(());
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
    audit::session_event(
        &session,
        "audit.session_attach",
        Some("zmx"),
        Some(name),
        "attach",
        req.user.as_deref(),
        req.cwd.as_deref(),
        req.argv.as_ref(),
    );
    let provider_argv = zmx.attach_argv(name, req.argv.as_deref())?;
    let shell_req = portl_proto::shell_v1::ShellReq {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::shell_v1::ALPN_SHELL_V1).into_owned(),
        },
        mode: portl_proto::shell_v1::ShellMode::Shell,
        argv: Some(provider_argv),
        env_patch: Vec::new(),
        cwd: req.cwd,
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
    }
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

async fn ensure_zmx_selected(
    zmx: &provider::ZmxProvider,
    requested: Option<&str>,
    op: SessionOp,
) -> Result<(), SessionReason> {
    if let Some(provider) = requested
        && provider != "zmx"
    {
        if provider == "raw" {
            return Err(SessionReason::CapabilityUnsupported {
                provider: provider.to_owned(),
                capability: op_name(op).to_owned(),
            });
        }
        return Err(SessionReason::ProviderNotFound(provider.to_owned()));
    }
    let status = zmx
        .probe()
        .await
        .map_err(|err| SessionReason::InternalError(err.to_string()))?;
    if status.available {
        Ok(())
    } else {
        Err(SessionReason::ProviderUnavailable("zmx".to_owned()))
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
        run: None,
        output: None,
    }
}

fn ok_empty() -> SessionAck {
    SessionAck {
        ok: true,
        reason: None,
        session_id: None,
        provider: Some("zmx".to_owned()),
        providers: None,
        sessions: None,
        run: None,
        output: None,
    }
}

fn ok_with_sessions(sessions: Vec<String>) -> SessionAck {
    SessionAck {
        sessions: Some(sessions),
        ..ok_empty()
    }
}
fn ok_with_run(run: portl_proto::session_v1::SessionRunResult) -> SessionAck {
    SessionAck {
        run: Some(run),
        ..ok_empty()
    }
}
fn ok_with_output(output: String) -> SessionAck {
    SessionAck {
        output: Some(output),
        ..ok_empty()
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
