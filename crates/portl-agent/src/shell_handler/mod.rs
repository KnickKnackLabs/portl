use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::AsyncReadExt;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::shell_permits;
use crate::session::Session;
use crate::stream_io::BufferedRecv;

mod exec_capture;
pub(crate) mod pty_master;
pub(crate) mod pumps;
mod reject;
mod shutdown;
pub(crate) mod spawn;
pub(crate) mod user;

pub use exec_capture::ExecCapture;
#[cfg(unix)]
pub use exec_capture::run_exec_capture;
pub(crate) use shutdown::begin_session_shutdown;
#[cfg(unix)]
pub use spawn::spawn_pty_for_test;

use pumps::{pump_exit, pump_output, pump_resizes, pump_signals, pump_stdin};
use shutdown::{ShellSessionGuard, fresh_session_id};
use spawn::spawn_process;
use user::resolve_requested_user;

const MAX_CONTROL_BYTES: usize = 64 * 1024;
const MAX_SIGNAL_BYTES: usize = 1024;
const MAX_RESIZE_BYTES: usize = 1024;
const IO_CHUNK: usize = 16 * 1024;
const SESSION_REAPER_GRACE: std::time::Duration = std::time::Duration::from_secs(5);
const PTY_DRAIN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

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
    let session_id = fresh_session_id();
    let audit_session_id = hex::encode(session_id);
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

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::path::PathBuf;

    #[cfg(unix)]
    #[test]
    fn session_reaper_helper_entrypoint() {
        let Ok(mode) = std::env::var("PORTL_SESSION_REAPER_HELPER") else {
            return;
        };
        let pid_file =
            PathBuf::from(std::env::var("PORTL_SESSION_REAPER_PID_FILE").expect("pid file"));
        match mode.as_str() {
            "double-fork-daemon" => {
                super::shutdown::tests::run_double_fork_daemon_helper(&pid_file);
            }
            other => panic!("unknown session reaper helper mode {other}"),
        }
    }
}
