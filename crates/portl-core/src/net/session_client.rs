use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};

use crate::io::BufferedRecv;
use crate::net::PeerSession;
use crate::wire::StreamPreamble;
use crate::wire::session::{
    ALPN_SESSION_V1, ProviderReport, SessionAck, SessionEntry, SessionFirstFrame, SessionOp,
    SessionReason, SessionReqBody, SessionRunResult, SessionStreamKind, SessionSubTail,
};
use crate::wire::shell::{ExitFrame, PtyCfg, ResizeFrame, SignalFrame};

const MAX_ACK_BYTES: usize = 256 * 1024;
const MAX_EXIT_BYTES: usize = 1024;

pub struct SessionClient {
    pub control_send: SendStream,
    #[allow(dead_code)]
    pub control_recv: BufferedRecv,
    pub stdin: SendStream,
    pub stdout: BufferedRecv,
    pub stderr: BufferedRecv,
    pub exit: BufferedRecv,
    pub signal: SendStream,
    pub resize: SendStream,
}

impl SessionClient {
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        let frame = ResizeFrame { cols, rows };
        self.resize
            .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
            .await
            .context("write resize frame")?;
        Ok(())
    }

    pub async fn send_signal(&mut self, sig: u8) -> Result<()> {
        let frame = SignalFrame { sig };
        self.signal
            .write_all(&postcard::to_stdvec(&frame).context("encode signal frame")?)
            .await
            .context("write signal frame")?;
        Ok(())
    }

    pub fn close_stdin(&mut self) -> Result<()> {
        self.stdin.finish().context("finish remote stdin")?;
        Ok(())
    }

    pub async fn wait_exit(&mut self) -> Result<i32> {
        let frame: ExitFrame = self
            .exit
            .read_frame(MAX_EXIT_BYTES)
            .await?
            .context("missing exit frame")?;
        Ok(frame.code)
    }
}

pub async fn open_session_providers(
    connection: &Connection,
    session: &PeerSession,
) -> Result<ProviderReport> {
    let ack = request_ack(
        connection,
        session,
        req(SessionOp::Providers, None, None, None),
    )
    .await?;
    ack.providers.context("session providers response missing")
}

pub async fn open_session_list(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
) -> Result<Vec<String>> {
    let ack = request_ack(
        connection,
        session,
        req(SessionOp::List, provider, None, None),
    )
    .await?;
    ack.sessions.context("session list response missing")
}

pub async fn open_session_entries(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
) -> Result<Vec<SessionEntry>> {
    let ack = request_ack(
        connection,
        session,
        req(SessionOp::List, provider, None, None),
    )
    .await?;
    if let Some(entries) = ack.session_entries {
        Ok(entries)
    } else {
        let provider = ack.provider.unwrap_or_else(|| "unknown".to_owned());
        let sessions = ack.sessions.context("session list response missing")?;
        Ok(sessions
            .into_iter()
            .map(|name| SessionEntry {
                provider: provider.clone(),
                name,
            })
            .collect())
    }
}

pub async fn open_session_run(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
    session_name: String,
    argv: Vec<String>,
) -> Result<SessionRunResult> {
    let ack = request_ack(
        connection,
        session,
        req(SessionOp::Run, provider, Some(session_name), Some(argv)),
    )
    .await?;
    ack.run.context("session run response missing")
}

pub async fn open_session_history(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
    session_name: String,
) -> Result<String> {
    let ack = request_ack(
        connection,
        session,
        req(SessionOp::History, provider, Some(session_name), None),
    )
    .await?;
    ack.output.context("session history response missing")
}

pub async fn open_session_kill(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
    session_name: String,
) -> Result<()> {
    let _ack = request_ack(
        connection,
        session,
        req(SessionOp::Kill, provider, Some(session_name), None),
    )
    .await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn open_session_attach(
    connection: &Connection,
    session: &PeerSession,
    provider: Option<String>,
    session_name: String,
    argv: Option<Vec<String>>,
    user: Option<String>,
    cwd: Option<String>,
    pty: PtyCfg,
) -> Result<SessionClient> {
    let (mut control_send, control_recv) = connection
        .open_bi()
        .await
        .context("open session control stream")?;
    control_send
        .write_all(&postcard::to_stdvec(&preamble(session)).context("encode session preamble")?)
        .await
        .context("write session preamble")?;
    control_send
        .write_all(
            &postcard::to_stdvec(&SessionFirstFrame::Control(SessionReqBody {
                op: SessionOp::Attach,
                provider,
                session_name: Some(session_name),
                user,
                cwd,
                argv,
                pty: Some(pty),
            }))
            .context("encode session attach request")?,
        )
        .await
        .context("write session attach request")?;
    let mut control_recv = BufferedRecv::new(control_recv, Vec::new());
    let ack: SessionAck = control_recv
        .read_frame(MAX_ACK_BYTES)
        .await?
        .context("missing session attach ack")?;
    ensure_ok(&ack)?;
    let session_id = ack.session_id.context("session ack missing session id")?;

    let exit = open_recv_stream(connection, session, session_id, SessionStreamKind::Exit).await?;
    let stdout =
        open_recv_stream(connection, session, session_id, SessionStreamKind::Stdout).await?;
    let stderr =
        open_recv_stream(connection, session, session_id, SessionStreamKind::Stderr).await?;
    let (stdin, _) =
        open_send_stream(connection, session, session_id, SessionStreamKind::Stdin).await?;
    let (signal, _) =
        open_send_stream(connection, session, session_id, SessionStreamKind::Signal).await?;
    let (resize, _) =
        open_send_stream(connection, session, session_id, SessionStreamKind::Resize).await?;

    Ok(SessionClient {
        control_send,
        control_recv,
        stdin,
        stdout,
        stderr,
        exit,
        signal,
        resize,
    })
}

async fn request_ack(
    connection: &Connection,
    session: &PeerSession,
    body: SessionReqBody,
) -> Result<SessionAck> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open session control stream")?;
    send.write_all(&postcard::to_stdvec(&preamble(session)).context("encode session preamble")?)
        .await
        .context("write session preamble")?;
    send.write_all(
        &postcard::to_stdvec(&SessionFirstFrame::Control(body))
            .context("encode session request")?,
    )
    .await
    .context("write session request")?;
    send.finish().context("finish session request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    let ack: SessionAck = recv
        .read_frame(MAX_ACK_BYTES)
        .await?
        .context("missing session ack")?;
    ensure_ok(&ack)?;
    Ok(ack)
}

fn req(
    op: SessionOp,
    provider: Option<String>,
    session_name: Option<String>,
    argv: Option<Vec<String>>,
) -> SessionReqBody {
    SessionReqBody {
        op,
        provider,
        session_name,
        user: None,
        cwd: None,
        argv,
        pty: None,
    }
}

fn ensure_ok(ack: &SessionAck) -> Result<()> {
    if ack.ok {
        Ok(())
    } else {
        bail!("{}", session_reason_message(ack.reason.as_ref()))
    }
}

fn session_reason_message(reason: Option<&SessionReason>) -> String {
    match reason {
        Some(SessionReason::CapDenied) => "ticket does not allow persistent sessions".to_owned(),
        Some(SessionReason::ProviderNotFound(provider)) => {
            format!("persistent session provider '{provider}' is not supported by the target")
        }
        Some(SessionReason::ProviderUnavailable(provider)) => {
            format!(
                "{provider} is not installed on the target; try `portl shell <target>` or install {provider} explicitly"
            )
        }
        Some(SessionReason::CapabilityUnsupported {
            provider,
            capability,
        }) => format!("persistent session provider '{provider}' does not support {capability}"),
        Some(SessionReason::MissingSessionName) => "persistent session name is required".to_owned(),
        Some(SessionReason::MissingArgv) => "session run requires a command after --".to_owned(),
        Some(SessionReason::SessionNotFound(name)) => {
            format!("persistent session '{name}' was not found on the target")
        }
        Some(SessionReason::SessionAmbiguous { name, providers }) => {
            format!(
                "persistent session '{name}' exists in multiple providers: {}; rerun with --provider or PORTL_SESSION_PROVIDER",
                providers.join(", ")
            )
        }
        Some(SessionReason::SpawnFailed(message)) => {
            format!("failed to start persistent session provider: {message}")
        }
        Some(SessionReason::InternalError(message)) => {
            format!("persistent session request failed: {message}")
        }
        None => "persistent session request rejected".to_owned(),
    }
}

async fn open_send_stream(
    connection: &Connection,
    session: &PeerSession,
    session_id: [u8; 16],
    kind: SessionStreamKind,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open session sub-stream")?;
    send.write_all(
        &postcard::to_stdvec(&preamble(session)).context("encode session sub preamble")?,
    )
    .await
    .context("write session sub preamble")?;
    send.write_all(
        &postcard::to_stdvec(&SessionFirstFrame::Sub(SessionSubTail { session_id, kind }))
            .context("encode session sub first frame")?,
    )
    .await
    .context("write session sub first frame")?;
    Ok((send, recv))
}

async fn open_recv_stream(
    connection: &Connection,
    session: &PeerSession,
    session_id: [u8; 16],
    kind: SessionStreamKind,
) -> Result<BufferedRecv> {
    let (mut send, recv) = open_send_stream(connection, session, session_id, kind).await?;
    send.finish()
        .context("finish session receive sub-stream preamble")?;
    Ok(BufferedRecv::new(recv, Vec::new()))
}

fn preamble(session: &PeerSession) -> StreamPreamble {
    StreamPreamble {
        peer_token: session.peer_token,
        alpn: String::from_utf8_lossy(ALPN_SESSION_V1).into_owned(),
    }
}
