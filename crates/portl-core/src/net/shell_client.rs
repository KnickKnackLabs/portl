use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize};

use crate::io::BufferedRecv;

use super::PeerSession;

const ALPN_SHELL_V1: &str = "portl/shell/v1";
const MAX_ACK_BYTES: usize = 64 * 1024;
const MAX_EXIT_BYTES: usize = 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StreamPreamble {
    peer_token: [u8; 16],
    alpn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShellReqBody {
    mode: ShellMode,
    argv: Option<Vec<String>>,
    env_patch: Vec<(String, EnvValue)>,
    cwd: Option<String>,
    pty: Option<PtyCfg>,
    user: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum ShellMode {
    Shell,
    Exec,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PtyCfg {
    pub term: String,
    pub cols: u16,
    pub rows: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum EnvValue {
    Set(String),
    Unset,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShellAck {
    ok: bool,
    reason: Option<ShellReason>,
    pid: Option<u32>,
    session_id: Option<[u8; 16]>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ShellReason {
    CapDenied,
    BadUser(String),
    SpawnFailed(String),
    InvalidPty,
    NotFound,
    InternalError(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ShellStreamKind {
    Stdin,
    Stdout,
    Stderr,
    Signal,
    Resize,
    Exit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ShellSubTail {
    session_id: [u8; 16],
    kind: ShellStreamKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
enum ShellFirstFrame {
    Control(ShellReqBody),
    Sub(ShellSubTail),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ResizeFrame {
    cols: u16,
    rows: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct SignalFrame {
    sig: u8,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct ExitFrame {
    code: i32,
}

pub struct ShellClient {
    pub control_send: SendStream,
    #[allow(dead_code)]
    pub control_recv: BufferedRecv,
    pub stdin: SendStream,
    pub stdout: BufferedRecv,
    pub stderr: BufferedRecv,
    pub exit: BufferedRecv,
    pub signal: Option<SendStream>,
    pub resize: Option<SendStream>,
}

impl ShellClient {
    pub async fn resize(&mut self, cols: u16, rows: u16) -> Result<()> {
        let Some(resize) = self.resize.as_mut() else {
            bail!("resize stream is unavailable for exec sessions")
        };
        let frame = ResizeFrame { cols, rows };
        resize
            .write_all(&postcard::to_stdvec(&frame).context("encode resize frame")?)
            .await
            .context("write resize frame")?;
        Ok(())
    }

    pub async fn send_signal(&mut self, sig: u8) -> Result<()> {
        let Some(signal) = self.signal.as_mut() else {
            bail!("signal stream is unavailable for exec sessions")
        };
        let frame = SignalFrame { sig };
        signal
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

    pub fn control_send_mut(&mut self) -> &mut SendStream {
        &mut self.control_send
    }
}

pub async fn open_shell(
    connection: &Connection,
    session: &PeerSession,
    user: Option<String>,
    cwd: Option<String>,
    pty: PtyCfg,
) -> Result<ShellClient> {
    let req = ShellReqBody {
        mode: ShellMode::Shell,
        argv: None,
        env_patch: Vec::new(),
        cwd,
        pty: Some(pty),
        user,
    };
    open_shell_session(connection, session, req, true).await
}

pub async fn open_exec(
    connection: &Connection,
    session: &PeerSession,
    user: Option<String>,
    cwd: Option<String>,
    argv: Vec<String>,
) -> Result<ShellClient> {
    let req = ShellReqBody {
        mode: ShellMode::Exec,
        argv: Some(argv),
        env_patch: Vec::new(),
        cwd,
        pty: None,
        user,
    };
    open_shell_session(connection, session, req, false).await
}

async fn open_shell_session(
    connection: &Connection,
    session: &PeerSession,
    req: ShellReqBody,
    interactive: bool,
) -> Result<ShellClient> {
    let (mut control_send, control_recv) = connection
        .open_bi()
        .await
        .context("open shell control stream")?;
    control_send
        .write_all(
            &postcard::to_stdvec(&preamble(session, ALPN_SHELL_V1.as_bytes()))
                .context("encode shell request preamble")?,
        )
        .await
        .context("write shell request preamble")?;
    control_send
        .write_all(
            &postcard::to_stdvec(&ShellFirstFrame::Control(req)).context("encode shell request")?,
        )
        .await
        .context("write shell request")?;
    let mut control_recv = BufferedRecv::new(control_recv, Vec::new());
    let ack: ShellAck = control_recv
        .read_frame(MAX_ACK_BYTES)
        .await?
        .context("missing shell ack")?;
    if !ack.ok {
        bail!("shell request rejected: {:?}", ack.reason);
    }
    let session_id = ack.session_id.context("shell ack missing session id")?;

    let (stdin, _) =
        open_send_stream(connection, session, session_id, ShellStreamKind::Stdin).await?;
    let stdout = open_recv_stream(connection, session, session_id, ShellStreamKind::Stdout).await?;
    let stderr = open_recv_stream(connection, session, session_id, ShellStreamKind::Stderr).await?;
    let exit = open_recv_stream(connection, session, session_id, ShellStreamKind::Exit).await?;
    let signal = if interactive {
        Some(
            open_send_stream(connection, session, session_id, ShellStreamKind::Signal)
                .await?
                .0,
        )
    } else {
        None
    };
    let resize = if interactive {
        Some(
            open_send_stream(connection, session, session_id, ShellStreamKind::Resize)
                .await?
                .0,
        )
    } else {
        None
    };

    Ok(ShellClient {
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

async fn open_send_stream(
    connection: &Connection,
    session: &PeerSession,
    session_id: [u8; 16],
    kind: ShellStreamKind,
) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open shell sub-stream")?;
    send.write_all(
        &postcard::to_stdvec(&preamble(session, ALPN_SHELL_V1.as_bytes()))
            .context("encode shell sub-stream preamble")?,
    )
    .await
    .context("write shell sub-stream preamble")?;
    send.write_all(
        &postcard::to_stdvec(&ShellFirstFrame::Sub(ShellSubTail { session_id, kind }))
            .context("encode shell sub-stream first frame")?,
    )
    .await
    .context("write shell sub-stream first frame")?;
    Ok((send, recv))
}

async fn open_recv_stream(
    connection: &Connection,
    session: &PeerSession,
    session_id: [u8; 16],
    kind: ShellStreamKind,
) -> Result<BufferedRecv> {
    let (mut send, recv) = open_send_stream(connection, session, session_id, kind).await?;
    send.finish()
        .context("finish shell receive sub-stream preamble")?;
    Ok(BufferedRecv::new(recv, Vec::new()))
}

fn preamble(session: &PeerSession, alpn: &[u8]) -> StreamPreamble {
    StreamPreamble {
        peer_token: session.peer_token,
        alpn: String::from_utf8_lossy(alpn).into_owned(),
    }
}
