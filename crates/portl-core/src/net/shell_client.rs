use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};

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
struct ShellReq {
    preamble: StreamPreamble,
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
struct ShellSubPreamble {
    peer_token: [u8; 16],
    alpn: String,
    session_id: [u8; 16],
    kind: ShellStreamKind,
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
    pub control_recv: RecvStream,
    pub stdin: SendStream,
    pub stdout: RecvStream,
    pub stderr: RecvStream,
    pub exit: RecvStream,
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
        let frame: ExitFrame = read_postcard_frame(&mut self.exit, MAX_EXIT_BYTES).await?;
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
    let req = ShellReq {
        preamble: preamble(session, ALPN_SHELL_V1.as_bytes()),
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
    let req = ShellReq {
        preamble: preamble(session, ALPN_SHELL_V1.as_bytes()),
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
    req: ShellReq,
    interactive: bool,
) -> Result<ShellClient> {
    let (mut control_send, mut control_recv) = connection
        .open_bi()
        .await
        .context("open shell control stream")?;
    control_send
        .write_all(&postcard::to_stdvec(&req).context("encode shell request")?)
        .await
        .context("write shell request")?;
    let ack: ShellAck = read_postcard_frame(&mut control_recv, MAX_ACK_BYTES).await?;
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
    let preamble = ShellSubPreamble {
        peer_token: session.peer_token,
        alpn: String::from_utf8_lossy(ALPN_SHELL_V1.as_bytes()).into_owned(),
        session_id,
        kind,
    };
    send.write_all(&postcard::to_stdvec(&preamble).context("encode shell sub-stream preamble")?)
        .await
        .context("write shell sub-stream preamble")?;
    Ok((send, recv))
}

async fn open_recv_stream(
    connection: &Connection,
    session: &PeerSession,
    session_id: [u8; 16],
    kind: ShellStreamKind,
) -> Result<RecvStream> {
    let (mut send, recv) = open_send_stream(connection, session, session_id, kind).await?;
    send.finish()
        .context("finish shell receive sub-stream preamble")?;
    Ok(recv)
}

async fn read_postcard_frame<T>(recv: &mut RecvStream, max_bytes: usize) -> Result<T>
where
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    let mut tmp = [0_u8; 1024];
    loop {
        match postcard::take_from_bytes::<T>(&buf) {
            Ok((value, _)) => return Ok(value),
            Err(postcard::Error::DeserializeUnexpectedEnd) => {
                if buf.len() >= max_bytes {
                    bail!("postcard frame exceeds {max_bytes} bytes");
                }
                match recv.read(&mut tmp).await.context("read postcard frame")? {
                    Some(read) => buf.extend_from_slice(&tmp[..read]),
                    None => bail!("truncated postcard frame"),
                }
            }
            Err(err) => return Err(err).context("decode postcard frame"),
        }
    }
}

fn preamble(session: &PeerSession, alpn: &[u8]) -> StreamPreamble {
    StreamPreamble {
        peer_token: session.peer_token,
        alpn: String::from_utf8_lossy(alpn).into_owned(),
    }
}
