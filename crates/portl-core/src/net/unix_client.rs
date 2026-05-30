use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{UnixListener, UnixStream};

use crate::io::{BufferedRecv, read_postcard_prefix};
use crate::wire::StreamPreamble;
use crate::wire::unix::{ALPN_UNIX_V1, UnixAck, UnixOp, UnixReq, UnixReqTail};

use super::PeerSession;

const MAX_UNIX_ACK_BYTES: usize = 64 * 1024;
const MAX_UNIX_REQ_BYTES: usize = 64 * 1024;
const MAX_UNIX_PREAMBLE_BYTES: usize = 8 * 1024;

pub async fn open_unix(
    connection: &Connection,
    session: &PeerSession,
    path: &str,
) -> Result<(SendStream, BufferedRecv)> {
    let req = unix_req(
        session,
        UnixOp::Connect {
            path: path.to_owned(),
        },
    );
    let (mut send, recv) = connection.open_bi().await.context("open unix stream")?;
    send.write_all(&postcard::to_stdvec(&req).context("encode unix request")?)
        .await
        .context("write unix request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    read_unix_ack(&mut recv, "unix request").await?;
    Ok((send, recv))
}

#[derive(Debug)]
pub struct UnixListenControl {
    pub remote_path: String,
    send: SendStream,
}

impl UnixListenControl {
    pub fn close(mut self) -> Result<()> {
        self.send.finish().context("finish unix listen control")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnixListenOptions {
    pub cleanup: bool,
    pub ssh_agent: bool,
}

pub async fn open_unix_listen(
    connection: &Connection,
    session: &PeerSession,
    path: &str,
    cleanup: bool,
) -> Result<UnixListenControl> {
    open_unix_listen_with_options(
        connection,
        session,
        path,
        UnixListenOptions {
            cleanup,
            ssh_agent: false,
        },
    )
    .await
}

pub async fn open_unix_listen_with_options(
    connection: &Connection,
    session: &PeerSession,
    path: &str,
    options: UnixListenOptions,
) -> Result<UnixListenControl> {
    let req = unix_req(
        session,
        UnixOp::Listen {
            path: path.to_owned(),
            cleanup: options.cleanup,
            ssh_agent: options.ssh_agent,
        },
    );
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open unix listen stream")?;
    send.write_all(&postcard::to_stdvec(&req).context("encode unix listen request")?)
        .await
        .context("write unix listen request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    read_unix_ack(&mut recv, "unix listen request").await?;

    Ok(UnixListenControl {
        remote_path: path.to_owned(),
        send,
    })
}

pub async fn run_local_unix_forward(
    connection: Connection,
    session: PeerSession,
    local_path: String,
    remote_path: String,
    cleanup: bool,
) -> Result<()> {
    let local_path_buf = PathBuf::from(&local_path);
    if cleanup {
        remove_existing_socket_for_bind(&local_path_buf)?;
    }
    let listener = UnixListener::bind(&local_path_buf)
        .with_context(|| format!("bind local unix listener on {local_path}"))?;
    let _cleanup = UnixSocketCleanup {
        path: local_path_buf,
        cleanup,
    };

    loop {
        let (local, _) = listener
            .accept()
            .await
            .context("accept local unix connection")?;
        let connection = connection.clone();
        let session = session.clone();
        let remote_path = remote_path.clone();
        tokio::spawn(async move {
            if let Err(err) = forward_one(local, connection, session, remote_path).await {
                tracing::debug!(%err, "unix forwarding connection failed");
            }
        });
    }
}

async fn forward_one(
    local: UnixStream,
    connection: Connection,
    session: PeerSession,
    remote_path: String,
) -> Result<()> {
    let (send, recv) = open_unix(&connection, &session, &remote_path).await?;
    copy_bidirectional_unix(local, send, recv).await
}

pub async fn run_unix_reverse_forward(
    connection: Connection,
    session: PeerSession,
    remote_path: String,
    local_path: String,
) -> Result<()> {
    loop {
        let Some((local, send, recv)) =
            accept_unix_reverse_connection(&connection, &session, &remote_path, &local_path)
                .await?
        else {
            continue;
        };
        tokio::spawn(async move {
            if let Err(err) = copy_bidirectional_unix(local, send, recv).await {
                tracing::debug!(%err, "reverse unix forwarding connection failed");
            }
        });
    }
}

pub async fn accept_unix_reverse_once(
    connection: &Connection,
    session: &PeerSession,
    remote_path: &str,
    local_path: &str,
) -> Result<()> {
    let Some((local, send, recv)) =
        accept_unix_reverse_connection(connection, session, remote_path, local_path).await?
    else {
        bail!("reverse unix request rejected: connect local unix target")
    };
    copy_bidirectional_unix(local, send, recv).await
}

async fn accept_unix_reverse_connection(
    connection: &Connection,
    session: &PeerSession,
    remote_path: &str,
    local_path: &str,
) -> Result<Option<(UnixStream, SendStream, BufferedRecv)>> {
    let (mut send, recv) = connection
        .accept_bi()
        .await
        .context("accept reverse unix stream")?;
    let (preamble, mut recv) =
        read_postcard_prefix::<StreamPreamble>(recv, MAX_UNIX_PREAMBLE_BYTES)
            .await
            .context("read reverse unix preamble")?;
    let tail = recv
        .read_frame::<UnixReqTail>(MAX_UNIX_REQ_BYTES)
        .await?
        .context("missing reverse unix request")?;
    let req = UnixReq::new(preamble, tail);
    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(ALPN_UNIX_V1)
    {
        write_unix_ack(&mut send, false, Some("invalid unix preamble".to_owned())).await?;
        send.finish().context("finish invalid reverse unix ack")?;
        bail!("invalid reverse unix preamble")
    }
    match &req.op {
        UnixOp::Connect { path } if path == remote_path => {}
        UnixOp::Connect { path } => {
            write_unix_ack(
                &mut send,
                false,
                Some(format!("unexpected reverse unix path {path}")),
            )
            .await?;
            send.finish()
                .context("finish unexpected reverse unix ack")?;
            bail!("unexpected reverse unix path {path}")
        }
        UnixOp::Listen { .. } => {
            write_unix_ack(
                &mut send,
                false,
                Some("unexpected reverse unix listen request".to_owned()),
            )
            .await?;
            send.finish()
                .context("finish unexpected reverse unix ack")?;
            bail!("unexpected reverse unix listen request")
        }
    }

    let local = match UnixStream::connect(local_path).await {
        Ok(local) => local,
        Err(err) => {
            write_unix_ack(&mut send, false, Some(err.to_string())).await?;
            send.finish().context("finish failed reverse unix ack")?;
            tracing::debug!(%err, local_path, "reverse unix local target unavailable");
            return Ok(None);
        }
    };

    write_unix_ack(&mut send, true, None).await?;
    Ok(Some((local, send, recv)))
}

fn unix_req(session: &PeerSession, op: UnixOp) -> UnixReq {
    UnixReq {
        preamble: StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(ALPN_UNIX_V1).into_owned(),
        },
        op,
    }
}

async fn read_unix_ack(recv: &mut BufferedRecv, context: &str) -> Result<()> {
    let ack: UnixAck = recv
        .read_frame(MAX_UNIX_ACK_BYTES)
        .await?
        .context("missing unix ack")?;
    if !ack.ok {
        bail!(
            "{context} rejected: {}",
            ack.error.unwrap_or_else(|| "unknown error".to_owned())
        );
    }
    Ok(())
}

async fn write_unix_ack(send: &mut SendStream, ok: bool, error: Option<String>) -> Result<()> {
    let ack = UnixAck { ok, error };
    send.write_all(&postcard::to_stdvec(&ack).context("encode unix ack")?)
        .await
        .context("write unix ack")
}

struct UnixSocketCleanup {
    path: PathBuf,
    cleanup: bool,
}

impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        if self.cleanup {
            remove_socket_if_present(&self.path);
        }
    }
}

fn remove_existing_socket_for_bind(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .with_context(|| format!("remove stale unix socket {}", path.display())),
        Ok(_) => bail!("refusing to remove non-socket path {}", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat unix socket path {}", path.display())),
    }
}

fn remove_socket_if_present(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
}

async fn copy_bidirectional_unix(
    local: UnixStream,
    mut send: SendStream,
    mut recv: BufferedRecv,
) -> Result<()> {
    let (mut local_read, mut local_write) = local.into_split();
    let upstream = async {
        copy(&mut recv, &mut local_write)
            .await
            .context("copy quic->unix")?;
        local_write
            .shutdown()
            .await
            .context("shutdown unix write")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut local_read, &mut send)
            .await
            .context("copy unix->quic")?;
        send.finish().context("finish unix stream")?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
