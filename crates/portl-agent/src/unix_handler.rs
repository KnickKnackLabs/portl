use std::os::unix::fs::FileTypeExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::{UnixListener, UnixStream};
use tracing::debug;

use crate::AgentState;
use crate::caps_enforce::unix_permits;
use crate::session::Session;
use crate::stream_io::BufferedRecv;

const MAX_UNIX_REQ_BYTES: usize = 64 * 1024;
const MAX_UNIX_ACK_BYTES: usize = 64 * 1024;

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    _state: Arc<AgentState>,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let tail = recv
        .read_frame::<portl_proto::unix_v1::UnixReqTail>(MAX_UNIX_REQ_BYTES)
        .await?
        .context("missing unix request")?;
    let req = portl_proto::unix_v1::UnixReq::new(preamble, tail);

    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(portl_proto::unix_v1::ALPN_UNIX_V1)
    {
        bail!("invalid unix preamble")
    }

    if let Err(error) = unix_permits(&session.caps, &req) {
        reject(send, error.to_owned()).await?;
        return Ok(());
    }

    match req.op {
        portl_proto::unix_v1::UnixOp::Connect { path } => serve_connect(send, recv, path).await,
        portl_proto::unix_v1::UnixOp::Listen { path, cleanup } => {
            serve_listen(connection, session, send, recv, path, cleanup).await
        }
    }
}

async fn serve_connect(mut send: SendStream, recv: BufferedRecv, path: String) -> Result<()> {
    let unix = match UnixStream::connect(&path).await {
        Ok(unix) => unix,
        Err(err) => {
            write_ack(&mut send, false, Some(err.to_string())).await?;
            send.finish().context("finish failed unix ack")?;
            return Ok(());
        }
    };

    write_ack(&mut send, true, None).await?;
    copy_bidirectional(unix, send, recv).await
}

async fn serve_listen(
    connection: Connection,
    session: Session,
    mut send: SendStream,
    recv: BufferedRecv,
    path: String,
    cleanup: bool,
) -> Result<()> {
    let path_buf = PathBuf::from(&path);
    if cleanup && let Err(err) = remove_existing_socket_for_bind(&path_buf) {
        write_ack(&mut send, false, Some(err.to_string())).await?;
        send.finish()
            .context("finish failed unix listen cleanup ack")?;
        return Ok(());
    }
    let listener = match UnixListener::bind(&path_buf) {
        Ok(listener) => listener,
        Err(err) => {
            write_ack(&mut send, false, Some(err.to_string())).await?;
            send.finish().context("finish failed unix listen ack")?;
            return Ok(());
        }
    };
    let _cleanup = UnixSocketCleanup {
        path: path_buf,
        cleanup,
    };
    write_ack(&mut send, true, None).await?;

    let mut control_task = tokio::spawn(wait_for_control_close(recv));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (unix, _) = accepted.context("accept unix listener connection")?;
                let connection = connection.clone();
                let session = session.clone();
                let path = path.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward_accepted(connection, session, path, unix).await {
                        debug!(%err, "unix reverse forwarding connection failed");
                    }
                });
            }
            result = &mut control_task => {
                result.context("join unix listen control task")??;
                break;
            }
        }
    }
    Ok(())
}

async fn forward_accepted(
    connection: Connection,
    session: Session,
    path: String,
    unix: UnixStream,
) -> Result<()> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open reverse unix stream")?;
    let req = portl_proto::unix_v1::UnixReq {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::unix_v1::ALPN_UNIX_V1).into_owned(),
        },
        op: portl_proto::unix_v1::UnixOp::Connect { path },
    };
    send.write_all(&postcard::to_stdvec(&req).context("encode reverse unix request")?)
        .await
        .context("write reverse unix request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    let ack = recv
        .read_frame::<portl_proto::unix_v1::UnixAck>(MAX_UNIX_ACK_BYTES)
        .await?
        .context("missing reverse unix ack")?;
    if !ack.ok {
        bail!(
            "reverse unix request rejected: {}",
            ack.error.unwrap_or_else(|| "unknown error".to_owned())
        );
    }

    copy_bidirectional(unix, send, recv).await
}

async fn wait_for_control_close(mut recv: BufferedRecv) -> Result<()> {
    let mut buf = [0_u8; 1];
    while recv.read(&mut buf).await? > 0 {}
    Ok(())
}

async fn reject(mut send: SendStream, error: String) -> Result<()> {
    write_ack(&mut send, false, Some(error)).await?;
    send.finish().context("finish rejected unix ack")
}

async fn write_ack(send: &mut SendStream, ok: bool, error: Option<String>) -> Result<()> {
    let ack = portl_proto::unix_v1::UnixAck { ok, error };
    send.write_all(&postcard::to_stdvec(&ack).context("encode unix ack")?)
        .await
        .context("write unix ack")
}

async fn copy_bidirectional(
    unix: UnixStream,
    mut send: SendStream,
    mut recv: BufferedRecv,
) -> Result<()> {
    let (mut unix_read, mut unix_write) = unix.into_split();
    let upstream = async {
        copy(&mut recv, &mut unix_write)
            .await
            .context("copy quic->unix")?;
        unix_write.shutdown().await.context("shutdown unix write")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut unix_read, &mut send)
            .await
            .context("copy unix->quic")?;
        send.finish().context("finish unix stream")?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(upstream, downstream)?;
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::remove_existing_socket_for_bind;

    #[test]
    fn cleanup_refuses_regular_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("not-a-socket");
        std::fs::write(&path, b"do not remove").unwrap();

        let err = remove_existing_socket_for_bind(&path).expect_err("regular files are protected");
        assert!(err.to_string().contains("non-socket"));
        assert_eq!(std::fs::read(&path).unwrap(), b"do not remove");
    }
}
