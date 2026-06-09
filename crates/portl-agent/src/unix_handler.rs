use std::os::unix::fs::{DirBuilderExt, FileTypeExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use portl_core::net::stream_priority;
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

    let priority = match &req.op {
        portl_proto::unix_v1::UnixOp::Listen {
            ssh_agent: true, ..
        } => stream_priority::INTERACTIVE,
        portl_proto::unix_v1::UnixOp::Connect { .. }
        | portl_proto::unix_v1::UnixOp::Listen { .. } => stream_priority::forward(),
    };
    stream_priority::apply(&send, priority);

    if let Err(error) = unix_permits(&session.caps, &req) {
        reject(send, error.to_owned()).await?;
        return Ok(());
    }

    match req.op {
        portl_proto::unix_v1::UnixOp::Connect { path } => serve_connect(send, recv, path).await,
        portl_proto::unix_v1::UnixOp::Listen {
            path,
            cleanup,
            ssh_agent,
        } => serve_listen(connection, session, send, recv, path, cleanup, ssh_agent).await,
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

#[allow(clippy::too_many_arguments)]
async fn serve_listen(
    connection: Connection,
    session: Session,
    mut send: SendStream,
    recv: BufferedRecv,
    path: String,
    cleanup: bool,
    ssh_agent: bool,
) -> Result<()> {
    let path_buf = PathBuf::from(&path);
    if ssh_agent && !cleanup {
        write_ack(
            &mut send,
            false,
            Some("ssh-agent forwarding listen requires cleanup".to_owned()),
        )
        .await?;
        send.finish()
            .context("finish failed ssh-agent cleanup-required ack")?;
        return Ok(());
    }
    let parent_cleanup = if ssh_agent {
        match create_private_agent_parent(&path_buf) {
            Ok(cleanup) => Some(cleanup),
            Err(err) => {
                write_ack(&mut send, false, Some(err.to_string())).await?;
                send.finish()
                    .context("finish failed ssh-agent listen setup ack")?;
                return Ok(());
            }
        }
    } else {
        match ensure_generated_forward_parent(&path_buf) {
            Ok(cleanup) => cleanup,
            Err(err) => {
                write_ack(&mut send, false, Some(err.to_string())).await?;
                send.finish()
                    .context("finish failed generated unix listen setup ack")?;
                return Ok(());
            }
        }
    };
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
    let _parent_cleanup = parent_cleanup;
    let _cleanup = UnixSocketCleanup {
        path: path_buf,
        cleanup,
    };
    if ssh_agent {
        crate::audit::ssh_agent_forward_enabled(&session, &path);
    }
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

struct AgentParentCleanup {
    path: PathBuf,
}

impl Drop for UnixSocketCleanup {
    fn drop(&mut self) {
        if self.cleanup {
            remove_socket_if_present(&self.path);
        }
    }
}

impl Drop for AgentParentCleanup {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir(&self.path);
    }
}

fn create_private_agent_parent(path: &Path) -> Result<AgentParentCleanup> {
    let parent = path
        .parent()
        .context("ssh-agent socket path must include a parent directory")?;
    validate_agent_parent(parent)?;
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(parent)
        .with_context(|| format!("create ssh-agent forwarding directory {}", parent.display()))?;
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("chmod ssh-agent forwarding directory {}", parent.display()))?;
    let metadata = std::fs::symlink_metadata(parent)
        .with_context(|| format!("stat ssh-agent forwarding directory {}", parent.display()))?;
    if !metadata.file_type().is_dir() {
        bail!(
            "ssh-agent forwarding parent is not a directory {}",
            parent.display()
        );
    }
    if metadata.permissions().mode() & 0o777 != 0o700 {
        bail!(
            "ssh-agent forwarding directory has unsafe permissions {}",
            parent.display()
        );
    }
    Ok(AgentParentCleanup {
        path: parent.to_path_buf(),
    })
}

fn ensure_generated_forward_parent(path: &Path) -> Result<Option<AgentParentCleanup>> {
    let Some(parent) = path.parent() else {
        return Ok(None);
    };
    if !is_generated_forward_parent(parent) {
        return Ok(None);
    }
    match std::fs::symlink_metadata(parent) {
        Ok(metadata) => validate_generated_forward_parent_type(parent, &metadata)?,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(parent)
                .with_context(|| {
                    format!(
                        "create generated unix forwarding directory {}",
                        parent.display()
                    )
                })?;
        }
        Err(err) => {
            return Err(err).with_context(|| {
                format!(
                    "stat generated unix forwarding directory {}",
                    parent.display()
                )
            });
        }
    }
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
        || {
            format!(
                "chmod generated unix forwarding directory {}",
                parent.display()
            )
        },
    )?;
    let metadata = std::fs::symlink_metadata(parent).with_context(|| {
        format!(
            "stat generated unix forwarding directory {}",
            parent.display()
        )
    })?;
    validate_generated_forward_parent_metadata(parent, &metadata)?;
    Ok(Some(AgentParentCleanup {
        path: parent.to_path_buf(),
    }))
}

fn validate_generated_forward_parent_type(
    parent: &Path,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    if !metadata.file_type().is_dir() {
        bail!(
            "generated unix forwarding parent is not a directory {}",
            parent.display()
        );
    }
    Ok(())
}

fn validate_generated_forward_parent_metadata(
    parent: &Path,
    metadata: &std::fs::Metadata,
) -> Result<()> {
    validate_generated_forward_parent_type(parent, metadata)?;
    if metadata.permissions().mode() & 0o777 != 0o700 {
        bail!(
            "generated unix forwarding directory has unsafe permissions {}",
            parent.display()
        );
    }
    Ok(())
}

fn is_generated_forward_parent(parent: &Path) -> bool {
    let Some(name) = parent.file_name().and_then(|name| name.to_str()) else {
        return false;
    };
    parent.parent() == Some(Path::new("/tmp")) && name.starts_with("portl-from-")
}

fn validate_agent_parent(parent: &Path) -> Result<()> {
    let Some(name) = parent.file_name().and_then(|name| name.to_str()) else {
        bail!("ssh-agent forwarding parent must have a utf-8 name");
    };
    if parent.parent() != Some(Path::new("/tmp")) || !name.starts_with("portl-agent-") {
        bail!("ssh-agent forwarding parent must be /tmp/portl-agent-*");
    }
    let suffix = &name["portl-agent-".len()..];
    if suffix.is_empty() || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("ssh-agent forwarding parent suffix must be hex");
    }
    Ok(())
}

fn remove_existing_socket_for_bind(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => {
            if unix_socket_is_active(path) {
                bail!("unix socket is already active: {}", path.display());
            }
            std::fs::remove_file(path)
                .with_context(|| format!("remove stale unix socket {}", path.display()))
        }
        Ok(_) => bail!("refusing to remove non-socket path {}", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("stat unix socket path {}", path.display())),
    }
}

fn unix_socket_is_active(path: &Path) -> bool {
    StdUnixStream::connect(path).is_ok()
}

fn remove_socket_if_present(path: &Path) {
    if std::fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_socket()) {
        let _ = std::fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixListener;

    use super::{ensure_generated_forward_parent, remove_existing_socket_for_bind};

    #[test]
    fn generated_forward_parent_is_created_private() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::path::PathBuf::from("/tmp")
            .join(format!("portl-from-test-{}-{unique}", std::process::id()));
        let path = parent.join("agent.sock");

        let cleanup = ensure_generated_forward_parent(&path)
            .unwrap()
            .expect("generated parent should return cleanup guard");

        let metadata = std::fs::symlink_metadata(&parent).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        drop(cleanup);
        assert!(!parent.exists());
    }

    #[test]
    fn generated_forward_parent_tightens_existing_directory_permissions() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let parent = std::path::PathBuf::from("/tmp").join(format!(
            "portl-from-existing-dir-test-{}-{unique}",
            std::process::id()
        ));
        std::fs::create_dir(&parent).unwrap();
        std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o755)).unwrap();
        let path = parent.join("agent.sock");

        let cleanup = ensure_generated_forward_parent(&path)
            .unwrap()
            .expect("generated parent should return cleanup guard");

        let metadata = std::fs::symlink_metadata(&parent).unwrap();
        assert!(metadata.file_type().is_dir());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
        drop(cleanup);
        assert!(!parent.exists());
    }

    #[test]
    fn generated_forward_parent_rejects_symlink_without_chmod_target() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let target = tempfile::tempdir().unwrap();
        std::fs::set_permissions(target.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let parent = std::path::PathBuf::from("/tmp").join(format!(
            "portl-from-symlink-test-{}-{unique}",
            std::process::id()
        ));
        std::os::unix::fs::symlink(target.path(), &parent).unwrap();
        let path = parent.join("agent.sock");

        let Err(err) = ensure_generated_forward_parent(&path) else {
            panic!("generated parent symlink should be rejected before chmod");
        };
        assert!(err.to_string().contains("not a directory"), "{err}");
        let target_mode = std::fs::symlink_metadata(target.path())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(target_mode, 0o755);
        std::fs::remove_file(parent).unwrap();
    }

    #[test]
    fn cleanup_refuses_active_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("active.sock");
        let _listener = UnixListener::bind(&path).unwrap();

        let err = remove_existing_socket_for_bind(&path).expect_err("active sockets are protected");
        assert!(err.to_string().contains("already active"), "{err}");
        assert!(path.exists());
    }

    #[test]
    fn cleanup_removes_stale_socket() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("stale.sock");
        let listener = UnixListener::bind(&path).unwrap();
        drop(listener);

        remove_existing_socket_for_bind(&path).unwrap();
        assert!(!path.exists());
    }

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
