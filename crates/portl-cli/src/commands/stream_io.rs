//! Byte streams do not support transparent reconnection or successful truncation.

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, copy};

/// Finish each write half on EOF, but keep reading the other direction.
/// An error ends this bridge; callers must not reuse the local stream with a
/// new destination because the delivered byte offset is unknown.
pub(crate) async fn forward_stream<L, R, W>(
    local: L,
    mut remote_read: R,
    mut remote_write: W,
) -> Result<(u64, u64)>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let (mut local_read, mut local_write) = tokio::io::split(local);
    let upstream = async {
        let bytes = copy(&mut local_read, &mut remote_write)
            .await
            .context("copy local to remote")?;
        remote_write
            .shutdown()
            .await
            .context("finish remote write")?;
        Ok::<_, anyhow::Error>(bytes)
    };
    let downstream = async {
        let bytes = copy(&mut remote_read, &mut local_write)
            .await
            .context("copy remote to local")?;
        local_write.shutdown().await.context("finish local write")?;
        Ok::<_, anyhow::Error>(bytes)
    };
    tokio::try_join!(upstream, downstream)
}

/// A remote exit status is not proof that stdout and stderr have drained.
pub(crate) async fn await_output_task(
    task: tokio::task::JoinHandle<Result<()>>,
    stream_name: &str,
) -> Result<()> {
    task.await
        .with_context(|| format!("join {stream_name} task"))?
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test]
    async fn local_test_pair_connects_without_external_interfaces() {
        let (client, server) = portl_core::test_util::pair().await.unwrap();
        for endpoint in [&client, &server] {
            assert!(
                endpoint
                    .inner()
                    .bound_sockets()
                    .iter()
                    .any(|addr| addr.ip().is_loopback())
            );
        }
        server
            .inner()
            .set_alpns(vec![b"portl/test/loopback".to_vec()]);
        let accept = async { server.inner().accept().await.unwrap().await.unwrap() };
        let dial = async {
            client
                .inner()
                .connect(server.addr(), b"portl/test/loopback")
                .await
                .unwrap()
        };
        let (incoming, outgoing) =
            tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(accept, dial) })
                .await
                .expect("loopback QUIC handshake");
        incoming.close(0u32.into(), b"done");
        outgoing.close(0u32.into(), b"done");
        client.inner().close().await;
        server.inner().close().await;
    }

    #[tokio::test]
    async fn local_half_close_keeps_delayed_response() {
        let (mut client, local) = tokio::io::duplex(64);
        let (remote, mut server) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(remote);
        let bridge = tokio::spawn(forward_stream(local, read, write));
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"request");
        server.write_all(b"response").await.unwrap();
        server.shutdown().await.unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"response");
        assert_eq!(bridge.await.unwrap().unwrap(), (7, 8));
    }

    #[tokio::test]
    async fn remote_half_close_keeps_client_upload() {
        let (mut client, local) = tokio::io::duplex(64);
        let (remote, mut server) = tokio::io::duplex(64);
        let (read, write) = tokio::io::split(remote);
        let bridge = tokio::spawn(forward_stream(local, read, write));
        server.shutdown().await.unwrap();
        assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
        client.write_all(b"upload").await.unwrap();
        client.shutdown().await.unwrap();
        let mut request = Vec::new();
        server.read_to_end(&mut request).await.unwrap();
        assert_eq!(request, b"upload");
        assert_eq!(bridge.await.unwrap().unwrap(), (6, 0));
    }

    #[tokio::test]
    async fn output_drain_waits_beyond_old_truncation_limit() {
        let task = tokio::spawn(async {
            tokio::time::sleep(Duration::from_millis(300)).await;
            anyhow::bail!("late output failure")
        });
        let err = await_output_task(task, "stdout").await.unwrap_err();
        assert!(err.to_string().contains("late output failure"));
    }

    #[tokio::test]
    async fn output_task_failure_is_not_success() {
        let task = tokio::spawn(async { Err(anyhow::anyhow!("broken pipe")) });
        assert!(await_output_task(task, "stderr").await.is_err());
    }
}
