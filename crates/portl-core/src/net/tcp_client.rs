use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

use crate::io::BufferedRecv;
use crate::wire::StreamPreamble;
use crate::wire::tcp::{ALPN_TCP_V1, TcpAck, TcpReq};

use super::PeerSession;

const MAX_TCP_ACK_BYTES: usize = 64 * 1024;

pub async fn open_tcp(
    connection: &Connection,
    session: &PeerSession,
    host: &str,
    port: u16,
) -> Result<(SendStream, BufferedRecv)> {
    let req = TcpReq {
        preamble: StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(ALPN_TCP_V1).into_owned(),
        },
        host: host.to_owned(),
        port,
    };
    let (mut send, recv) = connection.open_bi().await.context("open tcp stream")?;
    send.write_all(&postcard::to_stdvec(&req).context("encode tcp request")?)
        .await
        .context("write tcp request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    let ack: TcpAck = recv
        .read_frame(MAX_TCP_ACK_BYTES)
        .await?
        .context("missing tcp ack")?;
    if !ack.ok {
        bail!(
            "tcp request rejected: {}",
            ack.error.unwrap_or_else(|| "unknown error".to_owned())
        );
    }
    Ok((send, recv))
}

pub async fn run_local_forward(
    connection: Connection,
    session: PeerSession,
    local_addr: &str,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    let listener = TcpListener::bind(local_addr)
        .await
        .with_context(|| format!("bind local listener on {local_addr}"))?;

    loop {
        let (local, _) = listener
            .accept()
            .await
            .context("accept local tcp connection")?;
        let connection = connection.clone();
        let session = session.clone();
        let remote_host = remote_host.clone();
        tokio::spawn(async move {
            if let Err(err) =
                forward_one(local, connection, session, &remote_host, remote_port).await
            {
                tracing::debug!(%err, "tcp forwarding connection failed");
            }
        });
    }
}

async fn forward_one(
    local: TcpStream,
    connection: Connection,
    session: PeerSession,
    remote_host: &str,
    remote_port: u16,
) -> Result<()> {
    let (mut send, mut recv) = open_tcp(&connection, &session, remote_host, remote_port).await?;
    let (mut local_read, mut local_write) = local.into_split();

    let upstream = async {
        copy(&mut local_read, &mut send)
            .await
            .context("copy local->remote")?;
        send.finish().context("finish remote tcp send")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut recv, &mut local_write)
            .await
            .context("copy remote->local")?;
        local_write
            .shutdown()
            .await
            .context("shutdown local write")?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(upstream, downstream)?;
    Ok(())
}
