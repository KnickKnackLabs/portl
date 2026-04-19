use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

use super::PeerSession;

const ALPN_TCP_V1: &str = "portl/tcp/v1";
const MAX_TCP_ACK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct StreamPreamble {
    peer_token: [u8; 16],
    alpn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TcpReq {
    preamble: StreamPreamble,
    host: String,
    port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TcpAck {
    ok: bool,
    error: Option<String>,
}

pub async fn open_tcp(
    connection: &Connection,
    session: &PeerSession,
    host: &str,
    port: u16,
) -> Result<(SendStream, RecvStream)> {
    let req = TcpReq {
        preamble: StreamPreamble {
            peer_token: session.peer_token,
            alpn: ALPN_TCP_V1.to_owned(),
        },
        host: host.to_owned(),
        port,
    };
    let (mut send, mut recv) = connection.open_bi().await.context("open tcp stream")?;
    send.write_all(&postcard::to_stdvec(&req).context("encode tcp request")?)
        .await
        .context("write tcp request")?;
    let ack: TcpAck = read_postcard_frame(&mut recv, MAX_TCP_ACK_BYTES).await?;
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
