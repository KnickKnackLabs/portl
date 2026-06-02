use std::net::SocketAddr;
use std::time::{Duration, Instant};

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct TcpForwardStats {
    upstream_bytes: u64,
    downstream_bytes: u64,
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
        let (local, client_addr) = listener
            .accept()
            .await
            .context("accept local tcp connection")?;
        let connection = connection.clone();
        let session = session.clone();
        let remote_host = remote_host.clone();
        let local_addr = local_addr.to_owned();
        tokio::spawn(async move {
            let started = Instant::now();
            eprintln!(
                "[tcp -L {local_addr}] opened client={client_addr} -> remote {remote_host}:{remote_port}"
            );
            match forward_one(local, connection, session, &remote_host, remote_port).await {
                Ok(stats) => eprintln!(
                    "{}",
                    format_close_line(&local_addr, client_addr, started.elapsed(), stats)
                ),
                Err(err) => {
                    eprintln!(
                        "[tcp -L {local_addr}] closed client={client_addr} after {}, error={err}",
                        format_duration(started.elapsed())
                    );
                    tracing::debug!(%err, "tcp forwarding connection failed");
                }
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
) -> Result<TcpForwardStats> {
    let (mut send, mut recv) = open_tcp(&connection, &session, remote_host, remote_port).await?;
    let (mut local_read, mut local_write) = local.into_split();

    let upstream = async {
        let copied = copy(&mut local_read, &mut send)
            .await
            .context("copy local->remote")?;
        send.finish().context("finish remote tcp send")?;
        Ok::<_, anyhow::Error>(copied)
    };
    let downstream = async {
        let copied = copy(&mut recv, &mut local_write)
            .await
            .context("copy remote->local")?;
        local_write
            .shutdown()
            .await
            .context("shutdown local write")?;
        Ok::<_, anyhow::Error>(copied)
    };

    let (upstream_bytes, downstream_bytes) = tokio::try_join!(upstream, downstream)?;
    Ok(TcpForwardStats {
        upstream_bytes,
        downstream_bytes,
    })
}

fn format_close_line(
    local_addr: &str,
    client_addr: SocketAddr,
    elapsed: Duration,
    stats: TcpForwardStats,
) -> String {
    format!(
        "[tcp -L {local_addr}] closed client={client_addr} after {}, up={} down={}",
        format_duration(elapsed),
        format_bytes(stats.upstream_bytes),
        format_bytes(stats.downstream_bytes)
    )
}

fn format_duration(elapsed: Duration) -> String {
    if elapsed.as_secs() >= 1 {
        format!("{:.1}s", elapsed.as_secs_f64())
    } else {
        format!("{}ms", elapsed.as_millis())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    if bytes >= MIB {
        format!("{} MiB", bytes / MIB)
    } else if bytes >= KIB {
        format!("{} KiB", bytes / KIB)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;
    use std::time::Duration;

    use super::{TcpForwardStats, format_close_line};

    #[test]
    fn tcp_close_line_includes_elapsed_and_byte_totals() {
        let client: SocketAddr = "127.0.0.1:52341".parse().unwrap();
        assert_eq!(
            format_close_line(
                "127.0.0.1:8080",
                client,
                Duration::from_millis(3200),
                TcpForwardStats {
                    upstream_bytes: 43 * 1024,
                    downstream_bytes: 181 * 1024,
                },
            ),
            "[tcp -L 127.0.0.1:8080] closed client=127.0.0.1:52341 after 3.2s, up=43 KiB down=181 KiB"
        );
    }
}
