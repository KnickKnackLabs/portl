use std::net::SocketAddr;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

use crate::io::BufferedRecv;
use crate::wire::StreamPreamble;
use crate::wire::tcp::{ALPN_TCP_V1, TcpAck, TcpReq};

use super::{PeerSession, stream_priority};

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
    stream_priority::apply(&send, stream_priority::forward());
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpForwardStats {
    pub upstream_bytes: u64,
    pub downstream_bytes: u64,
}

pub async fn bind_local_forward_listener(local_addr: &str) -> Result<TcpListener> {
    TcpListener::bind(local_addr)
        .await
        .with_context(|| format!("bind local listener on {local_addr}"))
}

pub async fn run_local_forward(
    connection: Connection,
    session: PeerSession,
    local_addr: &str,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    let listener = bind_local_forward_listener(local_addr).await?;
    run_local_forward_with_listener(
        listener,
        connection,
        session,
        local_addr.to_owned(),
        remote_host,
        remote_port,
    )
    .await
}

pub async fn run_local_forward_with_listener(
    listener: TcpListener,
    connection: Connection,
    session: PeerSession,
    local_addr: String,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    run_local_forward_with_listener_logged(
        listener,
        connection,
        session,
        local_addr,
        remote_host,
        remote_port,
        true,
    )
    .await
}

pub async fn run_local_forward_with_listener_quiet(
    listener: TcpListener,
    connection: Connection,
    session: PeerSession,
    local_addr: String,
    remote_host: String,
    remote_port: u16,
) -> Result<()> {
    run_local_forward_with_listener_logged(
        listener,
        connection,
        session,
        local_addr,
        remote_host,
        remote_port,
        false,
    )
    .await
}

async fn run_local_forward_with_listener_logged(
    listener: TcpListener,
    connection: Connection,
    session: PeerSession,
    local_addr: String,
    remote_host: String,
    remote_port: u16,
    log_to_stderr: bool,
) -> Result<()> {
    loop {
        let (local, client_addr) = listener
            .accept()
            .await
            .context("accept local tcp connection")?;
        let connection = connection.clone();
        let session = session.clone();
        let remote_host = remote_host.clone();
        let local_addr = local_addr.clone();
        tokio::spawn(async move {
            let started = Instant::now();
            let open_line = format!(
                "[tcp -L {local_addr}] opened client={client_addr} -> remote {remote_host}:{remote_port}"
            );
            log_forward_line(log_to_stderr, &open_line);
            match forward_one(local, connection, session, &remote_host, remote_port).await {
                Ok(stats) => log_forward_line(
                    log_to_stderr,
                    &format_close_line(&local_addr, client_addr, started.elapsed(), stats),
                ),
                Err(err) => {
                    let close_line = format!(
                        "[tcp -L {local_addr}] closed client={client_addr} after {}, error={err}",
                        format_duration(started.elapsed())
                    );
                    log_forward_line(log_to_stderr, &close_line);
                    tracing::debug!(%err, "tcp forwarding connection failed");
                }
            }
        });
    }
}

fn log_forward_line(log_to_stderr: bool, line: &str) {
    if log_to_stderr {
        eprintln!("{line}");
    } else {
        tracing::info!(message = line, "tcp forwarding event");
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

pub fn format_close_line(
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

    use super::{TcpForwardStats, bind_local_forward_listener, format_close_line};

    #[tokio::test]
    async fn tcp_forward_listener_bind_fails_when_addr_is_in_use() {
        let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = occupied.local_addr().unwrap().to_string();

        let err = bind_local_forward_listener(&addr)
            .await
            .expect_err("occupied local port should fail before session starts");
        assert!(err.to_string().contains("bind local listener"), "{err}");
    }

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
