use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use portl_core::net::stream_priority;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy};
use tokio::net::{TcpListener, TcpStream};

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::{tcp_listen_permits, tcp_permits};
use crate::session::Session;
use crate::stream_io::BufferedRecv;

const MAX_TCP_REQ_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TcpReqBody {
    host: String,
    port: u16,
}

pub(crate) async fn serve_stream(
    connection: Connection,
    session: Session,
    _state: Arc<AgentState>,
    send: SendStream,
    recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    if preamble.peer_token != session.peer_token {
        bail!("invalid tcp preamble")
    }

    match preamble.alpn.as_str() {
        value if value == String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1) => {
            serve_v1_connect(session, send, recv, preamble).await
        }
        value if value == String::from_utf8_lossy(portl_proto::tcp_v2::ALPN_TCP_V2) => {
            serve_v2(connection, session, send, recv, preamble).await
        }
        _ => bail!("invalid tcp preamble"),
    }
}

async fn serve_v1_connect(
    session: Session,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let body = recv
        .read_frame::<TcpReqBody>(MAX_TCP_REQ_BYTES)
        .await?
        .context("missing tcp request")?;
    serve_connect(session, send, recv, preamble, body.host, body.port).await
}

async fn serve_v2(
    connection: Connection,
    session: Session,
    send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let tail = recv
        .read_frame::<portl_proto::tcp_v2::TcpReqV2Tail>(MAX_TCP_REQ_BYTES)
        .await?
        .context("missing tcp v2 request")?;
    let req = portl_proto::tcp_v2::TcpReqV2::new(preamble, tail);
    match req.op {
        portl_proto::tcp_v2::TcpOp::Connect { host, port } => {
            serve_connect(session, send, recv, req.preamble, host, port).await
        }
        portl_proto::tcp_v2::TcpOp::Listen {
            bind_host,
            bind_port,
        } => serve_listen(connection, session, send, recv, bind_host, bind_port).await,
        portl_proto::tcp_v2::TcpOp::Accepted { .. } => {
            let mut send = send;
            write_ack(
                &mut send,
                false,
                Some("client may not send tcp accepted requests".to_owned()),
            )
            .await?;
            send.finish().context("finish invalid tcp accepted ack")
        }
    }
}

async fn serve_connect(
    session: Session,
    mut send: SendStream,
    recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
    host: String,
    port: u16,
) -> Result<()> {
    stream_priority::apply(&send, stream_priority::forward());
    let req = portl_proto::tcp_v1::TcpReq {
        preamble,
        host,
        port,
    };

    if let Err(error) = tcp_permits(&session.caps, &req) {
        write_ack(&mut send, false, Some(error.to_owned())).await?;
        send.finish().context("finish rejected tcp ack")?;
        return Ok(());
    }

    let tcp = match TcpStream::connect((req.host.as_str(), req.port)).await {
        Ok(tcp) => tcp,
        Err(err) => {
            write_ack(&mut send, false, Some(err.to_string())).await?;
            send.finish().context("finish failed tcp ack")?;
            return Ok(());
        }
    };

    audit::tcp_connect(&session, &req.host, req.port);
    write_ack(&mut send, true, None).await?;
    let result = copy_bidirectional_tcp(tcp, send, recv).await;
    audit::tcp_disconnect(&session, &req.host, req.port);
    result
}

async fn serve_listen(
    connection: Connection,
    session: Session,
    mut send: SendStream,
    recv: BufferedRecv,
    bind_host: String,
    bind_port: u16,
) -> Result<()> {
    stream_priority::apply(&send, stream_priority::forward());
    if let Err(error) = tcp_listen_permits(&session.caps, &bind_host, bind_port) {
        write_listen_ack(&mut send, false, Some(error.to_owned()), None).await?;
        send.finish().context("finish rejected tcp listen ack")?;
        return Ok(());
    }
    let listener = match TcpListener::bind((bind_host.as_str(), bind_port)).await {
        Ok(listener) => listener,
        Err(err) => {
            write_listen_ack(&mut send, false, Some(err.to_string()), None).await?;
            send.finish().context("finish failed tcp listen ack")?;
            return Ok(());
        }
    };
    let bound_port = listener.local_addr()?.port();
    write_listen_ack(&mut send, true, None, Some(bound_port)).await?;

    let mut control_task = tokio::spawn(wait_for_control_close(recv));
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let (tcp, originator) = accepted.context("accept tcp listener connection")?;
                let connection = connection.clone();
                let session = session.clone();
                let bind_host = bind_host.clone();
                tokio::spawn(async move {
                    if let Err(err) = forward_accepted(connection, session, bind_host, bound_port, tcp, originator).await {
                        tracing::debug!(%err, "tcp reverse forwarding connection failed");
                    }
                });
            }
            result = &mut control_task => {
                result.context("join tcp listen control task")??;
                break;
            }
        }
    }
    Ok(())
}

async fn forward_accepted(
    connection: Connection,
    session: Session,
    bind_host: String,
    bind_port: u16,
    tcp: TcpStream,
    originator: std::net::SocketAddr,
) -> Result<()> {
    let (mut send, recv) = connection
        .open_bi()
        .await
        .context("open reverse tcp stream")?;
    let req = portl_proto::tcp_v2::TcpReqV2 {
        preamble: portl_proto::wire::StreamPreamble {
            peer_token: session.peer_token,
            alpn: String::from_utf8_lossy(portl_proto::tcp_v2::ALPN_TCP_V2).into_owned(),
        },
        op: portl_proto::tcp_v2::TcpOp::Accepted {
            bind_host,
            bind_port,
            originator_host: originator.ip().to_string(),
            originator_port: originator.port(),
        },
    };
    send.write_all(&postcard::to_stdvec(&req).context("encode reverse tcp request")?)
        .await
        .context("write reverse tcp request")?;
    let mut recv = BufferedRecv::new(recv, Vec::new());
    let ack = recv
        .read_frame::<portl_proto::tcp_v1::TcpAck>(MAX_TCP_REQ_BYTES)
        .await?
        .context("missing reverse tcp ack")?;
    if !ack.ok {
        bail!(
            "reverse tcp request rejected: {}",
            ack.error.unwrap_or_else(|| "unknown error".to_owned())
        );
    }

    copy_bidirectional_tcp(tcp, send, recv).await
}

async fn copy_bidirectional_tcp(
    tcp: TcpStream,
    mut send: SendStream,
    mut recv: BufferedRecv,
) -> Result<()> {
    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    let upstream = async {
        copy(&mut recv, &mut tcp_write)
            .await
            .context("copy quic->tcp")?;
        tcp_write.shutdown().await.context("shutdown tcp write")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut tcp_read, &mut send)
            .await
            .context("copy tcp->quic")?;
        send.finish().context("finish tcp stream")?;
        Ok::<_, anyhow::Error>(())
    };

    tokio::try_join!(upstream, downstream)?;
    Ok(())
}

async fn wait_for_control_close(mut recv: BufferedRecv) -> Result<()> {
    let mut buf = [0_u8; 1];
    while recv.read(&mut buf).await? > 0 {}
    Ok(())
}

async fn write_ack(send: &mut SendStream, ok: bool, error: Option<String>) -> Result<()> {
    let ack = portl_proto::tcp_v1::TcpAck { ok, error };
    send.write_all(&postcard::to_stdvec(&ack).context("encode tcp ack")?)
        .await
        .context("write tcp ack")
}

async fn write_listen_ack(
    send: &mut SendStream,
    ok: bool,
    error: Option<String>,
    bound_port: Option<u16>,
) -> Result<()> {
    let ack = portl_proto::tcp_v2::TcpListenAck {
        ok,
        error,
        bound_port,
    };
    send.write_all(&postcard::to_stdvec(&ack).context("encode tcp listen ack")?)
        .await
        .context("write tcp listen ack")
}
