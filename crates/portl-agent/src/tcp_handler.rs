use std::sync::Arc;

use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, SendStream};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncWriteExt, copy};
use tokio::net::TcpStream;

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::tcp_permits;
use crate::session::Session;
use crate::stream_io::BufferedRecv;

const MAX_TCP_REQ_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TcpReqBody {
    host: String,
    port: u16,
}

pub(crate) async fn serve_stream(
    _connection: Connection,
    session: Session,
    _state: Arc<AgentState>,
    mut send: SendStream,
    mut recv: BufferedRecv,
    preamble: portl_proto::wire::StreamPreamble,
) -> Result<()> {
    let body = recv
        .read_frame::<TcpReqBody>(MAX_TCP_REQ_BYTES)
        .await?
        .context("missing tcp request")?;
    let req = portl_proto::tcp_v1::TcpReq {
        preamble,
        host: body.host,
        port: body.port,
    };

    if req.preamble.peer_token != session.peer_token
        || req.preamble.alpn != String::from_utf8_lossy(portl_proto::tcp_v1::ALPN_TCP_V1)
    {
        bail!("invalid tcp preamble")
    }

    if let Err(error) = tcp_permits(&session.caps, &req) {
        let ack = portl_proto::tcp_v1::TcpAck {
            ok: false,
            error: Some(error.to_owned()),
        };
        send.write_all(&postcard::to_stdvec(&ack)?).await?;
        send.finish().context("finish rejected tcp ack")?;
        return Ok(());
    }

    let tcp = match TcpStream::connect((req.host.as_str(), req.port)).await {
        Ok(tcp) => tcp,
        Err(err) => {
            let ack = portl_proto::tcp_v1::TcpAck {
                ok: false,
                error: Some(err.to_string()),
            };
            send.write_all(&postcard::to_stdvec(&ack)?).await?;
            send.finish().context("finish failed tcp ack")?;
            return Ok(());
        }
    };

    audit::tcp_connect(&session, &req.host, req.port);
    let ack = portl_proto::tcp_v1::TcpAck {
        ok: true,
        error: None,
    };
    send.write_all(&postcard::to_stdvec(&ack)?).await?;

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

    let result = tokio::try_join!(upstream, downstream).map(|_| ());
    audit::tcp_disconnect(&session, &req.host, req.port);
    result
}
