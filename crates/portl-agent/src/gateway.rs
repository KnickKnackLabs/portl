use std::sync::Arc;

use anyhow::{Context, Result, anyhow, bail};
use iroh::endpoint::{Connection, SendStream};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy};
use tokio::net::TcpStream;

use crate::AgentState;
use crate::audit;
use crate::caps_enforce::tcp_permits;
use crate::session::Session;
use crate::stream_io::BufferedRecv;

const MAX_TCP_REQ_BYTES: usize = 64 * 1024;
const MAX_HTTP_HEADER_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
struct TcpReqBody {
    host: String,
    port: u16,
}

pub(crate) async fn serve_stream(
    _connection: Connection,
    session: Session,
    state: Arc<AgentState>,
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
        bail!("invalid tcp preamble");
    }

    let (upstream_url, upstream_host, upstream_port) = match &state.mode {
        crate::AgentMode::Gateway {
            upstream_url,
            upstream_host,
            upstream_port,
        } => (upstream_url.clone(), upstream_host.clone(), *upstream_port),
        crate::AgentMode::Listener => bail!("gateway stream called in listener mode"),
    };

    let forced_req = portl_proto::tcp_v1::TcpReq {
        preamble: req.preamble.clone(),
        host: upstream_host.clone(),
        port: upstream_port,
    };
    if let Err(error) = tcp_permits(&session.caps, &forced_req) {
        reject(&mut send, error).await?;
        return Ok(());
    }
    if req.host != upstream_host || req.port != upstream_port {
        reject(&mut send, "destination restricted by gateway mode").await?;
        return Ok(());
    }

    let Some(bearer) = session.bearer.as_ref().filter(|bearer| !bearer.is_empty()) else {
        reject(&mut send, "gateway mode requires a ticket bearer").await?;
        return Ok(());
    };

    let tcp = match TcpStream::connect((upstream_host.as_str(), upstream_port)).await {
        Ok(tcp) => tcp,
        Err(err) => {
            reject(&mut send, &err.to_string()).await?;
            return Ok(());
        }
    };

    audit::tcp_connect(&session, &upstream_host, upstream_port);
    send.write_all(&postcard::to_stdvec(&portl_proto::tcp_v1::TcpAck {
        ok: true,
        error: None,
    })?)
    .await
    .context("write gateway tcp ack")?;

    let (mut tcp_read, mut tcp_write) = tcp.into_split();
    if !inject_authorization_header(&mut recv, &mut tcp_write, bearer).await? {
        bail!("gateway expected an HTTP/1.1 header block");
    }

    let upstream = async {
        copy(&mut recv, &mut tcp_write)
            .await
            .context("copy quic->gateway tcp")?;
        tcp_write
            .shutdown()
            .await
            .context("shutdown gateway tcp write")?;
        Ok::<_, anyhow::Error>(())
    };
    let downstream = async {
        copy(&mut tcp_read, &mut send)
            .await
            .context("copy gateway tcp->quic")?;
        send.finish().context("finish gateway tcp stream")?;
        Ok::<_, anyhow::Error>(())
    };

    let result = tokio::try_join!(upstream, downstream).map(|_| ());
    audit::tcp_disconnect(&session, &upstream_url, upstream_port);
    result
}

async fn reject(send: &mut SendStream, error: &str) -> Result<()> {
    send.write_all(&postcard::to_stdvec(&portl_proto::tcp_v1::TcpAck {
        ok: false,
        error: Some(error.to_owned()),
    })?)
    .await
    .context("write rejected gateway tcp ack")?;
    send.finish().context("finish rejected gateway tcp ack")?;
    Ok(())
}

async fn read_initial_headers<R>(recv: &mut R) -> Result<Option<Vec<u8>>>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        let read = recv
            .read(&mut byte)
            .await
            .context("read gateway HTTP headers")?;
        if read == 0 {
            return if bytes.is_empty() {
                Ok(None)
            } else {
                Err(anyhow!("gateway expected an HTTP/1.1 header block"))
            };
        }
        bytes.push(byte[0]);
        if bytes.len() > MAX_HTTP_HEADER_BYTES {
            bail!("gateway header block exceeded 65536 bytes")
        }
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(Some(bytes));
        }
    }
}

pub async fn inject_authorization_header<R, W>(
    reader: &mut R,
    writer: &mut W,
    bearer: &[u8],
) -> Result<bool>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Some(headers) = read_initial_headers(reader).await? else {
        return Ok(false);
    };
    let rewritten = rewrite_request_headers(&headers, bearer)?;
    writer
        .write_all(&rewritten)
        .await
        .context("write rewritten upstream headers")?;
    Ok(true)
}

fn rewrite_request_headers(headers: &[u8], bearer: &[u8]) -> Result<Vec<u8>> {
    let request_line_end = headers
        .windows(2)
        .position(|window| window == b"\r\n")
        .context("gateway request line terminator missing")?;
    let request_line = &headers[..request_line_end + 2];
    validate_http11_request_line(request_line)?;

    let header_value = bearer_to_header_value(bearer)?;
    let header_block = &headers[request_line_end + 2..headers.len() - 2];

    let mut rewritten = Vec::with_capacity(headers.len() + 64 + header_value.len());
    rewritten.extend_from_slice(request_line);
    rewritten.extend_from_slice(format!("Authorization: Bearer {header_value}\r\n").as_bytes());
    rewritten.extend_from_slice(b"Connection: close\r\n");
    for line in header_block.split(|byte| *byte == b'\n') {
        if line.is_empty() || line == b"\r" || is_header_named(line, b"connection") {
            continue;
        }
        rewritten.extend_from_slice(line);
        rewritten.extend_from_slice(b"\n");
    }
    rewritten.extend_from_slice(b"\r\n");
    Ok(rewritten)
}

fn is_header_named(line: &[u8], name: &[u8]) -> bool {
    let Some(header_name) = line.split(|byte| *byte == b':').next() else {
        return false;
    };
    header_name.eq_ignore_ascii_case(name)
}

fn bearer_to_header_value(bearer: &[u8]) -> Result<String> {
    let value =
        std::str::from_utf8(bearer).map_err(|_| anyhow!("bearer contains non-UTF-8 bytes"))?;
    if value.is_empty() {
        bail!("bearer is empty");
    }
    for c in value.chars() {
        if !matches!(c, '\x21'..='\x7e') {
            bail!("bearer contains non-printable characters");
        }
    }
    Ok(value.to_owned())
}

fn validate_http11_request_line(line: &[u8]) -> Result<()> {
    let line = std::str::from_utf8(line).context("gateway request line was not utf-8")?;
    if !line.ends_with(" HTTP/1.1\r\n") {
        bail!("gateway requires an HTTP/1.1 request line");
    }
    let trimmed = line.trim_end_matches("\r\n");
    let mut parts = trimmed.split(' ');
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    let version = parts.next().unwrap_or_default();
    if method.is_empty() || target.is_empty() || version != "HTTP/1.1" || parts.next().is_some() {
        bail!("gateway received a malformed HTTP/1.1 request line");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{bearer_to_header_value, rewrite_request_headers, validate_http11_request_line};

    #[test]
    fn accepts_http11_request_line() {
        validate_http11_request_line(b"GET / HTTP/1.1\r\n").expect("valid request line");
    }

    #[test]
    fn rejects_non_http_request_line() {
        let err = validate_http11_request_line(b"\x16\x03\x01\r\n").expect_err("must reject");
        assert!(err.to_string().contains("gateway"));
    }

    #[test]
    fn injects_authorization_header_after_request_line() {
        let rewritten = rewrite_request_headers(
            b"GET / HTTP/1.1\r\nHost: example.test\r\n\r\n",
            b"slicer-token",
        )
        .expect("inject header");
        let rewritten = String::from_utf8(rewritten).expect("utf-8 header block");
        assert!(rewritten.starts_with(
            "GET / HTTP/1.1\r\nAuthorization: Bearer slicer-token\r\nConnection: close\r\nHost: example.test"
        ));
    }

    #[test]
    fn rewrite_request_headers_forces_connection_close() {
        let rewritten = rewrite_request_headers(
            b"GET / HTTP/1.1\r\nHost: example.test\r\nConnection: keep-alive\r\n\r\n",
            b"slicer-token",
        )
        .expect("inject header");
        let rewritten = String::from_utf8(rewritten).expect("utf-8 header block");
        assert!(rewritten.contains("\r\nConnection: close\r\n"));
        assert!(!rewritten.contains("keep-alive"));
    }

    #[test]
    fn bearer_to_header_value_rejects_non_utf8() {
        let err = bearer_to_header_value(&[0xff]).expect_err("must reject non-utf8 bearer");
        assert!(err.to_string().contains("non-UTF-8"));
    }

    #[test]
    fn bearer_to_header_value_rejects_non_printable_characters() {
        let err = bearer_to_header_value(b"bad token")
            .expect_err("must reject whitespace and other non-printable characters");
        assert!(err.to_string().contains("non-printable"));
    }
}
