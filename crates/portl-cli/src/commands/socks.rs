use std::net::{Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use portl_core::net::tcp_client::TcpForwardStats;
use portl_core::net::{PeerSession, open_tcp};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use super::network_lifecycle;
use super::stream_io::forward_stream;

const SUCCESS: u8 = 0x00;
const GENERAL_FAILURE: u8 = 0x01;
const NETWORK_UNREACHABLE: u8 = 0x03;
const HOST_UNREACHABLE: u8 = 0x04;
const CONNECTION_REFUSED: u8 = 0x05;
const COMMAND_UNSUPPORTED: u8 = 0x07;
const ADDRESS_UNSUPPORTED: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DynamicForwardSpec {
    bind: String,
    local_port: u16,
}

impl DynamicForwardSpec {
    pub(crate) fn local_addr(&self) -> String {
        format!("{}:{}", self.bind, self.local_port)
    }
}

pub(crate) fn parse_dynamic_spec(spec: &str) -> Result<DynamicForwardSpec> {
    let (bind, port) = if let Some(ipv6) = spec.strip_prefix('[') {
        let (host, port) = ipv6
            .split_once("]:")
            .with_context(|| format!("invalid -D spec: {spec}"))?;
        host.parse::<Ipv6Addr>()
            .context("parse -D IPv6 bind address")?;
        (&spec[..host.len() + 2], port)
    } else if let Some((bind, port)) = spec.split_once(':') {
        if bind.is_empty() || port.contains(':') {
            bail!("invalid -D spec: {spec}; bracket IPv6 bind addresses");
        }
        (bind, port)
    } else {
        ("127.0.0.1", spec)
    };
    Ok(DynamicForwardSpec {
        bind: bind.to_owned(),
        local_port: port.parse().context("parse -D local port")?,
    })
}

#[derive(Debug, PartialEq, Eq)]
struct ConnectRequest {
    host: String,
    port: u16,
}

#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct RejectedRequest {
    reply: u8,
    message: &'static str,
}

pub(crate) async fn forward_client(
    mut local: TcpStream,
    peer: Option<(&Connection, &PeerSession)>,
) -> Result<TcpForwardStats> {
    // Snapshot the peer at accept time. Offline clients never wait for a future
    // generation, and an established byte stream is never replayed on reconnect.
    let request = network_lifecycle::setup("SOCKS5 handshake", async {
        negotiate_no_auth(&mut local).await?;
        match read_connect_request(&mut local).await {
            Ok(request) => Ok(request),
            Err(error) => {
                write_reply(&mut local, reply_for_error(&error)).await?;
                Err(error)
            }
        }
    })
    .await?;
    // While the peer reconnects, answer with a SOCKS failure at once so the
    // client fails fast instead of seeing a bare close or waiting on setup.
    let Some((connection, session)) =
        peer.filter(|(connection, _)| connection.close_reason().is_none())
    else {
        write_reply(&mut local, NETWORK_UNREACHABLE).await?;
        bail!("forward unavailable while peer reconnects");
    };
    let (send, recv) = match network_lifecycle::setup(
        "SOCKS5 TCP forward setup",
        open_tcp(connection, session, &request.host, request.port),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            write_reply(&mut local, reply_for_error(&error)).await?;
            return Err(error);
        }
    };
    // open_tcp returns only after the agent has accepted and connected the
    // destination. Domains remain untouched so resolution happens at the agent.
    write_reply(&mut local, SUCCESS).await?;
    let (upstream_bytes, downstream_bytes) = forward_stream(local, recv, send).await?;
    Ok(TcpForwardStats {
        upstream_bytes,
        downstream_bytes,
    })
}

async fn negotiate_no_auth<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0; 2];
    stream
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 greeting")?;
    if header[0] != 5 {
        bail!("unsupported SOCKS version");
    }
    let mut methods = [0; 255];
    let methods = &mut methods[..usize::from(header[1])];
    stream
        .read_exact(methods)
        .await
        .context("read SOCKS5 methods")?;
    let method = if methods.contains(&0) { 0 } else { 0xff };
    stream
        .write_all(&[5, method])
        .await
        .context("write SOCKS5 method")?;
    if method == 0xff {
        bail!("SOCKS5 client did not offer no-auth authentication");
    }
    Ok(())
}

async fn read_connect_request<S: AsyncRead + Unpin>(stream: &mut S) -> Result<ConnectRequest> {
    let mut header = [0; 4];
    stream
        .read_exact(&mut header)
        .await
        .context("read SOCKS5 request")?;
    if header[0] != 5 || header[2] != 0 {
        return Err(RejectedRequest {
            reply: GENERAL_FAILURE,
            message: "invalid SOCKS5 request header",
        }
        .into());
    }
    if header[1] != 1 {
        return Err(RejectedRequest {
            reply: COMMAND_UNSUPPORTED,
            message: "SOCKS5 supports CONNECT only",
        }
        .into());
    }
    let host = match header[3] {
        1 => {
            let mut octets = [0; 4];
            stream
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv4 address")?;
            Ipv4Addr::from(octets).to_string()
        }
        3 => {
            let length = usize::from(
                stream
                    .read_u8()
                    .await
                    .context("read SOCKS5 domain length")?,
            );
            if length == 0 {
                return Err(RejectedRequest {
                    reply: GENERAL_FAILURE,
                    message: "SOCKS5 domain must not be empty",
                }
                .into());
            }
            let mut domain = [0; 255];
            stream
                .read_exact(&mut domain[..length])
                .await
                .context("read SOCKS5 domain")?;
            std::str::from_utf8(&domain[..length])
                .context("invalid SOCKS5 domain encoding")?
                .to_owned()
        }
        4 => {
            let mut octets = [0; 16];
            stream
                .read_exact(&mut octets)
                .await
                .context("read SOCKS5 IPv6 address")?;
            Ipv6Addr::from(octets).to_string()
        }
        _ => {
            return Err(RejectedRequest {
                reply: ADDRESS_UNSUPPORTED,
                message: "unsupported SOCKS5 address type",
            }
            .into());
        }
    };
    let port = stream
        .read_u16()
        .await
        .context("read SOCKS5 destination port")?;
    Ok(ConnectRequest { host, port })
}

fn reply_for_error(error: &anyhow::Error) -> u8 {
    for cause in error.chain() {
        if let Some(error) = cause.downcast_ref::<RejectedRequest>() {
            return error.reply;
        }
        if let Some(error) = cause.downcast_ref::<std::io::Error>() {
            match error.kind() {
                std::io::ErrorKind::ConnectionRefused => return CONNECTION_REFUSED,
                std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
                    return HOST_UNREACHABLE;
                }
                _ => {}
            }
        }
    }
    // TCP v1/v2 acknowledgements currently carry an error string, not an
    // errno. Only classify recognizable agent rejection messages; transport
    // and ticket failures remain general failures.
    let message = error.root_cause().to_string();
    let Some(remote) = message
        .strip_prefix("tcp request rejected: ")
        .or_else(|| message.strip_prefix("tcp v2 request rejected: "))
    else {
        return GENERAL_FAILURE;
    };
    if remote.starts_with("Connection refused") || remote.starts_with("connection refused") {
        return CONNECTION_REFUSED;
    }
    if remote.starts_with("No route to host")
        || remote.starts_with("Network is unreachable")
        || remote.starts_with("Host is unreachable")
        || remote.starts_with("failed to lookup address information:")
    {
        return HOST_UNREACHABLE;
    }
    GENERAL_FAILURE
}

async fn write_reply<S: AsyncWrite + Unpin>(stream: &mut S, reply: u8) -> Result<()> {
    // The portl TCP ack does not expose the agent's bound address.
    stream
        .write_all(&[5, reply, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .context("write SOCKS5 reply")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dynamic_bind_defaults_to_loopback_and_accepts_bracketed_ipv6() {
        assert_eq!(
            parse_dynamic_spec("1080").unwrap().local_addr(),
            "127.0.0.1:1080"
        );
        assert_eq!(
            parse_dynamic_spec("0.0.0.0:1080").unwrap().local_addr(),
            "0.0.0.0:1080"
        );
        assert_eq!(
            parse_dynamic_spec("[::1]:1080").unwrap().local_addr(),
            "[::1]:1080"
        );
    }

    #[test]
    fn dynamic_bind_rejects_invalid_ports_and_unbracketed_ipv6() {
        for spec in [
            "",
            "108000",
            ":1080",
            "::1:1080",
            "[invalid]:1080",
            "[::1]",
            "localhost:bad",
        ] {
            assert!(parse_dynamic_spec(spec).is_err(), "{spec}");
        }
    }

    #[tokio::test]
    async fn connect_parses_ipv4_and_big_endian_port_without_consuming_payload() {
        let mut bytes = &[5, 1, 0, 1, 10, 5, 1, 8, 0x01, 0xbb, 42][..];
        assert_eq!(
            read_connect_request(&mut bytes).await.unwrap(),
            ConnectRequest {
                host: "10.5.1.8".to_owned(),
                port: 443,
            }
        );
        assert_eq!(bytes, &[42]);
    }

    #[tokio::test]
    async fn connect_parses_ipv6() {
        let mut bytes = &[
            5, 1, 0, 4, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0x1f, 0x90,
        ][..];
        assert_eq!(
            read_connect_request(&mut bytes).await.unwrap(),
            ConnectRequest {
                host: "2001:db8::1".to_owned(),
                port: 8080,
            }
        );
    }

    #[tokio::test]
    async fn connect_preserves_unresolved_domain() {
        let mut bytes = &b"\x05\x01\x00\x03\x13rancher.tcbs.com.vn\x01\xbb"[..];
        assert_eq!(
            read_connect_request(&mut bytes).await.unwrap(),
            ConnectRequest {
                host: "rancher.tcbs.com.vn".to_owned(),
                port: 443,
            }
        );
    }

    #[tokio::test]
    async fn connect_rejects_zero_length_domain() {
        let mut bytes = &[5, 1, 0, 3, 0, 0, 80][..];
        let error = read_connect_request(&mut bytes).await.unwrap_err();
        assert_eq!(reply_for_error(&error), GENERAL_FAILURE);
        assert!(error.to_string().contains("must not be empty"));
    }

    #[tokio::test]
    async fn connect_accepts_255_byte_domain() {
        let mut packet = vec![5, 1, 0, 3, 255];
        packet.extend_from_slice(&[b'a'; 255]);
        packet.extend_from_slice(&[0xff, 0xff]);
        let mut bytes = packet.as_slice();
        let request = read_connect_request(&mut bytes).await.unwrap();
        assert_eq!(request.host, "a".repeat(255));
        assert_eq!(request.port, 65535);
    }

    #[tokio::test]
    async fn connect_rejects_bind_and_udp_associate() {
        for command in [2, 3] {
            let packet = [5, command, 0, 1];
            let mut bytes = packet.as_slice();
            let error = read_connect_request(&mut bytes).await.unwrap_err();
            assert_eq!(reply_for_error(&error), COMMAND_UNSUPPORTED);
        }
    }

    #[tokio::test]
    async fn connect_rejects_unknown_address_type() {
        let mut bytes = &[5, 1, 0, 2][..];
        let error = read_connect_request(&mut bytes).await.unwrap_err();
        assert_eq!(reply_for_error(&error), ADDRESS_UNSUPPORTED);
    }

    #[tokio::test]
    async fn connect_rejects_invalid_header_and_truncated_addresses() {
        for packet in [
            &[4, 1, 0, 1][..],
            &[5, 1, 1, 1],
            &[5, 1, 0, 1, 127],
            &[5, 1, 0, 3, 2, b'a'],
        ] {
            let mut bytes = packet;
            let error = read_connect_request(&mut bytes).await.unwrap_err();
            assert_eq!(reply_for_error(&error), GENERAL_FAILURE);
        }
    }

    #[tokio::test]
    async fn no_auth_is_selected_even_when_other_methods_are_offered() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&[5, 3, 2, 0, 1]).await.unwrap();
        negotiate_no_auth(&mut server).await.unwrap();
        let mut reply = [0; 2];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply, [5, 0]);
    }

    #[tokio::test]
    async fn no_auth_rejects_missing_method_and_empty_method_list() {
        for greeting in [&[5, 1, 2][..], &[5, 0]] {
            let (mut client, mut server) = tokio::io::duplex(16);
            client.write_all(greeting).await.unwrap();
            assert!(negotiate_no_auth(&mut server).await.is_err());
            let mut reply = [0; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0xff]);
        }
    }

    #[test]
    fn maps_recognizable_agent_connect_errors_and_defaults_other_failures() {
        for (message, reply) in [
            (
                "tcp request rejected: Connection refused (os error 111)",
                CONNECTION_REFUSED,
            ),
            (
                "tcp v2 request rejected: Connection refused (os error 61)",
                CONNECTION_REFUSED,
            ),
            (
                "tcp request rejected: No route to host (os error 113)",
                HOST_UNREACHABLE,
            ),
            (
                "tcp v2 request rejected: Network is unreachable (os error 101)",
                HOST_UNREACHABLE,
            ),
            (
                "tcp request rejected: failed to lookup address information: Name or service not known",
                HOST_UNREACHABLE,
            ),
            (
                "tcp request rejected: destination not permitted by ticket",
                GENERAL_FAILURE,
            ),
            ("open tcp stream: connection lost", GENERAL_FAILURE),
            (
                "SOCKS5 TCP forward setup deadline exceeded",
                GENERAL_FAILURE,
            ),
        ] {
            assert_eq!(
                reply_for_error(&anyhow::anyhow!(message).context("forward setup")),
                reply,
                "{message}"
            );
        }
    }

    #[test]
    fn maps_typed_connect_errors() {
        for (kind, reply) in [
            (std::io::ErrorKind::ConnectionRefused, CONNECTION_REFUSED),
            (std::io::ErrorKind::HostUnreachable, HOST_UNREACHABLE),
            (std::io::ErrorKind::NetworkUnreachable, HOST_UNREACHABLE),
            (std::io::ErrorKind::Other, GENERAL_FAILURE),
        ] {
            let error =
                anyhow::Error::new(std::io::Error::from(kind)).context("connect destination");
            assert_eq!(reply_for_error(&error), reply);
        }
    }

    #[tokio::test]
    async fn replies_encode_socks5_status_and_unspecified_bound_address() {
        for status in [
            SUCCESS,
            GENERAL_FAILURE,
            HOST_UNREACHABLE,
            CONNECTION_REFUSED,
            COMMAND_UNSUPPORTED,
            ADDRESS_UNSUPPORTED,
        ] {
            let (mut client, mut server) = tokio::io::duplex(16);
            write_reply(&mut server, status).await.unwrap();
            let mut reply = [0; 10];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, status, 0, 1, 0, 0, 0, 0, 0, 0]);
        }
    }
}
