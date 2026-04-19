use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_TCP_V1: &[u8] = b"portl/tcp/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpReq {
    pub preamble: StreamPreamble,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpAck {
    pub ok: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ALPN_TCP_V1, TcpAck, TcpReq};
    use crate::wire::StreamPreamble;

    #[test]
    fn tcp_req_roundtrips_via_postcard() {
        let value = TcpReq {
            preamble: StreamPreamble {
                peer_token: [5; 16],
                alpn: String::from_utf8_lossy(ALPN_TCP_V1).into_owned(),
            },
            host: "127.0.0.1".to_owned(),
            port: 22,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp req");
        let decoded: TcpReq = postcard::from_bytes(&encoded).expect("decode tcp req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn tcp_ack_roundtrips_via_postcard() {
        let value = TcpAck {
            ok: false,
            error: Some("denied".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp ack");
        let decoded: TcpAck = postcard::from_bytes(&encoded).expect("decode tcp ack");
        assert_eq!(decoded, value);
    }
}
