use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_TCP_V1: &[u8] = b"portl/tcp/v1";
pub const ALPN_TCP_V2: &[u8] = b"portl/tcp/v2";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpReq {
    pub preamble: StreamPreamble,
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpReqV2 {
    pub preamble: StreamPreamble,
    pub op: TcpOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpReqV2Tail {
    pub op: TcpOp,
}

impl TcpReqV2 {
    #[must_use]
    pub fn new(preamble: StreamPreamble, tail: TcpReqV2Tail) -> Self {
        Self {
            preamble,
            op: tail.op,
        }
    }

    #[must_use]
    pub fn tail(&self) -> TcpReqV2Tail {
        TcpReqV2Tail {
            op: self.op.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TcpOp {
    Connect {
        host: String,
        port: u16,
    },
    Listen {
        bind_host: String,
        bind_port: u16,
    },
    Accepted {
        bind_host: String,
        bind_port: u16,
        originator_host: String,
        originator_port: u16,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpAck {
    pub ok: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TcpListenAck {
    pub ok: bool,
    pub error: Option<String>,
    pub bound_port: Option<u16>,
}

#[cfg(test)]
mod tests {
    use super::{ALPN_TCP_V1, ALPN_TCP_V2, TcpAck, TcpListenAck, TcpOp, TcpReq, TcpReqV2};
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

    #[test]
    fn tcp_v2_connect_req_roundtrips_via_postcard() {
        let value = TcpReqV2 {
            preamble: StreamPreamble {
                peer_token: [7; 16],
                alpn: String::from_utf8_lossy(ALPN_TCP_V2).into_owned(),
            },
            op: TcpOp::Connect {
                host: "db.internal".to_owned(),
                port: 5432,
            },
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp v2 connect req");
        let decoded: TcpReqV2 = postcard::from_bytes(&encoded).expect("decode tcp v2 connect req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn tcp_v2_listen_req_roundtrips_via_postcard() {
        let value = TcpReqV2 {
            preamble: StreamPreamble {
                peer_token: [9; 16],
                alpn: String::from_utf8_lossy(ALPN_TCP_V2).into_owned(),
            },
            op: TcpOp::Listen {
                bind_host: "127.0.0.1".to_owned(),
                bind_port: 0,
            },
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp v2 listen req");
        let decoded: TcpReqV2 = postcard::from_bytes(&encoded).expect("decode tcp v2 listen req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn tcp_v2_accepted_req_roundtrips_via_postcard() {
        let value = TcpReqV2 {
            preamble: StreamPreamble {
                peer_token: [10; 16],
                alpn: String::from_utf8_lossy(ALPN_TCP_V2).into_owned(),
            },
            op: TcpOp::Accepted {
                bind_host: "127.0.0.1".to_owned(),
                bind_port: 2200,
                originator_host: "127.0.0.1".to_owned(),
                originator_port: 56123,
            },
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp v2 accepted req");
        let decoded: TcpReqV2 = postcard::from_bytes(&encoded).expect("decode tcp v2 accepted req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn tcp_v2_listen_ack_roundtrips_via_postcard() {
        let value = TcpListenAck {
            ok: true,
            error: None,
            bound_port: Some(49152),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode tcp v2 listen ack");
        let decoded: TcpListenAck =
            postcard::from_bytes(&encoded).expect("decode tcp v2 listen ack");
        assert_eq!(decoded, value);
    }
}
