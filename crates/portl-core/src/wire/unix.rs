use serde::{Deserialize, Serialize};

use crate::wire::StreamPreamble;

pub const ALPN_UNIX_V1: &[u8] = b"portl/unix/v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixReq {
    pub preamble: StreamPreamble,
    pub op: UnixOp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixReqTail {
    pub op: UnixOp,
}

impl UnixReq {
    #[must_use]
    pub fn new(preamble: StreamPreamble, tail: UnixReqTail) -> Self {
        Self {
            preamble,
            op: tail.op,
        }
    }

    #[must_use]
    pub fn tail(&self) -> UnixReqTail {
        UnixReqTail {
            op: self.op.clone(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnixOp {
    Connect { path: String },
    Listen { path: String, cleanup: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnixAck {
    pub ok: bool,
    pub error: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::{ALPN_UNIX_V1, UnixAck, UnixOp, UnixReq};
    use crate::wire::StreamPreamble;

    #[test]
    fn unix_req_roundtrips_via_postcard() {
        let value = UnixReq {
            preamble: StreamPreamble {
                peer_token: [8; 16],
                alpn: String::from_utf8_lossy(ALPN_UNIX_V1).into_owned(),
            },
            op: UnixOp::Listen {
                path: "/tmp/portl-agent.sock".to_owned(),
                cleanup: true,
            },
        };

        let encoded = postcard::to_stdvec(&value).expect("encode unix req");
        let decoded: UnixReq = postcard::from_bytes(&encoded).expect("decode unix req");
        assert_eq!(decoded, value);
    }

    #[test]
    fn unix_ack_roundtrips_via_postcard() {
        let value = UnixAck {
            ok: false,
            error: Some("denied".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode unix ack");
        let decoded: UnixAck = postcard::from_bytes(&encoded).expect("decode unix ack");
        assert_eq!(decoded, value);
    }
}
