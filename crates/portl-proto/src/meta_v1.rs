use serde::{Deserialize, Serialize};

use crate::error::Error;

pub const ALPN_META_V1: &[u8] = b"portl/meta/v1";

/// Requests served over the authenticated metadata channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaReq {
    Ping { t_client_us: u64 },
    Info,
    PublishRevocations { items: Vec<Vec<u8>> },
}

/// Responses served over the authenticated metadata channel.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaResp {
    Pong {
        t_server_us: u64,
    },
    Info {
        agent_version: String,
        supported_alpns: Vec<String>,
        uptime_s: u64,
        hostname: String,
        os: String,
        tags: Vec<(String, String)>,
    },
    PublishedRevocations {
        accepted: u32,
        rejected: Vec<(Vec<u8>, String)>,
    },
    Error(Error),
}

#[cfg(test)]
mod tests {
    use super::{MetaReq, MetaResp};
    use crate::error::{Error, ErrorKind};

    #[test]
    fn request_roundtrips_via_postcard() {
        let value = MetaReq::PublishRevocations {
            items: vec![vec![1; 16], vec![2; 16]],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode request");
        let decoded: MetaReq = postcard::from_bytes(&encoded).expect("decode request");
        assert_eq!(decoded, value);
    }

    #[test]
    fn response_roundtrips_via_postcard() {
        let value = MetaResp::Info {
            agent_version: env!("CARGO_PKG_VERSION").to_owned(),
            supported_alpns: vec!["portl/ticket/v1".to_owned(), "portl/meta/v1".to_owned()],
            uptime_s: 42,
            hostname: "host-a".to_owned(),
            os: std::env::consts::OS.to_owned(),
            tags: vec![("role".to_owned(), "test".to_owned())],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode response");
        let decoded: MetaResp = postcard::from_bytes(&encoded).expect("decode response");
        assert_eq!(decoded, value);
    }

    #[test]
    fn error_response_roundtrips_via_postcard() {
        let value = MetaResp::Error(Error {
            kind: ErrorKind::InternalError,
            message: "not yet implemented".to_owned(),
            retry_after_ms: None,
        });

        let encoded = postcard::to_stdvec(&value).expect("encode error response");
        let decoded: MetaResp = postcard::from_bytes(&encoded).expect("decode error response");
        assert_eq!(decoded, value);
    }
}
