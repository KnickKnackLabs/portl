use serde::{Deserialize, Serialize};

/// Common protocol error envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Error {
    pub kind: ErrorKind,
    pub message: String,
    pub retry_after_ms: Option<u32>,
}

/// Stable error taxonomy shared across ALPNs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorKind {
    ProtoError,
    CapDenied,
    NotFound,
    RateLimited,
    Overloaded,
    VersionMismatch,
    InternalError,
    Timeout,
    Cancelled,
}

#[cfg(test)]
mod tests {
    use super::{Error, ErrorKind};

    #[test]
    fn error_roundtrips_via_postcard() {
        let value = Error {
            kind: ErrorKind::RateLimited,
            message: "slow down".to_owned(),
            retry_after_ms: Some(5_000),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode error");
        let decoded: Error = postcard::from_bytes(&encoded).expect("decode error");
        assert_eq!(decoded, value);
    }
}
