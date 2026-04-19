//! Shared wire types for portl protocols.

pub mod shell;
pub mod tcp;

use crate::ticket::schema::Capabilities;
use serde::{Deserialize, Serialize};

/// Preamble carried on every post-handshake stream open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamPreamble {
    pub peer_token: [u8; 16],
    pub alpn: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketOffer {
    pub ticket: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    #[serde(with = "option_signature_bytes")]
    pub proof: Option<[u8; 64]>,
    pub client_nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketAck {
    pub ok: bool,
    pub reason: Option<AckReason>,
    pub peer_token: Option<[u8; 16]>,
    pub effective_caps: Option<Capabilities>,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckReason {
    BadSignature,
    BadChain,
    CapsExceedParent,
    NotYetValid,
    Expired,
    Revoked,
    ProofMissing,
    ProofInvalid,
    RateLimited,
    InternalError { detail: Option<String> },
}

mod option_signature_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    #[allow(clippy::ref_option)]
    pub fn serialize<S>(value: &Option<[u8; 64]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(bytes) => serializer.serialize_some(&bytes.as_slice()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 64]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let maybe = Option::<Vec<u8>>::deserialize(deserializer)?;
        maybe
            .map(|bytes| {
                bytes
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 64 proof bytes"))
            })
            .transpose()
    }
}
