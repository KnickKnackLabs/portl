use portl_core::ticket::schema::Capabilities;
use serde::{Deserialize, Serialize};

pub const ALPN_TICKET_V1: &[u8] = b"portl/ticket/v1";

/// Client offer on the ticket handshake stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketOffer {
    pub ticket: Vec<u8>,
    pub chain: Vec<Vec<u8>>,
    #[serde(with = "option_signature_bytes")]
    pub proof: Option<[u8; 64]>,
    pub client_nonce: [u8; 16],
}

/// Agent response for the ticket handshake stream.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TicketAck {
    pub ok: bool,
    pub reason: Option<AckReason>,
    pub peer_token: Option<[u8; 16]>,
    pub effective_caps: Option<Capabilities>,
    pub server_time: u64,
}

/// Closed rejection taxonomy for `ticket/v1`.
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

#[cfg(test)]
mod tests {
    use super::{AckReason, TicketAck, TicketOffer};
    use portl_core::ticket::schema::{Capabilities, MetaCaps};

    #[test]
    fn offer_roundtrips_via_postcard() {
        let value = TicketOffer {
            ticket: vec![1, 2, 3],
            chain: vec![vec![4, 5], vec![6, 7, 8]],
            proof: Some([9; 64]),
            client_nonce: [10; 16],
        };

        let encoded = postcard::to_stdvec(&value).expect("encode offer");
        let decoded: TicketOffer = postcard::from_bytes(&encoded).expect("decode offer");
        assert_eq!(decoded, value);
    }

    #[test]
    fn ack_roundtrips_via_postcard() {
        let value = TicketAck {
            ok: true,
            reason: None,
            peer_token: Some([11; 16]),
            effective_caps: Some(Capabilities {
                presence: 0b0010_0000,
                shell: None,
                tcp: None,
                udp: None,
                fs: None,
                vpn: None,
                meta: Some(MetaCaps {
                    ping: true,
                    info: true,
                }),
            }),
            server_time: 1_735_689_600,
        };

        let encoded = postcard::to_stdvec(&value).expect("encode ack");
        let decoded: TicketAck = postcard::from_bytes(&encoded).expect("decode ack");
        assert_eq!(decoded, value);
    }

    #[test]
    fn ack_reason_roundtrips_via_postcard() {
        let value = AckReason::InternalError {
            detail: Some("boom".to_owned()),
        };

        let encoded = postcard::to_stdvec(&value).expect("encode reason");
        let decoded: AckReason = postcard::from_bytes(&encoded).expect("decode reason");
        assert_eq!(decoded, value);
    }
}
