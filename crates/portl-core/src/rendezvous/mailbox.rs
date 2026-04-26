//! Mailbox protocol message types (skeleton).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_message_serializes_to_protocol_json() {
        let msg = ClientMessage::bind("portl.exchange.v1", "a1b2");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "bind");
        assert_eq!(json["appid"], "portl.exchange.v1");
        assert_eq!(json["side"], "a1b2");
    }

    #[test]
    fn add_message_hex_encodes_body() {
        let msg = ClientMessage::add("pake", b"abc");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(json["type"], "add");
        assert_eq!(json["phase"], "pake");
        assert_eq!(json["body"], "616263");
    }

    #[test]
    fn server_message_decodes_message_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"6869","id":"x"}"#;
        let msg: ServerMessage = serde_json::from_slice(raw).unwrap();
        match msg {
            ServerMessage::Message { side, phase, body } => {
                assert_eq!(side, "peer");
                assert_eq!(phase, "1");
                assert_eq!(body, b"hi");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn allocate_claim_release_open_close_serialize() {
        let allocate = serde_json::to_value(&ClientMessage::Allocate).unwrap();
        assert_eq!(allocate["type"], "allocate");

        let claim = serde_json::to_value(&ClientMessage::Claim {
            nameplate: "4".into(),
        })
        .unwrap();
        assert_eq!(claim["type"], "claim");
        assert_eq!(claim["nameplate"], "4");

        let release = serde_json::to_value(&ClientMessage::Release {
            nameplate: "4".into(),
        })
        .unwrap();
        assert_eq!(release["type"], "release");
        assert_eq!(release["nameplate"], "4");

        let open = serde_json::to_value(&ClientMessage::Open {
            mailbox: "mb1".into(),
        })
        .unwrap();
        assert_eq!(open["type"], "open");
        assert_eq!(open["mailbox"], "mb1");

        let close = serde_json::to_value(&ClientMessage::Close {
            mailbox: Some("mb1".into()),
            mood: Some("happy".into()),
        })
        .unwrap();
        assert_eq!(close["type"], "close");
        assert_eq!(close["mailbox"], "mb1");
        assert_eq!(close["mood"], "happy");
    }

    #[test]
    fn server_message_variants_decode() {
        let welcome: ServerMessage =
            serde_json::from_str(r#"{"type":"welcome","welcome":{"motd":"hi"}}"#).unwrap();
        assert!(matches!(welcome, ServerMessage::Welcome { .. }));

        let allocated: ServerMessage =
            serde_json::from_str(r#"{"type":"allocated","nameplate":"4"}"#).unwrap();
        match allocated {
            ServerMessage::Allocated { nameplate } => assert_eq!(nameplate, "4"),
            _ => panic!("expected allocated"),
        }

        let claimed: ServerMessage =
            serde_json::from_str(r#"{"type":"claimed","mailbox":"mb1"}"#).unwrap();
        assert!(matches!(claimed, ServerMessage::Claimed { .. }));

        let released: ServerMessage =
            serde_json::from_str(r#"{"type":"released"}"#).unwrap();
        assert!(matches!(released, ServerMessage::Released));

        let closed: ServerMessage = serde_json::from_str(r#"{"type":"closed"}"#).unwrap();
        assert!(matches!(closed, ServerMessage::Closed));

        let ack: ServerMessage = serde_json::from_str(r#"{"type":"ack"}"#).unwrap();
        assert!(matches!(ack, ServerMessage::Ack));

        let err: ServerMessage =
            serde_json::from_str(r#"{"type":"error","error":"boom"}"#).unwrap();
        match err {
            ServerMessage::Error { error } => assert_eq!(error, "boom"),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn server_message_rejects_invalid_hex_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"zz"}"#;
        let err = serde_json::from_slice::<ServerMessage>(raw).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("invalid character") || msg.contains("hex"),
            "unexpected error: {msg}"
        );
    }
}

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors produced while encoding or decoding mailbox protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// The peer sent a `body` field that was not valid lowercase hex.
    #[error("invalid hex in mailbox body: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// The rendezvous server returned an `error` frame.
    #[error("rendezvous server error: {0}")]
    Server(String),
}

/// Messages a client sends to the Magic Wormhole mailbox server.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ClientMessage {
    /// Bind this connection to an `appid`/`side` pair.
    Bind {
        appid: String,
        side: String,
    },
    /// Ask the server to allocate a fresh nameplate.
    Allocate,
    /// Claim a nameplate; the server responds with a mailbox id.
    Claim { nameplate: String },
    /// Release a previously claimed nameplate.
    Release { nameplate: String },
    /// Open the mailbox to start exchanging phase messages.
    Open { mailbox: String },
    /// Add a phase message; `body` is hex-encoded ciphertext.
    Add { phase: String, body: String },
    /// Close the mailbox, optionally signalling a mood.
    Close {
        #[serde(skip_serializing_if = "Option::is_none")]
        mailbox: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        mood: Option<String>,
    },
}

impl ClientMessage {
    /// Convenience constructor for `bind` frames.
    pub fn bind(appid: impl Into<String>, side: impl Into<String>) -> Self {
        Self::Bind {
            appid: appid.into(),
            side: side.into(),
        }
    }

    /// Convenience constructor for `add` frames; hex-encodes `body`.
    pub fn add(phase: impl Into<String>, body: &[u8]) -> Self {
        Self::Add {
            phase: phase.into(),
            body: hex::encode(body),
        }
    }
}

/// Messages the mailbox server sends back to clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum ServerMessage {
    Welcome {
        welcome: serde_json::Value,
    },
    Allocated {
        nameplate: String,
    },
    Claimed {
        mailbox: String,
    },
    Released,
    Closed,
    Ack,
    Message {
        side: String,
        phase: String,
        #[serde(serialize_with = "serialize_hex", deserialize_with = "deserialize_hex")]
        body: Vec<u8>,
    },
    Error {
        error: String,
    },
}

fn serialize_hex<S: Serializer>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&hex::encode(bytes))
}

fn deserialize_hex<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let s = String::deserialize(deserializer)?;
    hex::decode(&s).map_err(serde::de::Error::custom)
}
