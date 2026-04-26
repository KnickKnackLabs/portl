//! Mailbox protocol message types.
//!
//! These types model the [Magic Wormhole mailbox server
//! protocol](https://github.com/magic-wormhole/magic-wormhole-protocols)
//! at the JSON wire level only. Transport, retries, and ack/redelivery
//! state are intentionally out of scope and live with the rendezvous
//! state machine (Task 7+).

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Errors produced while encoding or decoding mailbox protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// The peer sent a `body` field that was not valid hex.
    #[error("invalid hex in mailbox body: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// The rendezvous server returned an `error` frame.
    #[error("rendezvous server error: {0}")]
    Server(String),
}

/// Hex-encoded binary body. Serializes to/from a hex string on the wire,
/// but is held as raw bytes in memory so that callers cannot smuggle
/// invalid encodings through direct construction of [`ClientMessage::Add`].
///
/// The protocol does not require a particular hex case; decoding is
/// case-insensitive and encoding emits lowercase.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HexBody(pub Vec<u8>);

impl HexBody {
    /// Construct a hex body from raw bytes.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    /// Borrow the underlying bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consume the body and return the inner bytes.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl From<Vec<u8>> for HexBody {
    fn from(value: Vec<u8>) -> Self {
        Self(value)
    }
}

impl From<&[u8]> for HexBody {
    fn from(value: &[u8]) -> Self {
        Self(value.to_vec())
    }
}

impl Serialize for HexBody {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&hex::encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for HexBody {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        hex::decode(&s).map(HexBody).map_err(serde::de::Error::custom)
    }
}

/// Messages a client sends to the Magic Wormhole mailbox server.
///
/// The wire-level `id` field that the server echoes back in `ack`
/// responses is *not* modelled here; framing/correlation is the
/// transport layer's responsibility.
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
    /// Add a phase message; `body` is hex-encoded ciphertext on the wire.
    Add { phase: String, body: HexBody },
    /// Close the mailbox. The protocol declares both `mailbox` and `mood`
    /// optional (`close {mailbox:?, mood:?}`), so we keep them optional
    /// and provide [`ClientMessage::close_happy`] for the common case.
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
            body: HexBody::new(body.to_vec()),
        }
    }

    /// Convenience constructor for the typical `close` frame with a mood
    /// but no mailbox echo.
    pub fn close_happy() -> Self {
        Self::Close {
            mailbox: None,
            mood: Some("happy".into()),
        }
    }
}

/// Messages the mailbox server sends back to clients.
///
/// Per the server protocol, every C->S command provokes an `ack` that
/// echoes the original `id`, and `message` frames carry an `id` copied
/// from the originating `add`. Both are preserved here so the upcoming
/// state machine (Task 7) can correlate acks and dedupe redeliveries.
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
    /// `closed` response to a `close` command. The protocol summary lists
    /// no fields, but real servers may echo `mood`; accept it optionally.
    Closed {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        mood: Option<String>,
    },
    /// Server ack of a prior C->S message; `id` echoes the client's `id`.
    Ack {
        #[serde(default)]
        id: String,
    },
    Message {
        side: String,
        phase: String,
        body: HexBody,
        /// Copied from the originating `add` message.
        id: String,
    },
    Error {
        error: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bind_message_exact_shape() {
        let msg = ClientMessage::bind("portl.exchange.v1", "a1b2");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "bind",
                "appid": "portl.exchange.v1",
                "side": "a1b2",
            })
        );
    }

    #[test]
    fn add_message_exact_shape_hex_encoded() {
        let msg = ClientMessage::add("pake", b"abc");
        let json = serde_json::to_value(&msg).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "add",
                "phase": "pake",
                "body": "616263",
            })
        );
    }

    #[test]
    fn close_happy_exact_shape() {
        let json = serde_json::to_value(ClientMessage::close_happy()).unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "close",
                "mood": "happy",
            })
        );
    }

    #[test]
    fn close_with_mailbox_serializes_both_fields() {
        let json = serde_json::to_value(ClientMessage::Close {
            mailbox: Some("mb1".into()),
            mood: Some("happy".into()),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({
                "type": "close",
                "mailbox": "mb1",
                "mood": "happy",
            })
        );
    }

    #[test]
    fn close_omits_optional_fields_when_absent() {
        let json = serde_json::to_value(ClientMessage::Close {
            mailbox: None,
            mood: None,
        })
        .unwrap();
        assert_eq!(json, serde_json::json!({ "type": "close" }));
    }

    #[test]
    fn allocate_claim_release_open_serialize() {
        let allocate = serde_json::to_value(ClientMessage::Allocate).unwrap();
        assert_eq!(allocate, serde_json::json!({ "type": "allocate" }));

        let claim = serde_json::to_value(ClientMessage::Claim {
            nameplate: "4".into(),
        })
        .unwrap();
        assert_eq!(claim, serde_json::json!({ "type": "claim", "nameplate": "4" }));

        let release = serde_json::to_value(ClientMessage::Release {
            nameplate: "4".into(),
        })
        .unwrap();
        assert_eq!(
            release,
            serde_json::json!({ "type": "release", "nameplate": "4" })
        );

        let open = serde_json::to_value(ClientMessage::Open {
            mailbox: "mb1".into(),
        })
        .unwrap();
        assert_eq!(open, serde_json::json!({ "type": "open", "mailbox": "mb1" }));
    }

    #[test]
    fn server_message_preserves_id_and_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"6869","id":"abc"}"#;
        let msg: ServerMessage = serde_json::from_slice(raw).unwrap();
        match msg {
            ServerMessage::Message {
                side,
                phase,
                body,
                id,
            } => {
                assert_eq!(side, "peer");
                assert_eq!(phase, "1");
                assert_eq!(body.as_bytes(), b"hi");
                assert_eq!(id, "abc");
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn server_ack_carries_id() {
        let ack: ServerMessage =
            serde_json::from_str(r#"{"type":"ack","id":"req-1"}"#).unwrap();
        match ack {
            ServerMessage::Ack { id } => assert_eq!(id, "req-1"),
            other => panic!("expected ack, got {other:?}"),
        }
    }

    #[test]
    fn server_closed_accepts_optional_mood() {
        let bare: ServerMessage = serde_json::from_str(r#"{"type":"closed"}"#).unwrap();
        match bare {
            ServerMessage::Closed { mood } => assert!(mood.is_none()),
            other => panic!("expected closed, got {other:?}"),
        }

        let with_mood: ServerMessage =
            serde_json::from_str(r#"{"type":"closed","mood":"happy"}"#).unwrap();
        match with_mood {
            ServerMessage::Closed { mood } => assert_eq!(mood.as_deref(), Some("happy")),
            other => panic!("expected closed, got {other:?}"),
        }
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

        let err: ServerMessage =
            serde_json::from_str(r#"{"type":"error","error":"boom"}"#).unwrap();
        match err {
            ServerMessage::Error { error } => assert_eq!(error, "boom"),
            _ => panic!("expected error"),
        }
    }

    #[test]
    fn server_message_rejects_invalid_hex_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"zz","id":"x"}"#;
        let err = serde_json::from_slice::<ServerMessage>(raw).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("invalid character") || msg.contains("hex"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn server_message_rejects_odd_length_hex_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"abc","id":"x"}"#;
        let err = serde_json::from_slice::<ServerMessage>(raw).unwrap_err();
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("odd") || msg.contains("length") || msg.contains("hex"),
            "unexpected error: {msg}"
        );
    }

    #[test]
    fn server_message_accepts_uppercase_hex_body() {
        let raw = br#"{"type":"message","side":"peer","phase":"1","body":"ABCD","id":"x"}"#;
        let msg: ServerMessage = serde_json::from_slice(raw).unwrap();
        match msg {
            ServerMessage::Message { body, .. } => {
                assert_eq!(body.as_bytes(), &[0xab, 0xcd]);
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }
}
