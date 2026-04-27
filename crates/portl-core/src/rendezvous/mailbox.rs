//! Mailbox protocol message types.
//!
//! These types model the [Magic Wormhole mailbox server
//! protocol](https://github.com/magic-wormhole/magic-wormhole-protocols)
//! at the JSON wire level only. Transport, retries, and ack/redelivery
//! state are intentionally out of scope and live with the rendezvous
//! state machine (Task 7+).

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use async_trait::async_trait;
use std::collections::VecDeque;

/// Errors produced while encoding or decoding mailbox protocol frames.
#[derive(Debug, thiserror::Error)]
pub enum MailboxError {
    /// The peer sent a `body` field that was not valid hex.
    #[error("invalid hex in mailbox body: {0}")]
    InvalidHex(#[from] hex::FromHexError),
    /// The rendezvous server returned an `error` frame.
    #[error("rendezvous server error: {0}")]
    Server(String),
    /// The transport surfaced an error while sending or receiving.
    #[error("mailbox transport error: {0}")]
    Transport(String),
    /// The server sent a frame the client did not expect at this state.
    #[error("unexpected mailbox frame: {0}")]
    Unexpected(String),
    /// The peer or server closed the mailbox while we were waiting for a
    /// phase message. Surfaced to callers so a wrong-code or peer abort
    /// produces a deterministic error rather than an indefinite wait.
    #[error("mailbox closed while waiting for peer (mood={mood:?})")]
    Closed {
        /// Optional mood echoed by the server.
        mood: Option<String>,
    },
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

/// A peer phase message returned from the mailbox.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhaseMessage {
    /// The peer's wire side identifier.
    pub side: String,
    /// Phase label, e.g. `"pake"` or `"version"`.
    pub phase: String,
    /// Raw body bytes (decoded from hex on the wire).
    pub body: Vec<u8>,
    /// Server-assigned message id, copied from the originating `add`.
    pub id: String,
}

/// Result of opening a mailbox; carries the negotiated nameplate and
/// mailbox identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSetup {
    pub nameplate: String,
    pub mailbox: String,
}

/// Transport abstraction over a single client/server frame channel.
#[async_trait]
pub trait MailboxTransport {
    /// Send a single client frame.
    async fn send(&mut self, msg: ClientMessage) -> Result<(), MailboxError>;
    /// Receive a single server frame.
    async fn recv(&mut self) -> Result<ServerMessage, MailboxError>;
}

/// Transport-neutral driver for the Magic Wormhole mailbox exchange.
pub struct MailboxClient<'a, T> {
    appid: &'a str,
    side: &'a str,
    transport: &'a mut T,
    mailbox: Option<String>,
    bound: bool,
    pending_messages: VecDeque<PhaseMessage>,
}

/// Maximum number of buffered peer phase messages while we wait for an
/// expected command response. Exceeding this is treated as a transport-
/// level error rather than allowing unbounded growth.
const MAX_PENDING_MESSAGES: usize = 64;

impl<'a, T: MailboxTransport + Send> MailboxClient<'a, T> {
    /// Create a new mailbox driver bound to the given appid/side.
    pub fn new(appid: &'a str, side: &'a str, transport: &'a mut T) -> Self {
        Self {
            appid,
            side,
            transport,
            mailbox: None,
            bound: false,
            pending_messages: VecDeque::new(),
        }
    }

    fn buffer_pending(&mut self, msg: PhaseMessage) -> Result<(), MailboxError> {
        if self.pending_messages.len() >= MAX_PENDING_MESSAGES {
            return Err(MailboxError::Unexpected(format!(
                "pending phase buffer exceeded cap of {MAX_PENDING_MESSAGES}"
            )));
        }
        self.pending_messages.push_back(msg);
        Ok(())
    }

    async fn ensure_bound(&mut self) -> Result<(), MailboxError> {
        if !self.bound {
            self.transport
                .send(ClientMessage::bind(self.appid, self.side))
                .await?;
            self.bound = true;
        }
        Ok(())
    }

    /// Receive the next "meaningful" frame, skipping `Ack`s and surfacing
    /// `Error` frames as [`MailboxError::Server`].
    async fn recv_meaningful(&mut self) -> Result<ServerMessage, MailboxError> {
        loop {
            let frame = self.transport.recv().await?;
            match frame {
                ServerMessage::Ack { .. } => {}
                ServerMessage::Error { error } => return Err(MailboxError::Server(error)),
                other => return Ok(other),
            }
        }
    }

    /// Like [`Self::recv_meaningful`] but used in setup paths where unsolicited
    /// peer `message` frames may arrive before the named response. Buffers any
    /// `Message` frames into [`Self::pending_messages`] so subsequent
    /// [`Self::recv_phase_from_peer`] calls observe them.
    async fn recv_meaningful_setup(&mut self) -> Result<ServerMessage, MailboxError> {
        loop {
            match self.recv_meaningful().await? {
                ServerMessage::Message {
                    side,
                    phase,
                    body,
                    id,
                } => {
                    self.buffer_pending(PhaseMessage {
                        side,
                        phase,
                        body: body.into_inner(),
                        id,
                    })?;
                }
                other => return Ok(other),
            }
        }
    }

    /// Await the per-command universal `ack` that the mailbox server sends in
    /// reply to every C->S message. `Error` frames are surfaced; any other
    /// frame at this point is unexpected (the server replies to commands
    /// before broadcasting derived `message`s).
    async fn await_command_accepted(&mut self) -> Result<(), MailboxError> {
        loop {
            match self.transport.recv().await? {
                ServerMessage::Ack { .. } => return Ok(()),
                ServerMessage::Error { error } => return Err(MailboxError::Server(error)),
                ServerMessage::Message {
                    side,
                    phase,
                    body,
                    id,
                } => {
                    self.buffer_pending(PhaseMessage {
                        side,
                        phase,
                        body: body.into_inner(),
                        id,
                    })?;
                }
                other => {
                    return Err(MailboxError::Unexpected(format!(
                        "expected ack, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Await the `closed` direct response to a `close` command, tolerating an
    /// intervening universal `ack` (the server emits ack for every C->S
    /// message and then the named `closed` response per the mailbox
    /// protocol).
    async fn await_closed(&mut self) -> Result<(), MailboxError> {
        loop {
            match self.transport.recv().await? {
                ServerMessage::Ack { .. } => {}
                ServerMessage::Closed { .. } => return Ok(()),
                ServerMessage::Error { error } => return Err(MailboxError::Server(error)),
                ServerMessage::Message {
                    side,
                    phase,
                    body,
                    id,
                } => {
                    self.buffer_pending(PhaseMessage {
                        side,
                        phase,
                        body: body.into_inner(),
                        id,
                    })?;
                }
                other => {
                    return Err(MailboxError::Unexpected(format!(
                        "expected closed, got {other:?}"
                    )))
                }
            }
        }
    }

    async fn await_welcome(&mut self) -> Result<(), MailboxError> {
        match self.recv_meaningful_setup().await? {
            ServerMessage::Welcome { .. } => Ok(()),
            other => Err(MailboxError::Unexpected(format!(
                "expected welcome, got {other:?}"
            ))),
        }
    }

    /// Allocate a fresh nameplate, claim it, and open the resulting mailbox.
    pub async fn allocate_and_open(&mut self) -> Result<MailboxSetup, MailboxError> {
        self.ensure_bound().await?;
        self.await_welcome().await?;

        self.transport.send(ClientMessage::Allocate).await?;
        let nameplate = match self.recv_meaningful_setup().await? {
            ServerMessage::Allocated { nameplate } => nameplate,
            other => {
                return Err(MailboxError::Unexpected(format!(
                    "expected allocated, got {other:?}"
                )));
            }
        };

        self.claim_nameplate_and_open(nameplate).await
    }

    /// Claim the supplied nameplate and open the resulting mailbox.
    pub async fn claim_and_open(
        &mut self,
        nameplate: impl Into<String>,
    ) -> Result<MailboxSetup, MailboxError> {
        self.ensure_bound().await?;
        self.await_welcome().await?;
        self.claim_nameplate_and_open(nameplate.into()).await
    }

    async fn claim_nameplate_and_open(
        &mut self,
        nameplate: String,
    ) -> Result<MailboxSetup, MailboxError> {
        self.transport
            .send(ClientMessage::Claim {
                nameplate: nameplate.clone(),
            })
            .await?;
        let mailbox = match self.recv_meaningful_setup().await? {
            ServerMessage::Claimed { mailbox } => mailbox,
            other => {
                return Err(MailboxError::Unexpected(format!(
                    "expected claimed, got {other:?}"
                )));
            }
        };

        self.transport
            .send(ClientMessage::Open {
                mailbox: mailbox.clone(),
            })
            .await?;
        // The protocol summary lists `open` as having no named response, but
        // every C->S command still draws the universal `ack` (or an `error`
        // if the open is rejected, e.g. mailbox already closed). Block on it
        // so callers don't proceed against a server that refused the open.
        self.await_command_accepted().await?;
        self.mailbox = Some(mailbox.clone());
        Ok(MailboxSetup { nameplate, mailbox })
    }

    /// Send a phase message body to the peer.
    pub async fn send_phase(
        &mut self,
        phase: impl Into<String>,
        body: &[u8],
    ) -> Result<(), MailboxError> {
        self.transport.send(ClientMessage::add(phase, body)).await?;
        // `add` does not have a named direct response, but the server emits
        // the universal `ack` for every C->S frame and an `error` if it
        // rejected the add (e.g. mailbox not opened on this side).
        self.await_command_accepted().await
    }

    /// Wait for a phase message from the peer, ignoring own-side echoes
    /// and skipping `Ack` frames.
    pub async fn recv_phase_from_peer(
        &mut self,
        expected_phase: &str,
    ) -> Result<PhaseMessage, MailboxError> {
        loop {
            if let Some(pending) = self.pending_messages.pop_front() {
                if pending.side == self.side {
                    continue;
                }
                if pending.phase != expected_phase {
                    return Err(MailboxError::Unexpected(format!(
                        "expected phase {expected_phase}, got {}",
                        pending.phase
                    )));
                }
                return Ok(pending);
            }
            match self.recv_meaningful().await? {
                ServerMessage::Message {
                    side,
                    phase,
                    body,
                    id,
                } => {
                    if side == self.side {
                        continue;
                    }
                    if phase != expected_phase {
                        return Err(MailboxError::Unexpected(format!(
                            "expected phase {expected_phase}, got {phase}"
                        )));
                    }
                    return Ok(PhaseMessage {
                        side,
                        phase,
                        body: body.into_inner(),
                        id,
                    });
                }
                ServerMessage::Closed { mood } => {
                    return Err(MailboxError::Closed { mood });
                }
                other => {
                    return Err(MailboxError::Unexpected(format!(
                        "expected message, got {other:?}"
                    )));
                }
            }
        }
    }

    /// Send a happy close frame.
    pub async fn close_happy(&mut self) -> Result<(), MailboxError> {
        self.transport.send(ClientMessage::close_happy()).await?;
        self.await_closed().await
    }

    /// Send a scary close frame with the supplied reason.
    pub async fn close_scary(&mut self, reason: &str) -> Result<(), MailboxError> {
        self.transport
            .send(ClientMessage::Close {
                mailbox: None,
                mood: Some(format!("scary: {reason}")),
            })
            .await?;
        self.await_closed().await
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
    Ack { id: String },
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
    use std::collections::VecDeque;

    /// Test transport that records sent client messages and replays
    /// queued server messages in FIFO order.
    pub(super) struct ScriptedMailboxTransport {
        sent: Vec<ClientMessage>,
        queued: VecDeque<ServerMessage>,
    }

    impl ScriptedMailboxTransport {
        pub(super) fn new(queued: Vec<ServerMessage>) -> Self {
            Self {
                sent: Vec::new(),
                queued: queued.into(),
            }
        }

        pub(super) fn sent_types(&self) -> Vec<String> {
            self.sent
                .iter()
                .map(|m| match m {
                    ClientMessage::Bind { .. } => "bind",
                    ClientMessage::Allocate => "allocate",
                    ClientMessage::Claim { .. } => "claim",
                    ClientMessage::Release { .. } => "release",
                    ClientMessage::Open { .. } => "open",
                    ClientMessage::Add { .. } => "add",
                    ClientMessage::Close { .. } => "close",
                })
                .map(str::to_owned)
                .collect()
        }

        pub(super) fn sent(&self) -> &[ClientMessage] {
            &self.sent
        }
    }

    #[async_trait]
    impl MailboxTransport for ScriptedMailboxTransport {
        async fn send(&mut self, msg: ClientMessage) -> Result<(), MailboxError> {
            self.sent.push(msg);
            Ok(())
        }

        async fn recv(&mut self) -> Result<ServerMessage, MailboxError> {
            self.queued
                .pop_front()
                .ok_or_else(|| MailboxError::Transport("no more queued frames".into()))
        }
    }

    #[tokio::test]
    async fn scripted_transport_drives_offer_setup() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Welcome {
                welcome: serde_json::json!({}),
            },
            ServerMessage::Allocated {
                nameplate: "2".to_owned(),
            },
            ServerMessage::Claimed {
                mailbox: "mailbox-1".to_owned(),
            },
            ServerMessage::Ack {
                id: "open".to_owned(),
            },
        ]);

        let setup = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport)
            .allocate_and_open()
            .await
            .unwrap();

        assert_eq!(setup.nameplate, "2");
        assert_eq!(setup.mailbox, "mailbox-1");
        assert_eq!(
            transport.sent_types(),
            vec!["bind", "allocate", "claim", "open"],
        );
    }

    #[tokio::test]
    async fn scripted_transport_drives_accept_setup() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Welcome {
                welcome: serde_json::json!({}),
            },
            ServerMessage::Claimed {
                mailbox: "mailbox-1".to_owned(),
            },
            ServerMessage::Ack {
                id: "open".to_owned(),
            },
        ]);

        let setup = MailboxClient::new("portl.exchange.v1", "side-b", &mut transport)
            .claim_and_open("2")
            .await
            .unwrap();

        assert_eq!(setup.nameplate, "2");
        assert_eq!(setup.mailbox, "mailbox-1");
        assert_eq!(transport.sent_types(), vec!["bind", "claim", "open"]);
    }

    #[tokio::test]
    async fn server_error_converts_to_mailbox_error() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Welcome {
                welcome: serde_json::json!({}),
            },
            ServerMessage::Error {
                error: "bad nameplate".to_owned(),
            },
        ]);

        let err = MailboxClient::new("portl.exchange.v1", "side-b", &mut transport)
            .claim_and_open("2")
            .await
            .unwrap_err();

        match err {
            MailboxError::Server(msg) => assert_eq!(msg, "bad nameplate"),
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn ack_frames_are_skipped_during_setup() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Ack {
                id: "ignored".to_owned(),
            },
            ServerMessage::Welcome {
                welcome: serde_json::json!({}),
            },
            ServerMessage::Ack {
                id: "ignored2".to_owned(),
            },
            ServerMessage::Claimed {
                mailbox: "mailbox-1".to_owned(),
            },
            ServerMessage::Ack {
                id: "open".to_owned(),
            },
        ]);

        let setup = MailboxClient::new("portl.exchange.v1", "side-b", &mut transport)
            .claim_and_open("2")
            .await
            .unwrap();
        assert_eq!(setup.mailbox, "mailbox-1");
    }

    #[tokio::test]
    async fn recv_phase_ignores_own_side_and_returns_peer() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Message {
                side: "me".into(),
                phase: "pake".into(),
                body: HexBody::new(b"echo".to_vec()),
                id: "1".into(),
            },
            ServerMessage::Ack {
                id: "1".into(),
            },
            ServerMessage::Message {
                side: "peer".into(),
                phase: "pake".into(),
                body: HexBody::new(b"hello".to_vec()),
                id: "2".into(),
            },
        ]);

        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        let msg = client.recv_phase_from_peer("pake").await.unwrap();
        assert_eq!(msg.side, "peer");
        assert_eq!(msg.phase, "pake");
        assert_eq!(msg.body, b"hello");
        assert_eq!(msg.id, "2");
    }

    #[tokio::test]
    async fn close_happy_sends_close_frame() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Closed {
            mood: None,
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        client.close_happy().await.unwrap();
        let sent = transport.sent();
        assert_eq!(sent.len(), 1);
        match &sent[0] {
            ClientMessage::Close { mailbox, mood } => {
                assert!(mailbox.is_none());
                assert_eq!(mood.as_deref(), Some("happy"));
            }
            other => panic!("expected close, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_scary_sends_scary_mood() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Ack { id: "close".into() },
            ServerMessage::Closed { mood: None },
        ]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        client.close_scary("mismatch").await.unwrap();
        match &transport.sent()[0] {
            ClientMessage::Close { mood: Some(m), .. } => {
                assert!(m.contains("scary"));
                assert!(m.contains("mismatch"));
            }
            other => panic!("expected scary close, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn open_surfaces_server_error_after_claim() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Welcome {
                welcome: serde_json::json!({}),
            },
            ServerMessage::Claimed {
                mailbox: "mailbox-1".to_owned(),
            },
            ServerMessage::Error {
                error: "mailbox already closed".to_owned(),
            },
        ]);

        let err = MailboxClient::new("portl.exchange.v1", "side-b", &mut transport)
            .claim_and_open("2")
            .await
            .unwrap_err();
        match err {
            MailboxError::Server(msg) => assert_eq!(msg, "mailbox already closed"),
            other => panic!("expected Server error, got {other:?}"),
        }
        assert_eq!(transport.sent_types(), vec!["bind", "claim", "open"]);
    }

    #[tokio::test]
    async fn send_phase_awaits_ack_and_records_add() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Ack {
            id: "add".into(),
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        client.send_phase("pake", b"hi").await.unwrap();
        assert_eq!(transport.sent_types(), vec!["add"]);
        match &transport.sent()[0] {
            ClientMessage::Add { phase, body } => {
                assert_eq!(phase, "pake");
                assert_eq!(body.as_bytes(), b"hi");
            }
            other => panic!("expected add, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_phase_surfaces_server_error_after_add() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Error {
            error: "mailbox not open".to_owned(),
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        let err = client.send_phase("pake", b"hi").await.unwrap_err();
        match err {
            MailboxError::Server(msg) => assert_eq!(msg, "mailbox not open"),
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_happy_awaits_closed_response() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Ack { id: "close".into() },
            ServerMessage::Closed {
                mood: Some("happy".into()),
            },
        ]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        client.close_happy().await.unwrap();
        assert_eq!(transport.sent_types(), vec!["close"]);
    }

    #[tokio::test]
    async fn close_happy_surfaces_server_error() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Error {
            error: "no mailbox open".to_owned(),
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        let err = client.close_happy().await.unwrap_err();
        match err {
            MailboxError::Server(msg) => assert_eq!(msg, "no mailbox open"),
            other => panic!("expected Server error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_scary_surfaces_server_error() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Error {
            error: "no mailbox open".to_owned(),
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "side-a", &mut transport);
        let err = client.close_scary("oops").await.unwrap_err();
        match err {
            MailboxError::Server(msg) => assert_eq!(msg, "no mailbox open"),
            other => panic!("expected Server error, got {other:?}"),
        }
    }

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
    fn server_ack_requires_id() {
        let result = serde_json::from_str::<ServerMessage>(r#"{"type":"ack"}"#);
        assert!(result.is_err(), "ack without id must fail to deserialize");
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

    #[tokio::test]
    async fn send_phase_buffers_peer_message_before_ack() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Message {
                side: "peer".into(),
                phase: "pake".into(),
                body: HexBody::new(b"hello".to_vec()),
                id: "m1".into(),
            },
            ServerMessage::Ack { id: "add".into() },
        ]);
        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        client.send_phase("pake", b"hi").await.unwrap();
        let msg = client.recv_phase_from_peer("pake").await.unwrap();
        assert_eq!(msg.side, "peer");
        assert_eq!(msg.body, b"hello");
        assert_eq!(msg.id, "m1");
    }

    #[tokio::test]
    async fn close_happy_buffers_peer_message_before_closed() {
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Ack { id: "close".into() },
            ServerMessage::Message {
                side: "peer".into(),
                phase: "version".into(),
                body: HexBody::new(b"v".to_vec()),
                id: "m2".into(),
            },
            ServerMessage::Closed {
                mood: Some("happy".into()),
            },
        ]);
        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        client.close_happy().await.unwrap();
        let msg = client.recv_phase_from_peer("version").await.unwrap();
        assert_eq!(msg.side, "peer");
        assert_eq!(msg.body, b"v");
        assert_eq!(msg.id, "m2");
    }

    #[tokio::test]
    async fn recv_phase_skips_buffered_own_side_message() {
        // First, stash an own-side message via send_phase racing with an Ack.
        let mut transport = ScriptedMailboxTransport::new(vec![
            ServerMessage::Message {
                side: "me".into(),
                phase: "pake".into(),
                body: HexBody::new(b"echo".to_vec()),
                id: "self".into(),
            },
            ServerMessage::Ack { id: "add".into() },
            // Then a real peer message via the live transport.
            ServerMessage::Message {
                side: "peer".into(),
                phase: "pake".into(),
                body: HexBody::new(b"hello".to_vec()),
                id: "m3".into(),
            },
        ]);
        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        client.send_phase("pake", b"hi").await.unwrap();
        let msg = client.recv_phase_from_peer("pake").await.unwrap();
        assert_eq!(msg.side, "peer");
        assert_eq!(msg.id, "m3");
    }

    #[tokio::test]
    async fn recv_phase_surfaces_closed_as_error() {
        let mut transport = ScriptedMailboxTransport::new(vec![ServerMessage::Closed {
            mood: Some("scary: peer aborted".into()),
        }]);
        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        let err = client.recv_phase_from_peer("1").await.unwrap_err();
        match err {
            MailboxError::Closed { mood } => {
                assert_eq!(mood.as_deref(), Some("scary: peer aborted"));
            }
            other => panic!("expected Closed error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pending_messages_cap_is_enforced() {
        let mut frames: Vec<ServerMessage> = (0..=MAX_PENDING_MESSAGES)
            .map(|i| ServerMessage::Message {
                side: "peer".into(),
                phase: "pake".into(),
                body: HexBody::new(format!("m{i}").into_bytes()),
                id: format!("id-{i}"),
            })
            .collect();
        // Followed by the ack we are nominally awaiting.
        frames.push(ServerMessage::Ack { id: "add".into() });
        let mut transport = ScriptedMailboxTransport::new(frames);
        let mut client = MailboxClient::new("portl.exchange.v1", "me", &mut transport);
        let err = client.send_phase("pake", b"hi").await.unwrap_err();
        match err {
            MailboxError::Unexpected(msg) => {
                assert!(msg.contains("pending phase buffer"), "got: {msg}");
            }
            other => panic!("expected Unexpected, got {other:?}"),
        }
    }
}
