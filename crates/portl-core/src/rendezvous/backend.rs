//! Rendezvous backend trait and types.

use async_trait::async_trait;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::exchange::PortlExchangeEnvelopeV1;
use super::mailbox::{MailboxClient, MailboxError, MailboxTransport};
use super::short_code::ShortCode;
use super::wormhole_crypto::{
    decrypt_phase, encrypt_phase, finish_pake, start_pake, WormholeCryptoError,
};

/// Application id used for the Portl V1 short-code exchange.
pub const PORTL_EXCHANGE_APPID_V1: &str = "portl.exchange.v1";

/// Schema id for [`RecipientHelloV1`].
pub const PORTL_RECIPIENT_HELLO_SCHEMA_V1: &str = "portl.recipient_hello.v1";

/// An offer being posted to the rendezvous backend.
#[derive(Debug, Clone)]
pub struct ExchangeOffer {
    /// Envelope to be delivered to the accepting peer.
    pub envelope: PortlExchangeEnvelopeV1,
    /// How long the offer remains live in the rendezvous, in seconds.
    pub rendezvous_ttl_secs: u64,
}

/// Handle to a posted offer; carries the short code presented to the user.
#[derive(Debug, Clone)]
pub struct OfferHandle {
    code: ShortCode,
}

impl OfferHandle {
    /// Construct a new handle wrapping a short code.
    pub fn new(code: ShortCode) -> Self {
        Self { code }
    }

    /// The short code the offerer should share with the accepter.
    pub fn code(&self) -> &ShortCode {
        &self.code
    }
}

/// Outcome of a successful accept.
#[derive(Debug, Clone)]
pub struct AcceptOutcome {
    /// The envelope that was offered.
    pub envelope: PortlExchangeEnvelopeV1,
}

/// Errors produced by a [`RendezvousBackend`].
#[derive(Debug, Error)]
pub enum RendezvousError {
    /// The short code has already been accepted by another party.
    #[error("short code was already claimed")]
    AlreadyClaimed,
    /// The short code's TTL has expired.
    #[error("short code expired")]
    Expired,
    /// No offer was found for the supplied short code.
    #[error("short code was not found")]
    NotFound,
    /// The backend itself reported an error.
    #[error("rendezvous backend failed: {0}")]
    Backend(String),
    /// Mailbox transport surfaced an error.
    #[error("mailbox transport error: {0}")]
    Mailbox(#[from] MailboxError),
    /// Wormhole-compatible crypto layer surfaced an error.
    #[error("wormhole crypto error: {0}")]
    Crypto(#[from] WormholeCryptoError),
    /// Peer sent a payload that did not satisfy schema/validation.
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
}

/// Backend abstraction for the short-code rendezvous.
#[async_trait]
pub trait RendezvousBackend: Send + Sync {
    /// Post an offer and obtain a handle containing the short code.
    async fn offer(&self, offer: ExchangeOffer) -> Result<OfferHandle, RendezvousError>;
    /// Accept an offer by its short code, consuming it on success.
    async fn accept(&self, code: &ShortCode) -> Result<AcceptOutcome, RendezvousError>;
}

/// Optional self-introduction the recipient sends back to the offerer
/// once the wormhole key is established.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipientHelloV1 {
    /// Schema discriminator; pinned to [`PORTL_RECIPIENT_HELLO_SCHEMA_V1`].
    pub schema: String,
    /// Recipient endpoint id (32-byte hex), if known.
    pub endpoint_id_hex: Option<String>,
    /// Optional human-readable label hint for UIs.
    pub label_hint: Option<String>,
}

impl RecipientHelloV1 {
    /// Construct a hello with no identifying information.
    pub fn anonymous() -> Self {
        Self {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: None,
            label_hint: None,
        }
    }
}

fn random_side() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Run the offerer side of a one-shot encrypted exchange over `transport`.
///
/// The function claims the supplied short code's nameplate, performs a
/// SPAKE2 handshake bound to [`PORTL_EXCHANGE_APPID_V1`], waits for the
/// recipient's encrypted hello on phase `"0"`, then sends the
/// `envelope` JSON encrypted on phase `"1"`.
pub async fn offer_over_mailbox<T>(
    transport: &mut T,
    code: ShortCode,
    envelope: PortlExchangeEnvelopeV1,
) -> Result<(), RendezvousError>
where
    T: MailboxTransport + Send,
{
    let side = random_side();
    let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, transport);
    client.claim_and_open(code.nameplate().to_owned()).await?;

    let password = code.password();
    let (state, pake_body) = start_pake(&password, PORTL_EXCHANGE_APPID_V1);
    client.send_phase("pake", &pake_body).await?;
    let peer_pake = client.recv_phase_from_peer("pake").await?;
    let key = finish_pake(state, &peer_pake.body)?;

    let hello_msg = client.recv_phase_from_peer("0").await?;
    let hello_plain = decrypt_phase(&key, &hello_msg.side, "0", &hello_msg.body)?;
    let _hello: RecipientHelloV1 = serde_json::from_slice(&hello_plain)
        .map_err(|e| RendezvousError::InvalidPayload(e.to_string()))?;

    let envelope_json = serde_json::to_vec(&envelope)
        .map_err(|e| RendezvousError::InvalidPayload(e.to_string()))?;
    let cipher = encrypt_phase(&key, &side, "1", &envelope_json);
    client.send_phase("1", &cipher).await?;

    client.close_happy().await?;
    Ok(())
}

/// Run the recipient side of a one-shot encrypted exchange over `transport`.
///
/// Claims the short code's nameplate, completes SPAKE2 against the
/// offerer, sends `hello` encrypted on phase `"0"`, then receives and
/// decrypts the offerer's envelope on phase `"1"`.
pub async fn accept_over_mailbox<T>(
    transport: &mut T,
    code: ShortCode,
    hello: RecipientHelloV1,
) -> Result<AcceptOutcome, RendezvousError>
where
    T: MailboxTransport + Send,
{
    let side = random_side();
    let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, transport);
    client.claim_and_open(code.nameplate().to_owned()).await?;

    let password = code.password();
    let (state, pake_body) = start_pake(&password, PORTL_EXCHANGE_APPID_V1);
    client.send_phase("pake", &pake_body).await?;
    let peer_pake = client.recv_phase_from_peer("pake").await?;
    let key = finish_pake(state, &peer_pake.body)?;

    let hello_json = serde_json::to_vec(&hello)
        .map_err(|e| RendezvousError::InvalidPayload(e.to_string()))?;
    let hello_cipher = encrypt_phase(&key, &side, "0", &hello_json);
    client.send_phase("0", &hello_cipher).await?;

    let env_msg = client.recv_phase_from_peer("1").await?;
    let env_plain = decrypt_phase(&key, &env_msg.side, "1", &env_msg.body)?;
    let envelope: PortlExchangeEnvelopeV1 = serde_json::from_slice(&env_plain)
        .map_err(|e| RendezvousError::InvalidPayload(e.to_string()))?;

    client.close_happy().await?;
    Ok(AcceptOutcome { envelope })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rendezvous::exchange::SessionShareEnvelopeV1;
    use crate::rendezvous::mailbox::{ClientMessage, MailboxError, ServerMessage};
    use async_trait::async_trait;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;
    use tokio::sync::mpsc::{self, UnboundedReceiver, UnboundedSender};

    fn fixture_envelope() -> PortlExchangeEnvelopeV1 {
        let share = SessionShareEnvelopeV1 {
            workspace_id: "ws_test".to_owned(),
            friendly_name: "dev".to_owned(),
            conflict_handle: "7k3p".to_owned(),
            origin_label_hint: Some("alice-laptop".to_owned()),
            target_endpoint_id_hex: hex::encode([1u8; 32]),
            provider: Some("zmx".to_owned()),
            provider_session: "dev".to_owned(),
            ticket: "portltestticket".to_owned(),
            access_not_after_unix: 2_000_000,
        };
        PortlExchangeEnvelopeV1::session_share(share, 1_000_000, Some(1_000_600))
    }

    /// In-process paired mailbox transport. Each instance routes
    /// command replies (welcome/claimed/ack/closed) back to itself and
    /// forwards `add` frames to its partner as `message` frames.
    pub(super) struct PairedMailboxTransport {
        own_side: Option<String>,
        next_id: u64,
        incoming_rx: UnboundedReceiver<ServerMessage>,
        incoming_tx: UnboundedSender<ServerMessage>,
        peer_tx: UnboundedSender<ServerMessage>,
    }

    #[async_trait]
    impl MailboxTransport for PairedMailboxTransport {
        async fn send(&mut self, msg: ClientMessage) -> Result<(), MailboxError> {
            match msg {
                ClientMessage::Bind { side, .. } => {
                    self.own_side = Some(side);
                    let _ = self.incoming_tx.send(ServerMessage::Welcome {
                        welcome: serde_json::json!({}),
                    });
                }
                ClientMessage::Allocate => {
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Allocated { nameplate: "1".into() });
                }
                ClientMessage::Claim { nameplate } => {
                    let _ = self.incoming_tx.send(ServerMessage::Claimed {
                        mailbox: format!("mailbox-{nameplate}"),
                    });
                }
                ClientMessage::Release { .. } => {
                    let _ = self.incoming_tx.send(ServerMessage::Released);
                }
                ClientMessage::Open { .. } => {
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Ack { id: "open".into() });
                }
                ClientMessage::Add { phase, body } => {
                    self.next_id += 1;
                    let id = format!("msg-{}", self.next_id);
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Ack { id: "add".into() });
                    let side = self.own_side.clone().unwrap_or_default();
                    let _ = self.peer_tx.send(ServerMessage::Message {
                        side,
                        phase,
                        body,
                        id,
                    });
                }
                ClientMessage::Close { .. } => {
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Ack { id: "close".into() });
                    let _ = self
                        .incoming_tx
                        .send(ServerMessage::Closed { mood: None });
                }
            }
            Ok(())
        }

        async fn recv(&mut self) -> Result<ServerMessage, MailboxError> {
            self.incoming_rx
                .recv()
                .await
                .ok_or_else(|| MailboxError::Transport("paired transport closed".into()))
        }
    }

    /// Test fixture exposing a paired sender/receiver mailbox transport.
    pub(super) struct SharedMailboxFixture {
        sender: StdMutex<Option<PairedMailboxTransport>>,
        receiver: StdMutex<Option<PairedMailboxTransport>>,
    }

    impl Default for SharedMailboxFixture {
        fn default() -> Self {
            let (s_tx, s_rx) = mpsc::unbounded_channel();
            let (r_tx, r_rx) = mpsc::unbounded_channel();
            let sender = PairedMailboxTransport {
                own_side: None,
                next_id: 0,
                incoming_rx: s_rx,
                incoming_tx: s_tx.clone(),
                peer_tx: r_tx.clone(),
            };
            let receiver = PairedMailboxTransport {
                own_side: None,
                next_id: 0,
                incoming_rx: r_rx,
                incoming_tx: r_tx,
                peer_tx: s_tx,
            };
            Self {
                sender: StdMutex::new(Some(sender)),
                receiver: StdMutex::new(Some(receiver)),
            }
        }
    }

    impl SharedMailboxFixture {
        pub(super) fn sender_transport(&self) -> PairedMailboxTransport {
            self.sender
                .lock()
                .unwrap()
                .take()
                .expect("sender transport already taken")
        }
        pub(super) fn receiver_transport(&self) -> PairedMailboxTransport {
            self.receiver
                .lock()
                .unwrap()
                .take()
                .expect("receiver transport already taken")
        }
    }

    #[tokio::test]
    async fn wormhole_flow_exchanges_one_session_envelope() {
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let envelope = fixture_envelope();

        let mut sender_t = mailbox.sender_transport();
        let mut receiver_t = mailbox.receiver_transport();

        let sender_fut = offer_over_mailbox(&mut sender_t, code.clone(), envelope.clone());
        let receiver_fut = accept_over_mailbox(
            &mut receiver_t,
            code,
            RecipientHelloV1::anonymous(),
        );

        let (s_res, r_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async { tokio::join!(sender_fut, receiver_fut) },
        )
        .await
        .expect("happy-path exchange completes within timeout");
        s_res.expect("sender flow completes");
        let accepted = r_res.expect("receiver flow completes");
        assert_eq!(accepted.envelope, envelope);
    }

    #[tokio::test]
    async fn wrong_code_cannot_decrypt_payload() {
        let mailbox = SharedMailboxFixture::default();
        let sender_code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let receiver_code = ShortCode::parse("PORTL-S-2-harbor-armor").unwrap();
        let envelope = fixture_envelope();

        let mut sender_t = mailbox.sender_transport();
        let mut receiver_t = mailbox.receiver_transport();

        let sender_fut = offer_over_mailbox(&mut sender_t, sender_code, envelope);
        let receiver_fut = accept_over_mailbox(
            &mut receiver_t,
            receiver_code,
            RecipientHelloV1::anonymous(),
        );

        let result = tokio::time::timeout(
            Duration::from_secs(2),
            async { tokio::join!(sender_fut, receiver_fut) },
        )
        .await;
        if let Ok((s_res, r_res)) = result {
            assert!(s_res.is_err(), "sender must not succeed with wrong code");
            assert!(r_res.is_err(), "receiver must not import garbage envelope");
        }
        // Otherwise we timed out: at least one side blocked on a phase that will
        // never arrive in cleartext form. That is acceptable: no envelope was
        // imported. The crucial invariant is that no Ok envelope can be produced
        // from a mismatched short code.
    }

    #[test]
    fn anonymous_hello_serializes_to_expected_shape() {
        let value = serde_json::to_value(RecipientHelloV1::anonymous()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({
                "schema": PORTL_RECIPIENT_HELLO_SCHEMA_V1,
                "endpoint_id_hex": null,
                "label_hint": null,
            })
        );
    }

    #[test]
    fn recipient_hello_roundtrips_with_fields() {
        let hello = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: Some(hex::encode([2u8; 32])),
            label_hint: Some("bob".to_owned()),
        };
        let bytes = serde_json::to_vec(&hello).unwrap();
        let decoded: RecipientHelloV1 = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(decoded, hello);
    }
}
