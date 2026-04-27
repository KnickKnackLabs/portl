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

    /// Validate self-consistency of a recipient hello before it is sent
    /// or trusted on receive.
    ///
    /// * `schema` must equal [`PORTL_RECIPIENT_HELLO_SCHEMA_V1`].
    /// * `endpoint_id_hex`, when present, must be 64 ASCII hex chars
    ///   decoding to exactly 32 bytes.
    /// * `label_hint`, when present, is bounded to 128 bytes to keep
    ///   the wire payload small.
    pub fn validate(&self) -> Result<(), RendezvousError> {
        if self.schema != PORTL_RECIPIENT_HELLO_SCHEMA_V1 {
            return Err(RendezvousError::InvalidPayload(format!(
                "unexpected hello schema {:?}",
                self.schema
            )));
        }
        if let Some(hexed) = self.endpoint_id_hex.as_deref() {
            if hexed.len() != 64 {
                return Err(RendezvousError::InvalidPayload(format!(
                    "endpoint_id_hex must be 64 chars, got {}",
                    hexed.len()
                )));
            }
            let decoded = hex::decode(hexed).map_err(|e| {
                RendezvousError::InvalidPayload(format!("endpoint_id_hex not valid hex: {e}"))
            })?;
            if decoded.len() != 32 {
                return Err(RendezvousError::InvalidPayload(format!(
                    "endpoint_id_hex must decode to 32 bytes, got {}",
                    decoded.len()
                )));
            }
        }
        if let Some(label) = self.label_hint.as_deref()
            && label.len() > 128
        {
            return Err(RendezvousError::InvalidPayload(format!(
                "label_hint exceeds 128 bytes ({} bytes)",
                label.len()
            )));
        }
        Ok(())
    }
}

fn random_side() -> String {
    let mut bytes = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut bytes);
    hex::encode(bytes)
}

/// Try to send a `scary` close on `client`, ignoring any error. Used to
/// signal the peer that we are aborting so they observe a deterministic
/// `Closed` instead of an indefinite wait.
async fn best_effort_close_scary<T>(client: &mut MailboxClient<'_, T>, reason: &str)
where
    T: MailboxTransport + Send,
{
    let _ = client.close_scary(reason).await;
}

/// Run the offerer side of a one-shot encrypted exchange over `transport`.
///
/// The function claims the supplied short code's nameplate, performs a
/// SPAKE2 handshake bound to [`PORTL_EXCHANGE_APPID_V1`], waits for the
/// recipient's encrypted hello on phase `"0"`, then sends the
/// `envelope` JSON encrypted on phase `"1"`.
///
/// Note: `code` here is assumed to be an already-established
/// `PORTL-S-*` short code (nameplate + password). Allocation/display of
/// fresh codes is the responsibility of the higher-level
/// [`RendezvousBackend`] (Task 9). This entry point is the
/// transport-level encrypted exchange only.
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
    let key = match finish_pake(state, &peer_pake.body) {
        Ok(k) => k,
        Err(e) => {
            best_effort_close_scary(&mut client, "pake failed").await;
            return Err(e.into());
        }
    };

    let hello_msg = client.recv_phase_from_peer("0").await?;
    let hello_plain = match decrypt_phase(&key, &hello_msg.side, "0", &hello_msg.body) {
        Ok(plain) => plain,
        Err(e) => {
            best_effort_close_scary(&mut client, "hello decrypt failed").await;
            return Err(e.into());
        }
    };
    let hello: RecipientHelloV1 = match serde_json::from_slice(&hello_plain) {
        Ok(h) => h,
        Err(e) => {
            best_effort_close_scary(&mut client, "hello deserialize failed").await;
            return Err(RendezvousError::InvalidPayload(e.to_string()));
        }
    };
    if let Err(e) = hello.validate() {
        best_effort_close_scary(&mut client, "hello validation failed").await;
        return Err(e);
    }

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
    hello.validate()?;
    let side = random_side();
    let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, transport);
    client.claim_and_open(code.nameplate().to_owned()).await?;

    let password = code.password();
    let (state, pake_body) = start_pake(&password, PORTL_EXCHANGE_APPID_V1);
    client.send_phase("pake", &pake_body).await?;
    let peer_pake = client.recv_phase_from_peer("pake").await?;
    let key = match finish_pake(state, &peer_pake.body) {
        Ok(k) => k,
        Err(e) => {
            best_effort_close_scary(&mut client, "pake failed").await;
            return Err(e.into());
        }
    };

    let hello_json = serde_json::to_vec(&hello)
        .map_err(|e| RendezvousError::InvalidPayload(e.to_string()))?;
    let hello_cipher = encrypt_phase(&key, &side, "0", &hello_json);
    client.send_phase("0", &hello_cipher).await?;

    let env_msg = client.recv_phase_from_peer("1").await?;
    let env_plain = match decrypt_phase(&key, &env_msg.side, "1", &env_msg.body) {
        Ok(plain) => plain,
        Err(e) => {
            best_effort_close_scary(&mut client, "envelope decrypt failed").await;
            return Err(e.into());
        }
    };
    let envelope: PortlExchangeEnvelopeV1 = match serde_json::from_slice(&env_plain) {
        Ok(env) => env,
        Err(e) => {
            best_effort_close_scary(&mut client, "envelope deserialize failed").await;
            return Err(RendezvousError::InvalidPayload(e.to_string()));
        }
    };

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
                    // Mirror to the peer so the partner observes a
                    // deterministic mailbox close instead of waiting
                    // forever on a phase that will never arrive.
                    let _ = self
                        .peer_tx
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

        let (s_res, r_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async { tokio::join!(sender_fut, receiver_fut) },
        )
        .await
        .expect("wrong-code flow must complete within bounded timeout");
        assert!(
            s_res.is_err() || r_res.is_err(),
            "at least one side must produce a deterministic error"
        );
        assert!(
            r_res.is_err(),
            "receiver must not import garbage envelope, got {:?}",
            r_res.as_ref().map(|_| "Ok")
        );
    }

    #[tokio::test]
    async fn invalid_hello_schema_rejected_before_send() {
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let mut receiver_t = mailbox.receiver_transport();
        let bad = RecipientHelloV1 {
            schema: "wrong.schema".to_owned(),
            endpoint_id_hex: None,
            label_hint: None,
        };
        let err = accept_over_mailbox(&mut receiver_t, code, bad)
            .await
            .expect_err("invalid schema must reject");
        assert!(matches!(err, RendezvousError::InvalidPayload(_)), "{err:?}");
    }

    #[tokio::test]
    async fn invalid_endpoint_id_rejected_before_send() {
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let mut receiver_t = mailbox.receiver_transport();
        let bad = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: Some("nothex".to_owned()),
            label_hint: None,
        };
        let err = accept_over_mailbox(&mut receiver_t, code, bad)
            .await
            .expect_err("invalid endpoint id must reject");
        assert!(matches!(err, RendezvousError::InvalidPayload(_)), "{err:?}");
    }

    #[tokio::test]
    async fn offer_rejects_invalid_hello_from_peer() {
        // Custom paired flow: receiver sends a hello with wrong schema.
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let envelope = fixture_envelope();

        let mut sender_t = mailbox.sender_transport();
        let mut receiver_t = mailbox.receiver_transport();

        // Drive the receiver side manually so it can send a hello whose
        // schema is invalid; the offer side must reject deterministically.

        let receiver_code = code.clone();
        let receiver_fut = async move {
            use crate::rendezvous::wormhole_crypto::{encrypt_phase, finish_pake, start_pake};
            let side = "receiver-side".to_owned();
            let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, &mut receiver_t);
            client
                .claim_and_open(receiver_code.nameplate().to_owned())
                .await
                .map_err(RendezvousError::from)?;
            let password = receiver_code.password();
            let (state, pake_body) = start_pake(&password, PORTL_EXCHANGE_APPID_V1);
            client.send_phase("pake", &pake_body).await?;
            let peer_pake = client.recv_phase_from_peer("pake").await?;
            let key = finish_pake(state, &peer_pake.body)?;
            let bad_hello = serde_json::json!({
                "schema": "evil.schema",
                "endpoint_id_hex": null,
                "label_hint": null,
            });
            let hello_json = serde_json::to_vec(&bad_hello).unwrap();
            let cipher = encrypt_phase(&key, &side, "0", &hello_json);
            client.send_phase("0", &cipher).await?;
            // Wait for envelope or close.
            let res = client.recv_phase_from_peer("1").await;
            Ok::<_, RendezvousError>(res.is_ok())
        };

        let sender_fut = offer_over_mailbox(&mut sender_t, code.clone(), envelope);
        let (s_res, r_res) = tokio::time::timeout(
            Duration::from_secs(5),
            async { tokio::join!(sender_fut, receiver_fut) },
        )
        .await
        .expect("flow completes within timeout");
        assert!(s_res.is_err(), "sender must reject invalid hello schema");
        if let Ok(got_envelope) = r_res {
            assert!(!got_envelope, "receiver must not get envelope");
        }
    }

    #[test]
    fn validate_accepts_anonymous() {
        RecipientHelloV1::anonymous().validate().unwrap();
    }

    #[test]
    fn validate_rejects_short_endpoint_id() {
        let h = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: Some("aa".to_owned()),
            label_hint: None,
        };
        assert!(matches!(
            h.validate().unwrap_err(),
            RendezvousError::InvalidPayload(_)
        ));
    }

    #[test]
    fn validate_rejects_long_label() {
        let h = RecipientHelloV1 {
            schema: PORTL_RECIPIENT_HELLO_SCHEMA_V1.to_owned(),
            endpoint_id_hex: None,
            label_hint: Some("x".repeat(129)),
        };
        assert!(matches!(
            h.validate().unwrap_err(),
            RendezvousError::InvalidPayload(_)
        ));
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

    /// Drive a partner that completes nameplate claim/open and then
    /// sends a deliberately malformed `pake` body, so the side under
    /// test fails inside `finish_pake` and must close-scary before
    /// returning.
    async fn malformed_pake_partner(
        transport: &mut PairedMailboxTransport,
        nameplate: String,
        bad_pake_body: Vec<u8>,
    ) -> Result<(), RendezvousError> {
        let side = "bad-partner".to_owned();
        let mut client = MailboxClient::new(PORTL_EXCHANGE_APPID_V1, &side, transport);
        client.claim_and_open(nameplate).await?;
        // Receive whatever pake the peer sent; we ignore it.
        let _ = client.recv_phase_from_peer("pake").await?;
        client.send_phase("pake", &bad_pake_body).await?;
        // Wait for the peer's scary close. Recv any further message;
        // the paired transport mirrors the peer's Close as a Closed
        // frame, which surfaces as `MailboxError::Closed`.
        let res = client.recv_phase_from_peer("0").await;
        match res {
            Err(MailboxError::Closed { .. }) => Ok(()),
            Err(e) => Err(RendezvousError::from(e)),
            Ok(_) => Err(RendezvousError::InvalidPayload(
                "peer unexpectedly proceeded after malformed pake".into(),
            )),
        }
    }

    #[tokio::test]
    async fn offer_closes_scary_on_malformed_peer_pake() {
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();
        let envelope = fixture_envelope();

        let mut sender_t = mailbox.sender_transport();
        let mut receiver_t = mailbox.receiver_transport();

        let nameplate = code.nameplate().to_owned();
        let sender_fut = offer_over_mailbox(&mut sender_t, code, envelope);
        let partner_fut = malformed_pake_partner(&mut receiver_t, nameplate, b"not-json".to_vec());

        let (s_res, p_res) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(sender_fut, partner_fut)
        })
        .await
        .expect("flow completes within timeout");
        assert!(
            matches!(s_res, Err(RendezvousError::Crypto(_))),
            "sender must surface crypto error after malformed pake, got {s_res:?}"
        );
        p_res.expect("partner observes deterministic close from peer");
    }

    #[tokio::test]
    async fn accept_closes_scary_on_malformed_peer_pake() {
        let mailbox = SharedMailboxFixture::default();
        let code = ShortCode::parse("PORTL-S-2-nebula-involve").unwrap();

        let mut sender_t = mailbox.sender_transport();
        let mut receiver_t = mailbox.receiver_transport();

        let nameplate = code.nameplate().to_owned();
        let accept_fut = accept_over_mailbox(
            &mut receiver_t,
            code,
            RecipientHelloV1::anonymous(),
        );
        let partner_fut = malformed_pake_partner(&mut sender_t, nameplate, b"not-json".to_vec());

        let (a_res, p_res) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(accept_fut, partner_fut)
        })
        .await
        .expect("flow completes within timeout");
        assert!(
            matches!(a_res, Err(RendezvousError::Crypto(_))),
            "accepter must surface crypto error after malformed pake, got {a_res:?}"
        );
        p_res.expect("partner observes deterministic close from peer");
    }
}
