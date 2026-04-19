use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;
use serde::{Deserialize, Serialize};

use crate::endpoint::Endpoint;
use crate::id::Identity;
use crate::ticket::hash::ticket_id;
use crate::ticket::offer::compute_pop_sig;
use crate::ticket::schema::{Capabilities, PortlTicket};

const MAX_ACK_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerSession {
    pub peer_token: [u8; 16],
    pub effective_caps: Capabilities,
    pub server_time: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TicketHandshakeError {
    pub reason: Option<AckReason>,
}

impl std::fmt::Display for TicketHandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.reason {
            Some(reason) => write!(f, "ticket handshake rejected: {reason:?}"),
            None => write!(f, "ticket handshake rejected"),
        }
    }
}

impl std::error::Error for TicketHandshakeError {}

pub async fn open_ticket_v1(
    endpoint: &Endpoint,
    ticket: &PortlTicket,
    chain: &[PortlTicket],
    identity: &Identity,
) -> Result<(Connection, PeerSession)> {
    endpoint.inner().online().await;

    let connection = endpoint
        .inner()
        .connect(ticket.addr.clone(), portl_alpn::ALPN_TICKET_V1)
        .await
        .context("connect ticket/v1")?;
    let (mut send, mut recv) = connection.open_bi().await.context("open ticket stream")?;

    let client_nonce = rand::random::<[u8; 16]>();
    let proof = ticket.body.to.map(|_| {
        compute_pop_sig(
            identity.signing_key(),
            &ticket_id(&ticket.sig),
            &client_nonce,
        )
    });
    let offer = TicketOffer {
        ticket: crate::ticket::encode(ticket).context("encode terminal ticket")?,
        chain: chain
            .iter()
            .map(|ticket| crate::ticket::encode(ticket).context("encode chain ticket"))
            .collect::<Result<Vec<_>>>()?,
        proof,
        client_nonce,
    };

    let offer_bytes = postcard::to_stdvec(&offer).context("encode ticket offer")?;
    send.write_all(&offer_bytes).await.context("write offer")?;
    send.finish().context("finish offer")?;

    let ack_bytes = recv.read_to_end(MAX_ACK_BYTES).await.context("read ack")?;
    let ack: TicketAck = postcard::from_bytes(&ack_bytes).context("decode ticket ack")?;
    if !ack.ok {
        return Err(TicketHandshakeError { reason: ack.reason }.into());
    }

    let peer_token = ack
        .peer_token
        .context("missing peer_token in accepted ack")?;
    let effective_caps = ack
        .effective_caps
        .context("missing effective_caps in accepted ack")?;
    if ack.reason.is_some() {
        bail!("accepted ack unexpectedly carried a rejection reason");
    }

    Ok((
        connection,
        PeerSession {
            peer_token,
            effective_caps,
            server_time: ack.server_time,
        },
    ))
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TicketOffer {
    ticket: Vec<u8>,
    chain: Vec<Vec<u8>>,
    #[serde(with = "option_signature_bytes")]
    proof: Option<[u8; 64]>,
    client_nonce: [u8; 16],
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct TicketAck {
    ok: bool,
    reason: Option<AckReason>,
    peer_token: Option<[u8; 16]>,
    effective_caps: Option<Capabilities>,
    server_time: u64,
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

mod portl_alpn {
    pub const ALPN_TICKET_V1: &[u8] = b"portl/ticket/v1";
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
