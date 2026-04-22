use anyhow::{Context, Result, bail};
use iroh::endpoint::Connection;

use crate::endpoint::Endpoint;
use crate::id::Identity;
use crate::ticket::hash::ticket_id;
use crate::ticket::offer::compute_pop_sig;
use crate::ticket::schema::{Capabilities, PortlTicket};
use crate::wire::{AckReason, TicketAck, TicketOffer};

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
    // NOTE: we used to `await endpoint.inner().online()` here to
    // ensure a relay was connected before dialing. That call has an
    // iroh 0.98.x bug (see crash on `Endpoint::online` /
    // `endpoint.rs:1291`): when `any()` on the home-relay-status
    // Flatten iterator short-circuits, dropping the underlying
    // `Vec<Option<(RelayUrl, HomeRelayStatus)>>` aborts the process
    // with `malloc: pointer being freed was not allocated` on
    // macOS. `Endpoint::connect()` already picks a relay on its own
    // if one isn't yet connected, so skipping the pre-wait costs us
    // only a tiny bit of first-dial latency in exchange for not
    // crashing the CLI. Drop this workaround once we move to an
    // iroh release that fixes the `online()` drop path.
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

mod portl_alpn {
    pub const ALPN_TICKET_V1: &[u8] = b"portl/ticket/v1";
}
